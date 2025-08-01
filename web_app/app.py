import os
import sys
import yaml
import subprocess
import json
import logging
import io
import threading
import time
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.websockets import WebSocket
from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any, Union

# Add parent directory to path so we can import from the main project
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import functions from clone_device_config.py
from clone_device_config import load_yaml, fetch_config_from_source, apply_config_to_destination, create_batches
from utils.fmc_api import authenticate, get_ftd_uuid, replace_vpn_endpoint, get_vpn_topologies, get_vpn_endpoints

# Configure logging
log_stream = io.StringIO()
log_handler = logging.StreamHandler(log_stream)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Store authentication information and operation status
fmc_auth = {
    "domain_uuid": None,
    "headers": None
}

operation_status = {
    "running": False,
    "operation": None,
    "start_time": None,
    "end_time": None,
    "success": None,
    "message": None,
    "stats": {
        "interfaces": {
            "total": 0,
            "details": {
                "loopbacks": 0,
                "physicals": 0,
                "etherchannels": 0,
                "subinterfaces": 0,
                "vtis": 0
            }
        },
        "routing": {
            "total": 0,
            "details": {
                "static_routes_ipv4": 0,
                "static_routes_ipv6": 0,
                "ospfv2_policies": 0,
                "ospfv2_interfaces": 0,
                "ospfv3_policies": 0,
                "ospfv3_interfaces": 0,
                "eigrp_policies": 0,
                "bgp_policies": 0,
                "bgp_general_settings": 0
            }
        },
        "vrfs": {
            "total": 0,
            "details": {}
        },
        "vpn": {
            "total": 0,
            "details": {}
        },
        "other": {
            "total": 0,
            "details": {
                "bfd_policies": 0,
                "pbr_policies": 0,
                "ecmp_zones": 0,
                "inline_sets": 0
            }
        }
    }
}

app = FastAPI(title="FMC Tool")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Pydantic models for request validation
class FMCConnectionRequest(BaseModel):
    fmc_ip: str
    username: str
    password: str
    
    @validator('fmc_ip')
    def ensure_https_prefix(cls, v):
        if not v.startswith('http'):
            return f"https://{v}"
        return v

class CloneConfigRequest(BaseModel):
    fmc_ip: str
    username: str
    password: str
    source_ftd: str
    destination_ftd: str
    batch_size: int = 50
    operation: str = "clone"  # clone, export, import
    config_path: str = "source_ftd_config.yaml"  # Just the filename, will be placed in inputs folder
    replace_vpn: bool = False
    
    @validator('fmc_ip')
    def ensure_https_prefix(cls, v):
        if not v.startswith('http'):
            return f"https://{v}"
        return v

class LogRequest(BaseModel):
    format: str = "text"  # text or download
    
class ConfigFileRequest(BaseModel):
    filename: str

@app.get("/", response_class=HTMLResponse)
async def index():
    return RedirectResponse(url="/dashboard")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "active_page": "dashboard"})

@app.get("/clone-device", response_class=HTMLResponse)
async def clone_device(request: Request):
    return templates.TemplateResponse("clone_device.html", {"request": request, "active_page": "clone_device"})

@app.post("/api/test-connection")
async def test_connection(request: FMCConnectionRequest):
    try:
        # Test authentication to FMC
        domain_uuid, headers = authenticate(request.fmc_ip, request.username, request.password)
        
        # Store authentication information for reuse
        fmc_auth["domain_uuid"] = domain_uuid
        fmc_auth["headers"] = headers
        
        logger.info(f"Authentication successful for {request.fmc_ip}. Token stored for reuse.")
        
        return {
            'success': True,
            'message': 'Successfully connected to FMC',
            'domain_uuid': domain_uuid
        }
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to connect to FMC: {str(e)}'
        }

@app.post("/api/get-devices")
async def get_devices(request: FMCConnectionRequest):
    try:
        try:
            from utils.fmc_api import get_devicerecords
            device_records = get_devicerecords(request.fmc_ip, fmc_auth["headers"], fmc_auth["domain_uuid"], bulk=True)
            devices = []
            
            for device in device_records:
                devices.append({
                    "name": device.get('name', ''),
                    "id": device.get('id', ''),
                    "hostName": device.get('hostName', ''),
                    "model": device.get('model', 'Unknown')
                })
            
            return {
                'success': True,
                'devices': devices
            }
        except Exception as api_error:
            # Fallback to sample devices if API call fails
            import logging
            logging.error(f"Error fetching devices from FMC API: {str(api_error)}")
            
            # For demo purposes, return some sample devices as fallback
            sample_devices = [
                {"name": "ftd-1", "id": "1"},
                {"name": "ftd-2", "id": "2"},
                {"name": "4245-1", "id": "3"},
                {"name": "tpk-5", "id": "4"},
                {"name": "wm-5", "id": "5"}
            ]
            
            return {
                'success': True,
                'devices': sample_devices,
                'note': 'Using sample devices due to API error'
            }
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to get devices: {str(e)}'
        }

def ensure_inputs_directory():
    """Ensure the inputs directory exists"""
    inputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'inputs')
    if not os.path.exists(inputs_dir):
        os.makedirs(inputs_dir)
    return inputs_dir

def get_config_path(filename):
    """Get the full path for a config file in the inputs directory"""
    # If filename already contains 'inputs/', don't add it again
    if filename.startswith('inputs/'):
        return filename
    
    # Otherwise, ensure it's in the inputs directory
    inputs_dir = ensure_inputs_directory()
    return os.path.join(inputs_dir, filename)

def run_clone_operation(request: CloneConfigRequest):
    """Run the clone operation in a background thread and update operation_status"""
    global operation_status, log_stream
    
    try:
        # Reset log stream
        log_stream.truncate(0)
        log_stream.seek(0)
        
        # Update operation status
        operation_status["running"] = True
        operation_status["operation"] = request.operation
        operation_status["start_time"] = time.time()
        operation_status["success"] = None
        operation_status["message"] = f"Starting {request.operation} operation..."
        
        # Create fmc_data structure
        fmc_data = {
            'fmc_ip': request.fmc_ip,
            'username': request.username,
            'password': request.password,
            'source_ftd': request.source_ftd,
            'destination_ftd': request.destination_ftd
        }
        
        # Handle VPN endpoint replacement
        if request.replace_vpn:
            logger.info(f"Replacing VPN endpoints from {request.source_ftd} to {request.destination_ftd}")
            
            # Use the authentication info from fmc_data
            domain_uuid = fmc_data.get('domain_uuid')
            headers = fmc_data.get('headers')
            
            # Fetch VPN topologies and endpoints from FMC
            vpn_topologies = get_vpn_topologies(request.fmc_ip, headers, domain_uuid)
            vpn_configs = []
            for vpn in vpn_topologies:
                vpn_id = vpn.get("id")
                vpn_name = vpn.get("name")
                endpoints = get_vpn_endpoints(request.fmc_ip, headers, domain_uuid, vpn_id, vpn_name=vpn_name)
                vpn_copy = dict(vpn)
                vpn_copy["endpoints"] = endpoints
                vpn_configs.append(vpn_copy)
            
            # Replace VPN endpoints
            replace_vpn_endpoint(request.fmc_ip, headers, domain_uuid, request.source_ftd, request.destination_ftd, vpn_configs)
            
            # Update stats
            operation_status["stats"]["vpn"]["total"] = len(vpn_configs)
            operation_status["success"] = True
            operation_status["message"] = f"Successfully replaced VPN endpoints from {request.source_ftd} to {request.destination_ftd}"
        
        # Handle export/import/clone operations
        elif request.operation == 'export':
            # Get full config path in inputs directory
            config_path = get_config_path(request.config_path)
            logger.info(f"Exporting configuration from {request.source_ftd} to {config_path}")
            
            # Create parent directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # Fetch config from source
            config = fetch_config_from_source(fmc_data)
            
            # Count stats
            operation_status["stats"]["interfaces"] = (len(config.get('loopbacks', [])) + 
                                              len(config.get('physicals', [])) + 
                                              len(config.get('etherchannels', [])) + 
                                              len(config.get('subinterfaces', [])) + 
                                              len(config.get('vtis', [])))
            operation_status["stats"]["routes"] = (len(config.get('ipv4_static_routes', [])) + 
                                           len(config.get('ipv6_static_routes', [])))
            operation_status["stats"]["vrfs"] = len(config.get('vrfs', []))
            
            # Save to file
            with open(config_path, 'w') as f:
                yaml.safe_dump(config, f)
            
            operation_status["success"] = True
            operation_status["message"] = f"Configuration exported from {request.source_ftd} to {config_path}"
            operation_status["config_path"] = config_path
            
        elif request.operation == 'import':
            # Get full config path in inputs directory
            config_path = get_config_path(request.config_path)
            logger.info(f"Importing configuration from {config_path} to {request.destination_ftd}")
            
            # Check if file exists
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            # Load config from file
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Count stats
            operation_status["stats"]["interfaces"] = (len(config.get('loopbacks', [])) + 
                                              len(config.get('physicals', [])) + 
                                              len(config.get('etherchannels', [])) + 
                                              len(config.get('subinterfaces', [])) + 
                                              len(config.get('vtis', [])))
            operation_status["stats"]["routes"] = (len(config.get('ipv4_static_routes', [])) + 
                                           len(config.get('ipv6_static_routes', [])))
            operation_status["stats"]["vrfs"] = len(config.get('vrfs', []))
            
            # Apply config
            apply_config_to_destination(fmc_data, config, request.batch_size)
            
            operation_status["success"] = True
            operation_status["message"] = f"Configuration imported from {config_path} to {request.destination_ftd}"
            
        else:  # clone
            logger.info(f"Cloning configuration from {request.source_ftd} to {request.destination_ftd}")
            
            # Fetch config from source
            config = fetch_config_from_source(fmc_data)
            
            # Count stats
            operation_status["stats"]["interfaces"] = (len(config.get('loopbacks', [])) + 
                                              len(config.get('physicals', [])) + 
                                              len(config.get('etherchannels', [])) + 
                                              len(config.get('subinterfaces', [])) + 
                                              len(config.get('vtis', [])))
            operation_status["stats"]["routes"] = (len(config.get('ipv4_static_routes', [])) + 
                                           len(config.get('ipv6_static_routes', [])))
            operation_status["stats"]["vrfs"] = len(config.get('vrfs', []))
            
            # Apply config to destination
            apply_config_to_destination(fmc_data, config, request.batch_size)
            
            operation_status["success"] = True
            operation_status["message"] = f"Configuration cloned from {request.source_ftd} to {request.destination_ftd}"
    
    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        operation_status["success"] = False
        operation_status["message"] = f"Operation failed: {str(e)}"
    
    finally:
        operation_status["running"] = False
        operation_status["end_time"] = time.time()

@app.post("/api/clone-config")
async def clone_config(request: CloneConfigRequest, background_tasks: BackgroundTasks):
    try:
        # Start the operation in a background task
        background_tasks.add_task(run_clone_operation, request)
        
        return {
            'success': True,
            'message': f'Operation started. Check logs for progress.',
            'operation': request.operation if not request.replace_vpn else 'replace_vpn'
        }
            
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to start operation: {str(e)}'
        }

@app.get("/api/operation-status")
async def get_operation_status():
    return operation_status

@app.get("/api/logs")
async def get_logs():
    return {
        "logs": log_stream.getvalue()
    }

@app.get("/api/download-logs")
async def download_logs():
    logs = log_stream.getvalue()
    log_file = io.BytesIO(logs.encode())
    
    return StreamingResponse(
        log_file,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=fmc_tool_logs.txt"}
    )

@app.get("/api/config-files")
async def list_config_files():
    """List all available configuration files in the inputs directory"""
    try:
        inputs_dir = ensure_inputs_directory()
        files = []
        
        # Files to exclude from the dropdown
        excluded_files = ["fmc_data.yaml", "scale_bgp_config.yaml", "scale_vrf_config.yaml"]
        
        for file in os.listdir(inputs_dir):
            if (file.endswith(".yaml") or file.endswith(".yml")) and file not in excluded_files:
                file_path = os.path.join(inputs_dir, file)
                files.append({
                    "name": file,
                    "path": file_path,
                    "size": os.path.getsize(file_path),
                    "modified": os.path.getmtime(file_path)
                })
        return {
            "success": True,
            "files": files
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to list configuration files: {str(e)}"
        }

@app.get("/api/download-config/{filename}")
async def download_config(filename: str):
    """Download a configuration file"""
    try:
        # Sanitize filename to prevent directory traversal
        filename = os.path.basename(filename)
        file_path = get_config_path(filename)
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {filename}")
        
        return FileResponse(
            file_path,
            media_type="application/x-yaml",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": f"Failed to download file: {str(e)}"}
        )

@app.post("/api/upload-config")
async def upload_config(file: UploadFile = File(...)):
    """Upload a configuration file"""
    try:
        # Ensure filename is safe
        filename = os.path.basename(file.filename)
        if not (filename.endswith(".yaml") or filename.endswith(".yml")):
            raise ValueError("Only YAML files are allowed")
        
        # Save the file to the inputs directory
        file_path = get_config_path(filename)
        contents = await file.read()
        
        # Validate YAML format
        try:
            yaml.safe_load(io.BytesIO(contents))
        except yaml.YAMLError:
            raise ValueError("Invalid YAML file format")
        
        # Write the file
        with open(file_path, "wb") as f:
            f.write(contents)
        
        return {
            "success": True,
            "message": f"File {filename} uploaded successfully",
            "filename": filename,
            "path": file_path
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to upload file: {str(e)}"
        }

# VPN endpoint replacement is now integrated into the clone-config endpoint with replace_vpn=True

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
