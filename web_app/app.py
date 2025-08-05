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
from utils.scapy_modules import SSHClient, ScapyTrafficGenerator

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

# Global variables to track operation status
operation_status = {
    "running": False,
    "success": None,
    "message": "",
    "operation": "",
    "start_time": None,
    "progress_percentage": 0,
    "current_step": "",
    "total_steps": 0,
    "completed_steps": 0,
    "stats": {
        "interfaces": {"total": 0, "completed": 0},
        "routes": {"total": 0, "completed": 0},
        "vrfs": {"total": 0, "completed": 0},
        "vpn": {"total": 0, "completed": 0},
        "policies": {"total": 0, "completed": 0}
    }
}

# Flag to indicate if operation should be stopped
stop_requested = False

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
    eigrp_password: Optional[str] = None
    ospf_md5_key: Optional[str] = None
    ospf_auth_key: Optional[str] = None
    bgp_secret: Optional[str] = None
    
    @validator('fmc_ip')
    def ensure_https_prefix(cls, v):
        if not v.startswith('http'):
            return f"https://{v}"
        return v

class LogRequest(BaseModel):
    format: str = "text"  # text or download
    
class ConfigFileRequest(BaseModel):
    filename: str

class SSHConnectionRequest(BaseModel):
    host_type: str  # 'client' or 'server'
    ip: str
    port: int = 22
    username: str
    password: str

class TrafficGenerationRequest(BaseModel):
    client_ip: str
    client_port: int = 22
    client_username: str
    client_password: str
    server_ip: str
    server_port: int = 22
    server_username: str
    server_password: str
    traffic_type: str = "icmp"  # 'icmp', 'tcp', 'udp', or 'all'
    count: int = 10
    port: int = 80

@app.get("/", response_class=HTMLResponse)
async def index():
    return RedirectResponse(url="/dashboard")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "active_page": "dashboard"})

@app.get("/clone-device", response_class=HTMLResponse)
async def clone_device(request: Request):
    return templates.TemplateResponse("clone_device.html", {"request": request, "active_page": "clone_device"})

@app.get("/settings")
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request, "active_page": "settings"})

@app.get("/scapy-traffic", response_class=HTMLResponse)
async def scapy_traffic_page(request: Request):
    return templates.TemplateResponse("scapy_traffic.html", {"request": request, "active_page": "scapy_traffic"})

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
    global operation_status, log_stream, stop_requested
    
    try:
        # Reset log stream and stop flag
        log_stream.truncate(0)
        log_stream.seek(0)
        stop_requested = False
        
        # Update operation status
        operation_status["running"] = True
        operation_status["operation"] = request.operation
        operation_status["start_time"] = time.time()
        operation_status["success"] = None
        operation_status["message"] = f"Running {request.operation} operation..."
        
        # Create fmc_data structure
        fmc_data = {
            'fmc_ip': request.fmc_ip,
            'username': request.username,
            'password': request.password,
            'source_ftd': request.source_ftd,
            'destination_ftd': request.destination_ftd
        }
        
        # Create auth values dict from UI inputs
        ui_auth_values = {}
        if request.eigrp_password:
            ui_auth_values['eigrp_password'] = request.eigrp_password
        if request.ospf_md5_key:
            ui_auth_values['ospf_md5_key'] = request.ospf_md5_key
        if request.ospf_auth_key:
            ui_auth_values['ospf_auth_key'] = request.ospf_auth_key
        if request.bgp_secret:
            ui_auth_values['bgp_secret'] = request.bgp_secret
            
        # Add auth values to fmc_data
        fmc_data['ui_auth_values'] = ui_auth_values
        
        # Handle VPN endpoint replacement (either from checkbox or dropdown selection)
        if request.replace_vpn or request.operation == 'replace_vpn':
            logger.info(f"Replacing VPN endpoints from {request.source_ftd} to {request.destination_ftd}")
            
            domain_uuid, headers = authenticate(request.fmc_ip, request.username, request.password)
        
            # Store authentication information for reuse
            fmc_auth["domain_uuid"] = domain_uuid
            fmc_auth["headers"] = headers
            
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
            
            # Check if operation should be stopped
            if stop_requested:
                raise InterruptedError("Operation stopped by user request")
                
            # Apply config to destination
            apply_config_to_destination(fmc_data, config, request.batch_size)
            
            operation_status["success"] = True
            operation_status["message"] = f"Configuration cloned from {request.source_ftd} to {request.destination_ftd}"
    
    except InterruptedError as e:
        logger.info(f"Operation interrupted: {str(e)}")
        operation_status["success"] = False
        operation_status["message"] = f"Operation stopped by user"
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
    global log_stream
    
    # Create a response with the log content
    return StreamingResponse(
        io.StringIO(log_stream.getvalue()),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=operation_logs.txt"}
    )

@app.post("/api/clear-logs")
async def clear_logs():
    global log_stream
    
    try:
        # Clear the log stream
        log_stream = io.StringIO()
        
        # Re-initialize the log handler with the new stream
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and hasattr(handler, 'stream') and handler.stream is not log_stream:
                handler.stream = log_stream
        
        # Add a message indicating logs were cleared
        log_message = f"\n{time.strftime('%Y-%m-%d %H:%M:%S')} - Logs cleared by user\n"
        log_stream.write(log_message)
        log_stream.flush()
        
        return {
            "success": True,
            "message": "Logs cleared successfully"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to clear logs: {str(e)}"
        }

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

@app.post("/api/stop-operation")
async def stop_operation():
    """Stop the currently running operation"""
    global operation_status, log_stream, stop_requested
    
    try:
        if operation_status["running"]:
            # Set the stop flag to true
            stop_requested = True
            
            # Set the operation to stopped
            operation_status["running"] = False
            operation_status["success"] = False
            operation_status["message"] = "Operation stopped by user"
            
            # Log the stop action
            import time
            log_message = f"\n{time.strftime('%Y-%m-%d %H:%M:%S')} - Operation stopped by user\n"
            log_stream.write(log_message)
            log_stream.flush()
            
            return {
                "success": True,
                "message": "Operation stopped successfully"
            }
        else:
            return {
                "success": False,
                "message": "No operation is currently running"
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to stop operation: {str(e)}"
        }

# Scapy Traffic Generator API endpoints
@app.post("/api/scapy/test-connection")
async def test_ssh_connection(request: SSHConnectionRequest):
    """Test SSH connection to a host"""
    try:
        # Create SSH client
        ssh_client = SSHClient(request.ip, request.port, request.username, request.password)
        
        # Try to connect
        success, message = ssh_client.connect()
        
        if success:
            # Check if Scapy is installed
            scapy_installed, scapy_message = ssh_client.check_scapy_installed()
            ssh_client.disconnect()
            
            if not scapy_installed:
                return {
                    "success": False,
                    "message": scapy_message
                }
            
            return {
                "success": True,
                "message": f"Successfully connected to {request.host_type}"
            }
        else:
            return {
                "success": False,
                "message": message
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"Connection error: {str(e)}"
        }

@app.post("/api/scapy/generate-traffic")
async def generate_traffic(request: TrafficGenerationRequest):
    """Generate traffic between client and server"""
    try:
        # Create SSH clients
        client_ssh = SSHClient(request.client_ip, request.client_port, request.client_username, request.client_password)
        server_ssh = SSHClient(request.server_ip, request.server_port, request.server_username, request.server_password)
        
        # Connect to hosts
        client_success, client_message = client_ssh.connect()
        if not client_success:
            return {
                "success": False,
                "message": f"Failed to connect to client: {client_message}"
            }
        
        server_success, server_message = server_ssh.connect()
        if not server_success:
            client_ssh.disconnect()
            return {
                "success": False,
                "message": f"Failed to connect to server: {server_message}"
            }
        
        # Create traffic generator
        traffic_gen = ScapyTrafficGenerator(client_ssh, server_ssh)
        
        # Generate traffic based on type
        output = []
        
        try:
            # Check connectivity first
            conn_success, conn_message = traffic_gen.check_connectivity()
            output.append(conn_message)
            
            if not conn_success:
                return {
                    "success": False,
                    "message": conn_message,
                    "output": "\n".join(output)
                }
            
            # Generate traffic
            if request.traffic_type == "icmp" or request.traffic_type == "all":
                success, message = traffic_gen.generate_icmp_traffic(request.count)
                output.append(message)
            
            if request.traffic_type == "tcp" or request.traffic_type == "all":
                success, message = traffic_gen.generate_tcp_traffic(request.port, request.count)
                output.append(message)
            
            if request.traffic_type == "udp" or request.traffic_type == "all":
                success, message = traffic_gen.generate_udp_traffic(request.port, request.count)
                output.append(message)
            
            return {
                "success": True,
                "message": "Traffic generation completed",
                "output": "\n".join(output)
            }
        finally:
            # Clean up connections
            client_ssh.disconnect()
            server_ssh.disconnect()
    except Exception as e:
        return {
            "success": False,
            "message": f"Error generating traffic: {str(e)}",
            "output": str(e)
        }

# VPN endpoint replacement is now integrated into the clone-config endpoint with replace_vpn=True

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
