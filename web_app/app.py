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
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, validator, Field
from typing import Optional, List, Dict, Any, Union, Set
import asyncio
import uuid

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

# Initialize the app
app = FastAPI()

# WebSocket connection manager for traffic generation output
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        self.traffic_sessions: Dict[str, Dict[str, Any]] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.ssh_connections: Dict[str, Dict[str, SSHClient]] = {}  # Store SSH connections by IP address
    
    async def connect(self, websocket: WebSocket, session_id: str, client_type: str):
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = {}
        self.active_connections[session_id][client_type] = websocket
    
    def disconnect(self, session_id: str, client_type: str):
        if session_id in self.active_connections and client_type in self.active_connections[session_id]:
            del self.active_connections[session_id][client_type]
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]
                # Stop any running tasks for this session
                self.stop_traffic_session(session_id)
    
    async def send_message(self, message: str, session_id: str, client_type: str, message_type: str = "output"):
        """Send a message to a WebSocket client
        
        Args:
            message: The message content
            session_id: The session ID
            client_type: 'client' or 'server'
            message_type: Type of message ('output', 'status', 'error', 'command')
        """
        if session_id in self.active_connections and client_type in self.active_connections[session_id]:
            try:
                # For output type messages (SSH session logs), send the raw content without additional formatting
                if message_type == "output":
                    await self.active_connections[session_id][client_type].send_json({
                        "type": message_type,
                        "content": message,
                        "timestamp": time.time(),
                        "raw": True  # Flag to indicate this is raw SSH output
                    })
                else:
                    # For other message types (status, error, command), keep the existing format
                    await self.active_connections[session_id][client_type].send_json({
                        "type": message_type,
                        "message": message,
                        "timestamp": time.time()
                    })
            except Exception as e:
                logger.error(f"Error sending message to {client_type} in session {session_id}: {str(e)}")
                # Fall back to plain text if JSON fails
                try:
                    await self.active_connections[session_id][client_type].send_text(f"{message_type}: {message}")
                except:
                    pass
    
    def create_traffic_session(self, session_id: str, traffic_generator, client_ssh=None, server_ssh=None):
        self.traffic_sessions[session_id] = {
            "generator": traffic_generator,
            "client_ssh": client_ssh,
            "server_ssh": server_ssh,
            "start_time": time.time(),
            "active": True
        }
    
    def store_ssh_connection(self, host_type: str, ip: str, port: int, ssh_client: SSHClient):
        """Store an SSH connection for later reuse"""
        key = f"{ip}:{port}"
        if key not in self.ssh_connections:
            self.ssh_connections[key] = {}
        self.ssh_connections[key][host_type] = ssh_client
    
    def get_ssh_connection(self, host_type: str, ip: str, port: int) -> Optional[SSHClient]:
        """Retrieve a stored SSH connection if available"""
        key = f"{ip}:{port}"
        if key in self.ssh_connections and host_type in self.ssh_connections[key]:
            return self.ssh_connections[key][host_type]
        return None
    
    def stop_traffic_session(self, session_id: str):
        if session_id in self.traffic_sessions:
            # Don't disconnect SSH connections as they may be reused
            # Just mark the session as inactive
            self.traffic_sessions[session_id]["active"] = False
            
            # Cancel any running tasks
            if session_id in self.running_tasks and self.running_tasks[session_id]:
                self.running_tasks[session_id].cancel()
            
            # Clean up session data
            del self.traffic_sessions[session_id]
            if session_id in self.running_tasks:
                del self.running_tasks[session_id]
    
    def start_output_monitoring(self, session_id: str):
        if session_id in self.traffic_sessions and session_id not in self.running_tasks:
            task = asyncio.create_task(self._monitor_output(session_id))
            self.running_tasks[session_id] = task
    
    async def _monitor_output(self, session_id: str):
        if session_id not in self.traffic_sessions:
            return
        
        generator = self.traffic_sessions[session_id]["generator"]
        retry_count = 0
        max_retries = 5
        no_output_count = 0
        
        # Send initial status message
        await self.send_message("Starting traffic monitoring...", session_id, "client", "status")
        await self.send_message("Starting traffic monitoring...", session_id, "server", "status")
        
        # Find and send information about running commands
        for host_type in ["client", "server"]:
            for process in generator.running_processes:
                if process['host_type'] == host_type:
                    command = process.get('command', 'Unknown command')
                    await self.send_message(f"Running: {command}", session_id, host_type, "command")
        
        try:
            while self.traffic_sessions[session_id]["active"]:
                has_output = False
                
                # Check if processes are still running
                client_running = generator.is_process_running("client")
                server_running = generator.is_process_running("server")
                
                # Get output from client
                try:
                    client_output = generator.get_process_output("client")
                    if client_output:
                        # Send raw SSH session logs directly to the client
                        await self.send_message(client_output, session_id, "client", "output")
                        has_output = True
                        no_output_count = 0
                except Exception as e:
                    logger.error(f"Error getting client output: {str(e)}")
                    await self.send_message(f"Error retrieving output: {str(e)}", session_id, "client", "error")
                
                # Get output from server
                try:
                    server_output = generator.get_process_output("server")
                    if server_output:
                        # Send raw SSH session logs directly to the server
                        await self.send_message(server_output, session_id, "server", "output")
                        has_output = True
                        no_output_count = 0
                except Exception as e:
                    logger.error(f"Error getting server output: {str(e)}")
                    await self.send_message(f"Error retrieving output: {str(e)}", session_id, "server", "error")
                
                # If no output for a while, send a status update
                if not has_output:
                    no_output_count += 1
                    if no_output_count >= 10:  # After 5 seconds with no output
                        if client_running:
                            await self.send_message("Process still running, waiting for output...", session_id, "client", "status")
                        if server_running:
                            await self.send_message("Process still running, waiting for output...", session_id, "server", "status")
                        no_output_count = 0
                
                # If neither process is running, we're done
                if not client_running and not server_running:
                    # Try to get any final output
                    try:
                        final_client_output = generator.get_process_output("client")
                        if final_client_output:
                            await self.send_message(final_client_output, session_id, "client", "output")
                    except Exception as e:
                        logger.error(f"Error getting final client output: {str(e)}")
                    
                    try:
                        final_server_output = generator.get_process_output("server")
                        if final_server_output:
                            await self.send_message(final_server_output, session_id, "server", "output")
                    except Exception as e:
                        logger.error(f"Error getting final server output: {str(e)}")
                    
                    await self.send_message("Traffic generation completed", session_id, "client", "status")
                    await self.send_message("Traffic monitoring completed", session_id, "server", "status")
                    self.traffic_sessions[session_id]["active"] = False
                    break
                
                # If we've had connection issues, retry a few times
                if not has_output and not client_running and not server_running:
                    retry_count += 1
                    if retry_count > max_retries:
                        await self.send_message("No output detected after multiple retries. Stopping monitoring.", session_id, "client", "error")
                        await self.send_message("No output detected after multiple retries. Stopping monitoring.", session_id, "server", "error")
                        self.traffic_sessions[session_id]["active"] = False
                        break
                
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            logger.info(f"Output monitoring for session {session_id} cancelled")
            await self.send_message("Monitoring cancelled by user", session_id, "client", "status")
            await self.send_message("Monitoring cancelled by user", session_id, "server", "status")
        except Exception as e:
            logger.error(f"Error in output monitoring for session {session_id}: {str(e)}")
            await self.send_message(f"Error: {str(e)}", session_id, "client", "error")
            await self.send_message(f"Error: {str(e)}", session_id, "server", "error")
        finally:
            # Ensure processes are stopped when monitoring ends
            if session_id in self.traffic_sessions:
                try:
                    generator.stop_all_processes()
                except Exception as e:
                    logger.error(f"Error stopping processes: {str(e)}")
                
                self.traffic_sessions[session_id]["active"] = False
                
                # Send final message
                await self.send_message("Session ended. You can start a new traffic generation session if needed.", session_id, "client", "status")
                await self.send_message("Session ended. You can start a new traffic generation session if needed.", session_id, "server", "status")

# Initialize the connection manager
manager = ConnectionManager()

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

class ScapyInstallRequest(BaseModel):
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
    client_interface: Optional[str] = None
    server_interface: Optional[str] = None
    client_ipv4: Optional[str] = None
    client_ipv6: Optional[str] = None
    server_ipv4: Optional[str] = None
    server_ipv6: Optional[str] = None
    use_ipv4: bool = True
    use_ipv6: bool = False
    packet_count: int = 10
    packet_interval: float = 0.1
    traffic_types: Dict[str, Any] = Field(default_factory=dict)

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

@app.websocket("/ws/traffic/{session_id}/{client_type}")
async def websocket_traffic(websocket: WebSocket, session_id: str, client_type: str):
    if client_type not in ["client", "server"]:
        await websocket.close(code=1008, reason=f"Invalid client type: {client_type}")
        return
    
    # Check if session exists in traffic_sessions
    if session_id not in manager.traffic_sessions:
        # Create an empty session if it doesn't exist yet
        # This allows the WebSocket to connect before traffic generation starts
        manager.traffic_sessions[session_id] = {
            "generator": None,
            "client_ssh": None,
            "server_ssh": None,
            "start_time": time.time(),
            "active": True
        }
    
    await manager.connect(websocket, session_id, client_type)
    try:
        # Send initial connection message as JSON
        await websocket.send_json({
            "type": "status",
            "message": f"Connected to {client_type} terminal output",
            "timestamp": time.time()
        })
        
        # If we already have a generator, send information about what command is running
        if manager.traffic_sessions[session_id]["generator"] is not None:
            generator = manager.traffic_sessions[session_id]["generator"]
            # Find the most recent process for this client type
            running_command = None
            for process in reversed(generator.running_processes):
                if process['host_type'] == client_type:
                    running_command = process.get('command', 'Unknown command')
                    # Send information about the command that's running
                    await websocket.send_json({
                        "type": "command",
                        "command": running_command,
                        "pid": process.get('pid', 'Unknown'),
                        "timestamp": time.time()
                    })
                    
                    # Check if the process is still running
                    is_running = generator.is_process_running(client_type)
                    status_message = "Process is running" if is_running else "Process may have completed"
                    await websocket.send_json({
                        "type": "status",
                        "message": status_message,
                        "timestamp": time.time()
                    })
                    
                    # Try to get any existing output
                    try:
                        output = generator.get_process_output(client_type)
                        if output:
                            await websocket.send_json({
                                "type": "output",
                                "content": output,
                                "timestamp": time.time(),
                                "raw": True  # Flag to indicate this is raw SSH output
                            })
                    except Exception as e:
                        logger.error(f"Error getting process output: {str(e)}")
                        await websocket.send_json({
                            "type": "error",
                            "message": f"Error retrieving output: {str(e)}",
                            "timestamp": time.time()
                        })
                    break
            
            if not running_command:
                await websocket.send_json({
                    "type": "status",
                    "message": f"No active commands found for {client_type}",
                    "timestamp": time.time()
                })
        
        while True:
            # Keep the connection alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": time.time()
                })
            elif data.startswith("get_output"):
                # Client is requesting the latest output
                if manager.traffic_sessions[session_id]["generator"] is not None:
                    generator = manager.traffic_sessions[session_id]["generator"]
                    try:
                        output = generator.get_process_output(client_type)
                        await websocket.send_json({
                            "type": "output",
                            "content": output,
                            "timestamp": time.time(),
                            "raw": True  # Flag to indicate this is raw SSH output
                        })
                    except Exception as e:
                        logger.error(f"Error getting process output: {str(e)}")
                        await websocket.send_json({
                            "type": "error",
                            "message": f"Error retrieving output: {str(e)}",
                            "timestamp": time.time()
                        })
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for {client_type} in session {session_id}")
        manager.disconnect(session_id, client_type)
    except Exception as e:
        logger.error(f"WebSocket error for {client_type} in session {session_id}: {str(e)}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": f"WebSocket error: {str(e)}",
                "timestamp": time.time()
            })
        except:
            pass
        manager.disconnect(session_id, client_type)

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
    """Test SSH connection to a host and check Scapy installation"""
    try:
        # Create SSH client
        ssh_client = SSHClient(request.ip, request.port, request.username, request.password)
        
        # Try to connect
        success, message = ssh_client.connect()
        
        if success:
            # Check if Scapy is installed and get version
            scapy_installed, scapy_message, scapy_version = ssh_client.check_scapy_installed()
            
            # Get network interfaces
            interfaces_success, interfaces, interfaces_error = ssh_client.get_network_interfaces()
            
            ssh_client.disconnect()
            
            return {
                "success": True,
                "message": f"Successfully connected to {request.host_type}",
                "scapy_installed": scapy_installed,
                "scapy_message": scapy_message,
                "scapy_version": scapy_version,
                "interfaces": interfaces if interfaces_success else [],
                "interfaces_error": interfaces_error if not interfaces_success else ""
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

# The /api/scapy/generate-traffic endpoint has been removed and consolidated with /api/scapy/start-traffic
# This avoids duplication and ensures we use the WebSocket-based approach for all traffic generation

# Install Scapy on a remote host
@app.post("/api/scapy/install")
async def install_scapy(request: ScapyInstallRequest):
    """Install Scapy on a remote host"""
    try:
        # Create SSH client
        ssh_client = SSHClient(request.ip, request.port, request.username, request.password)
        
        # Connect to host
        success, message = ssh_client.connect()
        
        if not success:
            return {
                "success": False,
                "message": message
            }
        
        # Store the SSH connection for later reuse
        manager.store_ssh_connection(request.host_type, request.ip, request.port, ssh_client)
        
        # Install Scapy
        install_success, install_message = ssh_client.install_scapy()
        
        # Return result but keep the connection open for reuse
        return {
            "success": install_success,
            "message": install_message
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error installing Scapy: {str(e)}"
        }

# VPN endpoint replacement is now integrated into the clone-config endpoint with replace_vpn=True

@app.post("/api/scapy/start-traffic")
async def start_traffic(request: TrafficGenerationRequest):
    try:
        # Create a unique session ID
        session_id = str(uuid.uuid4())
        
        # Try to get existing SSH connections or create new ones if not available
        client_ssh = manager.get_ssh_connection("client", request.client_ip, request.client_port)
        server_ssh = manager.get_ssh_connection("server", request.server_ip, request.server_port)
        
        # Create new connections if needed
        if not client_ssh:
            client_ssh = SSHClient(
                hostname=request.client_ip,
                port=request.client_port,
                username=request.client_username,
                password=request.client_password
            )
            client_success, client_message = client_ssh.connect()
            if not client_success:
                return {"success": False, "message": f"Failed to connect to client: {client_message}"}
            # Store the new connection
            manager.store_ssh_connection("client", request.client_ip, request.client_port, client_ssh)
        
        if not server_ssh:
            server_ssh = SSHClient(
                hostname=request.server_ip,
                port=request.server_port,
                username=request.server_username,
                password=request.server_password
            )
            server_success, server_message = server_ssh.connect()
            if not server_success:
                return {"success": False, "message": f"Failed to connect to server: {server_message}"}
            # Store the new connection
            manager.store_ssh_connection("server", request.server_ip, request.server_port, server_ssh)
        
        # Create a new ScapyTrafficGenerator instance
        generator = ScapyTrafficGenerator(
            client_ssh=client_ssh,
            server_ssh=server_ssh,
            client_interface=request.client_interface,
            server_interface=request.server_interface,
            client_ipv4=request.client_ipv4,
            client_ipv6=request.client_ipv6,
            server_ipv4=request.server_ipv4,
            server_ipv6=request.server_ipv6
        )
        
        # Register the traffic session
        manager.create_traffic_session(session_id, generator, client_ssh, server_ssh)
        
        # Build the traffic generation commands based on the request
        client_commands = []
        server_commands = []
        
        # Process each traffic type
        for traffic_type, options in request.traffic_types.items():
            if traffic_type == "icmp":
                if options.get("enabled", False):
                    # ICMP traffic generation
                    icmp_type = options.get("type", 8)  # Default to echo request
                    icmp_code = options.get("code", 0)
                    
                    if request.use_ipv4:
                        client_cmd = generator.build_icmp_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            icmp_type=icmp_type,
                            icmp_code=icmp_code,
                            use_ipv6=False
                        )
                        client_commands.append(client_cmd)
                    
                    if request.use_ipv6:
                        client_cmd_v6 = generator.build_icmp_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            icmp_type=icmp_type,
                            icmp_code=icmp_code,
                            use_ipv6=True
                        )
                        client_commands.append(client_cmd_v6)
            
            elif traffic_type == "tcp":
                if options.get("enabled", False):
                    # TCP traffic generation
                    src_port = options.get("srcPort", 1024)
                    dst_port = options.get("dstPort", 80)
                    flags = options.get("flags", "S")  # Default to SYN
                    
                    if request.use_ipv4:
                        client_cmd = generator.build_tcp_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            src_port=src_port,
                            dst_port=dst_port,
                            flags=flags,
                            use_ipv6=False
                        )
                        client_commands.append(client_cmd)
                    
                    if request.use_ipv6:
                        client_cmd_v6 = generator.build_tcp_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            src_port=src_port,
                            dst_port=dst_port,
                            flags=flags,
                            use_ipv6=True
                        )
                        client_commands.append(client_cmd_v6)
            
            elif traffic_type == "udp":
                if options.get("enabled", False):
                    # UDP traffic generation
                    src_port = options.get("srcPort", 1024)
                    dst_port = options.get("dstPort", 53)
                    payload_size = options.get("payloadSize", 64)
                    
                    if request.use_ipv4:
                        client_cmd = generator.build_udp_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            src_port=src_port,
                            dst_port=dst_port,
                            payload_size=payload_size,
                            use_ipv6=False
                        )
                        client_commands.append(client_cmd)
                    
                    if request.use_ipv6:
                        client_cmd_v6 = generator.build_udp_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            src_port=src_port,
                            dst_port=dst_port,
                            payload_size=payload_size,
                            use_ipv6=True
                        )
                        client_commands.append(client_cmd_v6)
            
            elif traffic_type == "arp":
                if options.get("enabled", False) and request.use_ipv4:  # ARP is IPv4 only
                    # ARP traffic generation
                    op_type = options.get("opType", "who-has")
                    
                    client_cmd = generator.build_arp_command(
                        count=request.packet_count,
                        interval=request.packet_interval,
                        op_type=op_type
                    )
                    client_commands.append(client_cmd)
            
            elif traffic_type == "fuzzing":
                if options.get("enabled", False):
                    # Fuzzing traffic generation
                    layer = options.get("layer", "IP")
                    field = options.get("field", "")
                    strategy = options.get("strategy", "random")
                    
                    if request.use_ipv4 and layer != "IPv6":
                        client_cmd = generator.build_fuzzing_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            layer=layer,
                            field=field,
                            strategy=strategy,
                            use_ipv6=False
                        )
                        client_commands.append(client_cmd)
                    
                    if request.use_ipv6 and (layer == "IPv6" or layer in ["TCP", "UDP", "ICMP"]):
                        client_cmd_v6 = generator.build_fuzzing_command(
                            count=request.packet_count,
                            interval=request.packet_interval,
                            layer=layer,
                            field=field,
                            strategy=strategy,
                            use_ipv6=True
                        )
                        client_commands.append(client_cmd_v6)
        
        # Start traffic generation on client
        if client_commands:
            combined_client_cmd = " && ".join(client_commands)
            client_success = generator.start_background_process(combined_client_cmd, "client")
            if not client_success:
                return {"success": False, "message": "Failed to start traffic generation on client"}
        
        # Start traffic monitoring on server with more detailed output
        # -n: Don't convert addresses to names
        # -v: Verbose output
        # -l: Line-buffered output (better for real-time viewing)
        # -X: Show packet contents in hex and ASCII
        # -s 0: Capture entire packet
        server_cmd = f"tcpdump -i {request.server_interface} -n -v -l -X -s 0 'host {request.client_ipv4 if request.use_ipv4 else request.client_ipv6}'"
        server_success = generator.start_background_process(server_cmd, "server")
        if not server_success:
            return {"success": False, "message": "Failed to start traffic monitoring on server"}
        
        # Start output monitoring
        manager.start_output_monitoring(session_id)
        
        return {"success": True, "message": "Traffic generation started", "session_id": session_id}
    except Exception as e:
        logger.error(f"Error starting traffic: {str(e)}")
        return {"success": False, "message": f"Error starting traffic: {str(e)}"}

@app.post("/api/scapy/stop-traffic")
async def stop_traffic(session_id: str):
    try:
        if session_id not in manager.traffic_sessions:
            return {"success": False, "message": "Traffic session not found"}
        
        # Stop the traffic session
        manager.stop_traffic_session(session_id)
        
        return {"success": True, "message": "Traffic generation stopped"}
    except Exception as e:
        logger.error(f"Error stopping traffic: {str(e)}")
        return {"success": False, "message": f"Error stopping traffic: {str(e)}"}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
