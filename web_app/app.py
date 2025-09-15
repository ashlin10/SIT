import os
import sys
import yaml
import subprocess
import json
import logging
import io
import threading
import time
import csv
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, File, UploadFile
from pydantic import BaseModel, validator, Field
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.websockets import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, validator, Field
from typing import Optional, List, Dict, Any, Union, Set
import asyncio
import queue
import uuid
from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction

# Add parent directory to path so we can import from the main project
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import functions from clone_device_config.py
from clone_device_config import load_yaml, fetch_config_from_source, apply_config_to_destination, create_batches
from utils.fmc_api import authenticate, get_ftd_uuid, replace_vpn_endpoint, get_vpn_topologies, get_vpn_endpoints

# Import traffic generators module from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from traffic_generators import SSHConnectionDetails, connect_to_hosts, get_interfaces, disconnect_all, check_tool_installation, TrafficGenerationRequest, generate_traffic, install_tool_on_host
from configure_http_proxy import configure_http_proxy_on_device as run_http_proxy_on_device
from configure_static_routes import run_static_routes_on_device
from copy_dev_crt import run_copy_dev_cert_on_device
from download_upgrade_package import run_download_upgrade_on_device
from restore_device_backup_runner import run_restore_backup_on_device

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

# Global variables to track installation status
installation_status = {}
# Format: {"client-scapy": {"status": "installing", "message": "...", "start_time": ..., "success": None, "version": None}}

# Flag to indicate if operation should be stopped
stop_requested = False

# Initialize the app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
import os

# Determine if we're running from project root or web_app directory
static_dir = "static" if os.path.exists("static") else "../static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Templates
templates_dir = "templates" if os.path.exists("templates") else "../templates"
templates = Jinja2Templates(directory=templates_dir)

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

# Models for Traffic Generators
class SSHConnectionRequestModel(BaseModel):
    ip_address: str
    port: int = 22
    username: str
    password: str

class TrafficGeneratorsConnectionRequest(BaseModel):
    client: SSHConnectionRequestModel
    server: SSHConnectionRequestModel

# Models for Command Center
class CCDevice(BaseModel):
    type: str  # 'FTD' or 'FMC'
    name: str
    ip_address: str
    username: str
    password: str
    # Keep for backward compatibility (single port uploads)
    port: Optional[int] = 22
    # New: raw port spec as uploaded (e.g., "13111-13120", "22,2222")
    port_spec: Optional[str] = None

class HttpProxyExecRequest(BaseModel):
    proxy_address: str
    proxy_port: int
    proxy_auth: bool = False
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None
    # For new flow, frontend will send device_ids only
    device_ids: Optional[List[str]] = None
    # Backward compatibility: still accept full devices list
    devices: Optional[List[CCDevice]] = None

class SimpleDevicesRequest(BaseModel):
    device_ids: Optional[List[str]] = None
    devices: Optional[List[CCDevice]] = None

# Static Routes models
class StaticRouteItem(BaseModel):
    ip_version: str = Field(..., regex=r"^(ipv4|ipv6)$")
    interface: str = "management0"
    ip_address: str
    netmask_or_prefix: str
    gateway: str

class StaticRoutesExecRequest(SimpleDevicesRequest):
    routes: Optional[List[StaticRouteItem]] = None

class DownloadUpgradeExecRequest(BaseModel):
    branch: str  # 'Release' or 'Development'
    version: str  # includes build if any
    models: List[str] = []  # e.g., ['1000','1200','FMC']
    device_ids: Optional[List[str]] = None
    devices: Optional[List[CCDevice]] = None

class RestoreBackupExecRequest(SimpleDevicesRequest):
    base_url: str
    do_restore: bool = True

# Persisted devices state (in-memory)
cc_devices_state: Dict[str, List[Dict[str, Any]]] = {"ftd": [], "fmc": []}
cc_proxy_presets: List[Dict[str, Any]] = []
cc_static_presets: List[Dict[str, Any]] = []

# ------------- Command Center Helpers -------------
def cc_sample_devices_csv() -> str:
    return (
        "type,name,ip_address,username,password,port\n"
        "FTD,WM-8,10.106.239.165,admin,Cisco@12,12056\n"
        "FTD,WM-9,10.106.239.165,admin,Cisco@12,12057\n"
        "FMC,FMC-1,10.106.239.200,admin,Cisco@123,22\n"
    )

def cc_sample_devices_txt() -> str:
    # TXT as CSV-style lines for simplicity
    return cc_sample_devices_csv()

def parse_devices_text(contents: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parse CSV/TXT device list without expanding port ranges.
    Each device will include 'port_spec' (str) and computed 'ports' (List[int]).
    Returns dict with keys 'ftd' and 'fmc'.
    """
    try:
        # Normalize newlines
        text = contents.replace("\r\n", "\n").replace("\r", "\n").strip()
        if not text:
            return {"ftd": [], "fmc": []}

        # Try to sniff dialect
        try:
            dialect = csv.Sniffer().sniff(text.split("\n", 1)[0])
        except Exception:
            dialect = csv.excel

        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        ftd_list: List[Dict[str, Any]] = []
        fmc_list: List[Dict[str, Any]] = []
        for row in reader:
            if not row:
                continue
            # Normalize keys to lowercase
            norm = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }
            dev_type = norm.get("type", "").upper()
            if dev_type not in ("FTD", "FMC"):
                continue

            port_field = norm.get("port", "").strip()
            ports: List[int] = []
            port_spec: Optional[str] = port_field if port_field else "22"
            if not port_field:
                ports = [22]
            elif "-" in port_field:
                parts = [p.strip() for p in port_field.split("-", 1)]
                if len(parts) != 2:
                    raise ValueError(f"Invalid port range spec: {port_field}")
                start, end = int(parts[0]), int(parts[1])
                if start > end:
                    start, end = end, start
                ports = list(range(start, end + 1))
            elif "," in port_field:
                try:
                    ports = [int(p.strip()) for p in port_field.split(",") if p.strip()]
                except Exception:
                    raise ValueError(f"Invalid comma-separated ports: {port_field}")
            else:
                ports = [int(port_field)]

            dev = {
                "id": str(uuid.uuid4()),
                "type": dev_type,
                "name": norm.get("name", ""),
                "ip_address": norm.get("ip_address", ""),
                "username": norm.get("username", ""),
                "password": norm.get("password", ""),
                "port_spec": port_spec,
                "ports": ports,
            }
            if dev_type == "FTD":
                ftd_list.append(dev)
            else:
                fmc_list.append(dev)
        return {"ftd": ftd_list, "fmc": fmc_list}
    except Exception as e:
        raise ValueError(f"Failed to parse devices: {e}")

## Duplicate SSH proxy configuration removed. Using implementation from configure_http_proxy.py

@app.get("/", response_class=HTMLResponse)
async def index():
    return RedirectResponse(url="/dashboard")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "active_page": "dashboard"})

@app.get("/clone-device", response_class=HTMLResponse)
async def clone_device(request: Request):
    return templates.TemplateResponse("clone_device.html", {"request": request, "active_page": "clone_device"})

@app.get("/traffic-generators", response_class=HTMLResponse)
async def traffic_generators(request: Request):
    return templates.TemplateResponse("traffic_generators.html", {"request": request, "active_page": "traffic_generators"})

@app.get("/command-center", response_class=HTMLResponse)
async def command_center(request: Request):
    return templates.TemplateResponse("command_center.html", {"request": request, "active_page": "command_center"})

@app.get("/api/command-center/sample-devices")
async def command_center_sample_devices(format: str = "csv"):
    try:
        content = cc_sample_devices_csv() if format.lower() == "csv" else cc_sample_devices_txt()
        media_type = "text/csv" if format.lower() == "csv" else "text/plain"
        filename = f"sample_devices.{ 'csv' if format.lower() == 'csv' else 'txt' }"
        return StreamingResponse(io.StringIO(content), media_type=media_type, headers={
            "Content-Disposition": f"attachment; filename={filename}"
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/command-center/proxy-presets")
async def cc_list_proxy_presets():
    return {"success": True, "presets": cc_proxy_presets}

@app.get("/api/command-center/static-presets")
async def cc_list_static_presets():
    return {"success": True, "presets": cc_static_presets}

@app.post("/api/command-center/proxy-presets/save")
async def cc_save_proxy_preset(payload: Dict[str, Any]):
    try:
        name = (payload.get("name") or f"Preset {len(cc_proxy_presets)+1}").strip()
        preset = {
            "id": str(uuid.uuid4()),
            "name": name,
            "proxy_address": payload.get("proxy_address", ""),
            "proxy_port": int(payload.get("proxy_port", 0)),
            "proxy_auth": bool(payload.get("proxy_auth", False)),
            "proxy_username": payload.get("proxy_username", ""),
            "proxy_password": payload.get("proxy_password", ""),
        }
        cc_proxy_presets.append(preset)
        return {"success": True, "preset": preset, "presets": cc_proxy_presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.post("/api/command-center/static-presets/save")
async def cc_save_static_preset(payload: Dict[str, Any]):
    try:
        name = (payload.get("name") or f"Preset {len(cc_static_presets)+1}").strip()
        routes = payload.get("routes") or []
        if not isinstance(routes, list) or len(routes) == 0:
            raise ValueError("At least one static route is required")
        # minimal validation mirroring model
        norm_routes: List[Dict[str, Any]] = []
        for r in routes:
            ipv = (r.get("ip_version") or "").lower()
            if ipv not in ("ipv4", "ipv6"):
                raise ValueError(f"Invalid ip_version: {ipv}")
            norm_routes.append({
                "ip_version": ipv,
                "interface": r.get("interface") or "management0",
                "ip_address": r.get("ip_address") or "",
                "netmask_or_prefix": str(r.get("netmask_or_prefix") or ""),
                "gateway": r.get("gateway") or "",
            })
        preset = {"id": str(uuid.uuid4()), "name": name, "routes": norm_routes}
        cc_static_presets.append(preset)
        return {"success": True, "preset": preset, "presets": cc_static_presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/command-center/proxy-presets/{preset_id}")
async def cc_delete_proxy_preset(preset_id: str):
    try:
        before = len(cc_proxy_presets)
        cc_proxy_presets[:] = [p for p in cc_proxy_presets if p.get("id") != preset_id]
        return {"success": True, "deleted": before - len(cc_proxy_presets), "presets": cc_proxy_presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/command-center/static-presets/{preset_id}")
async def cc_delete_static_preset(preset_id: str):
    try:
        before = len(cc_static_presets)
        cc_static_presets[:] = [p for p in cc_static_presets if p.get("id") != preset_id]
        return {"success": True, "deleted": before - len(cc_static_presets), "presets": cc_static_presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.post("/api/command-center/upload-devices")
async def command_center_upload_devices(file: UploadFile = File(...)):
    try:
        raw = await file.read()
        text = raw.decode("utf-8", errors="ignore")
        parsed = parse_devices_text(text)
        # Append to persisted state
        cc_devices_state["ftd"].extend(parsed.get("ftd", []))
        cc_devices_state["fmc"].extend(parsed.get("fmc", []))
        return {"success": True, "ftd": cc_devices_state.get("ftd", []), "fmc": cc_devices_state.get("fmc", [])}
    except Exception as e:
        logger.error(f"Device upload parse error: {e}")
        return {"success": False, "message": f"Failed to parse file: {str(e)}"}

@app.get("/api/command-center/devices")
async def command_center_get_devices():
    return {"success": True, "ftd": cc_devices_state.get("ftd", []), "fmc": cc_devices_state.get("fmc", [])}

@app.post("/api/command-center/delete-devices")
async def command_center_delete_devices(payload: Dict[str, Any]):
    try:
        ids: List[str] = payload.get("device_ids", [])
        if not ids:
            return {"success": False, "message": "No device IDs provided"}
        before_ftd = len(cc_devices_state["ftd"])
        before_fmc = len(cc_devices_state["fmc"])
        cc_devices_state["ftd"] = [d for d in cc_devices_state["ftd"] if d.get("id") not in ids]
        cc_devices_state["fmc"] = [d for d in cc_devices_state["fmc"] if d.get("id") not in ids]
        return {
            "success": True,
            "deleted": before_ftd + before_fmc - len(cc_devices_state["ftd"]) - len(cc_devices_state["fmc"]),
            "ftd": cc_devices_state.get("ftd", []),
            "fmc": cc_devices_state.get("fmc", []),
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/command-center/execute-http-proxy")
async def command_center_execute_http_proxy(request: HttpProxyExecRequest):
    try:
        # Resolve selected devices from persisted state
        selected: List[Dict[str, Any]] = []
        ids = request.device_ids or []
        if request.devices:
            # Backward compatibility: map provided devices to ad-hoc entries
            for d in request.devices:
                if (d.type or '').upper() != 'FTD':
                    continue
                # Build ports list from port or port_spec if provided
                ports = []
                if d.port_spec:
                    ps = d.port_spec.strip()
                    if '-' in ps:
                        a, b = [int(x.strip()) for x in ps.split('-', 1)]
                        if a > b: a, b = b, a
                        ports = list(range(a, b+1))
                    elif ',' in ps:
                        ports = [int(x.strip()) for x in ps.split(',') if x.strip()]
                    else:
                        ports = [int(ps)]
                else:
                    ports = [int(d.port or 22)]
                selected.append({
                    "id": str(uuid.uuid4()),
                    "type": d.type,
                    "name": d.name,
                    "ip_address": d.ip_address,
                    "username": d.username,
                    "password": d.password,
                    "port_spec": d.port_spec or str(d.port or 22),
                    "ports": ports,
                })
        else:
            # From persisted state via IDs
            all_ftd = {d['id']: d for d in cc_devices_state.get('ftd', [])}
            selected = [all_ftd[i] for i in ids if i in all_ftd]

        # Only FTD devices support the clish http-proxy command
        devices = [d for d in selected if (d.get('type') or '').upper() == 'FTD']
        results = []

        from concurrent.futures import ThreadPoolExecutor, as_completed
        tasks = []
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=16) as executor:
            future_map = {}
            for d in devices:
                for prt in d.get('ports', []) or [22]:
                    future = executor.submit(
                        run_http_proxy_on_device,
                        ip=d.get('ip_address'),
                        ssh_port=prt,
                        username=d.get('username'),
                        device_password=d.get('password'),
                        proxy_address=request.proxy_address,
                        proxy_port=request.proxy_port,
                        proxy_auth=request.proxy_auth,
                        proxy_username=request.proxy_username or "",
                        proxy_password=request.proxy_password or "",
                        timeout=30,
                    )
                    future_map[future] = (d, prt)
            for future in as_completed(future_map):
                d, prt = future_map[future]
                try:
                    r = future.result()
                    results.append({
                        "type": d.get('type'),
                        "name": d.get('name'),
                        "ip_address": d.get('ip_address'),
                        "port": prt,
                        **r,
                    })
                except Exception as e:
                    results.append({
                        "type": d.get('type'),
                        "name": d.get('name'),
                        "ip_address": d.get('ip_address'),
                        "port": prt,
                        "success": False,
                        "error": str(e),
                    })

        success_count = sum(1 for r in results if r.get("success"))
        return {
            "success": True,
            "message": "Execution completed",
            "total": len(devices),
            "success_count": success_count,
            "results": results,
        }
    except Exception as e:
        logger.error(f"HTTP proxy execution error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/command-center/execute-http-proxy/stream")
async def command_center_execute_http_proxy_stream(request: HttpProxyExecRequest):
    """Stream live logs with emojis while executing proxy configuration on devices."""
    try:
        # Resolve selected devices from persisted state or request.devices
        selected: List[Dict[str, Any]] = []
        ids = request.device_ids or []
        if request.devices:
            for d in request.devices:
                if (d.type or '').upper() != 'FTD':
                    continue
                ports: List[int] = []
                if d.port_spec:
                    ps = d.port_spec.strip()
                    if '-' in ps:
                        a, b = [int(x.strip()) for x in ps.split('-', 1)]
                        if a > b: a, b = b, a
                        ports = list(range(a, b+1))
                    elif ',' in ps:
                        ports = [int(x.strip()) for x in ps.split(',') if x.strip()]
                    else:
                        ports = [int(ps)]
                else:
                    ports = [int(d.port or 22)]
                selected.append({
                    "id": str(uuid.uuid4()),
                    "type": d.type,
                    "name": d.name,
                    "ip_address": d.ip_address,
                    "username": d.username,
                    "password": d.password,
                    "port_spec": d.port_spec or str(d.port or 22),
                    "ports": ports,
                })
        else:
            all_ftd = {d['id']: d for d in cc_devices_state.get('ftd', [])}
            selected = [all_ftd[i] for i in ids if i in all_ftd]

        devices = [d for d in selected if (d.get('type') or '').upper() == 'FTD']

        def event_stream():
            q: "queue.Queue[str]" = queue.Queue()
            STOP = object()
            results: List[Dict[str, Any]] = []

            def runner():
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    future_map = {}
                    with ThreadPoolExecutor(max_workers=16) as executor:
                        for d in devices:
                            name = d.get('name') or d.get('ip_address')
                            for prt in d.get('ports', []) or [22]:
                                label = f"{name}"
                                def mk_logger(lbl: str):
                                    return lambda msg, icon="": q.put(f"[{lbl}] {icon} {msg}\n")
                                future = executor.submit(
                                    run_http_proxy_on_device,
                                    ip=d.get('ip_address'),
                                    ssh_port=prt,
                                    username=d.get('username'),
                                    device_password=d.get('password'),
                                    proxy_address=request.proxy_address,
                                    proxy_port=request.proxy_port,
                                    proxy_auth=request.proxy_auth,
                                    proxy_username=request.proxy_username or "",
                                    proxy_password=request.proxy_password or "",
                                    timeout=30,
                                    log_fn=mk_logger(label),
                                )
                                future_map[future] = (d, prt, label)
                        for future in as_completed(future_map):
                            d, prt, label = future_map[future]
                            try:
                                r = future.result()
                                results.append({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                })
                                q.put("RESULT " + json.dumps({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                }) + "\n")
                            except Exception as e:
                                err = {
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    "success": False,
                                    "error": str(e),
                                }
                                results.append(err)
                                q.put("RESULT " + json.dumps(err) + "\n")
                    success_count = sum(1 for r in results if r.get("success"))
                    summary = {"total": len(results), "success_count": success_count}
                    q.put("SUMMARY " + json.dumps(summary) + "\n")
                finally:
                    q.put(STOP)

            t = threading.Thread(target=runner, daemon=True)
            t.start()

            while True:
                item = q.get()
                if item is STOP:
                    break
                yield item

        return StreamingResponse(event_stream(), media_type="text/plain")
    except Exception as e:
        logger.error(f"HTTP proxy stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _resolve_selected_devices(request_devices: Optional[List[CCDevice]], ids: List[str]) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    if request_devices:
        for d in request_devices:
            if (d.type or '').upper() != 'FTD':
                continue
            ports: List[int] = []
            if d.port_spec:
                ps = d.port_spec.strip()
                if '-' in ps:
                    a, b = [int(x.strip()) for x in ps.split('-', 1)]
                    if a > b: a, b = b, a
                    ports = list(range(a, b+1))
                elif ',' in ps:
                    ports = [int(x.strip()) for x in ps.split(',') if x.strip()]
                else:
                    ports = [int(ps)]
            else:
                ports = [int(d.port or 22)]
            selected.append({
                "id": str(uuid.uuid4()),
                "type": d.type,
                "name": d.name,
                "ip_address": d.ip_address,
                "username": d.username,
                "password": d.password,
                "port_spec": d.port_spec or str(d.port or 22),
                "ports": ports,
            })
    else:
        all_ftd = {d['id']: d for d in cc_devices_state.get('ftd', [])}
        selected = [all_ftd[i] for i in ids if i in all_ftd]
    return [d for d in selected if (d.get('type') or '').upper() == 'FTD']

def _resolve_selected_fmc_devices(request_devices: Optional[List[CCDevice]], ids: List[str]) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    if request_devices:
        for d in request_devices:
            if (d.type or '').upper() != 'FMC':
                continue
            ports: List[int] = []
            if d.port_spec:
                ps = d.port_spec.strip()
                if '-' in ps:
                    a, b = [int(x.strip()) for x in ps.split('-', 1)]
                    if a > b: a, b = b, a
                    ports = list(range(a, b+1))
                elif ',' in ps:
                    ports = [int(x.strip()) for x in ps.split(',') if x.strip()]
                else:
                    ports = [int(ps)]
            else:
                ports = [int(d.port or 22)]
            selected.append({
                "id": str(uuid.uuid4()),
                "type": d.type,
                "name": d.name,
                "ip_address": d.ip_address,
                "username": d.username,
                "password": d.password,
                "port_spec": d.port_spec or str(d.port or 22),
                "ports": ports,
            })
    else:
        all_fmc = {d['id']: d for d in cc_devices_state.get('fmc', [])}
        selected = [all_fmc[i] for i in ids if i in all_fmc]
    return [d for d in selected if (d.get('type') or '').upper() == 'FMC']

@app.post("/api/command-center/execute-static-routes/stream")
async def command_center_execute_static_routes_stream(request: StaticRoutesExecRequest):
    try:
        devices = _resolve_selected_devices(request.devices, request.device_ids or [])
        # Build commands from routes if provided
        # Build commands from routes; if none provided, do not run any commands
        cmds: List[str] = []
        if request.routes:
            cmds = [
                f"configure network static-routes {r.ip_version} add {r.interface or 'management0'} {r.ip_address} {r.netmask_or_prefix} {r.gateway}"
                for r in request.routes
            ]
        def event_stream():
            q: "queue.Queue[str]" = queue.Queue()
            STOP = object()
            results: List[Dict[str, Any]] = []
            def runner():
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    future_map = {}
                    with ThreadPoolExecutor(max_workers=16) as executor:
                        for d in devices:
                            name = d.get('name') or d.get('ip_address')
                            for prt in d.get('ports', []) or [22]:
                                label = f"{name}"
                                def mk_logger(lbl: str):
                                    return lambda msg, icon="": q.put(f"[{lbl}] {icon} {msg}\n")
                                future = executor.submit(
                                    run_static_routes_on_device,
                                    ip=d.get('ip_address'),
                                    ssh_port=prt,
                                    username=d.get('username'),
                                    device_password=d.get('password'),
                                    commands=cmds,
                                    timeout=30,
                                    log_fn=mk_logger(label),
                                )
                                future_map[future] = (d, prt, label)
                        for future in as_completed(future_map):
                            d, prt, label = future_map[future]
                            try:
                                r = future.result()
                                results.append({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                })
                                q.put("RESULT " + json.dumps({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                }) + "\n")
                            except Exception as e:
                                err = {
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    "success": False,
                                    "error": str(e),
                                }
                                results.append(err)
                                q.put("RESULT " + json.dumps(err) + "\n")
                    success_count = sum(1 for r in results if r.get("success"))
                    summary = {"total": len(results), "success_count": success_count}
                    q.put("SUMMARY " + json.dumps(summary) + "\n")
                finally:
                    q.put(STOP)
            t = threading.Thread(target=runner, daemon=True)
            t.start()
            while True:
                item = q.get()
                if item is STOP:
                    break
                yield item
        return StreamingResponse(event_stream(), media_type="text/plain")
    except Exception as e:
        logger.error(f"Static routes stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/command-center/execute-copy-dev-crt/stream")
async def command_center_execute_copy_dev_crt_stream(request: SimpleDevicesRequest):
    try:
        # Resolve both FTD and FMC devices; run in parallel across all
        devices_ftd = _resolve_selected_devices(request.devices, request.device_ids or [])
        devices_fmc = _resolve_selected_fmc_devices(request.devices, request.device_ids or [])
        devices = devices_ftd + devices_fmc
        def event_stream():
            q: "queue.Queue[str]" = queue.Queue()
            STOP = object()
            results: List[Dict[str, Any]] = []
            def runner():
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    future_map = {}
                    with ThreadPoolExecutor(max_workers=16) as executor:
                        for d in devices:
                            name = d.get('name') or d.get('ip_address')
                            for prt in d.get('ports', []) or [22]:
                                label = f"{name}"
                                def mk_logger(lbl: str):
                                    return lambda msg, icon="": q.put(f"[{lbl}] {icon} {msg}\n")
                                future = executor.submit(
                                    run_copy_dev_cert_on_device,
                                    ip=d.get('ip_address'),
                                    ssh_port=prt,
                                    username=d.get('username'),
                                    device_password=d.get('password'),
                                    label=label,
                                    device_type=d.get('type'),
                                    timeout=60,
                                    log_fn=mk_logger(label),
                                )
                                future_map[future] = (d, prt, label)
                        for future in as_completed(future_map):
                            d, prt, label = future_map[future]
                            try:
                                r = future.result()
                                results.append({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                })
                                q.put("RESULT " + json.dumps({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                }) + "\n")
                            except Exception as e:
                                err = {
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    "success": False,
                                    "error": str(e),
                                }
                                results.append(err)
                                q.put("RESULT " + json.dumps(err) + "\n")
                    success_count = sum(1 for r in results if r.get("success"))
                    summary = {"total": len(results), "success_count": success_count}
                    q.put("SUMMARY " + json.dumps(summary) + "\n")
                finally:
                    q.put(STOP)
            t = threading.Thread(target=runner, daemon=True)
            t.start()
            while True:
                item = q.get()
                if item is STOP:
                    break
                yield item
        return StreamingResponse(event_stream(), media_type="text/plain")
    except Exception as e:
        logger.error(f"Copy dev cert stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/command-center/download-upgrade/stream")
async def command_center_download_upgrade_stream(request: DownloadUpgradeExecRequest):
    try:
        devices = _resolve_selected_fmc_devices(request.devices, request.device_ids or [])
        branch = request.branch
        version = request.version
        models = request.models or []
        def event_stream():
            q: "queue.Queue[str]" = queue.Queue()
            STOP = object()
            results: List[Dict[str, Any]] = []
            def runner():
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    future_map = {}
                    with ThreadPoolExecutor(max_workers=8) as executor:
                        for d in devices:
                            name = d.get('name') or d.get('ip_address')
                            for prt in d.get('ports', []) or [22]:
                                label = f"{name}"
                                def mk_logger(lbl: str):
                                    return lambda msg, icon="": q.put(f"[{lbl}] {icon} {msg}\n")
                                future = executor.submit(
                                    run_download_upgrade_on_device,
                                    ip=d.get('ip_address'),
                                    ssh_port=prt,
                                    username_on_device=d.get('username'),
                                    device_password=d.get('password'),
                                    branch=branch,
                                    version=version,
                                    models=models,
                                    timeout=1200,
                                    log_fn=mk_logger(label),
                                )
                                future_map[future] = (d, prt, label)
                        for future in as_completed(future_map):
                            d, prt, label = future_map[future]
                            try:
                                r = future.result()
                                results.append({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                })
                                q.put("RESULT " + json.dumps({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                }) + "\n")
                            except Exception as e:
                                err = {
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    "success": False,
                                    "error": str(e),
                                }
                                results.append(err)
                                q.put("RESULT " + json.dumps(err) + "\n")
                    success_count = sum(1 for r in results if r.get("success"))
                    summary = {"total": len(results), "success_count": success_count}
                    q.put("SUMMARY " + json.dumps(summary) + "\n")
                finally:
                    q.put(STOP)
            t = threading.Thread(target=runner, daemon=True)
            t.start()
            while True:
                item = q.get()
                if item is STOP:
                    break
                yield item
        return StreamingResponse(event_stream(), media_type="text/plain")
    except Exception as e:
        logger.error(f"Download upgrade stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/command-center/restore-backup/stream")
async def command_center_restore_backup_stream(request: RestoreBackupExecRequest):
    try:
        devices = _resolve_selected_devices(request.devices, request.device_ids or [])
        base_url = request.base_url
        do_restore = bool(request.do_restore)

        def event_stream():
            q: "queue.Queue[str]" = queue.Queue()
            STOP = object()
            results: List[Dict[str, Any]] = []

            def runner():
                try:
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    future_map = {}
                    with ThreadPoolExecutor(max_workers=16) as executor:
                        for d in devices:
                            name = d.get('name') or d.get('ip_address')
                            for prt in d.get('ports', []) or [22]:
                                label = f"{name}"
                                def mk_logger(lbl: str):
                                    return lambda msg, icon="": q.put(f"[{lbl}] {icon} {msg}\n")
                                future = executor.submit(
                                    run_restore_backup_on_device,
                                    ip=d.get('ip_address'),
                                    ssh_port=prt,
                                    username=d.get('username'),
                                    device_password=d.get('password'),
                                    base_url=base_url,
                                    device_label=name,
                                    do_restore=do_restore,
                                    timeout=1800,
                                    log_fn=mk_logger(label),
                                )
                                future_map[future] = (d, prt, label)
                        for future in as_completed(future_map):
                            d, prt, label = future_map[future]
                            try:
                                r = future.result()
                                results.append({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                })
                                q.put("RESULT " + json.dumps({
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    **r,
                                }) + "\n")
                            except Exception as e:
                                err = {
                                    "type": d.get('type'),
                                    "name": d.get('name'),
                                    "ip_address": d.get('ip_address'),
                                    "port": prt,
                                    "success": False,
                                    "error": str(e),
                                }
                                results.append(err)
                                q.put("RESULT " + json.dumps(err) + "\n")
                    success_count = sum(1 for r in results if r.get("success"))
                    summary = {"total": len(results), "success_count": success_count}
                    q.put("SUMMARY " + json.dumps(summary) + "\n")
                finally:
                    q.put(STOP)

            t = threading.Thread(target=runner, daemon=True)
            t.start()
            while True:
                item = q.get()
                if item is STOP:
                    break
                yield item

        return StreamingResponse(event_stream(), media_type="text/plain")
    except Exception as e:
        logger.error(f"Restore backup stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/settings")
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request, "active_page": "settings"})

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

# Traffic Generators API endpoints
@app.post("/api/traffic-generators/connect")
async def connect_ssh_hosts(request: TrafficGeneratorsConnectionRequest):
    """Connect to client and server hosts via SSH"""
    try:
        # Convert request models to SSHConnectionDetails objects
        client_details = SSHConnectionDetails(
            ip_address=request.client.ip_address,
            port=request.client.port,
            username=request.client.username,
            password=request.client.password
        )
        
        server_details = SSHConnectionDetails(
            ip_address=request.server.ip_address,
            port=request.server.port,
            username=request.server.username,
            password=request.server.password
        )
        
        # Connect to both hosts
        results = connect_to_hosts(client_details, server_details)
        
        return results
    except Exception as e:
        logger.error(f"Error connecting to SSH hosts: {str(e)}")
        return {
            "client": {"success": False, "message": "Internal server error"},
            "server": {"success": False, "message": "Internal server error"},
            "overall_success": False
        }

@app.get("/api/traffic-generators/interfaces/{host_type}")
async def get_host_interfaces(host_type: str):
    """Get network interfaces for the specified host"""
    if host_type not in ["client", "server"]:
        raise HTTPException(status_code=400, detail="Invalid host type. Must be 'client' or 'server'")
    
    try:
        interfaces = get_interfaces(host_type)
        return interfaces
    except Exception as e:
        logger.error(f"Error getting interfaces for {host_type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get interfaces: {str(e)}")

@app.post("/api/traffic-generators/disconnect")
async def disconnect_ssh_hosts():
    """Disconnect all SSH connections"""
    try:
        disconnect_all()
        return {"success": True, "message": "All SSH connections closed"}
    except Exception as e:
        logger.error(f"Error disconnecting SSH hosts: {str(e)}")
        return {"success": False, "message": f"Failed to disconnect: {str(e)}"}

# Removed redundant check-scapy endpoint - consolidated with check-tool endpoint

@app.get("/api/traffic-generators/check-tool/{host_type}/{tool}")
async def check_tool(host_type: str, tool: str):
    """Check if a specific tool is installed on the specified host"""
    if host_type not in ["client", "server"]:
        raise HTTPException(status_code=400, detail="Invalid host type. Must be 'client' or 'server'")
    
    if tool not in ["scapy", "hping3", "iperf3", "samba"]:
        raise HTTPException(status_code=400, detail="Invalid tool. Must be 'scapy', 'hping3', 'iperf3', or 'samba'")
    
    try:
        result = check_tool_installation(host_type, tool)
        return result
    except Exception as e:
        logger.error(f"Error checking {tool} installation on {host_type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to check {tool} installation: {str(e)}")


async def install_tool_async(host_type: str, tool: str):
    """Asynchronously install a tool on the specified host"""
    install_key = f"{host_type}-{tool}"
    
    try:
        # Update status to installing
        installation_status[install_key] = {
            "status": "installing",
            "message": f"Starting installation of {tool} on {host_type}...",
            "start_time": time.time(),
            "success": None,
            "version": None
        }
        
        # Call the actual installation function
        result = install_tool_on_host(host_type, tool)
        
        # Update status based on result
        if result["success"]:
            # Try to get version from the message or check again
            version = None
            if "version" in result:
                version = result["version"]
            else:
                # Try to extract version from message or check installation
                try:
                    check_result = check_tool_installation(host_type, tool)
                    if check_result["installed"]:
                        version = check_result["version"]
                except Exception:
                    pass
            
            installation_status[install_key] = {
                "status": "completed",
                "message": result["message"],
                "start_time": installation_status[install_key]["start_time"],
                "success": True,
                "version": version
            }
        else:
            installation_status[install_key] = {
                "status": "failed",
                "message": result["message"],
                "start_time": installation_status[install_key]["start_time"],
                "success": False,
                "version": None
            }
            
    except Exception as e:
        logger.error(f"Error in async installation of {tool} on {host_type}: {str(e)}")
        installation_status[install_key] = {
            "status": "failed",
            "message": f"Installation error: {str(e)}",
            "start_time": installation_status[install_key].get("start_time", time.time()),
            "success": False,
            "version": None
        }

@app.get("/api/traffic-generators/installation-status/{host_type}/{tool}")
async def get_installation_status(host_type: str, tool: str):
    """Get the installation status for a specific tool on a host"""
    if host_type not in ["client", "server"]:
        raise HTTPException(status_code=400, detail="Invalid host type. Must be 'client' or 'server'")
    
    if tool not in ["scapy", "hping3", "iperf3", "samba"]:
        raise HTTPException(status_code=400, detail="Invalid tool. Must be 'scapy', 'hping3', 'iperf3', or 'samba'")
    
    install_key = f"{host_type}-{tool}"
    
    if install_key not in installation_status:
        return {
            "status": "not_started",
            "message": "Installation not started",
            "success": None,
            "version": None
        }
    
    return installation_status[install_key]

@app.post("/api/traffic-generators/install-tool/{host_type}/{tool}")
async def install_tool(host_type: str, tool: str, background_tasks: BackgroundTasks):
    """Start installation of a specific tool on the specified host"""
    if host_type not in ["client", "server"]:
        raise HTTPException(status_code=400, detail="Invalid host type. Must be 'client' or 'server'")
    
    if tool not in ["scapy", "hping3", "iperf3", "samba"]:
        raise HTTPException(status_code=400, detail="Invalid tool. Must be 'scapy', 'hping3', 'iperf3', or 'samba'")
    
    install_key = f"{host_type}-{tool}"
    
    # Check if installation is already in progress
    if install_key in installation_status and installation_status[install_key]["status"] == "installing":
        return {
            "success": True,
            "message": f"Installation of {tool} on {host_type} is already in progress",
            "status": "installing"
        }
    
    try:
        # Start async installation
        background_tasks.add_task(install_tool_async, host_type, tool)
        
        return {
            "success": True,
            "message": f"Started installation of {tool} on {host_type}",
            "status": "installing"
        }
    except Exception as e:
        logger.error(f"Error starting installation of {tool} on {host_type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start installation of {tool}: {str(e)}")

@app.post("/api/traffic-generators/generate-traffic")
async def generate_network_traffic(request: TrafficGenerationRequest):
    """Generate network traffic using the specified tool"""
    try:
        # Validate source host
        if request.source_host not in ["client", "server"]:
            raise HTTPException(status_code=400, detail="Invalid source host. Must be 'client' or 'server'")
        
        # Validate tool
        if request.tool not in ["scapy", "hping3", "iperf3", "samba"]:
            raise HTTPException(status_code=400, detail="Invalid tool. Must be 'scapy', 'hping3', 'iperf3', or 'samba'")
        
        # Generate traffic
        result = generate_traffic(request)
        
        if not result["success"]:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": result["message"],
                    "command": result.get("command", "")
                }
            )
        
        return {
            "success": True,
            "message": result["message"],
            "output": result.get("output", ""),
            "command": result.get("command", "")
        }
    except Exception as e:
        logger.error(f"Error generating traffic: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Failed to generate traffic: {str(e)}"
            }
        )