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
import requests
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, File, UploadFile
from pydantic import BaseModel, validator, Field
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.websockets import WebSocket, WebSocketDisconnect
from urllib.parse import urljoin, urlparse
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
from utils.fmc_api import authenticate, get_ftd_uuid, replace_vpn_endpoint, get_vpn_topologies, get_vpn_endpoints, get_domains
from utils.fmc_api import delete_devices_bulk, delete_ha_pair, delete_cluster

# Import traffic generators module from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from traffic_generators import SSHConnectionDetails, connect_to_hosts, get_interfaces, disconnect_all, check_tool_installation, TrafficGenerationRequest, generate_traffic, install_tool_on_host
from configure_http_proxy import configure_http_proxy_on_device as run_http_proxy_on_device
from configure_static_routes import run_static_routes_on_device
from copy_dev_crt import run_copy_dev_cert_on_device
from download_upgrade_package import run_download_upgrade_on_device
from restore_device_backup_runner import run_restore_backup_on_device
from utils.dependency_resolver import DependencyResolver

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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(BASE_DIR, "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Templates
templates_dir = os.path.join(BASE_DIR, "templates")
templates = Jinja2Templates(directory=templates_dir)

# Pydantic models for request validation
class FMCConnectionRequest(BaseModel):
    fmc_ip: str
    username: str
    password: str
    domain_uuid: Optional[str] = None
    
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
    # Optional: mapping from device name/label to absolute backup URL. If provided, runner will skip discovery.
    backup_url_map: Optional[Dict[str, str]] = None


class BackupListRequest(BaseModel):
    base_url: str
    # Optional device names to compute best matches; if omitted, only the raw backups list is returned
    device_names: Optional[List[str]] = None


@app.post("/api/command-center/backups/list")
async def command_center_list_backups(req: BackupListRequest):
    try:
        base_url = (req.base_url or "").strip()
        if not base_url:
            return JSONResponse(status_code=400, content={"success": False, "message": "base_url is required"})
        # Fetch directory listing
        try:
            r = requests.get(base_url, timeout=10)
            r.raise_for_status()
            html = r.text or ""
        except Exception as e:
            return JSONResponse(status_code=502, content={"success": False, "message": f"Failed to fetch base_url: {e}"})

        # Extract .tar links from HTML (anchor tags or plain text)
        import re as _re
        links = _re.findall(r'href=["\']([^"\']+\.tar)["\']', html, flags=_re.IGNORECASE)
        if not links:
            pt = _re.findall(r'(^|\s)([^\s]+\.tar)($|\s)', html, flags=_re.IGNORECASE)
            links = [m[1] for m in pt]

        def make_abs(u: str) -> str:
            try:
                if _re.match(r'^https?://', u, _re.IGNORECASE):
                    return u
                return urljoin(base_url if base_url.endswith('/') else base_url + '/', u.lstrip('/'))
            except Exception:
                return u

        backups = []
        for u in links:
            absu = make_abs(u)
            file = absu.rsplit('/', 1)[-1]
            # Derive a naive device candidate: prefix before first underscore
            dev_guess = file.rsplit('.', 1)[0]
            if '_' in dev_guess:
                dev_guess = dev_guess.split('_', 1)[0]
            backups.append({"device_name": dev_guess, "file": file, "url": absu})

        result: Dict[str, Any] = {"success": True, "base_url": base_url, "backups": backups}

        # Optional matching for provided device_names with boundary-aware scoring
        names = req.device_names or []
        if names:
            scored_matches = []
            for name in names:
                label_esc = _re.escape(name)
                p_strong = _re.compile(rf'(^|[_\-/]){label_esc}([_\-/\.]|$)', _re.IGNORECASE)
                p_weak = _re.compile(rf'{label_esc}', _re.IGNORECASE)
                best = None
                best_score = -1
                for b in backups:
                    bn = b.get("file") or ""
                    score = 0
                    if p_strong.search(bn):
                        score += 100
                    elif p_weak.search(bn):
                        score += 10
                    # Prefer larger numeric tokens in filename
                    nums = _re.findall(r'(\d{8,})', bn)
                    if nums:
                        try:
                            score += max(int(x) for x in nums)
                        except Exception:
                            score += len(nums)
                    if score > best_score:
                        best_score = score
                        best = b
                if best:
                    scored_matches.append({"device_name": name, "file": best.get("file"), "url": best.get("url"), "score": best_score})
            result["matches"] = scored_matches

        return result
    except Exception as e:
        logger.error(f"Backup list error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# Persisted devices state (in-memory)
cc_devices_state: Dict[str, List[Dict[str, Any]]] = {"ftd": [], "fmc": []}
cc_proxy_presets: List[Dict[str, Any]] = []
cc_static_presets: List[Dict[str, Any]] = []
fmc_config_presets: List[Dict[str, Any]] = []

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

@app.get("/fmc-configuration", response_class=HTMLResponse)
async def fmc_configuration(request: Request):
    return templates.TemplateResponse("fmc_configuration.html", {"request": request, "active_page": "fmc_configuration"})

@app.get("/api/fmc-config/presets")
async def fmc_list_presets():
    return {"success": True, "presets": fmc_config_presets}

@app.post("/api/fmc-config/presets/save")
async def fmc_save_preset(payload: Dict[str, Any]):
    try:
        name = (payload.get("name") or f"Preset {len(fmc_config_presets)+1}").strip()
        preset = {
            "id": str(uuid.uuid4()),
            "name": name,
            "fmc_ip": payload.get("fmc_ip", ""),
            "username": payload.get("username", ""),
            "password": payload.get("password", ""),
        }
        fmc_config_presets.append(preset)
        return {"success": True, "preset": preset, "presets": fmc_config_presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/fmc-config/presets/{preset_id}")
async def fmc_delete_preset(preset_id: str):
    try:
        before = len(fmc_config_presets)
        fmc_config_presets[:] = [p for p in fmc_config_presets if p.get("id") != preset_id]
        return {"success": True, "deleted": before - len(fmc_config_presets), "presets": fmc_config_presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.post("/api/fmc-config/connect")
async def fmc_connect(request: FMCConnectionRequest):
    try:
        # Authenticate using existing fmc_api helper
        default_domain_uuid, headers = authenticate(request.fmc_ip, request.username, request.password)
        # Save auth context for future operations
        fmc_auth["domain_uuid"] = default_domain_uuid
        fmc_auth["headers"] = headers

        # Fetch domains for dropdown
        domains = get_domains(request.fmc_ip, headers)

        # Determine which domain to use for device list
        selected_domain_uuid = request.domain_uuid or default_domain_uuid
        if isinstance(selected_domain_uuid, str) and selected_domain_uuid.lower() == 'undefined':
            selected_domain_uuid = default_domain_uuid

        # Fetch all registered device records (FTDs managed by FMC) for selected domain
        url = f"{request.fmc_ip}/api/fmc_config/v1/domain/{selected_domain_uuid}/devices/devicerecords?expanded=true&limit=1000"
        headers_for_domain = dict(headers)
        headers_for_domain["DOMAIN_UUID"] = selected_domain_uuid
        logger.info(f"Fetching device records for domain {selected_domain_uuid} -> {url}")
        resp = requests.get(url, headers=headers_for_domain, verify=False)
        resp.raise_for_status()
        try:
            items = resp.json().get("items", [])
        except Exception:
            items = []
        logger.info(f"Fetched {len(items)} device record(s) for domain {selected_domain_uuid}")
        # Update current domain for subsequent operations
        fmc_auth["domain_uuid"] = selected_domain_uuid
        # Sort domains by name for UI convenience
        try:
            domains_sorted = sorted(domains, key=lambda d: (d.get("name") or "").lower())
        except Exception:
            domains_sorted = domains
        # Provide additional hints to the UI
        global_domain = next((d for d in domains_sorted if (d.get("name") or "").lower() == "global"), None)
        ui_domain_uuid = (global_domain or {}).get("id") or selected_domain_uuid
        return {
            "success": True,
            "devices": items,
            "domains": domains_sorted,
            "domain_uuid": selected_domain_uuid,  # domain actually used to fetch devices
            "default_domain_uuid": default_domain_uuid,
            "global_domain_uuid": (global_domain or {}).get("id"),
            "ui_domain_uuid": ui_domain_uuid
        }
    except Exception as e:
        logger.error(f"FMC connect failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/fmc-config/delete/stream")
async def fmc_delete_devices_stream(payload: Dict[str, Any]):
    """Stream deletion logs while unregistering selected devices from FMC.
    Expects: { fmc_ip: str, device_ids: [str, ...] }
    """
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        device_ids: List[str] = payload.get("device_ids") or []
        if not fmc_ip or not device_ids:
            return JSONResponse(status_code=400, content={"success": False, "message": "fmc_ip and device_ids are required"})
        if not fmc_auth.get("headers") or not fmc_auth.get("domain_uuid"):
            return JSONResponse(status_code=400, content={"success": False, "message": "Not authenticated to FMC. Please Connect first."})

        headers = fmc_auth["headers"]
        domain_uuid = (payload.get("domain_uuid") or fmc_auth.get("domain_uuid"))

        def event_stream():
            try:
                yield f"Starting deletion of {len(device_ids)} device(s)\n"
                # For richer logs, we could loop, but FMC supports bulk delete, so do it in one call
                headers_for_domain = dict(headers)
                if domain_uuid:
                    headers_for_domain["DOMAIN_UUID"] = domain_uuid
                result = delete_devices_bulk(fmc_ip, headers_for_domain, domain_uuid, device_ids)
                yield f"Delete response: {json.dumps(result)}\n"
                yield "SUMMARY {\"deleted\": true}\n"
            except Exception as ex:
                yield f"ERROR {str(ex)}\n"

        return StreamingResponse(event_stream(), media_type="text/plain")
    except Exception as e:
        logger.error(f"FMC delete stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ---------------- Device Configuration (Upload / Schema Downloads / Apply) ----------------

@app.get("/api/fmc-config/schema/components")
async def fmc_schema_components():
    """Download the entire components.schemas section from merged OpenAPI as JSON."""
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        oas_path = os.path.join(project_root, "utils/merged_oas3.json")
        with open(oas_path, "r", encoding="utf-8") as f:
            oas = json.load(f)
        schemas = ((oas.get("components") or {}).get("schemas") or {})
        content = json.dumps(schemas, indent=2)
        return StreamingResponse(io.StringIO(content), media_type="application/json", headers={
            "Content-Disposition": "attachment; filename=fmc_components_schemas.json"
        })
    except Exception as e:
        logger.error(f"Failed to read components.schemas: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/fmc-config/schema/sample-yaml")
async def fmc_schema_sample_yaml():
    """Download curated Sample Schema YAML with only necessary fields and inline enum annotations."""
    try:
        # Enumerations sourced from OpenAPI
        duplex_vals = "AUTO | FULL | HALF"
        fec_vals = "AUTO | CL108RS | CL74FC | CL91RS | DISABLE"
        flow_vals = "ON | OFF"
        speed_vals = "AUTO | TEN | HUNDRED | THOUSAND | TWO_THOUSAND_FIVE_HUNDRED | TEN_THOUSAND | TWENTY_FIVE_THOUSAND | FORTY_THOUSAND | FIFTY_THOUSAND | HUNDRED_THOUSAND | TWO_HUNDRED_THOUSAND | FOUR_HUNDRED_THOUSAND | DETECT_SFP"
        mode_vals = "INLINE | PASSIVE | TAP | ERSPAN | NONE | SWITCHPORT"
        lacp_mode_vals = "ACTIVE | PASSIVE | ON"
        lacp_rate_vals = "DEFAULT | NORMAL | FAST"
        lb_vals = "DST_IP | DST_IP_PORT | DST_PORT | DST_MAC | SRC_IP | SRC_IP_PORT | SRC_PORT | SRC_MAC | SRC_DST_IP | SRC_DST_IP_PORT | SRC_DST_PORT | SRC_DST_MAC | VLAN_DST_IP | VLAN_DST_IP_PORT | VLAN_SRC_IP | VLAN_SRC_IP_PORT | VLAN_SRC_DST_IP | VLAN_SRC_DST_IP_PORT | VLAN_ONLY"
        pm_type_vals = "AUTO | PEER_IPV4 | PEER_IPV6 | AUTO4 | AUTO6"
        ppp_auth_vals = "PAP | CHAP | MSCHAP"
        ipsec_mode_vals = "ipv4 | ipv6"  # from examples (type is string in OAS)
        tunnel_type_vals = "STATIC | DYNAMIC"       # from examples (type is string in OAS)

        yaml_text = f"""
# FMC Device Configuration Sample Schema (Minimal)
# Notes:
# - Enum fields list all possible values next to the example values.
# - All id fields use placeholders; replace with real UUIDs when applying.

loopback_interfaces:
  - enabled: true
    ifname: loopback-5
    ipv4:
      static:
        address: 169.254.100.1
        netmask: 255.255.255.252
    ipv6:
      addresses:
        - address: ee::11
          prefix: "64"
    loopbackId: 5
    type: LoopbackInterface

physical_interfaces:
  - LLDP:
      receive: false
      transmit: false
    MTU: 1500
    enableSGTPropagate: false
    enabled: true
    hardware:
      autoNegState: true
      duplex: FULL # values: {duplex_vals}
      fecMode: CL108RS # values: {fec_vals}
      flowControlSend: OFF # values: {flow_vals}
      speed: TWENTY_FIVE_THOUSAND # values: {speed_vals}
    id: PLACEHOLDER-UUID
    ifname: inside
    ipv4:
      static:
        address: 169.254.100.1
        netmask: 255.255.255.252
    ipv6:
      addresses:
        - address: ee::11
          prefix: "64"
    managementOnly: false
    mode: NONE # values: {mode_vals}
    name: Ethernet1/16
    nveOnly: false
    type: PhysicalInterface

etherchannel_interfaces:
  - LLDP:
      receive: false
      transmit: false
    MTU: 1500
    applicationMonitoring:
      enable: true
    enableAntiSpoofing: false
    enableSGTPropagate: true
    enabled: true
    etherChannelId: 1
    hardware:
      autoNegState: true
      duplex: FULL # values: {duplex_vals}
      flowControlSend: OFF # values: {flow_vals}
      speed: THOUSAND # values: {speed_vals}
    ifname: NewEthChannel
    ipv4:
      static:
        address: 1.2.3.5
        netmask: "25"
    ipv6:
      addresses:
        - address: "9090::"
          prefix: "12"
      dadAttempts: 1
      nsInterval: 10000
      reachableTime: 0
    lacpMode: ACTIVE # values: {lacp_mode_vals}
    lacpRate: DEFAULT # values: {lacp_rate_vals}
    loadBalancing: SRC_IP_PORT # values: {lb_vals}
    managementOnly: false
    maxActivePhysicalInterface: 8
    minActivePhysicalInterface: 1
    mode: NONE # values: {mode_vals}
    nveOnly: false
    overrideDefaultFragmentSetting: {{}}
    pathMonitoring:
      enable: true
      monitoredIp: 1.2.3.4
      type: AUTO # values: {pm_type_vals}
    priority: 10
    securityZone:
      name: INSIDE
      id: PLACEHOLDER-UUID
      type: SecurityZone
    selectedInterfaces:
      - id: PLACEHOLDER-UUID
        name: Ethernet1/1
        type: PhysicalInterface
    type: EtherChannelInterface

subinterfaces:
  - MTU: 1500
    applicationMonitoring:
      enable: true
    arpConfig:
      - enableAlias: false
        ipAddress: 101.101.101.101/25
        macAddress: 03DC.1234.2323
    enableAntiSpoofing: true
    enableSGTPropagate: true
    enabled: true
    ifname: Intf_name
    ipv4:
      dhcp:
        dhcpRouteMetric: 1
        enableDefaultRouteDHCP: true
      pppoe:
        enableRouteSettings: true
        ipAddress: 1.2.3.4/25
        pppAuth: PAP # values: {ppp_auth_vals}
        pppoePassword: User_password
        pppoeRouteMetric: 1
        pppoeUser: User_name
        storeCredsInFlash: false
        vpdnGroupName: VPDN_group_name
      static:
        address: 1.2.3.4
        netmask: "25"
    ipv6:
      addresses:
        - address: 2001::
          enforceEUI64: false
          prefix: "124"
        - address: 8080::
          enforceEUI64: true
          prefix: "12"
      dadAttempts: 1
      enableAutoConfig: true
      enableDHCPAddrConfig: true
      enableDHCPNonAddrConfig: false
      enableIPV6: true
      enableIPV6DadLoopbackDetect: true
      enableRA: false
      enforceEUI64: false
      linkLocalAddress: FE80::
      nsInterval: 10000
      prefixes:
        - address: 2001::/124
          advertisement:
            autoConfig: false
            offlink: false
            preferLifeTime:
              duration:
                preferLifeTime: 604800
                validLifeTime: 2592300
              expirationLifeTime:
                preferDateTime: 2016-11-05T08:15:30-05:00
                validDateTime: 2016-12-05T08:15:30-05:00
          default: false
      raDnsDomains:
        - domainName: asia-zone.com
          lifeTime: 201
      raDnsServers:
        - address: 1001::1
          lifeTime: 201
      raInterval: 200
      raLifeTime: 1800
      reachableTime: 0
    managementOnly: true
    name: Ethernet1/1
    overrideDefaultFragmentSetting:
      chain: 24
      size: 200
      timeout: 5
    pathMonitoring:
      enable: true
      monitoredIp: 1.2.3.4
      type: AUTO # values: {pm_type_vals}
    priority: 10
    securityZone:
      name: INSIDE
      id: PLACEHOLDER-UUID
      type: SecurityZone
    subIntfId: 12345
    type: SubInterface
    vlanId: 30

# - Static Virtual Tunnel Interface with Configure IP and IPv4 tunnel source

vti_interfaces:
  - enabled: true
    ifname: tunnel-5
    ipsecMode: ipv4 # values: {ipsec_mode_vals}
    ipv4:
      static:
        address: 169.254.100.1
        netmask: 255.255.255.252
    name: Tunnel5
    securityZone:
      name: INSIDE
      id: PLACEHOLDER-UUID
      type: SecurityZone
    tunnelId: 5
    tunnelSource:
      id: PLACEHOLDER-UUID
      name: GigabitEthernet0/0
      type: PhysicalInterface
    tunnelType: STATIC # values: {tunnel_type_vals}
    type: VTIInterface

# - Dynamic Virtual Tunnel Interface with Borrow IP and IPv6 tunnel source

vti_interfaces:
  - enabled: true
    ifname: dvti-1
    ipsecMode: ipv6 # values: {ipsec_mode_vals}
    borrowIPfrom:
        id: PLACEHOLDER-UUID
        name: Loopback12
        type: LoopbackInterface
    name: Virtual-Template1
    securityZone:
      name: INSIDE
      id: PLACEHOLDER-UUID
      type: SecurityZone
    tunnelId: 1
    tunnelSource:
      id: PLACEHOLDER-UUID
      name: GigabitEthernet0/0
      type: PhysicalInterface
    tunnelSrcIPv6IntfAddr: 2000::1
    tunnelType: DYNAMIC # values: {tunnel_type_vals}
    type: VTIInterface


# Optional: definitions for auto-creation of missing dependencies
objects:
  interface:
    security_zones:
      - name: INSIDE
        type: SecurityZone
        interfaceMode: ROUTED  # Recommended; default used if omitted
"""
        return StreamingResponse(io.StringIO(yaml_text.strip() + "\n"), media_type="text/yaml", headers={
            "Content-Disposition": "attachment; filename=sample_device_schema.yaml"
        })
    except Exception as e:
        logger.error(f"Failed to build sample schema YAML: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/fmc-config/config/upload")
async def fmc_config_upload(file: UploadFile = File(...)):
    try:
        raw = await file.read()
        data = yaml.safe_load(raw) or {}
        cfg = {
            "loopback_interfaces": data.get("loopback_interfaces") or [],
            "physical_interfaces": data.get("physical_interfaces") or [],
            "etherchannel_interfaces": data.get("etherchannel_interfaces") or [],
            "subinterfaces": data.get("subinterfaces") or [],
            "vti_interfaces": data.get("vti_interfaces") or [],
            # Pass-through optional objects for dependency creation (e.g., security_zones)
            "objects": data.get("objects") or {}
        }
        # Count only list-based config sections + nested object counts we present in UI
        counts = {k: len(v) for k, v in cfg.items() if isinstance(v, list)}
        try:
            obj_if_sz = ((cfg.get("objects") or {}).get("interface") or {}).get("security_zones") or []
            counts["objects_interface_security_zones"] = len(obj_if_sz)
        except Exception:
            counts["objects_interface_security_zones"] = 0
        return {"success": True, "config": cfg, "counts": counts}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid YAML: {e}"})


@app.post("/api/fmc-config/config/apply")
async def fmc_config_apply(payload: Dict[str, Any]):
    """Apply selected configuration types to the selected device, in required order.
    Expects JSON with:
      fmc_ip, username, password, device_id, domain_uuid (optional),
      apply_loopbacks, apply_physicals, apply_etherchannels, apply_subinterfaces, apply_vtis,
      config: { loopback_interfaces: [...], physical_interfaces: [...], etherchannel_interfaces: [...], subinterfaces: [...], vti_interfaces: [...] }
    """
    try:
        # Execute heavy operation in thread to allow /api/logs polling concurrently
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _apply_config_sync(payload))
        return result
    except Exception as e:
        logger.error(f"FMC config apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _apply_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    fmc_ip = (payload.get("fmc_ip") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    device_id = (payload.get("device_id") or "").strip()
    if not fmc_ip or not username or not password or not device_id:
        return {"success": False, "message": "Missing fmc_ip, username, password, or device_id"}

    sel_domain = (payload.get("domain_uuid") or fmc_auth.get("domain_uuid") or "").strip()
    auth_domain, headers = authenticate(fmc_ip, username, password)
    domain_uuid = sel_domain or auth_domain

    cfg = payload.get("config") or {}
    loops = cfg.get("loopback_interfaces") or []
    phys = cfg.get("physical_interfaces") or []
    eths = cfg.get("etherchannel_interfaces") or []
    subs = cfg.get("subinterfaces") or []
    vtis = cfg.get("vti_interfaces") or []

    apply_bulk = bool(payload.get("apply_bulk", True))
    batch_size = int(payload.get("batch_size") or 25)
    if batch_size <= 0:
        batch_size = 25

    # Build interface maps for the destination device
    from utils.fmc_api import get_physical_interfaces, get_etherchannel_interfaces, get_subinterfaces, get_vti_interfaces
    from utils.fmc_api import create_loopback_interface, put_physical_interface, post_etherchannel_interface, post_subinterface, post_vti_interface

    dest_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, device_id)
    phys_map = { (item.get('name') or item.get('ifname')): item.get('id') for item in dest_phys if item.get('id') }
    dest_eth = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, device_id)
    eth_map = { item.get('name'): item.get('id') for item in dest_eth if item.get('id') }

    # Prime resolver for interfaces and security zones
    resolver = DependencyResolver(fmc_ip, headers, domain_uuid, device_id)
    resolver.prime_device_interfaces()
    resolver.prime_security_zones()

    # Ensure required SecurityZones exist (create-if-missing)
    def _collect_zone_names(items: List[Dict[str, Any]], field: str = "securityZone") -> Set[str]:
        names: Set[str] = set()
        for it in (items or []):
            try:
                sz = it.get(field) or {}
                nm = (sz.get("name") or "").strip()
                if nm:
                    names.add(nm)
            except Exception:
                continue
        return names

    cfg_objects = (cfg.get("objects") or {}) if isinstance(cfg, dict) else {}
    obj_interface = (cfg_objects.get("interface") or {}) if isinstance(cfg_objects, dict) else {}
    sec_zone_defs = obj_interface.get("security_zones") or []

    needed_zones: Set[str] = set()
    needed_zones |= _collect_zone_names(phys)
    needed_zones |= _collect_zone_names(eths)
    needed_zones |= _collect_zone_names(subs)
    needed_zones |= _collect_zone_names(vtis)
    if needed_zones:
        if bool(payload.get("apply_obj_if_security_zones", False)):
            logger.info(f"[Objects > Interface] Ensuring SecurityZones exist for: {sorted(list(needed_zones))}")
            created_zones = resolver.ensure_security_zones(sec_zone_defs, needed_zones)
            if created_zones:
                logger.info(f"Created {len(created_zones)} SecurityZone(s): {[z.get('name') for z in created_zones]}")
            else:
                logger.info("All referenced SecurityZones already exist; none created")
        else:
            logger.info("[Objects > Interface] Skipping SecurityZones creation (checkbox not selected)")

    applied = {"loopbacks": 0, "physicals": 0, "etherchannels": 0, "subinterfaces": 0, "vtis": 0}
    errors: List[str] = []

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    # 1) Loopback interfaces (no bulk API -> process in batches, item-by-item)
    if payload.get("apply_loopbacks") and loops:
        logger.info(f"Applying {len(loops)} loopback interface(s) in batches of {batch_size if apply_bulk else 1}")
        for group in (chunks(loops, batch_size) if apply_bulk else [loops]):
            for lb in group:
                try:
                    if not lb.get("type"): lb["type"] = "LoopbackInterface"
                    create_loopback_interface(fmc_ip, headers, domain_uuid, device_id, lb)
                    logger.info(f"Created loopback {lb.get('ifname') or lb.get('name')}")
                    applied["loopbacks"] += 1
                except Exception as ex:
                    errors.append(f"Loopback {lb.get('ifname') or lb.get('name')}: {ex}")
        # Refresh interface caches so subsequent steps (e.g., VTI borrowIPfrom) can resolve newly created loopbacks
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Loopback creation: {e}")

    # 2) Physical interfaces (update; no bulk -> in batches)
    if payload.get("apply_physicals") and phys:
        logger.info(f"Applying {len(phys)} physical interface(s)")
        for group in (chunks(phys, batch_size) if apply_bulk else [phys]):
            for ph in group:
                try:
                    nm = ph.get("name") or ph.get("ifname")
                    obj_id = phys_map.get(nm)
                    if not obj_id:
                        raise Exception(f"Physical interface '{nm}' not found on device")
                    ph_payload = dict(ph)
                    ph_payload["id"] = obj_id
                    # Resolve SecurityZone by name (and any nested interface refs if provided)
                    resolver.resolve_interfaces_in_payload(ph_payload)
                    put_physical_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, ph_payload)
                    logger.info(f"Updated PhysicalInterface {nm} (id={obj_id})")
                    applied["physicals"] += 1
                except Exception as ex:
                    errors.append(f"Physical {ph.get('name') or ph.get('ifname')}: {ex}")

    # 3) EtherChannel interfaces (create; no bulk -> in batches)
    if payload.get("apply_etherchannels") and eths:
        logger.info(f"Applying {len(eths)} EtherChannel interface(s)")
        for group in (chunks(eths, batch_size) if apply_bulk else [eths]):
            for ec in group:
                try:
                    p = dict(ec)
                    p.setdefault("type", "EtherChannelInterface")
                    members = []
                    for m in (ec.get("members") or []):
                        mname = m.get("name")
                        mid = phys_map.get(mname)
                        if not mid:
                            raise Exception(f"Member interface '{mname}' not found on device")
                        members.append({"id": mid, "type": "PhysicalInterface", "name": mname})
                    if members:
                        p["memberInterfaces"] = members
                    # Resolve SecurityZone by name
                    resolver.resolve_interfaces_in_payload(p)
                    post_etherchannel_interface(fmc_ip, headers, domain_uuid, device_id, p)
                    logger.info(f"Created EtherChannel {ec.get('name')}")
                    applied["etherchannels"] += 1
                except Exception as ex:
                    errors.append(f"EtherChannel {ec.get('name')}: {ex}")

    # 4) Subinterfaces (create; supports bulk) - pass payload as-is
    if payload.get("apply_subinterfaces") and subs:
        logger.info(f"Applying {len(subs)} subinterface(s) in {'bulk' if apply_bulk else 'single'} mode")
        if apply_bulk:
            for group in chunks(subs, batch_size):
                try:
                    out_payload = []
                    for si in group:
                        p = dict(si)
                        p.setdefault("type", "SubInterface")
                        # Resolve parentInterface and securityZone ids
                        resolver.resolve_interfaces_in_payload(p)
                        out_payload.append(p)
                    if out_payload:
                        post_subinterface(fmc_ip, headers, domain_uuid, device_id, out_payload, bulk=True)
                        logger.info(f"Posted {len(out_payload)} SubInterface(s) in bulk")
                        applied["subinterfaces"] += len(out_payload)
                except Exception as ex:
                    errors.append(f"Subinterface batch: {ex}")
        else:
            for si in subs:
                try:
                    p = dict(si)
                    p.setdefault("type", "SubInterface")
                    resolver.resolve_interfaces_in_payload(p)
                    post_subinterface(fmc_ip, headers, domain_uuid, device_id, p, bulk=False)
                    logger.info(f"Created SubInterface {p.get('name')}.{p.get('subIntfId')}")
                    applied["subinterfaces"] += 1
                except Exception as ex:
                    errors.append(f"Subinterface {si.get('subIntfId')}: {ex}")

        # Refresh interface caches so subsequent steps can resolve newly created subinterfaces
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Subinterface creation: {e}")

    # 5) VTI interfaces (create; supports bulk) - pass payload as-is
    if payload.get("apply_vtis") and vtis:
        logger.info(f"Applying {len(vtis)} VTI interface(s) in {'bulk' if apply_bulk else 'single'} mode")
        if apply_bulk:
            for group in chunks(vtis, batch_size):
                try:
                    out_payload = []
                    for vt in group:
                        p = dict(vt)
                        p.setdefault("type", "VTIInterface")
                        # Resolve tunnelSource, borrowIPfrom and securityZone
                        resolver.resolve_interfaces_in_payload(p)
                        out_payload.append(p)
                    if out_payload:
                        post_vti_interface(fmc_ip, headers, domain_uuid, device_id, out_payload if len(out_payload) > 1 else out_payload[0], bulk=(len(out_payload) > 1))
                        logger.info(f"Posted {len(out_payload)} VTI Interface(s) in {'bulk' if len(out_payload) > 1 else 'single'} mode")
                        applied["vtis"] += len(out_payload)
                except Exception as ex:
                    errors.append(f"VTI batch: {ex}")
        else:
            try:
                for vt in vtis:
                    p = dict(vt)
                    p.setdefault("type", "VTIInterface")
                    resolver.resolve_interfaces_in_payload(p)
                    post_vti_interface(fmc_ip, headers, domain_uuid, device_id, p, bulk=False)
                    logger.info(f"Created VTIInterface {p.get('name') or p.get('ifname')}")
                    applied["vtis"] += 1
            except Exception as ex:
                errors.append(f"VTI: {ex}")

    # Log a summary so UI tailer shows the same info as popups
    if errors:
        logger.info("Configuration applied with some errors. See terminal.")
    else:
        logger.info("Configuration applied successfully")
    return {"success": True, "applied": applied, "errors": errors}

def _export_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a YAML export for exactly one selected device and return in-memory content.

    Expected payload:
      { fmc_ip, username, password, domain_uuid?, device_ids: [singleId] }
    Returns: { success, filename, content }
    """
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        device_ids: List[str] = payload.get("device_ids") or []
        if not fmc_ip or not username or not password or not device_ids:
            return {"success": False, "message": "Missing fmc_ip, username, password, or device_ids"}
        if len(device_ids) != 1:
            return {"success": False, "message": "Select exactly one device for Get Config export"}

        sel_domain = (payload.get("domain_uuid") or fmc_auth.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain

        # Resolve device names for nicer filename
        from utils.fmc_api import get_devicerecords, get_security_zones
        from utils.fmc_api import (
            get_loopback_interfaces,
            get_physical_interfaces,
            get_etherchannel_interfaces,
            get_subinterfaces,
            get_vti_interfaces,
        )

        records = get_devicerecords(fmc_ip, headers, domain_uuid, bulk=True) or []
        rec_map = {str(r.get("id")): r for r in records}

        dev_id = device_ids[0]
        dev_rec = rec_map.get(dev_id) or {}
        dev_name = (dev_rec.get("name") or dev_rec.get("hostName") or dev_id).strip() or dev_id
        logger.info(f"Exporting configuration for device {dev_name} ({dev_id})")

        loops = get_loopback_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        eths = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        subs = get_subinterfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []

        # Remove non-portable keys
        def _strip(lst: List[Dict[str, Any]]):
            out = []
            for it in (lst or []):
                p = dict(it)
                p.pop("links", None)
                p.pop("metadata", None)
                out.append(p)
            return out

        phys = _strip(phys)
        eths = _strip(eths)
        subs = _strip(subs)
        vtis = _strip(vtis)

        # Collect referenced SecurityZone names
        def _collect_zone_names(items: List[Dict[str, Any]], field: str = "securityZone") -> Set[str]:
            names: Set[str] = set()
            for it in (items or []):
                try:
                    sz = it.get(field) or {}
                    nm = (sz.get("name") or "").strip()
                    if nm:
                        names.add(nm)
                except Exception:
                    continue
            return names

        # VRF export removed per user request; only Security Zones are exported.

        all_zones = get_security_zones(fmc_ip, headers, domain_uuid) or []
        zones_by_name = {str(z.get("name")): z for z in all_zones if z.get("name")}
        zones_by_id = {str(z.get("id")): z for z in all_zones if z.get("id")}

        # Ensure each interface's securityZone has a name (resolve by id)
        def _fill_zone_names(items: List[Dict[str, Any]], field: str = "securityZone"):
            for it in (items or []):
                try:
                    sz = it.get(field) or {}
                    if isinstance(sz, dict) and sz.get("id") and not sz.get("name"):
                        zid = str(sz.get("id"))
                        z = zones_by_id.get(zid)
                        if z and z.get("name"):
                            sz["name"] = z.get("name")
                            it[field] = sz
                except Exception:
                    continue

        _fill_zone_names(phys)
        _fill_zone_names(eths)
        _fill_zone_names(subs)
        _fill_zone_names(vtis)

        needed_zone_names: Set[str] = set()
        needed_zone_names |= _collect_zone_names(phys)
        needed_zone_names |= _collect_zone_names(eths)
        needed_zone_names |= _collect_zone_names(subs)
        needed_zone_names |= _collect_zone_names(vtis)
        sz_defs: List[Dict[str, Any]] = []
        for nm in sorted(list(needed_zone_names)):
            z = zones_by_name.get(nm)
            if not z:
                continue
            entry = {"name": z.get("name"), "type": "SecurityZone"}
            if z.get("interfaceMode"):
                entry["interfaceMode"] = z.get("interfaceMode")
            sz_defs.append(entry)

        # Routing export removed per user request; keep empty block so downstream logic remains intact.
        routing_block: Dict[str, Any] = {}

        cfg_out = {
            "loopback_interfaces": loops,
            "physical_interfaces": phys,
            "etherchannel_interfaces": eths,
            "subinterfaces": subs,
            "vti_interfaces": vtis,
        }
        if sz_defs:
            cfg_out["objects"] = {"interface": {"security_zones": sz_defs}}
        if routing_block:
            cfg_out["routing"] = routing_block

        # Build filename and content (no saving to disk)
        safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "-" for c in dev_name)
        ts = time.strftime("%Y%m%d-%H%M%S")
        filename = f"{safe_name}_{ts}.yaml"
        content = yaml.safe_dump(cfg_out, sort_keys=False)
        return {"success": True, "filename": filename, "content": content}
    except Exception as e:
        logger.error(f"Export error: {e}")
        return {"success": False, "message": str(e)}

@app.post("/api/fmc-config/config/get")
async def fmc_config_get(payload: Dict[str, Any]):
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _export_config_sync(payload))
        if not result.get("success"):
            return JSONResponse(status_code=400, content=result)
        filename = result.get("filename") or "export.yaml"
        content = (result.get("content") or "").encode("utf-8", errors="ignore")
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"FMC config get error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/fmc-config/config/delete")
async def fmc_config_delete(payload: Dict[str, Any]):
    """Delete selected configuration types from the selected device.

    Expects JSON with:
      fmc_ip, username, password, device_id, domain_uuid (optional),
      delete_loopbacks, delete_physicals, delete_etherchannels, delete_subinterfaces, delete_vtis,
      delete_obj_if_security_zones,
      config: { loopback_interfaces: [...], physical_interfaces: [...], etherchannel_interfaces: [...], subinterfaces: [...], vti_interfaces: [...] }
    """
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _delete_config_sync(payload))
        return result
    except Exception as e:
        logger.error(f"FMC config delete error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _delete_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        device_id = (payload.get("device_id") or "").strip()
        if not fmc_ip or not username or not password or not device_id:
            return {"success": False, "message": "Missing fmc_ip, username, password, or device_id"}

        sel_domain = (payload.get("domain_uuid") or fmc_auth.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain

        cfg = payload.get("config") or {}
        loops = cfg.get("loopback_interfaces") or []
        phys = cfg.get("physical_interfaces") or []
        eths = cfg.get("etherchannel_interfaces") or []
        subs = cfg.get("subinterfaces") or []
        vtis = cfg.get("vti_interfaces") or []

        # Fetch current items on device (limit=1000)
        from utils.fmc_api import (
            get_loopback_interfaces,
            get_physical_interfaces,
            get_etherchannel_interfaces,
            get_subinterfaces,
            get_vti_interfaces,
            get_security_zones,
            delete_security_zones,
        )
        from utils.fmc_api import (
            delete_loopback_interfaces,
            delete_etherchannel_interfaces,
            delete_subinterfaces as delete_subinterfaces_api,
            delete_vti_interfaces,
            put_physical_interface,
        )

        # Build maps name->id for each type
        # Loopbacks
        dev_loops = get_loopback_interfaces(fmc_ip, headers, domain_uuid, device_id)
        loop_map: Dict[str, str] = {}
        for it in dev_loops:
            key1 = (it.get("ifname") or it.get("name") or "").strip()
            if it.get("id") and key1:
                loop_map[key1] = it["id"]

        # Physicals
        dev_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, device_id)
        phys_map: Dict[str, str] = {}
        for it in dev_phys:
            for k in [it.get("name"), it.get("ifname")]:
                if it.get("id") and k:
                    phys_map[str(k)] = it["id"]

        # EtherChannel
        dev_eths = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, device_id)
        eth_map: Dict[str, str] = {}
        for it in dev_eths:
            if it.get("id") and it.get("name"):
                eth_map[str(it.get("name"))] = it["id"]

        # Subinterfaces
        dev_subs = get_subinterfaces(fmc_ip, headers, domain_uuid, device_id)
        sub_map: Dict[str, str] = {}
        for it in dev_subs:
            sid = it.get("id")
            if not sid:
                continue
            # Index by both name and ifname (when present) to improve matching
            for k in [it.get("name"), it.get("ifname")]:
                if k:
                    sub_map[str(k)] = sid
            # Also index by parentName.subIntfId if derivable
            parent = None
            try:
                parent = (it.get("parentInterface") or {}).get("name")
            except Exception:
                parent = None
            sub_id = it.get("subIntfId")
            if parent and sub_id is not None:
                sub_map[f"{parent}.{sub_id}"] = sid

        # VTIs
        dev_vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, device_id)
        vti_map: Dict[str, str] = {}
        for it in dev_vtis:
            for k in [it.get("name"), it.get("ifname")]:
                if it.get("id") and k:
                    vti_map[str(k)] = it["id"]

        deleted_summary: Dict[str, int] = {"loopbacks": 0, "physicals": 0, "etherchannels": 0, "subinterfaces": 0, "vtis": 0, "objects_interface_security_zones": 0}
        errors: List[str] = []

        # Build id lists to delete from uploaded YAML entries
        # Recommended dependency-safe order:
        # 1) VTIs (may borrow IP from physicals)
        # 2) Subinterfaces (depend on physical or EtherChannel)
        # 3) EtherChannels (depend on physical members)
        # 4) Physical interfaces (clear)
        # 5) Loopbacks (independent)

        if payload.get("delete_vtis") and vtis:
            ids = []
            for vt in vtis:
                key = (vt.get("name") or vt.get("ifname") or "").strip()
                if key and key in vti_map:
                    ids.append(vti_map[key])
                else:
                    errors.append(f"VTI not found on device: {key}")
            if ids:
                res = delete_vti_interfaces(fmc_ip, headers, domain_uuid, device_id, list(set(ids)))
                deleted_summary["vtis"] = res.get("deleted", 0)
                for er in res.get("errors", []):
                    errors.append(f"VTI delete failed: {er}")

        if payload.get("delete_subinterfaces") and subs:
            ids = []
            for si in subs:
                # Prefer composite parentName.subIntfId, then ifname, then name
                parent = si.get("parentName") or si.get("parent") or si.get("parentInterfaceName")
                sid_val = si.get("subIntfId") or si.get("vlanId")
                cand_composite_1 = f"{parent}.{sid_val}" if parent and (sid_val is not None) else None
                cand_composite_2 = f"{si.get('name')}.{sid_val}" if si.get("name") and (sid_val is not None) else None
                candidates = [
                    (cand_composite_1 or "").strip() if cand_composite_1 else None,
                    (cand_composite_2 or "").strip() if cand_composite_2 else None,
                    (si.get("ifname") or "").strip() or None,
                    (si.get("name") or "").strip() or None,
                ]
                found_id = None
                for key in candidates:
                    if key and key in sub_map:
                        found_id = sub_map[key]
                        break
                if found_id:
                    ids.append(found_id)
                else:
                    # Provide best-effort key in error
                    err_key = next((k for k in candidates if k), "<unknown>")
                    errors.append(f"Subinterface not found on device: {err_key}")
            if ids:
                res = delete_subinterfaces_api(fmc_ip, headers, domain_uuid, device_id, list(set(ids)))
                deleted_summary["subinterfaces"] = res.get("deleted", 0)
                for er in res.get("errors", []):
                    errors.append(f"Subinterface delete failed: {er}")

        if payload.get("delete_etherchannels") and eths:
            ids = []
            for ec in eths:
                key = (ec.get("name") or "").strip()
                if key and key in eth_map:
                    ids.append(eth_map[key])
                else:
                    errors.append(f"EtherChannel not found on device: {key}")
            if ids:
                res = delete_etherchannel_interfaces(fmc_ip, headers, domain_uuid, device_id, list(set(ids)))
                deleted_summary["etherchannels"] = res.get("deleted", 0)
                for er in res.get("errors", []):
                    errors.append(f"EtherChannel delete failed: {er}")

        if payload.get("delete_physicals") and phys:
            # Clear physical interfaces using a minimal payload instead of deleting (unsupported)
            cleared = 0
            for ph in phys:
                key = (ph.get("name") or ph.get("ifname") or "").strip()
                obj_id = phys_map.get(key)
                if not obj_id:
                    errors.append(f"Physical interface not found on device: {key}")
                    continue
                current = next((it for it in dev_phys if it.get("id") == obj_id), None)
                iface_name = (current or {}).get("name") or key
                p = {
                    "enabled": False,
                    "id": obj_id,
                    "name": iface_name,
                    "type": "PhysicalInterface",
                    "mode": "NONE",
                }
                try:
                    put_physical_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                    cleared += 1
                except Exception as ex:
                    errors.append(f"Physical interface clear failed for {iface_name}: {ex}")
            deleted_summary["physicals"] = cleared

        if payload.get("delete_loopbacks") and loops:
            ids = []
            for lb in loops:
                key = (lb.get("ifname") or lb.get("name") or "").strip()
                if key and key in loop_map:
                    ids.append(loop_map[key])
                else:
                    errors.append(f"Loopback not found on device: {key}")
            if ids:
                res = delete_loopback_interfaces(fmc_ip, headers, domain_uuid, device_id, list(set(ids)))
                deleted_summary["loopbacks"] = res.get("deleted", 0)
                for er in res.get("errors", []):
                    errors.append(f"Loopback delete failed: {er}")

        # 6) Objects > Interface: Security Zones (delete after interfaces)
        def _collect_zone_names(items: List[Dict[str, Any]], field: str = "securityZone") -> Set[str]:
            names: Set[str] = set()
            for it in (items or []):
                try:
                    sz = it.get(field) or {}
                    nm = (sz.get("name") or "").strip()
                    if nm:
                        names.add(nm)
                except Exception:
                    continue
            return names

        if bool(payload.get("delete_obj_if_security_zones")):
            needed_zones: Set[str] = set()
            needed_zones |= _collect_zone_names(phys)
            needed_zones |= _collect_zone_names(eths)
            needed_zones |= _collect_zone_names(subs)
            needed_zones |= _collect_zone_names(vtis)
            if needed_zones:
                logger.info(f"[Delete Objects > Interface] Deleting SecurityZones referenced by config: {sorted(list(needed_zones))}")
                zones = get_security_zones(fmc_ip, headers, domain_uuid) or []
                name_to_id = {str(z.get("name")): z.get("id") for z in zones if z.get("name") and z.get("id")}
                ids = [name_to_id[n] for n in needed_zones if n in name_to_id]
                if ids:
                    res = delete_security_zones(fmc_ip, headers, domain_uuid, list(set(ids)))
                    deleted_summary["objects_interface_security_zones"] = res.get("deleted", 0)
                    for er in res.get("errors", []):
                        errors.append(f"SecurityZone delete failed: {er}")
                else:
                    logger.info("No matching SecurityZone IDs found to delete")
            else:
                logger.info("[Delete Objects > Interface] No referenced SecurityZones found in config")

        if errors:
            logger.info("Delete completed with some errors. See terminal.")
        else:
            logger.info("Delete completed successfully")
        return {"success": True, "deleted": deleted_summary, "errors": errors}
    except Exception as e:
        logger.error(f"FMC config delete error: {e}")
        return {"success": False, "message": str(e)}

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

                    # 1) Pre-fetch and print backups table BEFORE any SSH connection
                    import re as _re
                    from collections import deque

                    # Match .tar and common compressed variants (e.g., .tar.gz, .tar.gpg)
                    _tar_ext = _re.compile(r"\.tar(?:\.[a-z0-9]+)?", _re.IGNORECASE)

                    def _fetch(url: str) -> str:
                        try:
                            resp = requests.get(url, timeout=10)
                            resp.raise_for_status()
                            return resp.text or ""
                        except Exception as ex:
                            q.put(f"[BACKUPS] ⚠️ Fetch failed for {url}: {ex}\n")
                            return ""

                    def _is_same_origin(u: str) -> bool:
                        try:
                            b = urlparse(base_url)
                            t = urlparse(u)
                            return (t.scheme in ("http", "https")) and (t.netloc == b.netloc)
                        except Exception:
                            return False

                    def _abs(base: str, u: str) -> str:
                        try:
                            return urljoin(base if base.endswith('/') else base + '/', u.lstrip('/'))
                        except Exception:
                            return u

                    def _extract_tars(page_html: str, base: str) -> set:
                        found = set()
                        # 1) All hrefs, then filter for '.tar*' anywhere in the URL
                        for href in _re.findall(r'href=["\']([^"\']+)["\']', page_html, flags=_re.IGNORECASE):
                            if href.lower().startswith('mailto:'):
                                continue
                            absu = _abs(base, href)
                            if _tar_ext.search(absu):
                                found.add(absu)
                        # 2) Plain text tokens that look like file URLs (not necessarily in href)
                        for tok in _re.findall(r'([^\s\"\'<>]+\.tar(?:\.[a-z0-9]+)?(?:\?[^\s\"\'<>]*)?)', page_html, flags=_re.IGNORECASE):
                            found.add(_abs(base, tok))
                        return found

                    def _extract_next_pages(page_html: str, base: str) -> set:
                        nxt = set()
                        for href in _re.findall(r'href=["\']([^"\']+)["\']', page_html, flags=_re.IGNORECASE):
                            if href.lower().startswith('mailto:'):
                                continue
                            absu = _abs(base, href)
                            if '.tar' in absu.lower():
                                continue
                            # Only same origin and likely a directory or html page
                            if not _is_same_origin(absu):
                                continue
                            if absu.endswith('/') or absu.lower().endswith(('.html', '.htm')):
                                nxt.add(absu)
                        return nxt

                    visited = set()
                    queue = deque()
                    start = base_url
                    queue.append((start, 0))
                    tar_urls = set()
                    max_depth = 3  # base page + up to two levels down

                    pages_scanned = 0
                    while queue:
                        url, depth = queue.popleft()
                        if url in visited:
                            continue
                        visited.add(url)
                        html = _fetch(url)
                        if not html:
                            continue
                        pages_scanned += 1
                        tars = _extract_tars(html, url)
                        tar_urls.update(tars)
                        if depth < max_depth:
                            for nxt in _extract_next_pages(html, url):
                                if nxt not in visited:
                                    queue.append((nxt, depth + 1))

                    backups = []
                    for absu in sorted(tar_urls):
                        file = absu.rsplit('/', 1)[-1]
                        dev_guess = file.rsplit('.', 1)[0]
                        if '_' in dev_guess:
                            dev_guess = dev_guess.split('_', 1)[0]
                        backups.append({"device_name": dev_guess, "file": file, "url": absu})
                    # Print simple table to the stream log
                    q.put(f"=== Backups discovered at {base_url} ===\n")
                    q.put(f"[BACKUPS] Scanned pages: {pages_scanned}, Found files: {len(tar_urls)}\n")
                    if backups:
                        hdrs = ["Device Name", "Backup File", "Backup File URL"]
                        # Compute widths
                        w1 = max(len(hdrs[0]), max((len(b.get('device_name') or '') for b in backups), default=0))
                        w2 = max(len(hdrs[1]), max((len(b.get('file') or '') for b in backups), default=0))
                        # URL can be long; don't fix width, print as-is
                        q.put(f"{hdrs[0]:<{w1}} | {hdrs[1]:<{w2}} | {hdrs[2]}\n")
                        q.put(f"{'-'*w1}-+-{'-'*w2}-+-{'-'*len(hdrs[2])}\n")
                        for b in backups:
                            q.put(f"{(b.get('device_name') or ''):<{w1}} | {(b.get('file') or ''):<{w2}} | {b.get('url') or ''}\n")
                    else:
                        q.put("No .tar backups found.\n")

                    # Build a boundary-aware match map for selected devices
                    names = [d.get('name') or d.get('ip_address') for d in devices]
                    computed_map: Dict[str, str] = {}
                    for name in names:
                        label_esc = _re.escape(name)
                        p_strong = _re.compile(rf'(^|[_\-/]){label_esc}([_\-/\.]|$)', _re.IGNORECASE)
                        p_weak = _re.compile(rf'{label_esc}', _re.IGNORECASE)
                        best = None
                        best_score = -1
                        for b in backups:
                            bn = b.get("file") or ""
                            score = 0
                            if p_strong.search(bn):
                                score += 100
                            elif p_weak.search(bn):
                                score += 10
                            nums = _re.findall(r'(\\d{8,})', bn)
                            if nums:
                                try:
                                    score += max(int(x) for x in nums)
                                except Exception:
                                    score += len(nums)
                            if score > best_score:
                                best_score = score
                                best = b
                        if best:
                            computed_map[name] = best.get("url")

                    # Merge any provided overrides
                    file_url_map = dict(computed_map)
                    if request.backup_url_map:
                        try:
                            file_url_map.update({k: v for k, v in (request.backup_url_map or {}).items() if v})
                        except Exception:
                            pass

                    # 2) Launch SSH tasks only for devices with a resolved URL; skip others without on-box search
                    with ThreadPoolExecutor(max_workers=16) as executor:
                        for d in devices:
                            name = d.get('name') or d.get('ip_address')
                            for prt in d.get('ports', []) or [22]:
                                label = f"{name}"
                                def mk_logger(lbl: str):
                                    return lambda msg, icon="": q.put(f"[{lbl}] {icon} {msg}\n")
                                file_url = (file_url_map or {}).get(name)
                                if not file_url:
                                    # Skip device; we do not search on-box as per new flow
                                    err = {
                                        "type": d.get('type'),
                                        "name": d.get('name'),
                                        "ip_address": d.get('ip_address'),
                                        "port": prt,
                                        "success": False,
                                        "error": f"No backup URL found for device at base_url",
                                    }
                                    results.append(err)
                                    q.put("RESULT " + json.dumps(err) + "\n")
                                    continue
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
                                    file_url=file_url,
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

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}