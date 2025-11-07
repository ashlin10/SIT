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
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, File, UploadFile, Form
from pydantic import BaseModel, validator, Field
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.websockets import WebSocket, WebSocketDisconnect
from urllib.parse import urljoin, urlparse
from pydantic import BaseModel, validator, Field
from typing import Optional, List, Dict, Any, Union, Set
import asyncio
import queue
import uuid
from datetime import datetime, timezone
from collections import deque
from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction

# Add parent directory to path so we can import from the main project
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import functions from clone_device_config.py
from clone_device_config import load_yaml, fetch_config_from_source, apply_config_to_destination, create_batches
from utils.fmc_api import authenticate, get_ftd_uuid, get_ftd_name_by_id, replace_vpn_endpoint, get_vpn_topologies, get_vpn_endpoints, get_domains
from utils.fmc_api import post_vpn_topology, post_vpn_endpoint, post_vpn_endpoints_bulk
from utils.fmc_api import delete_devices_bulk, delete_ha_pair, delete_cluster
from utils import fmc_api as fmc

# Import traffic generators module from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from traffic_generators import SSHConnectionDetails, connect_to_hosts, get_interfaces, disconnect_all, check_tool_installation, TrafficGenerationRequest, generate_traffic, install_tool_on_host
from configure_http_proxy import configure_http_proxy_on_device as run_http_proxy_on_device
from configure_static_routes import run_static_routes_on_device
from copy_dev_crt import run_copy_dev_cert_on_device
from download_upgrade_package import run_download_upgrade_on_device
from restore_device_backup_runner import run_restore_backup_on_device
from utils.dependency_resolver import DependencyResolver

# Module logger (no global stream capture; per-user logs handled elsewhere)
logger = logging.getLogger(__name__)

# Note: installation_status is now tracked per-user within get_user_ctx(username)["installation_status"]

# Initialize the app
app = FastAPI()

# Sessions for login
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("WEB_APP_SESSION_SECRET", "sit-secret-key"),
    max_age=60 * 60 * 24 * 7,  # 7 days
)

# In-memory session/activity tracking
USERS = {
    "cisco": "cisco",
    "admin": "Cisco@123",
    "aleroyds": "aleroyds",
    "preddyn": "preddyn",
    "iyer": "iyer",
    "jazhagar": "jazhagar",
    "laktata": "laktata",
    "sathiyag": "sathiyag"
}

active_sessions: Dict[str, Dict[str, Any]] = {}
recent_activities: "deque[Dict[str, Any]]" = deque(maxlen=500)

# In-memory per-user contexts (persisted to disk per user directory as needed)
user_contexts: Dict[str, Dict[str, Any]] = {}

def record_activity(username: str, action: str, details: Optional[Dict[str, Any]] = None):
    try:
        recent_activities.appendleft({
            "username": username,
            "action": action,
            "details": details or {},
            "ts": datetime.utcnow().isoformat() + "Z",
        })
    except Exception:
        pass

def get_current_username(request: Request) -> Optional[str]:
    try:
        return request.session.get("username")
    except Exception:
        return None

@app.middleware("http")
async def update_last_seen(request: Request, call_next):
    username = get_current_username(request)
    if username:
        now = datetime.utcnow().isoformat() + "Z"
        sess_id = request.session.get("sid") or str(uuid.uuid4())
        request.session["sid"] = sess_id
        active_sessions[sess_id] = {
            "username": username,
            "login_time": active_sessions.get(sess_id, {}).get("login_time") or now,
            "last_seen": now,
        }
    response = await call_next(request)
    return response

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

# Per-user data directory helpers
DATA_USERS_DIR = os.path.join(BASE_DIR, "data", "users")
os.makedirs(DATA_USERS_DIR, exist_ok=True)

def _user_dir(username: str) -> str:
    p = os.path.join(DATA_USERS_DIR, username)
    os.makedirs(p, exist_ok=True)
    return p

def _read_json(path: str, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default

def _write_json(path: str, data) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        logging.exception("Failed to write %s", path)

def get_user_ctx(username: str) -> Dict[str, Any]:
    """Get or initialize per-user context and load persisted items."""
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    ctx = user_contexts.get(username)
    if ctx is None:
        # Initialize
        ctx = {
            "fmc_auth": {"domain_uuid": None, "headers": None},
            "operation_status": {
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
                },
            },
            "log_stream": io.StringIO(),
            "stop_requested": False,
            "installation_status": {},
            "cc_devices_state": {"ftd": [], "fmc": []},
            "cc_proxy_presets": [],
            "cc_static_presets": [],
            "fmc_config_presets": [],
        }
        # Load persisted
        ud = _user_dir(username)
        ctx["cc_devices_state"] = _read_json(os.path.join(ud, "devices.json"), {"ftd": [], "fmc": []})
        ctx["cc_proxy_presets"] = _read_json(os.path.join(ud, "proxy_presets.json"), [])
        ctx["cc_static_presets"] = _read_json(os.path.join(ud, "static_presets.json"), [])
        ctx["fmc_config_presets"] = _read_json(os.path.join(ud, "fmc_config_presets.json"), [])
        user_contexts[username] = ctx
    return ctx

def _attach_user_log_handlers(username: str) -> None:
    """Attach a per-user StreamHandler that writes INFO+ logs to the user's in-memory log_stream.
    Captures logs from this module and from utils.fmc_api so UI can tail them via /api/logs.
    """
    ctx = get_user_ctx(username)
    try:
        if ctx.get("log_handler_attached"):
            return
        # Ensure a stream exists (do not reset here to preserve history; UI tailer manages cursor)
        if not ctx.get("log_stream"):
            ctx["log_stream"] = io.StringIO()

        handler = logging.StreamHandler(ctx["log_stream"])
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        handler.setLevel(logging.INFO)

        # Also persist logs to a per-user file so multi-process deployments can be tailed reliably
        user_dir = _user_dir(username)
        log_file_path = os.path.join(user_dir, "operation.log")
        file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        file_handler.setLevel(logging.INFO)

        # Target loggers: this module and FMC helpers
        app_logger = logging.getLogger(__name__)
        fmc_logger = logging.getLogger("utils.fmc_api")
        app_logger.setLevel(logging.INFO)
        fmc_logger.setLevel(logging.INFO)
        app_logger.addHandler(handler)
        fmc_logger.addHandler(handler)
        app_logger.addHandler(file_handler)
        fmc_logger.addHandler(file_handler)

        ctx["log_handler"] = handler
        ctx["log_file_handler"] = file_handler
        ctx["log_file_path"] = log_file_path
        ctx["log_handler_targets"] = [app_logger.name, fmc_logger.name]
        ctx["log_handler_attached"] = True
    except Exception:
        # Best-effort; do not break main flow if logging attachment fails
        pass

def _detach_user_log_handlers(username: str) -> None:
    """Detach previously attached per-user handlers (if any)."""
    try:
        ctx = get_user_ctx(username)
        handler = ctx.pop("log_handler", None)
        file_handler = ctx.pop("log_file_handler", None)
        targets = ctx.pop("log_handler_targets", [])
        ctx["log_handler_attached"] = False
        if handler:
            for name in targets:
                try:
                    logging.getLogger(name).removeHandler(handler)
                except Exception:
                    pass
        if file_handler:
            for name in targets:
                try:
                    logging.getLogger(name).removeHandler(file_handler)
                except Exception:
                    pass
    except Exception:
        pass

def persist_user_devices(username: str):
    ud = _user_dir(username)
    _write_json(os.path.join(ud, "devices.json"), get_user_ctx(username)["cc_devices_state"])

def persist_user_presets(username: str):
    ud = _user_dir(username)
    ctx = get_user_ctx(username)
    _write_json(os.path.join(ud, "proxy_presets.json"), ctx["cc_proxy_presets"])
    _write_json(os.path.join(ud, "static_presets.json"), ctx["cc_static_presets"])
    _write_json(os.path.join(ud, "fmc_config_presets.json"), ctx["fmc_config_presets"])

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


@app.post("/api/fmc-config/vpn/list")
async def fmc_vpn_list(payload: Dict[str, Any], http_request: Request):
    """Fetch all VPN topologies from FMC and expand with endpoints and settings.
    Returns items suitable for UI table with full raw payloads for YAML download.
    """
    try:
        # Attach per-user log handlers so logs appear in UI tailer
        session_user = get_current_username(http_request)
        _attach_user_log_handlers(session_user)

        loop = asyncio.get_running_loop()

        def work():
            fmc_ip = (payload.get("fmc_ip") or "").strip()
            user = (payload.get("username") or "").strip()
            password = payload.get("password") or ""
            if not fmc_ip or not user or not password:
                return {"success": False, "message": "Missing fmc_ip, username or password"}

            sel_domain = (payload.get("domain_uuid") or "").strip()
            logger.info("[VPN] Authenticating to FMC for VPN topology listing...")
            auth_domain, headers = authenticate(fmc_ip, user, password)
            domain_uuid = sel_domain or auth_domain
            logger.info(f"[VPN] Using domain: {domain_uuid}")

            # List topologies via summaries API
            summaries_base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/s2svpnsummaries"
            try:
                r = fmc.fmc_get(f"{summaries_base}?limit=1000&expanded=true")
                r.raise_for_status()
                items = (r.json() or {}).get("items", [])
            except Exception as ex:
                return {"success": False, "message": f"Failed to fetch VPN summaries: {ex}"}

            # Also fetch full FTDS2SVpn objects to use for YAML endpoints replacement
            ftds_map: Dict[str, Any] = {}
            try:
                logger.info("[VPN] Fetching FTDS2SVpn objects for domain...")
                all_vpn_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns?expanded=true&limit=1000"
                rv = fmc.fmc_get(all_vpn_url)
                rv.raise_for_status()
                raw_items = (rv.json() or {}).get("items", [])
                # Keep FTDS2SVpn objects RAW per requirement (no sanitization)
                for itx in raw_items or []:
                    vid = itx.get("id")
                    if vid:
                        ftds_map[vid] = itx
                logger.info(f"[VPN] Collected {len(ftds_map)} FTDS2SVpn object(s)")
            except Exception as ex:
                logger.warning(f"[VPN] Failed to fetch FTDS2SVpn list: {ex}")

            out = []
            logger.info(f"[VPN] Found {len(items)} topology item(s)")

            for it in items:
                try:
                    vpn_id = it.get('id')
                    name = it.get('name')
                    route_based = bool(it.get('routeBased'))
                    topo_type = it.get('topologyType') or ''
                    logger.info(f"[VPN] Expanding topology: {name} ({vpn_id}) routeBased={route_based} topologyType={topo_type}")

                    # Fetch endpoints for full view
                    eps = []
                    try:
                        logger.info(f"[VPN]  - Fetching endpoints for {name} via ftds2svpns/{vpn_id}/endpoints...")
                        endpoints_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints?expanded=true&limit=1000"
                        re = fmc.fmc_get(endpoints_url)
                        re.raise_for_status()
                        eps = (re.json() or {}).get('items', [])
                    except Exception:
                        eps = []
                    logger.info(f"[VPN]  - Endpoints fetched: {len(eps)} for {name}")

                    # Compose a full raw entry with explicit summary and endpoints
                    raw = {
                        'summary': dict(it),
                        'endpoints': eps,
                        'ftds2svpn': ftds_map.get(vpn_id)
                    }

                    # Peers for UI (preserve role for grouping)
                    peers_info = []
                    for ep in eps or []:
                        try:
                            nm = ep.get('name') or (ep.get('device') or {}).get('name')
                            rl = (ep.get('role') or '').upper() if isinstance(ep.get('role'), str) else ''
                            pt = (ep.get('peerType') or ep.get('role') or '').upper() if isinstance(ep.get('peerType') or ep.get('role'), str) else ''
                            ex = bool(ep.get('extranet')) if isinstance(ep.get('extranet'), (bool, str, int)) else False
                            if nm:
                                peers_info.append({'name': str(nm), 'role': rl or None, 'peerType': pt or None, 'extranet': ex})
                        except Exception:
                            continue

                    out.append({
                        'name': name,
                        'type': it.get('type') or 'S2SVpnSummary',
                        'topologyType': topo_type,
                        'routeBased': route_based,
                        'peers': peers_info,
                        'raw': raw,
                    })
                except Exception as ex:
                    # Skip but continue others
                    logger.warning(f"Failed to expand VPN topology: {ex}")
                    continue

            logger.info("[VPN] Completed VPN topology listing.")
            return {"success": True, "topologies": out}

        result = await loop.run_in_executor(None, work)
        if isinstance(result, dict) and result.get("success") is False:
            return JSONResponse(status_code=502, content=result)
        return result
    except Exception as e:
        logger.error(f"VPN list error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/fmc-config/vpn/download")
async def fmc_vpn_download(payload: Dict[str, Any]):
    """Download selected topologies as YAML. Expects payload.topologies as list of raw dicts.
    Returns a downloadable YAML file with 'topologies' (summaries) and 'endpoints' (grouped) sections.
    """
    try:
        items = payload.get('topologies') or []
        if not isinstance(items, list) or not items:
            return JSONResponse(status_code=400, content={"success": False, "message": "No topologies provided"})
        # Recursively strip verbose keys like metadata and links
        def _strip_keys_recursive(obj: Any, keys: set = {"metadata", "links"}):
            try:
                if isinstance(obj, dict):
                    return {k: _strip_keys_recursive(v, keys) for k, v in obj.items() if k not in keys}
                if isinstance(obj, list):
                    return [_strip_keys_recursive(x, keys) for x in obj]
                return obj
            except Exception:
                return obj

        # Build sections: topologies (summaries) and endpoints (FTDS2SVpn objects when available)
        topologies = []
        endpoints_flat = []
        ftds_objects = []
        for raw in items:
            # Support both legacy raw dict and new {summary,endpoints}
            if isinstance(raw, dict) and 'summary' in raw and 'endpoints' in raw:
                summary = _strip_keys_recursive(dict(raw.get('summary') or {}))
                eps = raw.get('endpoints') or []
                ftds = raw.get('ftds2svpn')
            else:
                # Fallback: treat whole dict as summary and take embedded endpoints if present
                summary = _strip_keys_recursive(dict(raw or {}))
                eps = (raw or {}).get('endpoints') or []
                ftds = (raw or {}).get('ftds2svpn')
            topologies.append(summary)
            eps_sanitized = _strip_keys_recursive(eps)
            if isinstance(eps_sanitized, list):
                endpoints_flat.extend(eps_sanitized)
            if ftds:
                # Keep FTDS2SVpn objects RAW per requirement
                ftds_objects.append(ftds)

        # Assemble YAML: prefer FTDS2SVpn objects for endpoints if present
        doc = { 'topologies': topologies, 'endpoints': (ftds_objects if ftds_objects else endpoints_flat) }
        content = yaml.safe_dump(doc, sort_keys=False)
        fname = payload.get('filename') or f"vpn-topologies-{int(time.time())}.yaml"
        return Response(content=content.encode('utf-8'), media_type="application/x-yaml", headers={
            "Content-Disposition": f"attachment; filename={fname}"
        })
    except Exception as e:
        logger.error(f"VPN download error: {e}")
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
    return RedirectResponse(url="/fmc-configuration")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/dashboard")
    return templates.TemplateResponse("dashboard.html", {"request": request, "active_page": "dashboard", "username": username})

@app.get("/clone-device", response_class=HTMLResponse)
async def clone_device(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/clone-device")
    return templates.TemplateResponse("clone_device.html", {"request": request, "active_page": "clone_device", "username": username})

@app.get("/traffic-generators", response_class=HTMLResponse)
async def traffic_generators(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/traffic-generators")
    return templates.TemplateResponse("traffic_generators.html", {"request": request, "active_page": "traffic_generators", "username": username})

@app.get("/command-center", response_class=HTMLResponse)
async def command_center(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/command-center")
    return templates.TemplateResponse("command_center.html", {"request": request, "active_page": "command_center", "username": username})

@app.get("/fmc-configuration", response_class=HTMLResponse)
async def fmc_configuration(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/fmc-configuration")
    return templates.TemplateResponse("fmc_configuration.html", {"request": request, "active_page": "fmc_configuration", "username": username})

# Login/Logout routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: Optional[str] = "/fmc-configuration"):
    return templates.TemplateResponse("login.html", {"request": request, "next": next})

@app.post("/login")
async def login_action(request: Request, username: str = Form(...), password: str = Form(...), next: Optional[str] = Form("/fmc-configuration")):
    u = (username or "").strip()
    p = password or ""
    if u in USERS and USERS[u] == p:
        request.session["username"] = u
        request.session["sid"] = request.session.get("sid") or str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        active_sessions[request.session["sid"]] = {"username": u, "login_time": now, "last_seen": now}
        record_activity(u, "login", {})
        return RedirectResponse(url=next or "/fmc-configuration", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "next": next, "error": "Invalid credentials"}, status_code=401)

@app.get("/logout")
async def logout(request: Request):
    u = get_current_username(request)
    if u:
        record_activity(u, "logout", {})
    try:
        request.session.clear()
    except Exception:
        pass
    return RedirectResponse(url="/login", status_code=303)

# APIs for Users and Activity
@app.get("/api/users/online")
async def users_online():
    try:
        # Deduplicate by username and keep the most recent last_seen
        by_user: Dict[str, Dict[str, Any]] = {}
        for _, info in list(active_sessions.items()):
            uname = info.get("username")
            if not uname:
                continue
            cur = by_user.get(uname)
            if not cur:
                by_user[uname] = dict(info)
            else:
                # Compare ISO timestamps; convert to aware datetimes
                def _p(ts: Optional[str]):
                    if not ts:
                        return datetime.min.replace(tzinfo=timezone.utc)
                    try:
                        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        return datetime.min.replace(tzinfo=timezone.utc)
                if _p(info.get("last_seen")) > _p(cur.get("last_seen")):
                    by_user[uname] = dict(info)

        # Filter to active users (seen within the last 5 minutes)
        now = datetime.now(timezone.utc)
        ACTIVE_SECONDS = 300
        users = []
        for uname, info in by_user.items():
            try:
                seen = datetime.fromisoformat((info.get("last_seen") or "").replace("Z", "+00:00"))
            except Exception:
                continue
            delta = (now - seen).total_seconds()
            if 0 <= delta <= ACTIVE_SECONDS:
                users.append({
                    "username": uname,
                    "login_time": info.get("login_time"),
                    "last_seen": info.get("last_seen"),
                })
        # Sort by last_seen desc
        users.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
        return {"success": True, "users": users}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/activity/recent")
async def activity_recent():
    try:
        return {"success": True, "activities": list(recent_activities)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/fmc-config/presets")
async def fmc_list_presets(request: Request):
    username = get_current_username(request)
    ctx = get_user_ctx(username)
    return {"success": True, "presets": ctx["fmc_config_presets"]}

@app.post("/api/fmc-config/presets/save")
async def fmc_save_preset(payload: Dict[str, Any], request: Request):
    try:
        username = get_current_username(request)
        ctx = get_user_ctx(username)
        name = (payload.get("name") or f"Preset {len(ctx['fmc_config_presets'])+1}").strip()
        preset = {
            "id": str(uuid.uuid4()),
            "name": name,
            "fmc_ip": payload.get("fmc_ip", ""),
            "username": payload.get("username", ""),
            "password": payload.get("password", ""),
        }
        ctx["fmc_config_presets"].append(preset)
        persist_user_presets(username)
        record_activity(username, "save_fmc_preset", {"name": name})
        return {"success": True, "preset": preset, "presets": ctx["fmc_config_presets"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/fmc-config/presets/{preset_id}")
async def fmc_delete_preset(preset_id: str, request: Request):
    try:
        username = get_current_username(request)
        ctx = get_user_ctx(username)
        before = len(ctx["fmc_config_presets"])
        ctx["fmc_config_presets"][:] = [p for p in ctx["fmc_config_presets"] if p.get("id") != preset_id]
        persist_user_presets(username)
        record_activity(username, "delete_fmc_preset", {"id": preset_id})
        return {"success": True, "deleted": before - len(ctx["fmc_config_presets"]), "presets": ctx["fmc_config_presets"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.post("/api/fmc-config/connect")
async def fmc_connect(request: FMCConnectionRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        _attach_user_log_handlers(username)
        # Authenticate using existing fmc_api helper
        default_domain_uuid, headers = authenticate(request.fmc_ip, request.username, request.password)
        # Save auth context for future operations
        ctx["fmc_auth"]["domain_uuid"] = default_domain_uuid
        ctx["fmc_auth"]["headers"] = headers

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
        ctx["fmc_auth"]["domain_uuid"] = selected_domain_uuid
        # Sort domains by name for UI convenience
        try:
            domains_sorted = sorted(domains, key=lambda d: (d.get("name") or "").lower())
        except Exception:
            domains_sorted = domains
        # Provide additional hints to the UI
        global_domain = next((d for d in domains_sorted if (d.get("name") or "").lower() == "global"), None)
        ui_domain_uuid = (global_domain or {}).get("id") or selected_domain_uuid
        out = {
            "success": True,
            "devices": items,
            "domains": domains_sorted,
            "domain_uuid": selected_domain_uuid,  # domain actually used to fetch devices
            "default_domain_uuid": default_domain_uuid,
            "global_domain_uuid": (global_domain or {}).get("id"),
            "ui_domain_uuid": ui_domain_uuid
        }
        record_activity(username, "fmc_connect", {"devices": len(items)})
        return out
    except Exception as e:
        logger.error(f"FMC connect failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/fmc-config/delete/stream")
async def fmc_delete_devices_stream(payload: Dict[str, Any], http_request: Request):
    """Stream deletion logs while unregistering selected devices from FMC.
    Expects: { fmc_ip: str, device_ids: [str, ...] }
    """
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        device_ids: List[str] = payload.get("device_ids") or []
        if not fmc_ip or not device_ids:
            return JSONResponse(status_code=400, content={"success": False, "message": "fmc_ip and device_ids are required"})
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        if not ctx.get("fmc_auth", {}).get("headers") or not ctx.get("fmc_auth", {}).get("domain_uuid"):
            return JSONResponse(status_code=400, content={"success": False, "message": "Not authenticated to FMC. Please Connect first."})

        headers = ctx["fmc_auth"]["headers"]
        domain_uuid = (payload.get("domain_uuid") or ctx["fmc_auth"].get("domain_uuid"))

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
            "inline_sets": data.get("inline_sets") or [],
            "bridge_group_interfaces": data.get("bridge_group_interfaces") or [],
            # Routing block (optional)
            "routing": data.get("routing") or {},
            # Pass-through optional objects for dependency creation (e.g., security_zones)
            "objects": data.get("objects") or {}
        }
        # Count only list-based config sections + nested object counts we present in UI
        counts = {k: len(v) for k, v in cfg.items() if isinstance(v, list)}
        # Routing counts (flatten per-section keys for UI)
        try:
            rt = cfg.get("routing") or {}
            def _len(key):
                v = rt.get(key)
                return len(v) if isinstance(v, list) else 0
            counts.update({
                "routing_bgp_general_settings": _len("bgp_general_settings"),
                "routing_bgp_policies": _len("bgp_policies"),
                "routing_bfd_policies": _len("bfd_policies"),
                "routing_ospfv2_policies": _len("ospfv2_policies"),
                "routing_ospfv2_interfaces": _len("ospfv2_interfaces"),
                "routing_ospfv3_policies": _len("ospfv3_policies"),
                "routing_ospfv3_interfaces": _len("ospfv3_interfaces"),
                "routing_eigrp_policies": _len("eigrp_policies"),
                "routing_pbr_policies": _len("pbr_policies"),
                "routing_ipv4_static_routes": _len("ipv4_static_routes"),
                "routing_ipv6_static_routes": _len("ipv6_static_routes"),
                "routing_ecmp_zones": _len("ecmp_zones"),
                "routing_vrfs": _len("vrfs"),
            })
            # VRF-specific not easily counted (dict); skip or count total entries
            try:
                vrf_spec = rt.get("vrf_specific") or {}
                counts["routing_vrf_specific_entries"] = sum(len(v or []) for v in vrf_spec.values() if isinstance(v, dict))
            except Exception:
                pass
        except Exception:
            pass
        # Object counts (nested structure is optional)
        obj = (cfg.get("objects") or {}) if isinstance(cfg, dict) else {}
        # Interface
        try:
            obj_if_sz = ((obj.get("interface") or {}).get("security_zones") or [])
            counts["objects_interface_security_zones"] = len(obj_if_sz)
        except Exception:
            counts["objects_interface_security_zones"] = 0
        # Network
        try:
            net = obj.get("network") or {}
            counts.update({
                "objects_network_hosts": len(net.get("hosts") or []),
                "objects_network_ranges": len(net.get("ranges") or []),
                "objects_network_networks": len(net.get("networks") or []),
                "objects_network_fqdns": len(net.get("fqdns") or []),
                "objects_network_groups": len(net.get("groups") or []),
            })
        except Exception:
            pass
        # Port
        try:
            prt = obj.get("port") or {}
            counts["objects_port_objects"] = len(prt.get("objects") or [])
        except Exception:
            pass
        # Routing templates and lists
        try:
            counts["objects_bfd_templates"] = len(obj.get("bfd_templates") or [])
            counts["objects_as_path_lists"] = len(obj.get("as_path_lists") or [])
            counts["objects_key_chains"] = len(obj.get("key_chains") or [])
            counts["objects_sla_monitors"] = len(obj.get("sla_monitors") or [])
            comm = obj.get("community_lists") or {}
            counts["objects_community_lists_community"] = len(comm.get("community") or [])
            counts["objects_community_lists_extended"] = len(comm.get("extended") or [])
            pref = obj.get("prefix_lists") or {}
            counts["objects_prefix_lists_ipv4"] = len(pref.get("ipv4") or [])
            counts["objects_prefix_lists_ipv6"] = len(pref.get("ipv6") or [])
            acls = obj.get("access_lists") or {}
            counts["objects_access_lists_extended"] = len(acls.get("extended") or [])
            counts["objects_access_lists_standard"] = len(acls.get("standard") or [])
            counts["objects_route_maps"] = len(obj.get("route_maps") or [])
            pools = obj.get("address_pools") or {}
            counts["objects_address_pools_ipv4"] = len(pools.get("ipv4") or [])
            counts["objects_address_pools_ipv6"] = len(pools.get("ipv6") or [])
            counts["objects_address_pools_mac"] = len(pools.get("mac") or [])
        except Exception:
            pass
        return {"success": True, "config": cfg, "counts": counts}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid YAML: {e}"})


# ---------------- VPN: Upload & Apply ----------------
@app.post("/api/fmc-config/vpn/upload")
async def fmc_vpn_upload(file: UploadFile = File(...)):
    """Upload a VPN topology YAML and return normalized topologies for UI.
    Expected flexible schema; we try common keys: vpn_topologies, vpn.topologies, topologies, or root list.
    Each topology in response includes: name, type, topologyType, peers (list[{name,role,extranet}]), raw (original dict).
    """
    try:
        raw = await file.read()
        data = yaml.safe_load(raw) or {}

        # Build output items from either new schema (topologies + endpoints) or legacy schemas
        out = []
        def _collect_peers(eps_list: list[Dict[str, Any]]):
            peers: list[Dict[str, Any]] = []
            if isinstance(eps_list, list):
                for ep in eps_list:
                    try:
                        if isinstance(ep, str):
                            peers.append({"name": ep, "role": None, "peerType": None, "extranet": False})
                        elif isinstance(ep, dict):
                            nm = ep.get("name") or (ep.get("device") or {}).get("name")
                            rl = (ep.get("role") or "").upper() if isinstance(ep.get("role"), str) else None
                            pt = (ep.get("peerType") or ep.get("role") or "").upper() if isinstance(ep.get("peerType") or ep.get("role"), str) else None
                            ex = bool(ep.get("extranet")) if isinstance(ep.get("extranet"), (bool, str, int)) else False
                            if nm:
                                peers.append({"name": str(nm), "role": rl, "peerType": pt, "extranet": ex})
                    except Exception:
                        continue
            return peers

        if isinstance(data, dict) and isinstance(data.get("topologies"), list):
            # New schema
            topologies = data.get("topologies") or []
            ep_val = data.get("endpoints")
            # Optional settings sections at file-level
            common_auto = data.get("autoVpnSettings")
            common_ike = data.get("ikeSettings")
            common_ipsec = data.get("ipsecSettings")
            common_adv = data.get("advancedSettings")
            # Build mapping from containerUUID=>items when 'endpoints' is grouped, or support flat list for single topology
            ep_map: Dict[str, list] = {}
            flat_endpoints: list = []
            if isinstance(ep_val, list):
                # Could be grouped list or flat list; detect grouped entries by presence of 'items'
                grouped_detected = any(isinstance(x, dict) and 'items' in x for x in ep_val)
                if grouped_detected:
                    for g in ep_val:
                        try:
                            cu = g.get("containerUUID")
                            items = g.get("items") or []
                            if cu:
                                ep_map[str(cu)] = items
                        except Exception:
                            continue
                else:
                    # Treat as flat endpoints list
                    flat_endpoints = ep_val
            elif isinstance(ep_val, dict) and isinstance(ep_val.get("items"), list):
                # Single group object
                flat_endpoints = ep_val.get("items")
            for summary in topologies:
                if not isinstance(summary, dict):
                    continue
                name = (summary.get("name") or "").strip()
                topology_type = summary.get("topologyType") or ""
                vpn_type_field = summary.get("type") or "S2SVpnSummary"
                eps = ep_map.get(str(summary.get("id"))) or ([] if len(topologies) != 1 else flat_endpoints)
                peers = _collect_peers(eps)
                out.append({
                    "name": name,
                    "type": vpn_type_field,
                    "topologyType": topology_type,
                    "routeBased": bool(summary.get("routeBased")) if isinstance(summary.get("routeBased"), (bool, str, int)) else None,
                    "peers": peers,
                    "raw": {
                        "summary": summary,
                        "endpoints": eps,
                        # propagate common settings for apply
                        "autoVpnSettings": common_auto,
                        "ikeSettings": common_ike,
                        "ipsecSettings": common_ipsec,
                        "advancedSettings": common_adv,
                    },
                })
        else:
            # Legacy schemas
            def _as_list(x):
                return x if isinstance(x, list) else []
            candidates = []
            if isinstance(data, dict):
                candidates.extend([
                    _as_list(data.get("vpn_topologies")),
                    _as_list((data.get("vpn") or {}).get("topologies")),
                    _as_list(data.get("topologies")),
                ])
            elif isinstance(data, list):
                candidates.append(_as_list(data))
            topologies = next((lst for lst in candidates if isinstance(lst, list) and len(lst) > 0), [])

            for t in topologies:
                if not isinstance(t, dict):
                    continue
                name = (t.get("name") or t.get("topologyName") or t.get("displayName") or "").strip()
                vpn_type_field = (t.get("type") or "FTDS2SVpn").strip() or "FTDS2SVpn"
                topo_raw = (t.get("topologyType") or t.get("networkTopology") or t.get("topology") or "").strip().lower()
                if ("hub" in topo_raw) and ("spoke" in topo_raw):
                    topology_type = "HUB_AND_SPOKE"
                elif ("full" in topo_raw) and ("mesh" in topo_raw):
                    topology_type = "FULL_MESH"
                elif ("peer" in topo_raw) or ("point" in topo_raw):
                    topology_type = "PEER_TO_PEER"
                else:
                    topology_type = t.get("topologyType") or t.get("networkTopology") or ""

                eps = t.get("endpoints") or t.get("peers") or []
                peers = _collect_peers(eps)
                out.append({
                    "name": name,
                    "type": vpn_type_field,
                    "topologyType": topology_type,
                    "peers": peers,
                    "raw": t,
                })

        return {"success": True, "topologies": out}
    except Exception as e:
        logger.error(f"VPN upload parse error: {e}")
        return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid VPN YAML: {e}"})


@app.post("/api/fmc-config/vpn/apply")
async def fmc_vpn_apply(payload: Dict[str, Any], http_request: Request):
    try:
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _vpn_apply_sync(payload))
        return result
    except Exception as e:
        logger.error(f"VPN apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _vpn_apply_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        if not fmc_ip or not username or not password:
            return {"success": False, "message": "Missing fmc_ip, username or password"}

        sel_domain = (payload.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain

        topo_list = payload.get("topologies") or []
        if not isinstance(topo_list, list) or not topo_list:
            return {"success": False, "message": "No VPN topologies provided"}

        created = 0
        endpoints_created = 0
        errors: list[str] = []

        def _sanitize(d: Dict[str, Any]) -> Dict[str, Any]:
            body = dict(d or {})
            for k in ("id", "links", "metadata"):
                body.pop(k, None)
            return body

        for raw_tp in topo_list:
            try:
                endpoints = []
                tp_body = {}
                if isinstance(raw_tp, dict) and ("summary" in raw_tp or "endpoints" in raw_tp):
                    tp_body = _sanitize(raw_tp.get("summary") or {})
                    tp_body.setdefault("type", "FTDS2SVpn")
                    eps = raw_tp.get("endpoints")
                    if isinstance(eps, list):
                        endpoints = eps
                    elif isinstance(eps, dict) and isinstance(eps.get("items"), list):
                        endpoints = eps.get("items")
                else:
                    tp_body = _sanitize(raw_tp if isinstance(raw_tp, dict) else {})
                    tp_body.setdefault("type", "FTDS2SVpn")
                    try:
                        eps = (raw_tp or {}).get("endpoints") if isinstance(raw_tp, dict) else None
                        if isinstance(eps, list):
                            endpoints = eps
                    except Exception:
                        endpoints = []

                vpn_id = None
                name_check = (tp_body.get("name") or "").strip()
                if name_check:
                    try:
                        existing = get_vpn_topologies(fmc_ip, headers, domain_uuid) or []
                        for it in existing:
                            if isinstance(it, dict) and (it.get("name") or "").strip() == name_check:
                                vpn_id = it.get("id")
                                break
                        if vpn_id:
                            logger.info(f"[VPN] Topology '{name_check}' already exists (id={vpn_id}); skipping creation")
                    except Exception:
                        pass

                if not vpn_id:
                    topology_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns"
                    try:
                        logger.info(f"[VPN] POST {topology_url}\nPayload: {json.dumps(tp_body, indent=2)}")
                    except Exception:
                        logger.info(f"[VPN] POST {topology_url} (payload logged as JSON failed)")

                    try:
                        created_tp = post_vpn_topology(fmc_ip, headers, domain_uuid, tp_body)
                        created += 1
                        vpn_id = created_tp.get("id")
                    except Exception as create_ex:
                        name = (tp_body.get("name") or "").strip()
                        if name:
                            try:
                                logger.info(f"[VPN] Create failed; checking if topology '{name}' exists to reuse...")
                                existing = get_vpn_topologies(fmc_ip, headers, domain_uuid) or []
                                for it in existing:
                                    if isinstance(it, dict) and (it.get("name") or "").strip() == name:
                                        vpn_id = it.get("id")
                                        break
                                if not vpn_id:
                                    errors.append(f"Existing topology '{name}' not found when resolving ID after create error: {create_ex}")
                                    continue
                            except Exception as resolve_ex:
                                errors.append(f"Failed to resolve existing topology '{name}': {resolve_ex}")
                                continue
                        else:
                            errors.append(f"Topology create failed: {create_ex}")
                            continue

                # Resolve placeholder UUIDs after topology creation and before settings/endpoints are applied
                if vpn_id:
                    try:
                        # Build caches to avoid repeated lookups
                        device_uuid_cache: Dict[str, str] = {}
                        iface_cache: Dict[str, List[Dict[str, Any]]] = {}

                        def _get_device_uuid_by_name(dev_name: str) -> Optional[str]:
                            dn = (dev_name or "").strip()
                            if not dn:
                                return None
                            if dn in device_uuid_cache:
                                return device_uuid_cache[dn]
                            try:
                                du = get_ftd_uuid(fmc_ip, headers, domain_uuid, dn)
                                device_uuid_cache[dn] = du
                                logger.info(f"[VPN] Resolved device UUID for '{dn}': {du}")
                                return du
                            except Exception as ex:
                                logger.warning(f"[VPN] Failed to resolve device UUID for '{dn}': {ex}")
                                return None

                        def _load_ifaces_for_device(dev_uuid: str) -> List[Dict[str, Any]]:
                            if not dev_uuid:
                                return []
                            if dev_uuid in iface_cache:
                                return iface_cache[dev_uuid]
                            try:
                                items = fmc.get_all_interfaces(fmc_ip, headers, domain_uuid, dev_uuid) or []
                                iface_cache[dev_uuid] = items
                                try:
                                    logger.info(f"[VPN] Loaded {len(items)} interfaces for device {dev_uuid}")
                                except Exception:
                                    pass
                                return items
                            except Exception as ex:
                                logger.warning(f"[VPN] Failed to load interfaces for device {dev_uuid}: {ex}")
                                iface_cache[dev_uuid] = []
                                return []

                        def _norm_type(t: str) -> str:
                            ts = (t or "").strip().lower()
                            if ts in ("vti", "virtualtunnelinterface", "virtual_tunnel_interface"):
                                return "virtualtunnelinterface"
                            if ts in ("physicalinterface", "physical"):
                                return "physicalinterface"
                            if ts in ("subinterface", "sub_interface"):
                                return "subinterface"
                            if ts in ("etherchannelinterface", "etherchannel"):
                                return "etherchannelinterface"
                            return ts

                        def _match_iface_id(items: List[Dict[str, Any]], want_type: str, want_name: str) -> Optional[str]:
                            wt = _norm_type(want_type)
                            wn = (want_name or "").strip().lower()
                            if not wn:
                                return None
                            for it in items or []:
                                try:
                                    it_type = _norm_type(it.get("type") or it.get("objectType") or it.get("deviceType"))
                                except Exception:
                                    it_type = _norm_type(it.get("type"))
                                n1 = (it.get("name") or "").strip().lower()
                                n2 = (it.get("ifname") or it.get("ifName") or "").strip().lower()
                                if (not wt or it_type == wt) and (wn == n1 or wn == n2):
                                    iid = it.get("id")
                                    if iid:
                                        return iid
                            # Fallback: loose contains match on names
                            for it in items or []:
                                n1 = (it.get("name") or "").strip().lower()
                                n2 = (it.get("ifname") or it.get("ifName") or "").strip().lower()
                                if wn and (wn in n1 or wn in n2):
                                    iid = it.get("id")
                                    if iid:
                                        return iid
                            return None

                        # Update endpoint placeholders
                        eps_src = None
                        if isinstance(raw_tp, dict):
                            v = raw_tp.get("endpoints")
                            if isinstance(v, list):
                                eps_src = v
                            elif isinstance(v, dict) and isinstance(v.get("items"), list):
                                eps_src = v.get("items")
                        if isinstance(eps_src, list):
                            for ep in eps_src:
                                try:
                                    dev = ep.get("device") if isinstance(ep, dict) else None
                                    dev_name = (dev or {}).get("name") if isinstance(dev, dict) else None
                                    dev_uuid = None
                                    if isinstance(dev, dict):
                                        cur = (dev.get("id") or "").strip()
                                        if (not cur) or cur.upper() == "<DEVICE_UUID>":
                                            dev_uuid = _get_device_uuid_by_name(dev_name)
                                            if dev_uuid:
                                                dev["id"] = dev_uuid
                                                logger.info(f"[VPN] Updated <DEVICE_UUID> for endpoint device '{dev_name}' -> {dev_uuid}")
                                        else:
                                            dev_uuid = cur

                                    # Load interfaces for this device if needed
                                    if not dev_uuid:
                                        dev_uuid = _get_device_uuid_by_name(dev_name)
                                    iface_items = _load_ifaces_for_device(dev_uuid) if dev_uuid else []

                                    # interface
                                    iface = ep.get("interface") if isinstance(ep, dict) else None
                                    if isinstance(iface, dict):
                                        iname = iface.get("name")
                                        itype = iface.get("type")
                                        cur = (iface.get("id") or "").strip()
                                        if (not cur) or cur.upper() == "<INTERFACE_UUID>":
                                            iid = _match_iface_id(iface_items, itype, iname)
                                            if iid:
                                                iface["id"] = iid
                                                logger.info(f"[VPN] Updated <INTERFACE_UUID> for interface '{iname}' ({itype}) on device '{dev_name}' -> {iid}")

                                    # tunnelSourceInterface
                                    ts = ep.get("tunnelSourceInterface") if isinstance(ep, dict) else None
                                    if isinstance(ts, dict):
                                        tname = ts.get("name")
                                        ttype = ts.get("type")
                                        cur = (ts.get("id") or "").strip()
                                        if (not cur) or cur.upper() == "<TUNNEL_SOURCE_UUID>":
                                            tid = _match_iface_id(iface_items, ttype, tname)
                                            if tid:
                                                ts["id"] = tid
                                                logger.info(f"[VPN] Updated <TUNNEL_SOURCE_UUID> for tunnel source '{tname}' ({ttype}) on device '{dev_name}' -> {tid}")
                                except Exception as rex:
                                    logger.warning(f"[VPN] Failed resolving endpoint placeholders: {rex}")

                        # Resolve settings IDs (IKE/IPsec/Advanced) if placeholders present
                        def _resolve_setting_id(kind: str) -> Optional[str]:
                            # kind in {"ike", "ipsec", "advanced"}
                            suffix = f"{kind}settings"
                            url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/{suffix}?expanded=true&limit=1000"
                            try:
                                resp = fmc.fmc_get(url)
                                if resp.status_code == 200:
                                    data = resp.json() or {}
                                    if isinstance(data, dict) and isinstance(data.get("items"), list) and data.get("items"):
                                        sid = (data["items"][0] or {}).get("id")
                                        if sid:
                                            logger.info(f"[VPN] Resolved {kind.upper()} settings UUID for vpn {vpn_id}: {sid}")
                                            return sid
                                    # Some FMC versions return single object without 'items'
                                    sid = data.get("id") if isinstance(data, dict) else None
                                    if sid:
                                        logger.info(f"[VPN] Resolved {kind.upper()} settings UUID for vpn {vpn_id}: {sid}")
                                        return sid
                            except Exception as ex:
                                logger.warning(f"[VPN] Failed to fetch {kind.upper()} settings id: {ex}")
                            return None

                        if isinstance(raw_tp, dict):
                            # IKE
                            try:
                                ike_val = raw_tp.get("ikeSettings")
                                ike_obj = (ike_val[0] if isinstance(ike_val, list) and ike_val else ike_val) if isinstance(ike_val, (list, dict)) else None
                                if isinstance(ike_obj, dict):
                                    cur = (ike_obj.get("id") or "").strip()
                                    if (not cur) or cur.upper() == "<IKE_SETTINGS_UUID>":
                                        sid = _resolve_setting_id("ike")
                                        if sid:
                                            ike_obj["id"] = sid
                                            logger.info(f"[VPN] Updated <IKE_SETTINGS_UUID> -> {sid}")
                            except Exception:
                                pass
                            # IPSEC
                            try:
                                ipsec_val = raw_tp.get("ipsecSettings")
                                ipsec_obj = (ipsec_val[0] if isinstance(ipsec_val, list) and ipsec_val else ipsec_val) if isinstance(ipsec_val, (list, dict)) else None
                                if isinstance(ipsec_obj, dict):
                                    cur = (ipsec_obj.get("id") or "").strip()
                                    if (not cur) or cur.upper() == "<IPSEC_SETTINGS_UUID>":
                                        sid = _resolve_setting_id("ipsec")
                                        if sid:
                                            ipsec_obj["id"] = sid
                                            logger.info(f"[VPN] Updated <IPSEC_SETTINGS_UUID> -> {sid}")
                            except Exception:
                                pass
                            # ADVANCED
                            try:
                                adv_val = raw_tp.get("advancedSettings")
                                adv_obj = (adv_val[0] if isinstance(adv_val, list) and adv_val else adv_val) if isinstance(adv_val, (list, dict)) else None
                                if isinstance(adv_obj, dict):
                                    cur = (adv_obj.get("id") or "").strip()
                                    if (not cur) or cur.upper() == "<ADVANCED_SETTINGS_UUID>":
                                        sid = _resolve_setting_id("advanced")
                                        if sid:
                                            adv_obj["id"] = sid
                                            logger.info(f"[VPN] Updated <ADVANCED_SETTINGS_UUID> -> {sid}")
                            except Exception:
                                pass
                    except Exception as resolve_ex:
                        logger.warning(f"[VPN] Placeholder resolution encountered an error: {resolve_ex}")

                if vpn_id and isinstance(raw_tp, dict):
                    ike_val = raw_tp.get("ikeSettings")
                    ike_obj = (ike_val[0] if isinstance(ike_val, list) and ike_val else ike_val) if isinstance(ike_val, (list, dict)) else None
                    if isinstance(ike_obj, dict) and ike_obj.get("id"):
                        ike_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/ikesettings/{ike_obj.get('id')}"
                        try:
                            logger.info(f"[VPN] PUT {ike_url}\nPayload: {json.dumps(ike_obj, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] PUT {ike_url} (payload logged as JSON failed)")
                        fmc.fmc_put(ike_url, ike_obj)
                    ipsec_val = raw_tp.get("ipsecSettings")
                    ipsec_obj = (ipsec_val[0] if isinstance(ipsec_val, list) and ipsec_val else ipsec_val) if isinstance(ipsec_val, (list, dict)) else None
                    if isinstance(ipsec_obj, dict) and ipsec_obj.get("id"):
                        ipsec_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/ipsecsettings/{ipsec_obj.get('id')}"
                        try:
                            logger.info(f"[VPN] PUT {ipsec_url}\nPayload: {json.dumps(ipsec_obj, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] PUT {ipsec_url} (payload logged as JSON failed)")
                        fmc.fmc_put(ipsec_url, ipsec_obj)
                    adv_val = raw_tp.get("advancedSettings")
                    adv_obj = (adv_val[0] if isinstance(adv_val, list) and adv_val else adv_val) if isinstance(adv_val, (list, dict)) else None
                    if isinstance(adv_obj, dict) and adv_obj.get("id"):
                        adv_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/advancedsettings/{adv_obj.get('id')}"
                        try:
                            logger.info(f"[VPN] PUT {adv_url}\nPayload: {json.dumps(adv_obj, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] PUT {adv_url} (payload logged as JSON failed)")
                        fmc.fmc_put(adv_url, adv_obj)

                if vpn_id and isinstance(endpoints, list) and endpoints:
                    bulk_payloads = [ _sanitize(ep) for ep in endpoints ]
                    bulk_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints?bulk=true"
                    try:
                        logger.info(f"[VPN] POST {bulk_url}\nPayload: {json.dumps(bulk_payloads, indent=2)}")
                    except Exception:
                        logger.info(f"[VPN] POST {bulk_url} (payload logged as JSON failed)")
                    try:
                        post_vpn_endpoints_bulk(fmc_ip, headers, domain_uuid, vpn_id, bulk_payloads)
                        endpoints_created += len(bulk_payloads)
                    except Exception as bulk_ex:
                        try:
                            logger.error(f"[VPN] Bulk endpoint create failed for {tp_body.get('name')}: {bulk_ex}")
                        except Exception:
                            pass
                        errors.append(f"Bulk endpoint create failed for {tp_body.get('name')}: {bulk_ex}")
            except Exception as ex:
                errors.append(f"Topology create failed: {ex}")

        return {"success": True, "created": created, "endpoints_created": endpoints_created, "errors": errors}
    except Exception as e:
        logger.error(f"VPN apply error: {e}")
        return {"success": False, "message": str(e)}


@app.post("/api/fmc-config/config/apply")
async def fmc_config_apply(payload: Dict[str, Any], http_request: Request):
    """Apply selected configuration types to one or more selected devices, in required order.
    Expects JSON with either device_id (single) or device_ids (list) along with:
      fmc_ip, username, password, domain_uuid (optional),
      apply_* flags,
      config: { loopback_interfaces: [...], physical_interfaces: [...], etherchannel_interfaces: [...], subinterfaces: [...], vti_interfaces: [...], routing: {...}, objects: {...} }
    """
    try:
        # Attach per-user logger so background work logs are visible in UI
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
        # Execute heavy operation in thread to allow /api/logs polling concurrently
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _apply_config_multi(payload))
        return result
    except Exception as e:
        logger.error(f"FMC config apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _apply_config_multi(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Multi-device wrapper. Iterates selected device_ids sequentially and aggregates results.

    Returns { success: True, results: [ { device_id, device_name, applied, errors, success }... ], applied: <totals>, errors: <all_errors> }
    Falls back to single-device behavior if only device_id is provided.
    """
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        device_ids: List[str] = payload.get("device_ids") or []
        single_device_id = (payload.get("device_id") or "").strip()
        if not fmc_ip or not username or not password:
            return {"success": False, "message": "Missing fmc_ip, username, or password"}

        # If explicit single device provided and no multi list, keep legacy path
        if single_device_id and not device_ids:
            return _apply_config_sync(payload)

        # Multi-device path
        if not device_ids:
            return {"success": False, "message": "No device_ids provided"}

        # Resolve domain and headers once for name lookups (each device apply will auth again inside _apply_config_sync)
        sel_domain = (payload.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain

        results: List[Dict[str, Any]] = []
        total_applied: Dict[str, int] = {}
        all_errors: List[str] = []

        for did in device_ids:
            did = (did or "").strip()
            if not did:
                continue
            # Build sub-payload for this device
            sub_payload = dict(payload)
            sub_payload["device_id"] = did
            sub_payload.pop("device_ids", None)
            # Apply
            try:
                res = _apply_config_sync(sub_payload)
            except Exception as ex:
                # Capture hard failure
                try:
                    dev_name = get_ftd_name_by_id(fmc_ip, headers, domain_uuid, did) or did
                except Exception:
                    dev_name = did
                err_msg = f"Apply failed for {dev_name}: {ex}"
                results.append({"device_id": did, "device_name": dev_name, "success": False, "applied": {}, "errors": [str(ex)]})
                all_errors.append(err_msg)
                continue

            # Aggregate
            try:
                dev_name = get_ftd_name_by_id(fmc_ip, headers, domain_uuid, did) or did
            except Exception:
                dev_name = did
            applied_map = dict(res.get("applied") or {})
            errors_list = list(res.get("errors") or [])
            results.append({
                "device_id": did,
                "device_name": dev_name,
                "success": bool(res.get("success", True)) and not bool(errors_list),
                "applied": applied_map,
                "errors": errors_list,
            })
            # Sum totals
            for k, v in applied_map.items():
                try:
                    total_applied[k] = int(total_applied.get(k, 0)) + int(v or 0)
                except Exception:
                    continue
            # Prefix errors with device for top-level aggregation
            for e in errors_list:
                try:
                    all_errors.append(f"{dev_name}: {e}")
                except Exception:
                    all_errors.append(str(e))

        return {"success": True, "results": results, "applied": total_applied, "errors": all_errors}
    except Exception as e:
        return {"success": False, "message": str(e)}

def _apply_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    fmc_ip = (payload.get("fmc_ip") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    device_id = (payload.get("device_id") or "").strip()
    if not fmc_ip or not username or not password or not device_id:
        return {"success": False, "message": "Missing fmc_ip, username, password, or device_id"}

    sel_domain = (payload.get("domain_uuid") or "").strip()
    auth_domain, headers = authenticate(fmc_ip, username, password)
    domain_uuid = sel_domain or auth_domain
    # Resolve device name for better logging downstream
    try:
        device_name = get_ftd_name_by_id(fmc_ip, headers, domain_uuid, device_id) or device_id
    except Exception:
        device_name = device_id
    # UI-provided auth overrides (Advanced > Auth)
    ui_auth_values: Dict[str, Any] = payload.get("ui_auth_values") or {}

    cfg = payload.get("config") or {}
    loops = cfg.get("loopback_interfaces") or []
    phys = cfg.get("physical_interfaces") or []
    eths = cfg.get("etherchannel_interfaces") or []
    subs = cfg.get("subinterfaces") or []
    vtis = cfg.get("vti_interfaces") or []
    inline_sets = cfg.get("inline_sets") or []
    bridge_groups = cfg.get("bridge_group_interfaces") or []
    routing = cfg.get("routing") or {}

    apply_bulk = bool(payload.get("apply_bulk", True))
    batch_size = int(payload.get("batch_size") or 25)
    if batch_size <= 0:
        batch_size = 25

    # Build interface maps for the destination device
    from utils.fmc_api import get_physical_interfaces, get_etherchannel_interfaces, get_subinterfaces, get_vti_interfaces
    from utils.fmc_api import create_loopback_interface, put_physical_interface, post_etherchannel_interface, post_subinterface, post_vti_interface
    from utils.fmc_api import post_inline_set, post_bridge_group_interface
    from utils.fmc_api import (
        post_bgp_general_settings,
        post_bgp_policy,
        post_bfd_policy,
        post_ospfv2_policy,
        post_ospfv2_interface,
        post_ospfv3_policy,
        post_ospfv3_interface,
        post_eigrp_policy,
        post_pbr_policy,
        post_ipv4_static_route,
        post_ipv6_static_route,
        post_ecmp_zone,
        get_vrfs,
        post_vrf,
    )

    dest_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    phys_map = { (item.get('name') or item.get('ifname')): item.get('id') for item in dest_phys if item.get('id') }
    dest_eth = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    eth_map = { item.get('name'): item.get('id') for item in dest_eth if item.get('id') }

    # Prime resolver for interfaces and security zones
    resolver = DependencyResolver(fmc_ip, headers, domain_uuid, device_id)
    resolver.prime_device_interfaces(device_name)
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

    applied = {
        # Objects
        "objects_interface_security_zones": 0,
        "objects_network_hosts": 0,
        "objects_network_ranges": 0,
        "objects_network_networks": 0,
        "objects_network_fqdns": 0,
        "objects_network_groups": 0,
        "objects_port_objects": 0,
        "objects_bfd_templates": 0,
        "objects_as_path_lists": 0,
        "objects_key_chains": 0,
        "objects_sla_monitors": 0,
        "objects_community_lists_community": 0,
        "objects_community_lists_extended": 0,
        "objects_prefix_lists_ipv4": 0,
        "objects_prefix_lists_ipv6": 0,
        "objects_access_lists_extended": 0,
        "objects_access_lists_standard": 0,
        "objects_route_maps": 0,
        "objects_address_pools_ipv4": 0,
        "objects_address_pools_ipv6": 0,
        "objects_address_pools_mac": 0,
        "loopbacks": 0,
        "physicals": 0,
        "etherchannels": 0,
        "subinterfaces": 0,
        "vtis": 0,
        "inline_sets": 0,
        "bridge_group_interfaces": 0,
        # Routing
        "routing_bgp_general_settings": 0,
        "routing_bgp_policies": 0,
        "routing_bfd_policies": 0,
        "routing_ospfv2_policies": 0,
        "routing_ospfv2_interfaces": 0,
        "routing_ospfv3_policies": 0,
        "routing_ospfv3_interfaces": 0,
        "routing_eigrp_policies": 0,
        "routing_pbr_policies": 0,
        "routing_ipv4_static_routes": 0,
        "routing_ipv6_static_routes": 0,
        "routing_ecmp_zones": 0,
        "routing_vrfs": 0,
    }
    errors: List[str] = []

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    # 0) Objects — always apply first if selected
    try:
        obj = (cfg.get("objects") or {}) if isinstance(cfg, dict) else {}
        # Ensure SecurityZones if selected (create missing by name)
        if bool(payload.get("apply_obj_if_security_zones", False)):
            defs = ((obj.get("interface") or {}).get("security_zones") or [])
            needed = set()
            # Collect referenced zones from interface payload sections
            for section in (phys or []) + (eths or []) + (subs or []) + (vtis or []):
                try:
                    nm = (((section.get("securityZone") or {}).get("name") or '').strip())
                    if nm: needed.add(nm)
                except Exception:
                    continue
            created = resolver.ensure_security_zones(defs, needed)
            applied["objects_interface_security_zones"] += len(created or [])
        # Helper to post a list of objects with a callable
        def _post_list(items, func, applied_key: str):
            for it in (items or []):
                try:
                    p = dict(it or {})
                    # strip api-only fields
                    for k in ("id","links","metadata"):
                        p.pop(k, None)
                    func(fmc_ip, headers, domain_uuid, p)
                    applied[applied_key] += 1
                except Exception as ex:
                    name = str((it or {}).get("name") or (it or {}).get("value") or "<unnamed>")
                    # Try to show a clean API error description
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"{applied_key} {name}: {desc}")
        # Network objects
        net = obj.get("network") or {}
        if payload.get("apply_obj_net_host"): _post_list(net.get("hosts"), fmc.post_host_object, "objects_network_hosts")
        if payload.get("apply_obj_net_range"): _post_list(net.get("ranges"), fmc.post_range_object, "objects_network_ranges")
        if payload.get("apply_obj_net_network"): _post_list(net.get("networks"), fmc.post_network_object, "objects_network_networks")
        if payload.get("apply_obj_net_fqdn"): _post_list(net.get("fqdns"), fmc.post_fqdn_object, "objects_network_fqdns")
        if payload.get("apply_obj_net_group"): _post_list(net.get("groups"), fmc.post_network_group, "objects_network_groups")
        # Port objects
        if payload.get("apply_obj_port_objects"):
            prt = obj.get("port") or {}
            _post_list(prt.get("objects"), fmc.post_port_object, "objects_port_objects")
        # Routing templates & lists
        # BFD templates need UI auth overrides
        if payload.get("apply_obj_bfd_templates"):
            for it in (obj.get("bfd_templates") or []):
                try:
                    p = dict(it or {})
                    for k in ("id","links","metadata"): p.pop(k, None)
                    fmc.post_bfd_template(fmc_ip, headers, domain_uuid, p, ui_auth_values=ui_auth_values)
                    applied["objects_bfd_templates"] += 1
                except Exception as ex:
                    nm = str((it or {}).get("name") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"objects_bfd_templates {nm}: {desc}")
        if payload.get("apply_obj_as_path_lists"): _post_list(obj.get("as_path_lists"), fmc.post_as_path_list, "objects_as_path_lists")
        if payload.get("apply_obj_key_chains"): _post_list(obj.get("key_chains"), fmc.post_key_chain, "objects_key_chains")
        if payload.get("apply_obj_sla_monitors"): _post_list(obj.get("sla_monitors"), fmc.post_sla_monitor, "objects_sla_monitors")
        comm = obj.get("community_lists") or {}
        if payload.get("apply_obj_community_lists_community"): _post_list(comm.get("community"), fmc.post_community_list, "objects_community_lists_community")
        if payload.get("apply_obj_community_lists_extended"): _post_list(comm.get("extended"), fmc.post_extended_community_list, "objects_community_lists_extended")
        pref = obj.get("prefix_lists") or {}
        if payload.get("apply_obj_prefix_lists_ipv4"): _post_list(pref.get("ipv4"), fmc.post_ipv4_prefix_list, "objects_prefix_lists_ipv4")
        if payload.get("apply_obj_prefix_lists_ipv6"): _post_list(pref.get("ipv6"), fmc.post_ipv6_prefix_list, "objects_prefix_lists_ipv6")
        acls = obj.get("access_lists") or {}
        if payload.get("apply_obj_access_lists_extended"): _post_list(acls.get("extended"), fmc.post_extended_access_list, "objects_access_lists_extended")
        if payload.get("apply_obj_access_lists_standard"): _post_list(acls.get("standard"), fmc.post_standard_access_list, "objects_access_lists_standard")
        if payload.get("apply_obj_route_maps"): _post_list(obj.get("route_maps"), fmc.post_route_map, "objects_route_maps")
        pools = obj.get("address_pools") or {}
        if payload.get("apply_obj_address_pools_ipv4"): _post_list(pools.get("ipv4"), fmc.post_ipv4_address_pool, "objects_address_pools_ipv4")
        if payload.get("apply_obj_address_pools_ipv6"): _post_list(pools.get("ipv6"), fmc.post_ipv6_address_pool, "objects_address_pools_ipv6")
        if payload.get("apply_obj_address_pools_mac"): _post_list(pools.get("mac"), fmc.post_mac_address_pool, "objects_address_pools_mac")
    except Exception as e:
        errors.append(f"Objects phase: {e}")


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
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Physical Interface creation: {e}")


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
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Ethernet Interface creation: {e}")

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
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after VTI creation: {e}")

    # 6) Inline Sets (create; no bulk endpoint)
    if payload.get("apply_inline_sets") and inline_sets:
        logger.info(f"Applying {len(inline_sets)} Inline Set(s)")
        for item in inline_sets:
            try:
                p = dict(item)
                resolver.resolve_interfaces_in_payload(p)
                post_inline_set(fmc_ip, headers, domain_uuid, device_id, p)
                applied["inline_sets"] += 1
            except Exception as ex:
                errors.append(f"Inline Set {item.get('name')}: {ex}")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Inline Set creation: {e}")

    # 7) Bridge Group Interfaces (create; no bulk endpoint)
    if payload.get("apply_bridge_group_interfaces") and bridge_groups:
        logger.info(f"Applying {len(bridge_groups)} Bridge Group Interface(s)")
        for item in bridge_groups:
            try:
                p = dict(item)
                resolver.resolve_interfaces_in_payload(p)
                post_bridge_group_interface(fmc_ip, headers, domain_uuid, device_id, p)
                applied["bridge_group_interfaces"] += 1
            except Exception as ex:
                errors.append(f"Bridge Group Interface {item.get('name')}: {ex}")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Bridge Group creation: {e}")

    # 8) Routing (in requested order)
    if isinstance(routing, dict):
        def chunks(lst, n):
            for i in range(0, len(lst), n):
                yield lst[i:i+n]

        # BGP General Settings
        if payload.get("apply_routing_bgp_general_settings"):
            items = routing.get("bgp_general_settings") or []
            logger.info(f"Applying {len(items)} BGP General Settings")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_bgp_general_settings(fmc_ip, headers, domain_uuid, device_id, p)
                    applied["routing_bgp_general_settings"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or "BGPGeneralSettings")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"BGP General {nm}: {desc}")

        # BGP Policies (device/global)
        if payload.get("apply_routing_bgp_policies"):
            items = routing.get("bgp_policies") or []
            logger.info(f"Applying {len(items)} BGP Policies")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_bgp_policy(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_bgp_policies"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"BGP policy {nm}: {desc}")

        # BFD Policies
        if payload.get("apply_routing_bfd_policies"):
            items = routing.get("bfd_policies") or []
            logger.info(f"Applying {len(items)} BFD Policies")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_bfd_policy(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_bfd_policies"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"BFD {nm}: {desc}")

        # OSPFv2 Policies
        if payload.get("apply_routing_ospfv2_policies"):
            items = routing.get("ospfv2_policies") or []
            logger.info(f"Applying {len(items)} OSPFv2 Policies")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_ospfv2_policy(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_ospfv2_policies"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or p.get("processId") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"OSPFv2 policy {nm}: {desc}")

        # OSPFv2 Interfaces
        if payload.get("apply_routing_ospfv2_interfaces"):
            items = routing.get("ospfv2_interfaces") or []
            logger.info(f"Applying {len(items)} OSPFv2 Interfaces")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_ospfv2_interface(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_ospfv2_interfaces"] += 1
                except Exception as ex:
                    try:
                        nm = (((p.get("deviceInterface") or {}).get("name")) or p.get("name") or "<unnamed>")
                    except Exception:
                        nm = "<unnamed>"
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"OSPFv2 interface {nm}: {desc}")

        # OSPFv3 Policies
        if payload.get("apply_routing_ospfv3_policies"):
            items = routing.get("ospfv3_policies") or []
            logger.info(f"Applying {len(items)} OSPFv3 Policies")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_ospfv3_policy(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_ospfv3_policies"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or p.get("processId") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"OSPFv3 policy {nm}: {desc}")

        # OSPFv3 Interfaces
        if payload.get("apply_routing_ospfv3_interfaces"):
            items = routing.get("ospfv3_interfaces") or []
            logger.info(f"Applying {len(items)} OSPFv3 Interfaces")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_ospfv3_interface(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_ospfv3_interfaces"] += 1
                except Exception as ex:
                    try:
                        nm = (((p.get("deviceInterface") or {}).get("name")) or p.get("name") or "<unnamed>")
                    except Exception:
                        nm = "<unnamed>"
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"OSPFv3 interface {nm}: {desc}")

        # EIGRP Policies
        if payload.get("apply_routing_eigrp_policies"):
            items = routing.get("eigrp_policies") or []
            logger.info(f"Applying {len(items)} EIGRP Policies")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_eigrp_policy(fmc_ip, headers, domain_uuid, device_id, p, ui_auth_values=ui_auth_values)
                    applied["routing_eigrp_policies"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"EIGRP policy {nm}: {desc}")

        # PBR Policies (supports bulk)
        if payload.get("apply_routing_pbr_policies"):
            items = routing.get("pbr_policies") or []
            logger.info(f"Applying {len(items)} PBR Policies in {'bulk' if apply_bulk else 'single'} mode")
            for group in (chunks(items, batch_size) if apply_bulk else [items]):
                try:
                    out = []
                    for it in group:
                        p = dict(it)
                        resolver.resolve_interfaces_in_payload(p)
                        out.append(p)
                    if out:
                        post_pbr_policy(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], bulk=(len(out) > 1))
                        applied["routing_pbr_policies"] += len(out)
                except Exception as ex:
                    errors.append(f"PBR: {ex}")

        # IPv4 Static Routes (supports bulk)
        if payload.get("apply_routing_ipv4_static_routes"):
            items = routing.get("ipv4_static_routes") or []
            logger.info(f"Applying {len(items)} IPv4 Static Routes in {'bulk' if apply_bulk else 'single'} mode")
            for group in (chunks(items, batch_size) if apply_bulk else [items]):
                try:
                    out = []
                    for it in group:
                        p = dict(it)
                        resolver.resolve_interfaces_in_payload(p)
                        out.append(p)
                    if out:
                        post_ipv4_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], bulk=(len(out) > 1))
                        applied["routing_ipv4_static_routes"] += len(out)
                except Exception as ex:
                    errors.append(f"IPv4 static route: {ex}")

        # IPv6 Static Routes (supports bulk)
        if payload.get("apply_routing_ipv6_static_routes"):
            items = routing.get("ipv6_static_routes") or []
            logger.info(f"Applying {len(items)} IPv6 Static Routes in {'bulk' if apply_bulk else 'single'} mode")
            for group in (chunks(items, batch_size) if apply_bulk else [items]):
                try:
                    out = []
                    for it in group:
                        p = dict(it)
                        resolver.resolve_interfaces_in_payload(p)
                        out.append(p)
                    if out:
                        post_ipv6_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], bulk=(len(out) > 1))
                        applied["routing_ipv6_static_routes"] += len(out)
                except Exception as ex:
                    errors.append(f"IPv6 static route: {ex}")

        # ECMP Zones
        if payload.get("apply_routing_ecmp_zones"):
            items = routing.get("ecmp_zones") or []
            logger.info(f"Applying {len(items)} ECMP Zones")
            for it in items:
                try:
                    p = dict(it)
                    resolver.resolve_interfaces_in_payload(p)
                    post_ecmp_zone(fmc_ip, headers, domain_uuid, device_id, p)
                    applied["routing_ecmp_zones"] += 1
                except Exception as ex:
                    nm = str(p.get("name") or "<unnamed>")
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"ECMP zone {nm}: {desc}")

        # VRFs and VRF-specific
        if payload.get("apply_routing_vrfs"):
            vrfs = routing.get("vrfs") or []
            logger.info(f"Applying {len(vrfs)} VRF(s)")
            name_to_id: Dict[str, str] = {}
            for vrf in vrfs:
                try:
                    p = dict(vrf)
                    # Skip creating the default Global VRF
                    vrf_name = (p.get("name") or "").strip()
                    if vrf_name and vrf_name.lower() == "global":
                        logger.info("Skipping VRF 'Global' (default)")
                        continue
                    resolver.resolve_interfaces_in_payload(p)
                    res = post_vrf(fmc_ip, headers, domain_uuid, device_id, p)
                    vid = res.get("id")
                    if vid and p.get("name"):
                        name_to_id[str(p["name"])] = vid
                    applied["routing_vrfs"] += 1
                except Exception as ex:
                    errors.append(f"VRF {vrf.get('name')}: {ex}")
            # Merge with existing VRFs
            try:
                cur = get_vrfs(fmc_ip, headers, domain_uuid, device_id) or []
                for v in cur:
                    nm = v.get("name"); vid = v.get("id")
                    if nm and vid and nm not in name_to_id:
                        name_to_id[str(nm)] = vid
            except Exception:
                pass
            vrf_spec = routing.get("vrf_specific") or {}
            if isinstance(vrf_spec, dict) and vrf_spec:
                logger.info("Applying VRF-specific routing configs")
                for vrf_name, sections in vrf_spec.items():
                    vid = name_to_id.get(vrf_name)
                    if not vid:
                        errors.append(f"VRF-specific skipped for '{vrf_name}' (VRF not found)")
                        continue
                    def _proc(items, post_func):
                        for it in (items or []):
                            try:
                                p = dict(it)
                                resolver.resolve_interfaces_in_payload(p)
                                post_func(fmc_ip, headers, domain_uuid, device_id, p, vrf_id=vid, vrf_name=vrf_name)
                            except Exception as ex2:
                                errors.append(f"VRF {vrf_name}: {ex2}")
                    _proc((sections or {}).get("bfd_policies"), post_bfd_policy)
                    _proc((sections or {}).get("ospfv2_policies"), post_ospfv2_policy)
                    _proc((sections or {}).get("ospfv2_interfaces"), post_ospfv2_interface)
                    _proc((sections or {}).get("bgp_policies"), post_bgp_policy)
                    # Bulk for static routes
                    ipv4s = (sections or {}).get("ipv4_static_routes") or []
                    if ipv4s:
                        for group in (chunks(ipv4s, batch_size) if apply_bulk else [ipv4s]):
                            try:
                                out = []
                                for it in group:
                                    p = dict(it)
                                    resolver.resolve_interfaces_in_payload(p)
                                    out.append(p)
                                if out:
                                    post_ipv4_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], vrf_id=vid, vrf_name=vrf_name, bulk=(len(out) > 1))
                            except Exception as ex2:
                                errors.append(f"VRF {vrf_name} ipv4_static_routes: {ex2}")
                    ipv6s = (sections or {}).get("ipv6_static_routes") or []
                    if ipv6s:
                        for group in (chunks(ipv6s, batch_size) if apply_bulk else [ipv6s]):
                            try:
                                out = []
                                for it in group:
                                    p = dict(it)
                                    resolver.resolve_interfaces_in_payload(p)
                                    out.append(p)
                                if out:
                                    post_ipv6_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], vrf_id=vid, vrf_name=vrf_name, bulk=(len(out) > 1))
                            except Exception as ex2:
                                errors.append(f"VRF {vrf_name} ipv6_static_routes: {ex2}")
                    _proc((sections or {}).get("ecmp_zones"), post_ecmp_zone)

    # --- Pretty summary tables ---
    def _names_from(items, type_key: str):
        names = []
        if not items:
            return names
        # Heuristics per type_key for better name extraction
        if type_key == "physicals":
            for it in items:
                names.append(str((it.get("name") or it.get("ifname") or "").strip() or "<unnamed>"))
        elif type_key == "etherchannels":
            for it in items:
                names.append(str((it.get("name") or "").strip() or "<unnamed>") )
        elif type_key == "subinterfaces":
            for it in items:
                nm = (it.get("name") or it.get("ifname") or "").strip()
                sid = it.get("subIntfId")
                names.append(f"{nm}.{sid}" if nm and sid is not None else (nm or "<unnamed>"))
        elif type_key == "vtis":
            for it in items:
                names.append(str((it.get("name") or it.get("ifname") or "").strip() or "<unnamed>"))
        elif type_key == "inline_sets":
            for it in items:
                names.append(str((it.get("name") or "").strip() or "<unnamed>"))
        elif type_key == "bridge_group_interfaces":
            for it in items:
                names.append(str((it.get("name") or "").strip() or "<unnamed>"))
        elif type_key == "routing_ospfv3_interfaces":
            for it in (items or []):
                try:
                    n = (((it.get("deviceInterface") or {}).get("name")) or it.get("name") or "").strip()
                except Exception:
                    n = ""
                names.append(n or "<unnamed>")
        elif type_key == "routing_ospfv2_interfaces":
            for it in (items or []):
                try:
                    n = (((it.get("deviceInterface") or {}).get("name")) or it.get("name") or "").strip()
                except Exception:
                    n = ""
                names.append(n or "<unnamed>")
        else:
            # Policies and routes: prefer 'name', otherwise a key field
            for it in items:
                cand = (it.get("name") or it.get("network") or it.get("destinationNetwork") or it.get("prefix") or it.get("processId"))
                names.append(str(cand if cand is not None else "<unnamed>"))
        return names

    def _display_name_for_type(key: str) -> str:
        return {
            # Objects
            "objects_interface_security_zones": "SecurityZone",
            "objects_network_hosts": "Host",
            "objects_network_ranges": "Range",
            "objects_network_networks": "Network",
            "objects_network_fqdns": "FQDN",
            "objects_network_groups": "NetworkGroup",
            "objects_port_objects": "PortObject",
            "objects_bfd_templates": "BFD Template",
            "objects_as_path_lists": "AS Path List",
            "objects_key_chains": "Key Chain",
            "objects_sla_monitors": "SLA Monitor",
            "objects_community_lists_community": "Community List (standard)",
            "objects_community_lists_extended": "Community List (extended)",
            "objects_prefix_lists_ipv4": "IPv4 Prefix List",
            "objects_prefix_lists_ipv6": "IPv6 Prefix List",
            "objects_access_lists_extended": "Extended ACL",
            "objects_access_lists_standard": "Standard ACL",
            "objects_route_maps": "Route Map",
            "objects_address_pools_ipv4": "IPv4 Address Pool",
            "objects_address_pools_ipv6": "IPv6 Address Pool",
            "objects_address_pools_mac": "MAC Address Pool",
            # Interfaces
            "loopbacks": "LoopbackInterface",
            "physicals": "PhysicalInterface",
            "etherchannels": "EtherChannelInterface",
            "subinterfaces": "SubInterface",
            "vtis": "VTIInterface",
            "inline_sets": "Inline Set",
            "bridge_group_interfaces": "Bridge Group Interface",
            # Routing
            "routing_bgp_general_settings": "BGP General Settings",
            "routing_bgp_policies": "BGP policy",
            "routing_bfd_policies": "BFD policy",
            "routing_ospfv2_policies": "OSPFv2 policy",
            "routing_ospfv2_interfaces": "OSPFv2 interface",
            "routing_ospfv3_policies": "OSPFv3 policy",
            "routing_ospfv3_interfaces": "OSPFv3 interface",
            "routing_eigrp_policies": "EIGRP policy",
            "routing_pbr_policies": "PBR policy",
            "routing_ipv4_static_routes": "IPv4 static route",
            "routing_ipv6_static_routes": "IPv6 static route",
            "routing_ecmp_zones": "ECMP zone",
            "routing_vrfs": "VRF",
        }.get(key, key)

    def _format_table(headers, rows):
        # Compute col widths considering multi-line cells
        def cell_width(val):
            parts = str(val).splitlines() or [""]
            return max(len(p) for p in parts)
        widths = [max(cell_width(h), *(cell_width(r[i]) for r in rows)) for i, h in enumerate(headers)] if rows else [len(h) for h in headers]
        sep = "+" + "+".join(["-" * (w + 2) for w in widths]) + "+"
        def render_row(vals):
            parts = [str(v).splitlines() or [""] for v in vals]
            height = max(len(p) for p in parts)
            lines = []
            for r in range(height):
                cells = []
                for i, p in enumerate(parts):
                    text = p[r] if r < len(p) else ""
                    cells.append(" " + text.ljust(widths[i]) + " ")
                lines.append("|" + "|".join(cells) + "|")
            return "\n".join(lines)
        out = [sep, render_row(headers), sep]
        for row in rows:
            out.append(render_row(row))
        out.append(sep)
        return "\n".join(out)

    # Build applied rows using counts and first N names from requested items
    applied_rows = []
    # Map applied key -> source items list
    applied_sources = {
        # Objects
        "objects_interface_security_zones": ((cfg.get("objects") or {}).get("interface") or {}).get("security_zones"),
        "objects_network_hosts": ((cfg.get("objects") or {}).get("network") or {}).get("hosts"),
        "objects_network_ranges": ((cfg.get("objects") or {}).get("network") or {}).get("ranges"),
        "objects_network_networks": ((cfg.get("objects") or {}).get("network") or {}).get("networks"),
        "objects_network_fqdns": ((cfg.get("objects") or {}).get("network") or {}).get("fqdns"),
        "objects_network_groups": ((cfg.get("objects") or {}).get("network") or {}).get("groups"),
        "objects_port_objects": ((cfg.get("objects") or {}).get("port") or {}).get("objects"),
        "objects_bfd_templates": (cfg.get("objects") or {}).get("bfd_templates"),
        "objects_as_path_lists": (cfg.get("objects") or {}).get("as_path_lists"),
        "objects_key_chains": (cfg.get("objects") or {}).get("key_chains"),
        "objects_sla_monitors": (cfg.get("objects") or {}).get("sla_monitors"),
        "objects_community_lists_community": ((cfg.get("objects") or {}).get("community_lists") or {}).get("community"),
        "objects_community_lists_extended": ((cfg.get("objects") or {}).get("community_lists") or {}).get("extended"),
        "objects_prefix_lists_ipv4": ((cfg.get("objects") or {}).get("prefix_lists") or {}).get("ipv4"),
        "objects_prefix_lists_ipv6": ((cfg.get("objects") or {}).get("prefix_lists") or {}).get("ipv6"),
        "objects_access_lists_extended": ((cfg.get("objects") or {}).get("access_lists") or {}).get("extended"),
        "objects_access_lists_standard": ((cfg.get("objects") or {}).get("access_lists") or {}).get("standard"),
        "objects_route_maps": (cfg.get("objects") or {}).get("route_maps"),
        "objects_address_pools_ipv4": ((cfg.get("objects") or {}).get("address_pools") or {}).get("ipv4"),
        "objects_address_pools_ipv6": ((cfg.get("objects") or {}).get("address_pools") or {}).get("ipv6"),
        "objects_address_pools_mac": ((cfg.get("objects") or {}).get("address_pools") or {}).get("mac"),
        # Interfaces
        "loopbacks": loops,
        "physicals": phys,
        "etherchannels": eths,
        "subinterfaces": subs,
        "vtis": vtis,
        "inline_sets": inline_sets,
        "bridge_group_interfaces": bridge_groups,
        # Routing
        "routing_bgp_general_settings": (routing or {}).get("bgp_general_settings"),
        "routing_bgp_policies": (routing or {}).get("bgp_policies"),
        "routing_bfd_policies": (routing or {}).get("bfd_policies"),
        "routing_ospfv2_policies": (routing or {}).get("ospfv2_policies"),
        "routing_ospfv2_interfaces": (routing or {}).get("ospfv2_interfaces"),
        "routing_ospfv3_policies": (routing or {}).get("ospfv3_policies"),
        "routing_ospfv3_interfaces": (routing or {}).get("ospfv3_interfaces"),
        "routing_eigrp_policies": (routing or {}).get("eigrp_policies"),
        "routing_pbr_policies": (routing or {}).get("pbr_policies"),
        "routing_ipv4_static_routes": (routing or {}).get("ipv4_static_routes"),
        "routing_ipv6_static_routes": (routing or {}).get("ipv6_static_routes"),
        "routing_ecmp_zones": (routing or {}).get("ecmp_zones"),
        "routing_vrfs": (routing or {}).get("vrfs"),
    }
    for key, cnt in applied.items():
        try:
            cnt = int(cnt or 0)
        except Exception:
            cnt = 0
        if cnt <= 0:
            continue
        disp = _display_name_for_type(key)
        items = applied_sources.get(key) or []
        names_all = _names_from(items, key)
        names = names_all[:cnt] if isinstance(names_all, list) else []
        name_cell = "\n".join(names)
        applied_rows.append([disp, name_cell, str(cnt)])

    applied_table = _format_table(["Type", "Name", "Count"], applied_rows)
    logger.info("\nConfigurations Applied\n" + applied_table)

    # Build failed rows: one row per failed item with cleaned error message
    failed_rows = []
    if errors:
        for e in errors:
            try:
                prefix, sep, msg = str(e).partition(": ")
                type_and_name = prefix.strip()  # e.g., "objects_network_networks sgt_server_nw"
                if " " in type_and_name:
                    t_full, name_val = type_and_name.split(" ", 1)
                else:
                    t_full = type_and_name
                    name_val = type_and_name
                failed_rows.append([t_full, name_val.strip(), "1", msg.strip()])
            except Exception:
                failed_rows.append(["<unknown>", "<unknown>", "1", str(e)])
        failed_table = _format_table(["Type", "Name", "Count", "Error"], failed_rows)
        logger.info("\nConfigurations Failed\n" + failed_table)

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

        sel_domain = (payload.get("domain_uuid") or "").strip()
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
            get_inline_sets,
            get_bridge_group_interfaces,
            get_bgp_general_settings,
            get_bgp_policies,
            get_bfd_policies,
            get_ospfv2_policies,
            get_ospfv2_interfaces,
            get_ospfv3_policies,
            get_ospfv3_interfaces,
            get_eigrp_policies,
            get_pbr_policies,
            get_ipv4_static_routes,
            get_ipv6_static_routes,
            get_ecmp_zones,
            get_vrfs,
        )
        # Object getters (ID-based selective fetch)
        from utils.fmc_api import get_objects_by_type_and_ids

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
        inlines = get_inline_sets(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        bgis = get_bridge_group_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []

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
        inlines = _strip(inlines)
        bgis = _strip(bgis)

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

        # Prepare objects block holder (we will fill it at the end)
        objects_block: Dict[str, Any] = {}
        if sz_defs:
            objects_block["interface"] = {"security_zones": sz_defs}

        # Routing export (global lists; plus VRF-specific)
        routing_block: Dict[str, Any] = {}
        try:
            routing_block = {
                "bgp_general_settings": get_bgp_general_settings(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "bgp_policies": get_bgp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "bfd_policies": get_bfd_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ospfv2_policies": get_ospfv2_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ospfv2_interfaces": get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ospfv3_policies": get_ospfv3_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ospfv3_interfaces": get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "eigrp_policies": get_eigrp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "pbr_policies": get_pbr_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ipv4_static_routes": get_ipv4_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ipv6_static_routes": get_ipv6_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "ecmp_zones": get_ecmp_zones(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
                "vrfs": get_vrfs(fmc_ip, headers, domain_uuid, dev_id, dev_name) or [],
            }
            # Strip links/metadata in routing items
            for k, v in list(routing_block.items()):
                if isinstance(v, list):
                    routing_block[k] = _strip(v)
            # Build VRF-specific by VRF name (skip Global)
            vrf_specific: Dict[str, Any] = {}
            for vrf in routing_block.get("vrfs", []) or []:
                try:
                    nm = (vrf.get("name") or "").strip()
                    vid = vrf.get("id")
                    if not nm or nm.lower() == "global" or not vid:
                        continue
                    vrf_sections = {
                        "bfd_policies": _strip(get_bfd_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                        "ospfv2_policies": _strip(get_ospfv2_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                        "ospfv2_interfaces": _strip(get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                        "bgp_policies": _strip(get_bgp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                        "ipv4_static_routes": _strip(get_ipv4_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                        "ipv6_static_routes": _strip(get_ipv6_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                        "ecmp_zones": _strip(get_ecmp_zones(fmc_ip, headers, domain_uuid, dev_id, dev_name, vrf_id=vid, vrf_name=nm) or []),
                    }
                    # Only include non-empty sections
                    if any(vrf_sections.get(k) for k in vrf_sections):
                        vrf_specific[nm] = vrf_sections
                except Exception as _ex:
                    continue
            if vrf_specific:
                routing_block["vrf_specific"] = vrf_specific
        except Exception as ex:
            logger.warning(f"Routing export failed partially: {ex}")

        # At the end: collect dependent FMC object references from interfaces and routing and fetch selectively
        try:
            # Deep scan for dicts with {"type": <ObjectType>, "id": <uuid>} that match known object types
            OBJECT_TYPES = {
                # Network
                "Host", "Range", "Network", "FQDN", "NetworkGroup",
                # Port
                "ProtocolPortObject",
                # Templates & Lists
                "BFDTemplate", "ASPathList", "KeyChain", "SLAMonitor",
                "CommunityList", "ExtendedCommunityList",
                "IPv4PrefixList", "IPv6PrefixList",
                "ExtendedAccessList", "StandardAccessList",
                "RouteMap",
                # Address Pools
                "IPv4AddressPool", "IPv6AddressPool", "MacAddressPool",
            }
            ids_by_type: Dict[str, Set[str]] = {t: set() for t in OBJECT_TYPES}

            def _collect(obj: Any):
                if isinstance(obj, dict):
                    t = obj.get("type")
                    oid = obj.get("id")
                    if t in OBJECT_TYPES and isinstance(oid, str) and oid:
                        ids_by_type[t].add(oid)
                    for v in obj.values():
                        _collect(v)
                elif isinstance(obj, list):
                    for it in obj:
                        _collect(it)

            # Scan device-level interface sections
            _collect(loops)
            _collect(phys)
            _collect(eths)
            _collect(subs)
            _collect(vtis)
            _collect(inlines)
            _collect(bgis)
            # Scan routing export
            _collect(routing_block)

            # Helper to sanitize lists
            def _sanitize(lst: List[Dict[str, Any]]):
                out = []
                for it in (lst or []):
                    d = dict(it or {})
                    d.pop("links", None)
                    d.pop("metadata", None)
                    out.append(d)
                return out

            # Fetch per type based on discovered IDs
            def _fetch(t: str) -> List[Dict[str, Any]]:
                if not ids_by_type.get(t):
                    return []
                return _sanitize(get_objects_by_type_and_ids(fmc_ip, headers, domain_uuid, t, ids_by_type[t]))

            # Network
            net_hosts = _fetch("Host")
            net_ranges = _fetch("Range")
            net_networks = _fetch("Network")
            net_fqdns = _fetch("FQDN")
            net_groups = _fetch("NetworkGroup")
            network = {k: v for k, v in {
                "hosts": net_hosts,
                "ranges": net_ranges,
                "networks": net_networks,
                "fqdns": net_fqdns,
                "groups": net_groups,
            }.items() if v}
            if network:
                objects_block["network"] = network

            # Port
            port_objs = _fetch("ProtocolPortObject")
            if port_objs:
                objects_block["port"] = {"objects": port_objs}

            # Templates & Lists
            bfd_tmpls = _fetch("BFDTemplate")
            if bfd_tmpls:
                objects_block["bfd_templates"] = bfd_tmpls
            as_paths = _fetch("ASPathList")
            if as_paths:
                objects_block["as_path_lists"] = as_paths
            key_chains = _fetch("KeyChain")
            if key_chains:
                objects_block["key_chains"] = key_chains
            sla_mons = _fetch("SLAMonitor")
            if sla_mons:
                objects_block["sla_monitors"] = sla_mons
            comm_comm = _fetch("CommunityList")
            comm_ext = _fetch("ExtendedCommunityList")
            community_lists = {k: v for k, v in {"community": comm_comm, "extended": comm_ext}.items() if v}
            if community_lists:
                objects_block["community_lists"] = community_lists
            pref_v4 = _fetch("IPv4PrefixList")
            pref_v6 = _fetch("IPv6PrefixList")
            prefix_lists = {k: v for k, v in {"ipv4": pref_v4, "ipv6": pref_v6}.items() if v}
            if prefix_lists:
                objects_block["prefix_lists"] = prefix_lists
            acls_ext = _fetch("ExtendedAccessList")
            acls_std = _fetch("StandardAccessList")
            access_lists = {k: v for k, v in {"extended": acls_ext, "standard": acls_std}.items() if v}
            if access_lists:
                objects_block["access_lists"] = access_lists
            route_maps = _fetch("RouteMap")
            if route_maps:
                objects_block["route_maps"] = route_maps
            pools_v4 = _fetch("IPv4AddressPool")
            pools_v6 = _fetch("IPv6AddressPool")
            pools_mac = _fetch("MacAddressPool")
            address_pools = {k: v for k, v in {"ipv4": pools_v4, "ipv6": pools_v6, "mac": pools_mac}.items() if v}
            if address_pools:
                objects_block["address_pools"] = address_pools

            # Second pass: discover dependent objects referenced inside fetched objects (e.g., PrefixLists in RouteMaps)
            try:
                TYPE_TO_PATH = {
                    "Host": ("network", "hosts"),
                    "Range": ("network", "ranges"),
                    "Network": ("network", "networks"),
                    "FQDN": ("network", "fqdns"),
                    "NetworkGroup": ("network", "groups"),
                    "ProtocolPortObject": ("port", "objects"),
                    "BFDTemplate": ("bfd_templates", None),
                    "ASPathList": ("as_path_lists", None),
                    "KeyChain": ("key_chains", None),
                    "SLAMonitor": ("sla_monitors", None),
                    "CommunityList": ("community_lists", "community"),
                    "ExtendedCommunityList": ("community_lists", "extended"),
                    "IPv4PrefixList": ("prefix_lists", "ipv4"),
                    "IPv6PrefixList": ("prefix_lists", "ipv6"),
                    "ExtendedAccessList": ("access_lists", "extended"),
                    "StandardAccessList": ("access_lists", "standard"),
                    "RouteMap": ("route_maps", None),
                    "IPv4AddressPool": ("address_pools", "ipv4"),
                    "IPv6AddressPool": ("address_pools", "ipv6"),
                    "MacAddressPool": ("address_pools", "mac"),
                }

                present: Dict[str, Set[str]] = {t: set() for t in OBJECT_TYPES}
                def _collect_present(o: Any):
                    if isinstance(o, dict):
                        t = o.get("type"); oid = o.get("id")
                        if t in present and isinstance(oid, str) and oid:
                            present[t].add(oid)
                        for v in o.values():
                            _collect_present(v)
                    elif isinstance(o, list):
                        for it in o:
                            _collect_present(it)
                _collect_present(objects_block)

                # Rescan fetched objects for new references
                _collect(objects_block)
                for t in OBJECT_TYPES:
                    missing = (ids_by_type.get(t) or set()) - (present.get(t) or set())
                    if not missing:
                        continue
                    new_items = _sanitize(get_objects_by_type_and_ids(fmc_ip, headers, domain_uuid, t, missing))
                    if not new_items:
                        continue
                    top, sub = TYPE_TO_PATH.get(t, (None, None))
                    if not top:
                        continue
                    if sub is None:
                        cur = list(objects_block.get(top) or [])
                        cur.extend(new_items)
                        objects_block[top] = cur
                    else:
                        group = dict(objects_block.get(top) or {})
                        lst = list(group.get(sub) or [])
                        lst.extend(new_items)
                        group[sub] = lst
                        objects_block[top] = group
            except Exception as _ex:
                logger.warning(f"Second-pass selective objects export warning: {_ex}")
        except Exception as ex:
            logger.warning(f"Selective Objects export failed partially: {ex}")

        # Apply Advanced Auth overrides into exported YAML if provided
        try:
            ui_auth_values: Dict[str, Any] = payload.get("ui_auth_values") or {}
            if ui_auth_values:
                # Routing overrides
                def _override(list_key: str, proto: str):
                    lst = routing_block.get(list_key) or []
                    if not isinstance(lst, list):
                        return
                    out = []
                    for it in lst:
                        try:
                            out.append(fmc.replace_masked_auth_values(dict(it or {}), proto, ui_auth_values=ui_auth_values))
                        except Exception:
                            out.append(it)
                    routing_block[list_key] = out

                _override("bgp_policies", "bgp")
                _override("bfd_policies", "bfd")
                _override("ospfv2_policies", "ospfv2")
                _override("ospfv2_interfaces", "ospfv2interface")
                _override("ospfv3_interfaces", "ospfv3interface")
                _override("eigrp_policies", "eigrp")

                # Objects overrides (BFD templates)
                if isinstance(objects_block.get("bfd_templates"), list):
                    try:
                        objects_block["bfd_templates"] = [
                            fmc.replace_masked_auth_values(dict(it or {}), "bfd_template", ui_auth_values=ui_auth_values)
                            for it in (objects_block.get("bfd_templates") or [])
                        ]
                    except Exception:
                        pass
        except Exception as ex:
            logger.warning(f"Failed to apply Advanced Auth overrides to export: {ex}")

        cfg_out = {
            "loopback_interfaces": loops,
            "physical_interfaces": phys,
            "etherchannel_interfaces": eths,
            "subinterfaces": subs,
            "vti_interfaces": vtis,
            "inline_sets": inlines,
            "bridge_group_interfaces": bgis,
        }
        if objects_block:
            cfg_out["objects"] = objects_block
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
async def fmc_config_get(payload: Dict[str, Any], http_request: Request):
    try:
        # Ensure logs from utils.fmc_api surface while exporting
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
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
async def fmc_config_delete(payload: Dict[str, Any], http_request: Request):
    """Delete selected configuration types from the selected device.

    Expects JSON with:
      fmc_ip, username, password, device_id, domain_uuid (optional),
      delete_loopbacks, delete_physicals, delete_etherchannels, delete_subinterfaces, delete_vtis,
      delete_obj_if_security_zones,
      config: { loopback_interfaces: [...], physical_interfaces: [...], etherchannel_interfaces: [...], subinterfaces: [...], vti_interfaces: [...] }
    """
    try:
        # Attach per-user logger
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
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

        sel_domain = (payload.get("domain_uuid") or "").strip()
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
            get_inline_sets,
            get_bridge_group_interfaces,
            get_security_zones,
            delete_security_zones,
        )
        from utils.fmc_api import (
            delete_loopback_interfaces,
            delete_etherchannel_interfaces,
            delete_subinterfaces as delete_subinterfaces_api,
            delete_vti_interfaces,
            delete_inline_sets as delete_inline_sets_api,
            delete_bridge_group_interfaces as delete_bridge_group_interfaces_api,
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

        # Inline Sets and Bridge Group Interfaces maps
        dev_inline_sets = get_inline_sets(fmc_ip, headers, domain_uuid, device_id) or []
        inline_map: Dict[str, str] = {str(it.get("name")): it.get("id") for it in dev_inline_sets if it.get("id") and it.get("name")}
        dev_bgis = get_bridge_group_interfaces(fmc_ip, headers, domain_uuid, device_id) or []
        bgi_map: Dict[str, str] = {str(it.get("name")): it.get("id") for it in dev_bgis if it.get("id") and it.get("name")}

        deleted_summary: Dict[str, int] = {"loopbacks": 0, "physicals": 0, "etherchannels": 0, "subinterfaces": 0, "vtis": 0, "inline_sets": 0, "bridge_group_interfaces": 0, "objects_interface_security_zones": 0}
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

        # Inline Sets (before EtherChannels/Physicals)
        inline_cfg = cfg.get("inline_sets") or []
        if payload.get("delete_inline_sets") and inline_cfg:
            ids = []
            for it in inline_cfg:
                key = (it.get("name") or "").strip()
                if key and key in inline_map:
                    ids.append(inline_map[key])
                else:
                    errors.append(f"Inline Set not found on device: {key}")
            if ids:
                res = delete_inline_sets_api(fmc_ip, headers, domain_uuid, device_id, list(set(ids)))
                deleted_summary["inline_sets"] = res.get("deleted", 0)
                for er in res.get("errors", []):
                    errors.append(f"Inline Set delete failed: {er}")

        # Bridge Group Interfaces (before EtherChannels/Physicals)
        bgi_cfg = cfg.get("bridge_group_interfaces") or []
        if payload.get("delete_bridge_group_interfaces") and bgi_cfg:
            ids = []
            for it in bgi_cfg:
                key = (it.get("name") or "").strip()
                if key and key in bgi_map:
                    ids.append(bgi_map[key])
                else:
                    errors.append(f"Bridge Group Interface not found on device: {key}")
            if ids:
                res = delete_bridge_group_interfaces_api(fmc_ip, headers, domain_uuid, device_id, list(set(ids)))
                deleted_summary["bridge_group_interfaces"] = res.get("deleted", 0)
                for er in res.get("errors", []):
                    errors.append(f"Bridge Group Interface delete failed: {er}")

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
async def cc_list_proxy_presets(http_request: Request):
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    return {"success": True, "presets": ctx["cc_proxy_presets"]}

@app.get("/api/command-center/static-presets")
async def cc_list_static_presets(http_request: Request):
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    return {"success": True, "presets": ctx["cc_static_presets"]}

@app.post("/api/command-center/proxy-presets/save")
async def cc_save_proxy_preset(payload: Dict[str, Any], http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        name = (payload.get("name") or f"Preset {len(ctx['cc_proxy_presets'])+1}").strip()
        preset = {
            "id": str(uuid.uuid4()),
            "name": name,
            "proxy_address": payload.get("proxy_address", ""),
            "proxy_port": int(payload.get("proxy_port", 0)),
            "proxy_auth": bool(payload.get("proxy_auth", False)),
            "proxy_username": payload.get("proxy_username", ""),
            "proxy_password": payload.get("proxy_password", ""),
        }
        ctx["cc_proxy_presets"].append(preset)
        persist_user_presets(username)
        record_activity(username, "save_proxy_preset", {"name": name})
        return {"success": True, "preset": preset, "presets": ctx["cc_proxy_presets"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.post("/api/command-center/static-presets/save")
async def cc_save_static_preset(payload: Dict[str, Any], http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        name = (payload.get("name") or f"Preset {len(ctx['cc_static_presets'])+1}").strip()
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
        ctx["cc_static_presets"].append(preset)
        persist_user_presets(username)
        record_activity(username, "save_static_preset", {"name": name})
        return {"success": True, "preset": preset, "presets": ctx["cc_static_presets"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/command-center/proxy-presets/{preset_id}")
async def cc_delete_proxy_preset(preset_id: str, http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        before = len(ctx["cc_proxy_presets"])
        ctx["cc_proxy_presets"][:] = [p for p in ctx["cc_proxy_presets"] if p.get("id") != preset_id]
        persist_user_presets(username)
        record_activity(username, "delete_proxy_preset", {"id": preset_id})
        return {"success": True, "deleted": before - len(ctx["cc_proxy_presets"]), "presets": ctx["cc_proxy_presets"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/command-center/static-presets/{preset_id}")
async def cc_delete_static_preset(preset_id: str, http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        before = len(ctx["cc_static_presets"])
        ctx["cc_static_presets"][:] = [p for p in ctx["cc_static_presets"] if p.get("id") != preset_id]
        persist_user_presets(username)
        record_activity(username, "delete_static_preset", {"id": preset_id})
        return {"success": True, "deleted": before - len(ctx["cc_static_presets"]), "presets": ctx["cc_static_presets"]}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.post("/api/command-center/upload-devices")
async def command_center_upload_devices(http_request: Request, file: UploadFile = File(...)):
    try:
        raw = await file.read()
        text = raw.decode("utf-8", errors="ignore")
        parsed = parse_devices_text(text)
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        ctx["cc_devices_state"]["ftd"].extend(parsed.get("ftd", []))
        ctx["cc_devices_state"]["fmc"].extend(parsed.get("fmc", []))
        persist_user_devices(username)
        record_activity(username, "upload_devices", {"ftd": len(parsed.get("ftd", [])), "fmc": len(parsed.get("fmc", []))})
        return {"success": True, "ftd": ctx["cc_devices_state"].get("ftd", []), "fmc": ctx["cc_devices_state"].get("fmc", [])}
    except Exception as e:
        logger.error(f"Device upload parse error: {e}")
        return {"success": False, "message": f"Failed to parse file: {str(e)}"}

@app.get("/api/command-center/devices")
async def command_center_get_devices(http_request: Request):
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    return {"success": True, "ftd": ctx["cc_devices_state"].get("ftd", []), "fmc": ctx["cc_devices_state"].get("fmc", [])}

@app.post("/api/command-center/delete-devices")
async def command_center_delete_devices(payload: Dict[str, Any], http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        ids: List[str] = payload.get("device_ids", [])
        if not ids:
            return {"success": False, "message": "No device IDs provided"}
        before_ftd = len(ctx["cc_devices_state"]["ftd"])
        before_fmc = len(ctx["cc_devices_state"]["fmc"])
        ctx["cc_devices_state"]["ftd"] = [d for d in ctx["cc_devices_state"]["ftd"] if d.get("id") not in ids]
        ctx["cc_devices_state"]["fmc"] = [d for d in ctx["cc_devices_state"]["fmc"] if d.get("id") not in ids]
        persist_user_devices(username)
        record_activity(username, "delete_devices", {"count": before_ftd + before_fmc - len(ctx["cc_devices_state"]["ftd"]) - len(ctx["cc_devices_state"]["fmc"])})
        return {
            "success": True,
            "deleted": before_ftd + before_fmc - len(ctx["cc_devices_state"]["ftd"]) - len(ctx["cc_devices_state"]["fmc"]),
            "ftd": ctx["cc_devices_state"].get("ftd", []),
            "fmc": ctx["cc_devices_state"].get("fmc", []),
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/command-center/execute-http-proxy")
async def command_center_execute_http_proxy(request: HttpProxyExecRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
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
            # From persisted state via IDs (per-user)
            all_ftd = {d['id']: d for d in ctx.get('cc_devices_state', {}).get('ftd', [])}
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
async def command_center_execute_http_proxy_stream(request: HttpProxyExecRequest, http_request: Request):
    """Stream live logs with emojis while executing proxy configuration on devices."""
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
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
            all_ftd = {d['id']: d for d in ctx.get('cc_devices_state', {}).get('ftd', [])}
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

def _resolve_selected_devices(request_devices: Optional[List[CCDevice]], ids: List[str], username: Optional[str] = None) -> List[Dict[str, Any]]:
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
        try:
            ctx = get_user_ctx(username)
            all_ftd = {d['id']: d for d in ctx.get('cc_devices_state', {}).get('ftd', [])}
        except Exception:
            all_ftd = {}
        selected = [all_ftd[i] for i in ids if i in all_ftd]
    return [d for d in selected if (d.get('type') or '').upper() == 'FTD']

def _resolve_selected_fmc_devices(request_devices: Optional[List[CCDevice]], ids: List[str], username: Optional[str] = None) -> List[Dict[str, Any]]:
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
        try:
            ctx = get_user_ctx(username)
            all_fmc = {d['id']: d for d in ctx.get('cc_devices_state', {}).get('fmc', [])}
        except Exception:
            all_fmc = {}
        selected = [all_fmc[i] for i in ids if i in all_fmc]
    return [d for d in selected if (d.get('type') or '').upper() == 'FMC']

@app.post("/api/command-center/execute-static-routes/stream")
async def command_center_execute_static_routes_stream(request: StaticRoutesExecRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        devices = _resolve_selected_devices(request.devices, request.device_ids or [], username)
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
async def command_center_execute_copy_dev_crt_stream(request: SimpleDevicesRequest, http_request: Request):
    try:
        # Resolve both FTD and FMC devices; run in parallel across all
        username = get_current_username(http_request)
        devices_ftd = _resolve_selected_devices(request.devices, request.device_ids or [], username)
        devices_fmc = _resolve_selected_fmc_devices(request.devices, request.device_ids or [], username)
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

@app.post("/api/command-center/restore-backup/stream")
async def command_center_restore_backup_stream(request: RestoreBackupExecRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        devices = _resolve_selected_devices(request.devices, request.device_ids or [], username)
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
                                    file_url=None,
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

@app.post("/api/command-center/download-upgrade/stream")
async def command_center_download_upgrade_stream(request: DownloadUpgradeExecRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        devices = _resolve_selected_fmc_devices(request.devices, request.device_ids or [], username)
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
                    with ThreadPoolExecutor(max_workers=16) as executor:
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
        logger.error(f"Restore backup stream error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/settings")
async def settings_page(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/settings")
    return templates.TemplateResponse("settings.html", {"request": request, "active_page": "settings", "username": username})

@app.post("/api/test-connection")
async def test_connection(request: FMCConnectionRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        # Test authentication to FMC
        domain_uuid, headers = authenticate(request.fmc_ip, request.username, request.password)
        
        # Store authentication information for reuse (per-user)
        ctx["fmc_auth"]["domain_uuid"] = domain_uuid
        ctx["fmc_auth"]["headers"] = headers
        
        logger.info(f"Authentication successful for {request.fmc_ip}. Token stored for reuse.")
        record_activity(username, "fmc_auth", {"fmc_ip": request.fmc_ip})
        
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
async def get_devices(request: FMCConnectionRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        try:
            from utils.fmc_api import get_devicerecords
            device_records = get_devicerecords(request.fmc_ip, ctx["fmc_auth"]["headers"], ctx["fmc_auth"]["domain_uuid"], bulk=True)
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

def ensure_user_inputs_directory(username: str):
    """Ensure per-user inputs directory exists under data/users/<user>/inputs"""
    base = _user_dir(username)
    p = os.path.join(base, 'inputs')
    os.makedirs(p, exist_ok=True)
    return p

def get_user_config_path(username: str, filename: str):
    """Get full path for a config file in the user's inputs directory"""
    filename = os.path.basename(filename)
    inputs_dir = ensure_user_inputs_directory(username)
    return os.path.join(inputs_dir, filename)

def run_clone_operation(username: str, request: CloneConfigRequest):
    """Run the clone operation in a background thread and update operation_status"""
    ctx = get_user_ctx(username)
    try:
        # Reset per-user log stream and stop flag
        _detach_user_log_handlers(username)
        ctx["log_stream"] = io.StringIO()
        ctx["stop_requested"] = False
        # Attach per-user handlers (captures both web_app.app and utils.fmc_api)
        _attach_user_log_handlers(username)
        
        # Update operation status
        ctx["operation_status"]["running"] = True
        ctx["operation_status"]["operation"] = request.operation
        ctx["operation_status"]["start_time"] = time.time()
        ctx["operation_status"]["success"] = None
        ctx["operation_status"]["message"] = f"Running {request.operation} operation..."
        
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
            # Store auth in per-user ctx
            ctx["fmc_auth"]["domain_uuid"] = domain_uuid
            ctx["fmc_auth"]["headers"] = headers
            
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
            ctx["operation_status"]["stats"]["vpn"]["total"] = len(vpn_configs)
            ctx["operation_status"]["success"] = True
            ctx["operation_status"]["message"] = f"Successfully replaced VPN endpoints from {request.source_ftd} to {request.destination_ftd}"
        
        # Handle export/import/clone operations
        elif request.operation == 'export':
            # Get full config path in inputs directory
            config_path = get_user_config_path(username, request.config_path)
            logger.info(f"Exporting configuration from {request.source_ftd} to {config_path}")
            
            # Create parent directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # Fetch config from source
            config = fetch_config_from_source(fmc_data)
            
            # Count stats
            ctx["operation_status"]["stats"]["interfaces"] = (len(config.get('loopbacks', [])) + 
                                              len(config.get('physicals', [])) + 
                                              len(config.get('etherchannels', [])) + 
                                              len(config.get('subinterfaces', [])) + 
                                              len(config.get('vtis', [])))
            ctx["operation_status"]["stats"]["routes"] = (len(config.get('ipv4_static_routes', [])) + 
                                           len(config.get('ipv6_static_routes', [])))
            ctx["operation_status"]["stats"]["vrfs"] = len(config.get('vrfs', []))
            
            # Save to file
            with open(config_path, 'w') as f:
                yaml.safe_dump(config, f)
            
            ctx["operation_status"]["success"] = True
            ctx["operation_status"]["message"] = f"Configuration exported from {request.source_ftd} to {config_path}"
            ctx["operation_status"]["config_path"] = config_path
            
        elif request.operation == 'import':
            # Get full config path in inputs directory
            config_path = get_user_config_path(username, request.config_path)
            logger.info(f"Importing configuration from {config_path} to {request.destination_ftd}")
            
            # Check if file exists
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            # Load config from file
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Count stats
            ctx["operation_status"]["stats"]["interfaces"] = (len(config.get('loopbacks', [])) + 
                                              len(config.get('physicals', [])) + 
                                              len(config.get('etherchannels', [])) + 
                                              len(config.get('subinterfaces', [])) + 
                                              len(config.get('vtis', [])))
            ctx["operation_status"]["stats"]["routes"] = (len(config.get('ipv4_static_routes', [])) + 
                                           len(config.get('ipv6_static_routes', [])))
            ctx["operation_status"]["stats"]["vrfs"] = len(config.get('vrfs', []))
            
            # Apply config
            apply_config_to_destination(fmc_data, config, request.batch_size)
            
            ctx["operation_status"]["success"] = True
            ctx["operation_status"]["message"] = f"Configuration imported from {config_path} to {request.destination_ftd}"
            
        else:  # clone
            logger.info(f"Cloning configuration from {request.source_ftd} to {request.destination_ftd}")
            
            # Fetch config from source
            config = fetch_config_from_source(fmc_data)
            
            # Count stats
            ctx["operation_status"]["stats"]["interfaces"] = (len(config.get('loopbacks', [])) + 
                                              len(config.get('physicals', [])) + 
                                              len(config.get('etherchannels', [])) + 
                                              len(config.get('subinterfaces', [])) + 
                                              len(config.get('vtis', [])))
            ctx["operation_status"]["stats"]["routes"] = (len(config.get('ipv4_static_routes', [])) + 
                                           len(config.get('ipv6_static_routes', [])))
            ctx["operation_status"]["stats"]["vrfs"] = len(config.get('vrfs', []))
            
            # Check if operation should be stopped
            if ctx["stop_requested"]:
                raise InterruptedError("Operation stopped by user request")
                
            # Apply config to destination
            apply_config_to_destination(fmc_data, config, request.batch_size)
            
            ctx["operation_status"]["success"] = True
            ctx["operation_status"]["message"] = f"Configuration cloned from {request.source_ftd} to {request.destination_ftd}"
    
    except InterruptedError as e:
        logger.info(f"Operation interrupted: {str(e)}")
        ctx["operation_status"]["success"] = False
        ctx["operation_status"]["message"] = f"Operation stopped by user"
    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        ctx["operation_status"]["success"] = False
        ctx["operation_status"]["message"] = f"Operation failed: {str(e)}"
    
    finally:
        ctx["operation_status"]["running"] = False
        ctx["operation_status"]["end_time"] = time.time()
        # Keep handlers attached so UI can continue tailing logs; do not detach here

@app.post("/api/clone-config")
async def clone_config(request: CloneConfigRequest, background_tasks: BackgroundTasks, http_request: Request):
    try:
        username = get_current_username(http_request)
        record_activity(username, "clone_operation_started", {"operation": request.operation})
        # Start the operation in a background task
        background_tasks.add_task(run_clone_operation, username, request)
        
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
async def get_operation_status(http_request: Request):
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    return ctx["operation_status"]

@app.get("/api/logs")
async def get_logs(http_request: Request):
    username = get_current_username(http_request)
    # Ensure handlers are attached on every poll so streaming survives reloads
    try:
        _attach_user_log_handlers(username)
    except Exception:
        pass
    ctx = get_user_ctx(username)
    # Prefer file-backed logs for multi-process reliability; fallback to in-memory stream
    try:
        fp = ctx.get("log_file_path") or os.path.join(_user_dir(username), "operation.log")
        if fp and os.path.exists(fp):
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                return {"logs": f.read()}
    except Exception:
        pass
    return {"logs": ctx["log_stream"].getvalue()}

@app.get("/api/download-logs")
async def download_logs(http_request: Request):
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    fp = ctx.get("log_file_path") or os.path.join(_user_dir(username), "operation.log")
    try:
        if fp and os.path.exists(fp):
            return FileResponse(
                fp,
                media_type="text/plain",
                filename="operation_logs.txt"
            )
    except Exception:
        pass
    # Fallback to in-memory stream
    return StreamingResponse(io.StringIO(ctx["log_stream"].getvalue()), media_type="text/plain", headers={"Content-Disposition": "attachment; filename=operation_logs.txt"})

@app.post("/api/clear-logs")
async def clear_logs(http_request: Request):
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    try:
        # Truncate the existing stream so attached handlers keep writing to the same buffer
        stream = ctx.get("log_stream")
        if isinstance(stream, io.StringIO):
            stream.seek(0)
            stream.truncate(0)
        else:
            # Fallback: create a new stream and re-attach handlers to it
            ctx["log_stream"] = io.StringIO()
            try:
                _detach_user_log_handlers(username)
                _attach_user_log_handlers(username)
            except Exception:
                pass
        log_message = f"\n{time.strftime('%Y-%m-%d %H:%M:%S')} - Logs cleared by user\n"
        ctx["log_stream"].write(log_message)
        ctx["log_stream"].flush()
        # Also truncate file-backed logs if present
        fp = ctx.get("log_file_path") or os.path.join(_user_dir(username), "operation.log")
        try:
            if fp:
                with open(fp, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(log_message)
        except Exception:
            pass
        return {"success": True, "message": "Logs cleared successfully"}
    except Exception as e:
        return {"success": False, "message": f"Failed to clear logs: {str(e)}"}

@app.get("/api/config-files")
async def list_config_files(http_request: Request):
    """List all available configuration files in the inputs directory"""
    try:
        username = get_current_username(http_request)
        inputs_dir = ensure_user_inputs_directory(username)
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
async def download_config(filename: str, http_request: Request):
    """Download a configuration file"""
    try:
        # Sanitize filename to prevent directory traversal
        filename = os.path.basename(filename)
        username = get_current_username(http_request)
        file_path = get_user_config_path(username, filename)
        
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
async def upload_config(http_request: Request, file: UploadFile = File(...)):
    """Upload a configuration file"""
    try:
        # Ensure filename is safe
        filename = os.path.basename(file.filename)
        if not (filename.endswith(".yaml") or filename.endswith(".yml")):
            raise ValueError("Only YAML files are allowed")
        
        # Save the file to the inputs directory
        username = get_current_username(http_request)
        file_path = get_user_config_path(username, filename)
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
async def stop_operation(http_request: Request):
    """Stop the currently running operation"""
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    try:
        if ctx["operation_status"]["running"]:
            # Set the stop flag to true
            ctx["stop_requested"] = True
            
            # Set the operation to stopped
            ctx["operation_status"]["running"] = False
            ctx["operation_status"]["success"] = False
            ctx["operation_status"]["message"] = "Operation stopped by user"
            
            # Log the stop action
            import time
            log_message = f"\n{time.strftime('%Y-%m-%d %H:%M:%S')} - Operation stopped by user\n"
            ctx["log_stream"].write(log_message)
            ctx["log_stream"].flush()
            
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


async def install_tool_async(host_type: str, tool: str, username: str):
    """Asynchronously install a tool on the specified host"""
    install_key = f"{host_type}-{tool}"
    ctx = get_user_ctx(username)
    
    try:
        # Update status to installing
        ctx["installation_status"][install_key] = {
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
            ctx["installation_status"][install_key] = {
                "status": "completed",
                "message": result["message"],
                "start_time": ctx["installation_status"][install_key]["start_time"],
                "success": True,
                "version": version
            }
        else:
            ctx["installation_status"][install_key] = {
                "status": "failed",
                "message": result["message"],
                "start_time": ctx["installation_status"][install_key]["start_time"],
                "success": False,
                "version": None
            }
            
    except Exception as e:
        logger.error(f"Error in async installation of {tool} on {host_type}: {str(e)}")
        ctx["installation_status"][install_key] = {
            "status": "failed",
            "message": f"Installation error: {str(e)}",
            "start_time": ctx["installation_status"].get(install_key, {}).get("start_time", time.time()),
            "success": False,
            "version": None
        }

@app.get("/api/traffic-generators/installation-status/{host_type}/{tool}")
async def get_installation_status(host_type: str, tool: str, http_request: Request):
    """Get the installation status for a specific tool on a host"""
    if host_type not in ["client", "server"]:
        raise HTTPException(status_code=400, detail="Invalid host type. Must be 'client' or 'server'")
    
    if tool not in ["scapy", "hping3", "iperf3", "samba"]:
        raise HTTPException(status_code=400, detail="Invalid tool. Must be 'scapy', 'hping3', 'iperf3', or 'samba'")
    
    install_key = f"{host_type}-{tool}"
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    status_map = ctx.get("installation_status", {})
    if install_key not in status_map:
        return {"status": "not_started", "message": "Installation not started", "success": None, "version": None}
    return status_map[install_key]

@app.post("/api/traffic-generators/install-tool/{host_type}/{tool}")
async def install_tool(host_type: str, tool: str, background_tasks: BackgroundTasks, http_request: Request):
    """Start installation of a specific tool on the specified host"""
    if host_type not in ["client", "server"]:
        raise HTTPException(status_code=400, detail="Invalid host type. Must be 'client' or 'server'")
    
    if tool not in ["scapy", "hping3", "iperf3", "samba"]:
        raise HTTPException(status_code=400, detail="Invalid tool. Must be 'scapy', 'hping3', 'iperf3', or 'samba'")
    
    install_key = f"{host_type}-{tool}"
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    # Check in per-user map
    if install_key in ctx["installation_status"] and ctx["installation_status"][install_key]["status"] == "installing":
        return {"success": True, "message": f"Installation of {tool} on {host_type} is already in progress", "status": "installing"}

    try:
        # Start async installation
        background_tasks.add_task(install_tool_async, host_type, tool, username)
        
        return {
            "success": True,
            "message": f"Started installation of {tool} on {host_type}",
            "status": "installing"
        }
    except Exception as e:
        logger.error(f"Error starting installation of {tool} on {host_type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start installation of {tool}: {str(e)}")

@app.post("/api/traffic-generators/generate-traffic")
async def generate_network_traffic(request: TrafficGenerationRequest, http_request: Request):
    """Generate network traffic using the specified tool"""
    try:
        username = get_current_username(http_request)
        record_activity(username, "generate_traffic", {"tool": request.tool, "source": request.source_host})
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