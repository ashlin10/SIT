import os
import sys
import re
import shlex

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

import yaml

# Custom SafeLoader that does NOT interpret colon-separated values (e.g. IPv6
# addresses like "15:0:0:0:0:0:0:1") as sexagesimal (base-60) integers.
# PyYAML's default SafeLoader uses YAML 1.1, which has this legacy behaviour.
class _SafeLoaderNoSexagesimal(yaml.SafeLoader):
    pass

# Remove the implicit resolver that matches sexagesimal integers
# (pattern like "1:2:3" → base-60 number).  We rebuild the int resolver
# list, dropping any regex that contains the sexagesimal ":" pattern.
_SafeLoaderNoSexagesimal.yaml_implicit_resolvers = {
    k: [(tag, regexp) for tag, regexp in v
        if not (tag == 'tag:yaml.org,2002:int' and ':' in regexp.pattern)]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.copy().items()
}

def _yaml_safe_load(stream):
    """yaml.safe_load replacement that preserves colon-separated strings."""
    return yaml.load(stream, Loader=_SafeLoaderNoSexagesimal)

import subprocess
import json
import logging
import io
import threading
import time
import csv
import requests
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks, File, UploadFile, Form, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, validator, Field
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import urljoin, urlparse
from typing import Optional, List, Dict, Any, Union, Set, Tuple
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
from utils.fmc_api import authenticate, get_ftd_uuid, get_device_info, get_ftd_name_by_id, replace_vpn_endpoint, get_vpn_topologies, get_vpn_endpoints, get_domains
from utils.fmc_api import post_vpn_topology, post_vpn_endpoint, post_vpn_endpoints_bulk
from utils.fmc_api import get_ikev2_policies, get_ikev2_ipsec_proposals, post_ikev2_policy, post_ikev2_ipsec_proposal
from utils.fmc_api import get_all_network_objects, get_all_accesslist_objects, post_network_object, post_accesslist_object
from utils.fmc_api import delete_devices_bulk, delete_ha_pair, delete_cluster, post_ftd_ha_pair
from utils import fmc_api as fmc
from utils.fmc_api import set_debug_mode as _set_fmc_debug

def _apply_debug_flag(payload: Dict[str, Any]):
    """Extract debug flag from frontend payload and set it on fmc_api."""
    _set_fmc_debug(bool(payload.get("debug", False)))

# Import traffic generators module from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from traffic_generators import SSHConnectionDetails, connect_to_hosts, get_interfaces, disconnect_all, check_tool_installation, TrafficGenerationRequest, generate_traffic, install_tool_on_host
from configure_http_proxy import configure_http_proxy_on_device as run_http_proxy_on_device
from configure_static_routes import run_static_routes_on_device
from copy_dev_crt import run_copy_dev_cert_on_device
from download_upgrade_package import run_download_upgrade_on_device
from restore_device_backup_runner import run_restore_backup_on_device
from utils.dependency_resolver import DependencyResolver
from utils.credential_manager import get_credential_manager, encrypt_password, decrypt_password
import dashboard_metrics as dm

# Module logger (no global stream capture; per-user logs handled elsewhere)
logger = logging.getLogger(__name__)

# Note: installation_status is now tracked per-user within get_user_ctx(username)["installation_status"]

# Initialize the app
app = FastAPI()

# Initialize dashboard metrics DB
dm.init_db()

# Sessions for login
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("WEB_APP_SESSION_SECRET", "sit-secret-key"),
    max_age=60 * 60 * 24 * 7,  # 7 days
)

# In-memory session/activity tracking
# Load users from external JSON file (not committed to git)
def _load_users() -> Dict[str, str]:
    """Load users from users.json file. Falls back to env var or empty dict."""
    users_file = os.path.join(os.path.dirname(__file__), "data", "users.json")
    if os.path.exists(users_file):
        try:
            with open(users_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load users.json: {e}")
    # Fallback: check for USERS_JSON env var (JSON string)
    users_json = os.environ.get("USERS_JSON")
    if users_json:
        try:
            return json.loads(users_json)
        except Exception as e:
            logger.warning(f"Failed to parse USERS_JSON: {e}")
    # Default empty - no hardcoded credentials
    logger.warning("No users configured. Create web_app/data/users.json or set USERS_JSON env var.")
    return {}

USERS = _load_users()

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
        # Also persist to dashboard metrics DB
        import json as _json
        dm.record_activity(username, action, _json.dumps(details) if details else None)
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

@app.middleware("http")
async def collect_request_metrics(request: Request, call_next):
    """Record request metrics (RPM, error rate, response time) to persistent DB."""
    start = time.time()
    response = await call_next(request)
    elapsed_ms = (time.time() - start) * 1000
    path = request.url.path
    # Skip static assets and health checks from metrics
    if not path.startswith(("/assets/", "/static/", "/favicon")):
        username = get_current_username(request)
        try:
            dm.record_request(request.method, path, response.status_code, elapsed_ms, username)
        except Exception:
            pass
    return response

# Background task: periodic system snapshots + active user counts
_metrics_bg_started = False

def _metrics_background_loop():
    """Runs every 30s: capture system stats and active user count."""
    while True:
        try:
            dm.record_system_snapshot()
            # Count active users from in-memory sessions
            now = datetime.now(timezone.utc)
            count = 0
            for _, info in list(active_sessions.items()):
                try:
                    seen = datetime.fromisoformat((info.get("last_seen") or "").replace("Z", "+00:00"))
                    if (now - seen).total_seconds() <= 300:
                        count += 1
                except Exception:
                    pass
            dm.record_active_user_count(count)
        except Exception:
            pass
        time.sleep(30)

@app.on_event("startup")
async def start_metrics_background():
    global _metrics_bg_started
    if not _metrics_bg_started:
        _metrics_bg_started = True
        t = threading.Thread(target=_metrics_background_loop, daemon=True)
        t.start()
        # Daily cleanup of old data (>400 days to support All Time / 1 Year range)
        def _daily_cleanup():
            while True:
                time.sleep(86400)
                dm.cleanup_old_data(400)
        tc = threading.Thread(target=_daily_cleanup, daemon=True)
        tc.start()

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

# Mount React SPA build (JS/CSS bundles + root-level files like favicon)
SPA_DIR = os.path.join(BASE_DIR, "spa")
SPA_ASSETS_DIR = os.path.join(SPA_DIR, "assets")
if os.path.isdir(SPA_ASSETS_DIR):
    app.mount("/assets", StaticFiles(directory=SPA_ASSETS_DIR), name="spa-assets")

# Templates (still needed for pages not yet migrated to React SPA)
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
            "fmc_connection": {"fmc_ip": None, "username": None, "password": None, "devices": [], "domains": [], "domain_uuid": None},
            "fmc_connections": {},
            "fmc_loaded_config": None,
            "fmc_loaded_config_yaml": None,
            "fmc_loaded_vpn_topologies": None,
            "fmc_loaded_vpn_yaml": None,
            "fmc_loaded_chassis_config": None,
            "fmc_loaded_chassis_config_yaml": None,
            "fmc_loaded_chassis_config_filename": None,
            "fmc_loaded_chassis_config_counts": None,
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
            "progress": {"percent": 0, "label": "", "active": False},
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
        # Load FMC presets and decrypt passwords
        raw_presets = _read_json(os.path.join(ud, "fmc_config_presets.json"), [])
        cm = get_credential_manager()
        ctx["fmc_config_presets"] = cm.decrypt_presets_file(raw_presets)
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
        targets = ctx.pop("log_handler_targets", [__name__, "utils.fmc_api"])
        ctx["log_handler_attached"] = False
        # Remove specific stored handlers
        for h in [handler, file_handler]:
            if h:
                for name in targets:
                    try:
                        logging.getLogger(name).removeHandler(h)
                    except Exception:
                        pass
        # Also scrub any leftover StreamHandler/FileHandler writing to this user's stream or log file
        log_stream = ctx.get("log_stream")
        log_file_path = ctx.get("log_file_path") or ""
        for name in targets:
            lg = logging.getLogger(name)
            for h in list(lg.handlers):
                try:
                    if isinstance(h, logging.StreamHandler) and hasattr(h, 'stream') and h.stream is log_stream:
                        lg.removeHandler(h)
                    elif isinstance(h, logging.FileHandler) and hasattr(h, 'baseFilename') and log_file_path and os.path.abspath(h.baseFilename) == os.path.abspath(log_file_path):
                        lg.removeHandler(h)
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
    # Encrypt passwords before saving FMC presets
    cm = get_credential_manager()
    encrypted_presets = cm.encrypt_presets_file(ctx["fmc_config_presets"])
    _write_json(os.path.join(ud, "fmc_config_presets.json"), encrypted_presets)

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
    devices: Optional[List[Dict[str, Any]]] = None
    device_ids: Optional[List[str]] = None

# Models for strongSwan
class StrongSwanConnectionRequest(BaseModel):
    ip: str
    port: int = 22
    username: str
    password: str

class StrongSwanTunnelDetailRequest(BaseModel):
    tunnel_name: str

# Models for Cisco Secure Client
class CSCConnectionRequest(BaseModel):
    ip: str
    port: int = 22
    username: str
    password: str

class CSCDeployRequest(BaseModel):
    count: int = 1
    headend: str
    vpn_user: str
    vpn_password: str
    vpn_group: Optional[str] = None
    local_ipv4_start: Optional[str] = None
    ipv4_increment_octet: Optional[int] = 4
    local_ipv6_start: Optional[str] = None
    ipv6_increment_hextet: Optional[int] = 8
    allow_untrusted_cert: bool = True
    image_tag: Optional[str] = None
    protocol: Optional[str] = None
    vpn_user_increment: bool = False
    vpn_password_increment: bool = False
    connection_type: Optional[str] = "ssl"  # "ssl" or "ipsec"
    enable_dtls: bool = True
    enable_pqc: bool = False

class CSCInstallRequest(BaseModel):
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    no_proxy: Optional[str] = None

class CSCContainerActionRequest(BaseModel):
    container_id: Optional[str] = None

class CSCConfigFileSaveRequest(BaseModel):
    filename: str
    content: str

class CSCImageDeleteRequest(BaseModel):
    image: str

class CSCConfigFileDeleteRequest(BaseModel):
    filename: str

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
            _apply_debug_flag(payload)
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
                    # Also fetch settings per VPN to embed into raw for download
                    # Return as lists to match FMC API format
                    ike_obj = None
                    ipsec_obj = None
                    adv_obj = None
                    try:
                        ike_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/ikesettings?expanded=true"
                        r_ike = fmc.fmc_get(ike_url)
                        rj = r_ike.json() if r_ike is not None else None
                        if isinstance(rj, dict):
                            items = rj.get('items') if 'items' in rj else None
                            # Return as list to match FMC format
                            if isinstance(items, list) and items:
                                ike_obj = items
                            elif rj and not items:  # Single object response
                                ike_obj = [rj]
                    except Exception as ex:
                        logger.warning(f"[VPN]  - Failed to fetch IKE settings for {name}: {ex}")
                        ike_obj = None
                    try:
                        ipsec_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/ipsecsettings?expanded=true"
                        r_ip = fmc.fmc_get(ipsec_url)
                        rj = r_ip.json() if r_ip is not None else None
                        if isinstance(rj, dict):
                            items = rj.get('items') if 'items' in rj else None
                            # Return as list to match FMC format
                            if isinstance(items, list) and items:
                                ipsec_obj = items
                            elif rj and not items:  # Single object response
                                ipsec_obj = [rj]
                    except Exception as ex:
                        logger.warning(f"[VPN]  - Failed to fetch IPSec settings for {name}: {ex}")
                        ipsec_obj = None
                    try:
                        adv_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/advancedsettings?expanded=true"
                        r_av = fmc.fmc_get(adv_url)
                        rj = r_av.json() if r_av is not None else None
                        if isinstance(rj, dict):
                            items = rj.get('items') if 'items' in rj else None
                            # Return as list to match FMC format
                            if isinstance(items, list) and items:
                                adv_obj = items
                            elif rj and not items:  # Single object response
                                adv_obj = [rj]
                    except Exception as ex:
                        logger.warning(f"[VPN]  - Failed to fetch Advanced settings for {name}: {ex}")
                        adv_obj = None

                    # Expand IKE policy and IPSec proposal references to full objects
                    if isinstance(ike_obj, list):
                        for ike_setting in ike_obj:
                            if not isinstance(ike_setting, dict):
                                continue
                            ikev2_settings = ike_setting.get("ikeV2Settings")
                            if isinstance(ikev2_settings, dict):
                                policies = ikev2_settings.get("policies")
                                if isinstance(policies, list):
                                    expanded_policies = []
                                    for policy_ref in policies:
                                        if isinstance(policy_ref, dict) and policy_ref.get("id"):
                                            try:
                                                policy_id = policy_ref["id"]
                                                policy_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2policies/{policy_id}"
                                                r_policy = fmc.fmc_get(policy_url)
                                                if r_policy and r_policy.status_code == 200:
                                                    expanded_policies.append(r_policy.json())
                                                else:
                                                    expanded_policies.append(policy_ref)
                                            except Exception:
                                                expanded_policies.append(policy_ref)
                                        else:
                                            expanded_policies.append(policy_ref)
                                    ikev2_settings["policies"] = expanded_policies
                    
                    if isinstance(ipsec_obj, list):
                        for ipsec_setting in ipsec_obj:
                            if not isinstance(ipsec_setting, dict):
                                continue
                            proposals = ipsec_setting.get("ikeV2IpsecProposal")
                            if isinstance(proposals, list):
                                expanded_proposals = []
                                for proposal_ref in proposals:
                                    if isinstance(proposal_ref, dict) and proposal_ref.get("id"):
                                        try:
                                            proposal_id = proposal_ref["id"]
                                            proposal_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2ipsecproposals/{proposal_id}"
                                            r_proposal = fmc.fmc_get(proposal_url)
                                            if r_proposal and r_proposal.status_code == 200:
                                                expanded_proposals.append(r_proposal.json())
                                            else:
                                                expanded_proposals.append(proposal_ref)
                                        except Exception:
                                            expanded_proposals.append(proposal_ref)
                                    else:
                                        expanded_proposals.append(proposal_ref)
                                ipsec_setting["ikeV2IpsecProposal"] = expanded_proposals

                    # Collect and fetch protected network objects
                    objects_section = {}
                    try:
                        # Collect all network and access list references from protectedNetworks
                        network_names = set()
                        accesslist_names = set()
                        
                        for ep in eps or []:
                            prot_nets = ep.get('protectedNetworks')
                            if isinstance(prot_nets, dict):
                                # Collect networks
                                nets = prot_nets.get('networks', [])
                                if isinstance(nets, list):
                                    for net in nets:
                                        if isinstance(net, dict):
                                            net_name = net.get('name')
                                            if net_name:
                                                network_names.add(net_name)
                                
                                # Collect access lists
                                acls = prot_nets.get('accessLists', [])
                                if isinstance(acls, list):
                                    for acl in acls:
                                        if isinstance(acl, dict):
                                            acl_name = acl.get('name')
                                            if acl_name:
                                                accesslist_names.add(acl_name)
                        
                        # Fetch objects from FMC if any were found
                        if network_names or accesslist_names:
                            logger.info(f"[VPN] Fetching {len(network_names)} networks and {len(accesslist_names)} access lists for topology {name}")
                            
                            if network_names:
                                all_networks = get_all_network_objects(fmc_ip, headers, domain_uuid)
                                network_objs = []
                                for net_name in network_names:
                                    if net_name in all_networks:
                                        network_objs.append(all_networks[net_name])
                                        logger.info(f"[VPN]  - Found network: {net_name}")
                                    else:
                                        logger.warning(f"[VPN]  - Network not found: {net_name}")
                                if network_objs:
                                    objects_section['networks'] = network_objs
                            
                            if accesslist_names:
                                all_accesslists = get_all_accesslist_objects(fmc_ip, headers, domain_uuid)
                                acl_objs = []
                                for acl_name in accesslist_names:
                                    if acl_name in all_accesslists:
                                        acl_objs.append(all_accesslists[acl_name])
                                        logger.info(f"[VPN]  - Found access list: {acl_name}")
                                    else:
                                        logger.warning(f"[VPN]  - Access list not found: {acl_name}")
                                if acl_objs:
                                    objects_section['accesslists'] = acl_objs
                    except Exception as ex:
                        logger.warning(f"[VPN] Failed to fetch protected network objects for {name}: {ex}")

                    raw = {
                        'summary': dict(it),
                        'endpoints': eps,
                        'ikeSettings': ike_obj,
                        'ipsecSettings': ipsec_obj,
                        'advancedSettings': adv_obj,
                        'ftds2svpn': ftds_map.get(vpn_id)
                    }
                    
                    # Add objects section if any were fetched
                    if objects_section:
                        raw['objects'] = objects_section

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

            # Generate VPN YAML from raw topology data (same logic as /vpn/download)
            vpn_yaml = ""
            vpn_filename = f"vpn-topologies-{int(time.time())}.yaml"
            if out:
                try:
                    raw_items = [t.get("raw", t) for t in out]
                    vpn_yaml = _generate_vpn_yaml(raw_items)
                except Exception as ex:
                    logger.warning(f"[VPN] Failed to generate YAML for viewer: {ex}")

            return {"success": True, "topologies": out, "vpn_yaml": vpn_yaml, "vpn_filename": vpn_filename}

        result = await loop.run_in_executor(None, work)
        if isinstance(result, dict) and result.get("success") is False:
            return JSONResponse(status_code=502, content=result)
        return result
    except Exception as e:
        logger.error(f"VPN list error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


def _generate_vpn_yaml(items: List[Dict[str, Any]]) -> str:
    """Generate VPN YAML string from raw topology dicts.
    Shared by /vpn/list (for viewer) and /vpn/download (for file download).
    """
    def _strip_keys_recursive(obj: Any, keys: set = {"metadata", "links"}):
        try:
            if isinstance(obj, dict):
                return {k: _strip_keys_recursive(v, keys) for k, v in obj.items() if k not in keys}
            if isinstance(obj, list):
                return [_strip_keys_recursive(x, keys) for x in obj]
            return obj
        except Exception:
            return obj

    def _replace_ids(obj: Any, parent_key: str = "", key_path: Tuple[str, ...] = ()) -> Any:
        try:
            if isinstance(obj, list):
                return [_replace_ids(x, parent_key, key_path) for x in obj]
            if not isinstance(obj, dict):
                return obj

            out: Dict[str, Any] = {}
            for k, v in obj.items():
                kp = key_path + (k,)
                vv = _replace_ids(v, k, kp)

                if k == 'id':
                    placeholder = None
                    if key_path == ('ikeSettings',):
                        placeholder = '<IKE_SETTINGS_UUID>'
                    elif key_path == ('ipsecSettings',):
                        placeholder = '<IPSEC_SETTINGS_UUID>'
                    elif key_path == ('advancedSettings',):
                        placeholder = '<ADVANCED_SETTINGS_UUID>'
                    elif parent_key in ('device',):
                        placeholder = '<DEVICE_UUID>'
                    elif parent_key in ('outsideInterface', 'interface'):
                        placeholder = '<INTERFACE_UUID>'
                    elif parent_key in ('tunnelSourceInterface', 'tunnelSource'):
                        placeholder = '<TUNNEL_SOURCE_UUID>'

                    if placeholder is not None:
                        out[k] = placeholder
                    continue

                out[k] = vv
            return out
        except Exception:
            return obj

    def _limited_summary(src: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'name': src.get('name'),
            'routeBased': bool(src.get('routeBased')) if src.get('routeBased') is not None else src.get('routeBased'),
            'ikeV1Enabled': bool(src.get('ikeV1Enabled')) if src.get('ikeV1Enabled') is not None else src.get('ikeV1Enabled'),
            'ikeV2Enabled': bool(src.get('ikeV2Enabled')) if src.get('ikeV2Enabled') is not None else src.get('ikeV2Enabled'),
            'topologyType': src.get('topologyType'),
        }

    vpn_items: List[Dict[str, Any]] = []
    for raw in items:
        raw_dict = dict(raw or {}) if isinstance(raw, dict) else {}
        if 'summary' in raw_dict:
            src_summary = dict(raw_dict.get('summary') or {})
            src_endpoints = list(raw_dict.get('endpoints') or [])
            src_ike = raw_dict.get('ikeSettings')
            src_ipsec = raw_dict.get('ipsecSettings')
            src_adv = raw_dict.get('advancedSettings')
            if (not isinstance(src_ike, (dict, list)) or not src_ike or
                not isinstance(src_ipsec, (dict, list)) or not src_ipsec or
                not isinstance(src_adv, (dict, list)) or not src_adv):
                ftds = raw_dict.get('ftds2svpn')
                if isinstance(ftds, dict):
                    src_ike = src_ike or ftds.get('ikeSettings')
                    src_ipsec = src_ipsec or ftds.get('ipsecSettings')
                    src_adv = src_adv or ftds.get('advancedSettings')
        else:
            src_summary = raw_dict
            src_endpoints = list(raw_dict.get('endpoints') or [])
            src_ike = raw_dict.get('ikeSettings')
            src_ipsec = raw_dict.get('ipsecSettings')
            src_adv = raw_dict.get('advancedSettings')

        src_summary = _strip_keys_recursive(src_summary)
        src_endpoints = _strip_keys_recursive(src_endpoints)
        src_ike = _strip_keys_recursive(src_ike) if isinstance(src_ike, (dict, list)) else src_ike
        src_ipsec = _strip_keys_recursive(src_ipsec) if isinstance(src_ipsec, (dict, list)) else src_ipsec
        src_adv = _strip_keys_recursive(src_adv) if isinstance(src_adv, (dict, list)) else src_adv

        item: Dict[str, Any] = _limited_summary(src_summary)
        if src_endpoints:
            item['endpoints'] = _replace_ids(src_endpoints)
        if isinstance(src_ike, (dict, list)) and src_ike:
            item['ikeSettings'] = _replace_ids(src_ike, parent_key='', key_path=('ikeSettings',))
        if isinstance(src_ipsec, (dict, list)) and src_ipsec:
            item['ipsecSettings'] = _replace_ids(src_ipsec, parent_key='', key_path=('ipsecSettings',))
        if isinstance(src_adv, (dict, list)) and src_adv:
            item['advancedSettings'] = _replace_ids(src_adv, parent_key='', key_path=('advancedSettings',))

        src_objects = raw_dict.get('objects')
        if isinstance(src_objects, dict) and src_objects:
            item['objects'] = _strip_keys_recursive(src_objects)

        vpn_items.append(item)

    doc = { 'vpn_topologies': vpn_items }
    return yaml.safe_dump(doc, sort_keys=False)


@app.post("/api/fmc-config/vpn/download")
async def fmc_vpn_download(payload: Dict[str, Any]):
    """Download selected topologies as YAML (Option A format).
    Expects payload.topologies as list of raw dicts (either Option A items or {summary,endpoints} form).
    Produces a YAML with root 'vpn_topologies', where each item contains only the summary fields
    (name, routeBased, ikeV1Enabled, ikeV2Enabled, topologyType) plus endpoints and settings blocks.
    All 'links'/'metadata' are removed and certain 'id' values are replaced with placeholders.
    """
    try:
        items = payload.get('topologies') or []
        if not isinstance(items, list) or not items:
            return JSONResponse(status_code=400, content={"success": False, "message": "No topologies provided"})

        content = _generate_vpn_yaml(items)
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

# ─── Legacy HTML routes (pages not yet migrated to React SPA) ────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    return RedirectResponse(url="/fmc-configuration")

@app.get("/fmc-configuration", response_class=HTMLResponse)
async def fmc_configuration():
    # Now served by React SPA — redirect to ensure SPA route at bottom handles it
    spa_index = os.path.join(SPA_DIR, "index.html")
    if os.path.isfile(spa_index):
        return FileResponse(spa_index, media_type="text/html")
    return HTMLResponse("<h1>SPA not built</h1><p>Run: cd ../frontend &amp;&amp; npm run build</p>", status_code=503)

@app.get("/vpn-console", response_class=HTMLResponse)
async def vpn_console_page(request: Request):
    # Now served by React SPA
    spa_index = os.path.join(SPA_DIR, "index.html")
    if os.path.isfile(spa_index):
        return FileResponse(spa_index, media_type="text/html")
    return HTMLResponse("<h1>SPA not built</h1><p>Run: cd ../frontend &amp;&amp; npm run build</p>", status_code=503)

@app.get("/vpn-debugger", response_class=HTMLResponse)
async def vpn_debugger_redirect(request: Request):
    """Backwards-compatible redirect to VPN Console."""
    return RedirectResponse(url="/vpn-console")

@app.get("/strongswan", response_class=HTMLResponse)
async def strongswan_page(request: Request):
    """Backwards-compatible redirect to VPN Console."""
    return RedirectResponse(url="/vpn-console")

# Login/Logout routes

@app.get("/logout")
async def logout(request: Request):
    u = get_current_username(request)
    if u:
        record_activity(u, "logout", {})
    try:
        sid = request.session.get("sid")
        if sid and sid in active_sessions:
            del active_sessions[sid]
        request.session.clear()
    except Exception:
        pass
    return RedirectResponse(url="/login", status_code=303)

# ─── Auth API (JSON) ──────────────────────────────────────────────────────────
@app.get("/api/auth/check")
async def auth_check(request: Request):
    username = get_current_username(request)
    if username:
        return {"authenticated": True, "username": username}
    return JSONResponse(status_code=401, content={"authenticated": False})

@app.post("/api/auth/login")
async def api_login(request: Request):
    body = await request.json()
    u = (body.get("username") or "").strip()
    p = body.get("password") or ""
    if u in USERS and USERS[u] == p:
        request.session["username"] = u
        request.session["sid"] = request.session.get("sid") or str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        active_sessions[request.session["sid"]] = {"username": u, "login_time": now, "last_seen": now}
        record_activity(u, "login", {})
        return {"success": True, "username": u}
    return JSONResponse(status_code=401, content={"success": False, "error": "Invalid credentials"})

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    u = get_current_username(request)
    if u:
        record_activity(u, "logout", {})
    try:
        sid = request.session.get("sid")
        if sid and sid in active_sessions:
            del active_sessions[sid]
        request.session.clear()
    except Exception:
        pass
    return {"success": True}

# ─── SAML SSO (Duo) routes ───────────────────────────────────────────────────
def _prepare_saml_request(request: Request) -> dict:
    """Build the request dict that python3-saml expects from a FastAPI/Starlette request."""
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return {
        "https": "on" if forwarded_proto == "https" else "off",
        "http_host": request.headers.get("host", request.url.netloc),
        "script_name": "",
        "server_port": request.url.port or (443 if forwarded_proto == "https" else 80),
        "get_data": dict(request.query_params),
        "post_data": {},
    }

def _get_saml_settings():
    """Load SAML settings from web_app/saml/ directory, with env-var overrides for IdP."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F811
    saml_dir = os.path.join(BASE_DIR, "saml")
    with open(os.path.join(saml_dir, "settings.json"), "r") as f:
        settings = json.load(f)
    with open(os.path.join(saml_dir, "advanced_settings.json"), "r") as f:
        advanced = json.load(f)

    # Allow env-var overrides for IdP settings so secrets stay out of files
    idp_entity = os.environ.get("SAML_IDP_ENTITY_ID")
    idp_sso_url = os.environ.get("SAML_IDP_SSO_URL")
    idp_cert = os.environ.get("SAML_IDP_CERT")
    if idp_entity:
        settings["idp"]["entityId"] = idp_entity
    if idp_sso_url:
        settings["idp"]["singleSignOnService"]["url"] = idp_sso_url
    if idp_cert:
        settings["idp"]["x509cert"] = idp_cert

    return settings, advanced, saml_dir

@app.get("/sso/metadata")
async def sso_metadata(request: Request):
    """Serve SP metadata XML. Use this URL as the Entity ID when configuring Duo."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    settings, advanced, saml_dir = _get_saml_settings()
    req = _prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_dir)
    metadata = auth.get_settings().get_sp_metadata()
    errors = auth.get_settings().validate_metadata(metadata)
    if errors:
        logger.error(f"SAML metadata validation errors: {errors}")
    return Response(content=metadata, media_type="application/xml")

@app.get("/sso/login")
async def sso_login(request: Request, next: Optional[str] = "/fmc-configuration"):
    """Initiate SAML AuthnRequest — redirects browser to Duo IdP."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    settings, advanced, saml_dir = _get_saml_settings()
    req = _prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_dir)
    redirect_url = auth.login(return_to=next or "/fmc-configuration")
    return RedirectResponse(url=redirect_url, status_code=303)

@app.post("/sso/acs")
async def sso_acs(request: Request):
    """Assertion Consumer Service — Duo posts the SAML response here."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    settings, advanced, saml_dir = _get_saml_settings()
    req = _prepare_saml_request(request)
    # python3-saml expects POST data in the request dict
    form_data = await request.form()
    req["post_data"] = dict(form_data)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_dir)
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        error_reason = auth.get_last_error_reason() or "; ".join(errors)
        logger.error(f"SAML ACS errors: {errors} — reason: {error_reason}")
        return RedirectResponse(
            url=f"/login?error={error_reason}",
            status_code=303,
        )

    # Successful authentication — extract user identity
    saml_attrs = auth.get_attributes()
    name_id = auth.get_nameid()
    # Use email/nameId as username; strip domain if present for display
    sso_username = name_id
    if "@" in sso_username:
        sso_username = sso_username.split("@")[0]

    logger.info(f"SSO login successful for: {name_id} (username={sso_username}), attrs={list(saml_attrs.keys())}")

    # Create session (same flow as local login)
    request.session["username"] = sso_username
    request.session["sid"] = request.session.get("sid") or str(uuid.uuid4())
    request.session["sso"] = True
    now = datetime.utcnow().isoformat() + "Z"
    active_sessions[request.session["sid"]] = {"username": sso_username, "login_time": now, "last_seen": now}
    record_activity(sso_username, "sso_login", {"idp": "duo", "name_id": name_id})

    # Redirect to the RelayState (return_to) or default
    relay_state = form_data.get("RelayState", "/fmc-configuration")
    if not relay_state or relay_state == auth.get_sso_url():
        relay_state = "/fmc-configuration"
    return RedirectResponse(url=relay_state, status_code=303)

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

# ── Dashboard Metrics API ──

@app.get("/api/dashboard/metrics")
async def dashboard_metrics(range: str = "1h"):
    """Key metrics: active users, RPM, error rate, avg response time."""
    try:
        return {"success": True, **dm.get_key_metrics(range)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/requests-timeseries")
async def dashboard_requests_ts(range: str = "1h"):
    """Bucketed request counts over time for charts."""
    try:
        return {"success": True, "data": dm.get_request_timeseries(range)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/users-timeseries")
async def dashboard_users_ts(range: str = "1h"):
    """Active user count over time for charts."""
    try:
        return {"success": True, "data": dm.get_user_activity_timeseries(range)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/system-health")
async def dashboard_system_health():
    """Current CPU, memory, disk, uptime, server status."""
    try:
        return {"success": True, **dm.get_system_health()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/system-timeseries")
async def dashboard_system_ts(range: str = "1h"):
    """CPU + memory over time for sparklines."""
    try:
        return {"success": True, "data": dm.get_system_timeseries(range)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/activities")
async def dashboard_activities(limit: int = 200, range: str = None):
    """Recent activities from persistent store, optionally filtered by time range."""
    try:
        return {"success": True, "activities": dm.get_recent_activities(limit, range_key=range)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/activity-timeseries")
async def dashboard_activity_timeseries(range: str = "1h"):
    """Time-bucketed activity counts grouped by user for line chart."""
    try:
        return {"success": True, **dm.get_activity_timeseries(range)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/dashboard/top-users")
async def dashboard_top_users(range: str = "1h"):
    """Top active users by action count."""
    try:
        return {"success": True, "users": dm.get_top_active_users(range)}
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

@app.post("/api/fmc-config/template-lookups")
async def fmc_template_lookups(payload: Dict[str, Any], http_request: Request):
    """Fetch access policies, device groups, platform settings policies, and resource profiles from FMC."""
    try:
        username = get_current_username(http_request)
        ctx = get_user_ctx(username)
        fmc_ip = payload.get("fmc_ip", "")
        fmc_username = payload.get("username", "")
        fmc_password = payload.get("password", "")
        domain_uuid = payload.get("domain_uuid", "") or ctx.get("fmc_auth", {}).get("domain_uuid", "")

        if not fmc_ip or not fmc_username or not fmc_password:
            return JSONResponse(status_code=400, content={"success": False, "message": "FMC connection details required"})

        # Always re-authenticate to avoid stale/expired tokens (401 errors)
        d_uuid, headers = authenticate(fmc_ip, fmc_username, fmc_password)
        if not domain_uuid:
            domain_uuid = d_uuid

        result = {}
        base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}"

        # Access Policies
        try:
            r = requests.get(f"{base}/policy/accesspolicies?limit=1000&expanded=false", headers=headers, verify=False)
            r.raise_for_status()
            result["accessPolicies"] = [{"id": i["id"], "name": i["name"]} for i in (r.json().get("items") or [])]
        except Exception as e:
            logger.warning(f"Template lookup - accesspolicies failed: {e}")
            result["accessPolicies"] = []

        # Device Groups
        try:
            r = requests.get(f"{base}/devicegroups/devicegrouprecords?limit=1000&expanded=false", headers=headers, verify=False)
            r.raise_for_status()
            result["deviceGroups"] = [{"id": i["id"], "name": i["name"]} for i in (r.json().get("items") or [])]
        except Exception as e:
            logger.warning(f"Template lookup - devicegroups failed: {e}")
            result["deviceGroups"] = []

        # Platform Settings Policies
        try:
            r = requests.get(f"{base}/policy/ftdplatformsettingspolicies?limit=1000&expanded=false", headers=headers, verify=False)
            r.raise_for_status()
            result["platformSettings"] = [{"id": i["id"], "name": i["name"]} for i in (r.json().get("items") or [])]
        except Exception as e:
            logger.warning(f"Template lookup - platformsettings failed: {e}")
            result["platformSettings"] = []

        # Resource Profiles
        try:
            r = requests.get(f"{base}/object/resourceprofiles?limit=1000&expanded=false", headers=headers, verify=False)
            r.raise_for_status()
            result["resourceProfiles"] = [{"id": i["id"], "name": i["name"]} for i in (r.json().get("items") or [])]
        except Exception as e:
            logger.warning(f"Template lookup - resourceprofiles failed: {e}")
            result["resourceProfiles"] = []

        # IKEv1 Policies
        try:
            r = requests.get(f"{base}/object/ikev1policies?limit=1000&expanded=true", headers=headers, verify=False)
            r.raise_for_status()
            result["ikev1Policies"] = (r.json().get("items") or [])
        except Exception as e:
            logger.warning(f"Template lookup - ikev1policies failed: {e}")
            result["ikev1Policies"] = []

        # IKEv2 Policies
        try:
            r = requests.get(f"{base}/object/ikev2policies?limit=1000&expanded=true", headers=headers, verify=False)
            r.raise_for_status()
            result["ikev2Policies"] = (r.json().get("items") or [])
        except Exception as e:
            logger.warning(f"Template lookup - ikev2policies failed: {e}")
            result["ikev2Policies"] = []

        # IKEv1 IPSec Proposals
        try:
            r = requests.get(f"{base}/object/ikev1ipsecproposals?limit=1000&expanded=true", headers=headers, verify=False)
            r.raise_for_status()
            result["ikev1IpsecProposals"] = (r.json().get("items") or [])
        except Exception as e:
            logger.warning(f"Template lookup - ikev1ipsecproposals failed: {e}")
            result["ikev1IpsecProposals"] = []

        # IKEv2 IPSec Proposals
        try:
            r = requests.get(f"{base}/object/ikev2ipsecproposals?limit=1000&expanded=true", headers=headers, verify=False)
            r.raise_for_status()
            result["ikev2IpsecProposals"] = (r.json().get("items") or [])
        except Exception as e:
            logger.warning(f"Template lookup - ikev2ipsecproposals failed: {e}")
            result["ikev2IpsecProposals"] = []

        result["success"] = True
        return result
    except Exception as e:
        logger.error(f"Template lookups failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/fmc-config/template-resource-profile")
async def fmc_create_resource_profile(payload: Dict[str, Any], http_request: Request):
    """Create a resource profile on FMC via POST /object/resourceprofiles."""
    try:
        fmc_ip = payload.get("fmc_ip", "")
        fmc_username = payload.get("username", "")
        fmc_password = payload.get("password", "")
        domain_uuid = payload.get("domain_uuid", "")
        name = payload.get("name", "")
        description = payload.get("description", "")
        cpu_cores = payload.get("cpuCoreCount", 6)

        if not fmc_ip or not fmc_username or not fmc_password:
            return JSONResponse(status_code=400, content={"success": False, "message": "FMC connection details required"})
        if not name:
            return JSONResponse(status_code=400, content={"success": False, "message": "Profile name is required"})

        d_uuid, headers = authenticate(fmc_ip, fmc_username, fmc_password)
        if not domain_uuid:
            domain_uuid = d_uuid

        body = {"type": "ResourceProfile", "name": name, "cpuCoreCount": cpu_cores}
        if description:
            body["description"] = description

        r = requests.post(
            f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/resourceprofiles",
            headers=headers, json=body, verify=False
        )
        r.raise_for_status()
        created = r.json()
        return {"success": True, "id": created.get("id"), "name": created.get("name")}
    except Exception as e:
        logger.error(f"Create resource profile failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


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
        _apply_debug_flag(payload)

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

# ---------------- HA Pair Creation ----------------

@app.post("/api/fmc-config/ha/create")
async def fmc_ha_create(payload: Dict[str, Any], http_request: Request):
    """Create FTD HA pairs on FMC.
    Expects: { fmc_ip, username, password, domain_uuid (optional), pairs: [ { name, primary_device, secondary_device, failover_link: {...}, stateful_failover_link: {...}, encryption: {...} } ] }
    """
    try:
        username = get_current_username(http_request)
        reset_progress(username)
        _start_user_operation(username, "ha-create")
        _attach_user_log_handlers(username)
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _create_ha_pairs_sync(payload))
        _finish_user_operation(username, bool(result.get("success", False)), result.get("message", "HA create completed"))
        return result
    except InterruptedError:
        try:
            _finish_user_operation(username, False, "Operation stopped by user")
        except Exception:
            pass
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"FMC HA create error: {e}")
        try:
            _finish_user_operation(username, False, f"HA create error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


def _create_ha_pairs_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronously create HA pairs against FMC, one at a time."""
    _apply_debug_flag(payload)
    fmc_ip = (payload.get("fmc_ip") or "").strip()
    fmc_username = (payload.get("username") or "").strip()
    fmc_password = payload.get("password") or ""
    pairs_data: List[Dict] = payload.get("pairs") or []
    app_username = payload.get("app_username", "")

    if not fmc_ip or not fmc_username or not fmc_password:
        return {"success": False, "message": "Missing fmc_ip, username, or password"}
    if not pairs_data:
        return {"success": False, "message": "No HA pairs provided"}

    # Authenticate
    logger.info(f"Authenticating to FMC {fmc_ip} for HA pair creation...")
    domain_uuid_sel = (payload.get("domain_uuid") or "").strip()
    auth_domain, headers = authenticate(fmc_ip, fmc_username, fmc_password)
    domain_uuid = domain_uuid_sel or auth_domain

    # Resolve device names → UUIDs
    logger.info("Resolving device names to UUIDs...")
    device_cache = {}  # name → uuid
    all_devices_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords?limit=1000"
    try:
        resp = fmc.fmc_get(all_devices_url)
        if resp.status_code == 200:
            for d in resp.json().get("items", []):
                device_cache[d.get("name", "")] = d.get("id", "")
    except Exception as ex:
        logger.warning(f"Failed to fetch device records: {ex}")

    # Helper: resolve interface name → { id, name, type } on a device
    # Caches per device UUID to avoid redundant API calls
    intf_cache = {}  # device_uuid → { intf_name → { id, name, type } }

    def _resolve_interface(dev_uuid, dev_name, intf_name):
        """Look up an interface by hardware name on a device, return interfaceObject dict or None."""
        if dev_uuid not in intf_cache:
            logger.info(f"  Fetching all interfaces for {dev_name} ({dev_uuid})...")
            intf_map = {}
            try:
                base_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{dev_uuid}/ftdallinterfaces"
                offset = 0
                limit = 1000
                while True:
                    url = f"{base_url}?expanded=true&offset={offset}&limit={limit}"
                    resp = fmc.fmc_get(url)
                    if resp.status_code != 200:
                        break
                    data = resp.json()
                    items = data.get("items", [])
                    for it in items:
                        hw_name = it.get("name", "")
                        if hw_name:
                            intf_map[hw_name] = {
                                "id": it.get("id", ""),
                                "name": hw_name,
                                "type": it.get("type", "PhysicalInterface"),
                            }
                    paging = data.get("paging", {})
                    total = paging.get("count", 0)
                    offset += len(items)
                    if offset >= total or not items:
                        break
            except Exception as ex:
                logger.warning(f"  Failed to fetch ftdallinterfaces for {dev_name}: {ex}")
            # ftdallinterfaces doesn't return subinterfaces — fetch them separately
            try:
                sub_base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{dev_uuid}/subinterfaces"
                offset = 0
                limit = 1000
                while True:
                    sub_url = f"{sub_base}?expanded=true&offset={offset}&limit={limit}"
                    sub_resp = fmc.fmc_get(sub_url)
                    if sub_resp.status_code != 200:
                        break
                    data = sub_resp.json()
                    items = data.get("items", [])
                    for it in items:
                        parent_name = it.get("name", "")
                        sub_id = it.get("subIntfId")
                        if parent_name and sub_id is not None:
                            full_name = f"{parent_name}.{sub_id}"
                            intf_map[full_name] = {
                                "id": it.get("id", ""),
                                "name": full_name,
                                "type": it.get("type", "SubInterface"),
                            }
                    paging = data.get("paging", {})
                    total = paging.get("count", 0)
                    offset += len(items)
                    if offset >= total or not items:
                        break
            except Exception as ex:
                logger.warning(f"  Failed to fetch subinterfaces for {dev_name}: {ex}")
            intf_cache[dev_uuid] = intf_map
            logger.info(f"  Found {len(intf_map)} interface(s) on {dev_name}: {list(intf_map.keys())}")
        return intf_cache[dev_uuid].get(intf_name)

    results = []
    created = 0
    errors = []

    for i, pair in enumerate(pairs_data):
        _check_stop_requested(app_username)
        pair_name = pair.get("name", f"HA-pair-{i+1}")
        # Frontend now sends API-matching keys: primary.id, secondary.id (device names)
        primary_name = (pair.get("primary") or {}).get("id", "")
        secondary_name = (pair.get("secondary") or {}).get("id", "")
        logger.info(f"━━━ HA Pair {i+1}/{len(pairs_data)}: {pair_name} ━━━")
        logger.info(f"  Primary:   {primary_name}")
        logger.info(f"  Secondary: {secondary_name}")

        primary_id = device_cache.get(primary_name)
        secondary_id = device_cache.get(secondary_name)

        if not primary_id:
            msg = f"Cannot find device UUID for primary '{primary_name}'"
            logger.error(f"  ✗ {msg}")
            errors.append(msg)
            results.append({"pair": pair_name, "success": False, "error": msg})
            continue
        if not secondary_id:
            msg = f"Cannot find device UUID for secondary '{secondary_name}'"
            logger.error(f"  ✗ {msg}")
            errors.append(msg)
            results.append({"pair": pair_name, "success": False, "error": msg})
            continue

        # Read ftdHABootstrap from frontend (already in API format)
        bootstrap = pair.get("ftdHABootstrap", {})
        lan_fo = bootstrap.get("lanFailover", {})
        st_fo = bootstrap.get("statefulFailover", {})

        # Resolve interface objects on the primary device (frontend sends name only)
        fo_intf_name = (lan_fo.get("interfaceObject") or {}).get("name", "")
        st_intf_name = (st_fo.get("interfaceObject") or {}).get("name", "")
        fo_intf_obj = _resolve_interface(primary_id, primary_name, fo_intf_name)
        st_intf_obj = _resolve_interface(primary_id, primary_name, st_intf_name) if st_intf_name != fo_intf_name else fo_intf_obj

        if not fo_intf_obj:
            msg = f"Cannot find failover interface '{fo_intf_name}' on device '{primary_name}'"
            logger.error(f"  ✗ {msg}")
            errors.append(msg)
            results.append({"pair": pair_name, "success": False, "error": msg})
            continue
        if not st_intf_obj:
            msg = f"Cannot find stateful interface '{st_intf_name}' on device '{primary_name}'"
            logger.error(f"  ✗ {msg}")
            errors.append(msg)
            results.append({"pair": pair_name, "success": False, "error": msg})
            continue

        # Build final lanFailover with resolved interfaceObject (id, name, type)
        lan_failover = dict(lan_fo)
        lan_failover["interfaceObject"] = fo_intf_obj

        stateful_failover = dict(st_fo)
        stateful_failover["interfaceObject"] = st_intf_obj

        fmc_payload = {
            "name": pair_name,
            "type": "DeviceHAPair",
            "primary": {"id": primary_id, "type": "Device", "name": primary_name},
            "secondary": {"id": secondary_id, "type": "Device", "name": secondary_name},
            "ftdHABootstrap": {
                "isEncryptionEnabled": bootstrap.get("isEncryptionEnabled", False),
                "lanFailover": lan_failover,
                "statefulFailover": stateful_failover,
                "useSameLinkForFailovers": bootstrap.get("useSameLinkForFailovers", False),
            },
        }

        # Encryption fields
        if bootstrap.get("encKeyGenerationScheme"):
            fmc_payload["ftdHABootstrap"]["encKeyGenerationScheme"] = bootstrap["encKeyGenerationScheme"]
        if bootstrap.get("sharedKey"):
            fmc_payload["ftdHABootstrap"]["sharedKey"] = bootstrap["sharedKey"]

        logger.info(f"  Failover link: {fo_intf_name} (id={fo_intf_obj['id'][:8]}...) | Active: {lan_fo.get('activeIP', '')} / Standby: {lan_fo.get('standbyIP', '')}")
        logger.info(f"  Stateful link: {st_intf_name} (id={st_intf_obj['id'][:8]}...) | Active: {st_fo.get('activeIP', '')} / Standby: {st_fo.get('standbyIP', '')}")
        enc_status = 'enabled' if bootstrap.get("isEncryptionEnabled") else 'disabled'
        logger.info(f"  Encryption: {enc_status} | Same link: {bootstrap.get('useSameLinkForFailovers', False)}")

        try:
            result = post_ftd_ha_pair(fmc_ip, headers, domain_uuid, fmc_payload)
            ha_id = result.get("id", "N/A")
            logger.info(f"  ✓ Created HA pair: {pair_name} (id={ha_id})")
            results.append({"pair": pair_name, "success": True, "id": ha_id})
            created += 1
        except Exception as ex:
            msg = str(ex)
            logger.error(f"  ✗ Failed to create HA pair {pair_name}: {msg}")
            errors.append(f"{pair_name}: {msg}")
            results.append({"pair": pair_name, "success": False, "error": msg})

    logger.info(f"━━━ HA Creation Summary: {created}/{len(pairs_data)} pair(s) created successfully ━━━")
    if errors:
        logger.warning(f"Errors: {len(errors)}")

    return {
        "success": created > 0 or len(errors) == 0,
        "message": f"Created {created}/{len(pairs_data)} HA pair(s)" + (f" ({len(errors)} error(s))" if errors else ""),
        "created": created,
        "total": len(pairs_data),
        "results": results,
        "errors": errors,
    }

# ---------------- Device Configuration (Upload / Schema Downloads / Apply) ----------------

@app.get("/api/fmc-config/schema/components")
async def fmc_schema_components():
    """Download the components.schemas section from merged_oas3_examples_rag.jsonl as JSON (if present)."""
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        jsonl_path = os.path.join(project_root, "utils", "merged_oas3_examples_rag.jsonl")
        if not os.path.exists(jsonl_path):
            return JSONResponse(status_code=404, content={"success": False, "message": "Merged RAG JSONL file not found"})
        schemas = {}
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("type") == "component_schema":
                    name = entry.get("metadata", {}).get("name", "")
                    if name and entry.get("json"):
                        schemas[name] = entry["json"]

        if not schemas:
            return JSONResponse(status_code=404, content={
                "success": False,
                "message": "No component schema entries found in merged RAG JSONL file"
            })

        content = json.dumps(schemas, indent=2)
        return StreamingResponse(io.StringIO(content), media_type="application/json", headers={
            "Content-Disposition": "attachment; filename=fmc_components_schemas.json"
        })
    except Exception as e:
        logger.error(f"Failed to read components.schemas from merged JSONL: {e}")
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
        data = _yaml_safe_load(raw) or {}
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
        data = _yaml_safe_load(raw) or {}

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
                    "routeBased": bool(t.get("routeBased")) if isinstance(t.get("routeBased"), (bool, str, int)) else None,
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
        _start_user_operation(username, "vpn-apply")
        _attach_user_log_handlers(username)
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _vpn_apply_sync(payload))
        _finish_user_operation(username, bool(result.get("success", False)), result.get("message", "VPN apply completed"))
        return result
    except Exception as e:
        logger.error(f"VPN apply error: {e}")
        try:
            _finish_user_operation(username, False, f"VPN apply error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _vpn_apply_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    _apply_debug_flag(payload)
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username
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
        
        # Track all topologies for comprehensive summary table
        topology_summary: List[Dict[str, Any]] = []

        # Build caches to avoid repeated lookups across all topologies
        device_uuid_cache: Dict[str, Tuple[str, str]] = {}  # device_name -> (container_uuid, device_type)
        actual_device_uuid_cache: Dict[str, str] = {}  # container_uuid -> actual_device_uuid (for HA/clusters)
        iface_cache: Dict[str, List[Dict[str, Any]]] = {}  # device_uuid -> interface list

        def _get_device_uuid_by_name(dev_name: str) -> Optional[str]:
            dn = (dev_name or "").strip()
            if not dn:
                return None
            if dn in device_uuid_cache:
                return device_uuid_cache[dn][0]  # Return just the UUID
            try:
                du, dt = get_device_info(fmc_ip, headers, domain_uuid, dn)
                device_uuid_cache[dn] = (du, dt)  # Cache both UUID and type
                logger.info(f"[VPN] Resolved device '{dn}': UUID={du}, Type={dt}")
                return du
            except Exception as ex:
                logger.warning(f"[VPN] Failed to resolve device UUID for '{dn}': {ex}")
                return None

        def _get_actual_device_uuid(container_uuid: str, dev_type: str) -> str:
            """Get actual device UUID for HA pairs/clusters, with caching."""
            if not container_uuid:
                return container_uuid
            cache_key = container_uuid
            if cache_key in actual_device_uuid_cache:
                cached = actual_device_uuid_cache[cache_key]
                logger.info(f"[VPN] Using cached actual device UUID: {cached} for {container_uuid}")
                return cached
            actual_uuid = fmc.get_device_uuid_for_interfaces(fmc_ip, headers, domain_uuid, container_uuid, dev_type)
            actual_device_uuid_cache[cache_key] = actual_uuid
            return actual_uuid

        def _load_ifaces_for_device(dev_uuid: str, dev_type: str = "Device") -> List[Dict[str, Any]]:
            if not dev_uuid:
                return []
            if dev_uuid in iface_cache:
                logger.info(f"[VPN] Using cached interfaces for device {dev_uuid} ({len(iface_cache[dev_uuid])} interfaces)")
                return iface_cache[dev_uuid]
            try:
                items = fmc.get_all_interfaces(fmc_ip, headers, domain_uuid, dev_uuid, dev_type) or []
                iface_cache[dev_uuid] = items
                logger.info(f"[VPN] Loaded {len(items)} interfaces for device {dev_uuid}")
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

        # Fetch IKE policies and IPSec proposals for reference resolution (both IKEv1 and IKEv2)
        _check_stop_requested(app_username)
        logger.info("[VPN] Fetching IKEv1 and IKEv2 policies and IPSec proposals for reference resolution...")
        ikev2_policies = get_ikev2_policies(fmc_ip, headers, domain_uuid)
        ikev2_ipsec_proposals = get_ikev2_ipsec_proposals(fmc_ip, headers, domain_uuid)
        ikev1_policies = fmc.get_ikev1_policies(fmc_ip, headers, domain_uuid)
        ikev1_ipsec_proposals = fmc.get_ikev1_ipsec_proposals(fmc_ip, headers, domain_uuid)

        def _extract_error_description(response) -> str:
            """Extract error description from FMC API error response."""
            if not response:
                return "No response received"
            try:
                error_json = response.json() if response.text else {}
                error_obj = error_json.get("error", {})
                messages = error_obj.get("messages", [])
                if messages and isinstance(messages, list) and len(messages) > 0:
                    return messages[0].get("description", "Unknown error")
                return response.text if response.text else "No response body"
            except Exception:
                return response.text if response.text else "No response body"

        def _resolve_vpn_policy_references(settings_obj: Dict[str, Any]) -> None:
            """
            Resolve IKE policy and IPSec proposal references by name, adding 'id' field.
            If a policy/proposal doesn't exist, create it from the YAML data.
            Modifies settings_obj in place.
            """
            # Resolve IKE policies in ikeSettings
            ike_settings = settings_obj.get("ikeSettings")
            if isinstance(ike_settings, list):
                for ike_setting in ike_settings:
                    if not isinstance(ike_setting, dict):
                        continue
                    # Check ikeV2Settings -> policies
                    ikev2_settings = ike_setting.get("ikeV2Settings")
                    if isinstance(ikev2_settings, dict):
                        policies = ikev2_settings.get("policies")
                        if isinstance(policies, list):
                            for policy in policies:
                                if isinstance(policy, dict):
                                    policy_name = policy.get("name")
                                    if not policy_name:
                                        continue
                                    
                                    # Check if policy exists
                                    if policy_name in ikev2_policies:
                                        policy_id = ikev2_policies[policy_name].get("id")
                                        if policy_id:
                                            policy["id"] = policy_id
                                            logger.info(f"[VPN] Resolved IKEv2 policy '{policy_name}' -> {policy_id}")
                                        else:
                                            logger.warning(f"[VPN] IKEv2 policy '{policy_name}' found but has no id")
                                    else:
                                        # Policy doesn't exist, create it
                                        try:
                                            logger.info(f"[VPN] IKEv2 policy '{policy_name}' not found, creating it...")
                                            created_policy = post_ikev2_policy(fmc_ip, headers, domain_uuid, policy)
                                            policy_id = created_policy.get("id")
                                            if policy_id:
                                                policy["id"] = policy_id
                                                ikev2_policies[policy_name] = created_policy  # Cache it
                                                logger.info(f"[VPN] Created IKEv2 policy '{policy_name}' -> {policy_id}")
                                            else:
                                                logger.warning(f"[VPN] Created IKEv2 policy '{policy_name}' but got no id")
                                        except Exception as ex:
                                            logger.error(f"[VPN] Failed to create IKEv2 policy '{policy_name}': {ex}")
                    
                    # Check ikeV1Settings -> policies
                    ikev1_settings = ike_setting.get("ikeV1Settings")
                    if isinstance(ikev1_settings, dict):
                        policies = ikev1_settings.get("policies")
                        if isinstance(policies, list):
                            for policy in policies:
                                if isinstance(policy, dict):
                                    policy_name = policy.get("name")
                                    if not policy_name:
                                        continue
                                    
                                    # Check if policy exists
                                    if policy_name in ikev1_policies:
                                        policy_id = ikev1_policies[policy_name].get("id")
                                        if policy_id:
                                            policy["id"] = policy_id
                                            logger.info(f"[VPN] Resolved IKEv1 policy '{policy_name}' -> {policy_id}")
                                        else:
                                            logger.warning(f"[VPN] IKEv1 policy '{policy_name}' found but has no id")
                                    else:
                                        # Policy doesn't exist, create it
                                        try:
                                            logger.info(f"[VPN] IKEv1 policy '{policy_name}' not found, creating it...")
                                            created_policy = fmc.post_ikev1_policy(fmc_ip, headers, domain_uuid, policy)
                                            policy_id = created_policy.get("id")
                                            if policy_id:
                                                policy["id"] = policy_id
                                                ikev1_policies[policy_name] = created_policy  # Cache it
                                                logger.info(f"[VPN] Created IKEv1 policy '{policy_name}' -> {policy_id}")
                                            else:
                                                logger.warning(f"[VPN] Created IKEv1 policy '{policy_name}' but got no id")
                                        except Exception as ex:
                                            logger.error(f"[VPN] Failed to create IKEv1 policy '{policy_name}': {ex}")
            
            # Resolve IPSec proposals in ipsecSettings
            ipsec_settings = settings_obj.get("ipsecSettings")
            if isinstance(ipsec_settings, list):
                for ipsec_setting in ipsec_settings:
                    if not isinstance(ipsec_setting, dict):
                        continue
                    # Check ikeV2IpsecProposal
                    proposals = ipsec_setting.get("ikeV2IpsecProposal")
                    if isinstance(proposals, list):
                        for proposal in proposals:
                            if isinstance(proposal, dict):
                                proposal_name = proposal.get("name")
                                if not proposal_name:
                                    continue
                                
                                # Check if proposal exists
                                if proposal_name in ikev2_ipsec_proposals:
                                    proposal_id = ikev2_ipsec_proposals[proposal_name].get("id")
                                    if proposal_id:
                                        proposal["id"] = proposal_id
                                        logger.info(f"[VPN] Resolved IKEv2 IPSec proposal '{proposal_name}' -> {proposal_id}")
                                    else:
                                        logger.warning(f"[VPN] IKEv2 IPSec proposal '{proposal_name}' found but has no id")
                                else:
                                    # Proposal doesn't exist, create it
                                    try:
                                        logger.info(f"[VPN] IKEv2 IPSec proposal '{proposal_name}' not found, creating it...")
                                        created_proposal = post_ikev2_ipsec_proposal(fmc_ip, headers, domain_uuid, proposal)
                                        proposal_id = created_proposal.get("id")
                                        if proposal_id:
                                            proposal["id"] = proposal_id
                                            ikev2_ipsec_proposals[proposal_name] = created_proposal  # Cache it
                                            logger.info(f"[VPN] Created IKEv2 IPSec proposal '{proposal_name}' -> {proposal_id}")
                                        else:
                                            logger.warning(f"[VPN] Created IKEv2 IPSec proposal '{proposal_name}' but got no id")
                                    except Exception as ex:
                                        logger.error(f"[VPN] Failed to create IKEv2 IPSec proposal '{proposal_name}': {ex}")
                    
                    # Check ikeV1IpsecProposal
                    proposals_v1 = ipsec_setting.get("ikeV1IpsecProposal")
                    if isinstance(proposals_v1, list):
                        for proposal in proposals_v1:
                            if isinstance(proposal, dict):
                                proposal_name = proposal.get("name")
                                if not proposal_name:
                                    continue
                                
                                # Check if proposal exists
                                if proposal_name in ikev1_ipsec_proposals:
                                    proposal_id = ikev1_ipsec_proposals[proposal_name].get("id")
                                    if proposal_id:
                                        proposal["id"] = proposal_id
                                        logger.info(f"[VPN] Resolved IKEv1 IPSec proposal '{proposal_name}' -> {proposal_id}")
                                    else:
                                        logger.warning(f"[VPN] IKEv1 IPSec proposal '{proposal_name}' found but has no id")
                                else:
                                    # Proposal doesn't exist, create it
                                    try:
                                        logger.info(f"[VPN] IKEv1 IPSec proposal '{proposal_name}' not found, creating it...")
                                        created_proposal = fmc.post_ikev1_ipsec_proposal(fmc_ip, headers, domain_uuid, proposal)
                                        proposal_id = created_proposal.get("id")
                                        if proposal_id:
                                            proposal["id"] = proposal_id
                                            ikev1_ipsec_proposals[proposal_name] = created_proposal  # Cache it
                                            logger.info(f"[VPN] Created IKEv1 IPSec proposal '{proposal_name}' -> {proposal_id}")
                                        else:
                                            logger.warning(f"[VPN] Created IKEv1 IPSec proposal '{proposal_name}' but got no id")
                                    except Exception as ex:
                                        logger.error(f"[VPN] Failed to create IKEv1 IPSec proposal '{proposal_name}': {ex}")

        def _resolve_protected_network_objects(topology_obj: Dict[str, Any]) -> None:
            """
            Resolve protectedNetworks objects by name, creating them if they don't exist.
            First checks the 'objects' section of the topology for the full object definitions.
            Modifies topology_obj in place.
            """
            try:
                # Fetch all existing network and accesslist objects from FMC
                logger.info("[VPN] Fetching network and access list objects for protectedNetworks resolution...")
                network_objects = get_all_network_objects(fmc_ip, headers, domain_uuid)
                accesslist_objects = get_all_accesslist_objects(fmc_ip, headers, domain_uuid)
            except Exception as ex:
                logger.error(f"[VPN] Failed to fetch network/access list objects from FMC: {ex}")
                return
            
            # Get objects defined in the topology YAML (if any)
            topology_objects = topology_obj.get("objects", {})
            topology_networks = {obj.get("name"): obj for obj in topology_objects.get("networks", []) if isinstance(obj, dict) and obj.get("name")}
            topology_accesslists = {obj.get("name"): obj for obj in topology_objects.get("accesslists", []) if isinstance(obj, dict) and obj.get("name")}
            
            # Process endpoints
            endpoints = topology_obj.get("endpoints")
            if not isinstance(endpoints, list):
                return
            
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    continue
                
                protected_networks = endpoint.get("protectedNetworks")
                if not protected_networks or not isinstance(protected_networks, dict):
                    continue
                
                # Process networks
                networks = protected_networks.get("networks", [])
                if isinstance(networks, list):
                    for net in networks:
                        if not isinstance(net, dict):
                            continue
                        
                        net_name = net.get("name")
                        if not net_name:
                            continue
                        
                        # Check if network exists in FMC
                        if net_name in network_objects:
                            net_id = network_objects[net_name].get("id")
                            if net_id:
                                net["id"] = net_id
                                logger.info(f"[VPN] Resolved network '{net_name}' -> {net_id}")
                            else:
                                logger.warning(f"[VPN] Network '{net_name}' found but has no id")
                        else:
                            # Network doesn't exist, check if we have it in topology objects
                            if net_name in topology_networks:
                                try:
                                    logger.info(f"[VPN] Network '{net_name}' not found in FMC, creating from topology objects...")
                                    full_obj = dict(topology_networks[net_name])
                                    # Remove metadata fields
                                    for k in ("id", "links", "metadata"):
                                        full_obj.pop(k, None)
                                    full_obj.setdefault("type", "Network")
                                    
                                    created_net = post_network_object(fmc_ip, headers, domain_uuid, full_obj)
                                    net_id = created_net.get("id")
                                    if net_id:
                                        net["id"] = net_id
                                        network_objects[net_name] = created_net  # Cache it
                                        logger.info(f"[VPN] Created network '{net_name}' -> {net_id}")
                                    else:
                                        logger.warning(f"[VPN] Created network '{net_name}' but got no id")
                                except Exception as ex:
                                    logger.error(f"[VPN] Failed to create network '{net_name}': {ex}")
                            else:
                                logger.warning(f"[VPN] Network '{net_name}' not found in FMC or topology objects")
                
                # Process access lists
                accesslists = protected_networks.get("accessLists", [])
                if isinstance(accesslists, list):
                    for acl in accesslists:
                        if not isinstance(acl, dict):
                            continue
                        
                        acl_name = acl.get("name")
                        if not acl_name:
                            continue
                        
                        # Check if access list exists in FMC
                        if acl_name in accesslist_objects:
                            acl_id = accesslist_objects[acl_name].get("id")
                            if acl_id:
                                acl["id"] = acl_id
                                logger.info(f"[VPN] Resolved access list '{acl_name}' -> {acl_id}")
                            else:
                                logger.warning(f"[VPN] Access list '{acl_name}' found but has no id")
                        else:
                            # Access list doesn't exist, check if we have it in topology objects
                            if acl_name in topology_accesslists:
                                try:
                                    logger.info(f"[VPN] Access list '{acl_name}' not found in FMC, creating from topology objects...")
                                    full_obj = dict(topology_accesslists[acl_name])
                                    # Remove metadata fields
                                    for k in ("id", "links", "metadata"):
                                        full_obj.pop(k, None)
                                    full_obj.setdefault("type", "ExtendedAccessList")
                                    
                                    created_acl = post_accesslist_object(fmc_ip, headers, domain_uuid, full_obj)
                                    acl_id = created_acl.get("id")
                                    if acl_id:
                                        acl["id"] = acl_id
                                        accesslist_objects[acl_name] = created_acl  # Cache it
                                        logger.info(f"[VPN] Created access list '{acl_name}' -> {acl_id}")
                                    else:
                                        logger.warning(f"[VPN] Created access list '{acl_name}' but got no id")
                                except Exception as ex:
                                    logger.error(f"[VPN] Failed to create access list '{acl_name}': {ex}")
                            else:
                                logger.warning(f"[VPN] Access list '{acl_name}' not found in FMC or topology objects")

        def _sanitize(d: Dict[str, Any]) -> Dict[str, Any]:
            body = dict(d or {})
            for k in ("id", "links", "metadata"):
                body.pop(k, None)
            # Remove non-summary sections that should not be sent in topology POST body
            for k in ("endpoints", "ikeSettings", "ipsecSettings", "advancedSettings", "autoVpnSettings", "objects"):
                body.pop(k, None)
            return body

        for raw_tp in topo_list:
            _check_stop_requested(app_username)
            # Unwrap React UI wrapper format: the upload endpoint returns
            # {name, type, topologyType, routeBased, peers, raw} where "raw"
            # contains the actual YAML topology dict with endpoints/settings.
            # If we detect this wrapper format, use the inner "raw" dict.
            if (isinstance(raw_tp, dict) and "raw" in raw_tp
                    and isinstance(raw_tp.get("raw"), dict)
                    and "peers" in raw_tp
                    and "endpoints" not in raw_tp):
                raw_tp = raw_tp["raw"]

            # Extract topology info for tracking (do this first, before any processing)
            topo_name = "Unknown"
            topo_type = "Unknown"
            topo_subtype = "Unknown"
            peer_count = 0
            
            # Track operation statuses for this topology
            status_tracker = {
                "name": topo_name,
                "type": topo_type,
                "subtype": topo_subtype,
                "peers": 0,
                "objects": "SKIPPED",
                "endpoints": "SKIPPED",
                "ike_settings": "SKIPPED",
                "ipsec_settings": "SKIPPED",
                "advanced_settings": "SKIPPED",
                "description": "",
                "error_details": []  # Track errors from each phase
            }
            
            try:
                if isinstance(raw_tp, dict):
                    if "summary" in raw_tp:
                        summary = raw_tp.get("summary", {})
                        topo_name = summary.get("name", "Unknown")
                        topo_type = summary.get("type", "FTDS2SVpn")
                        topo_subtype = summary.get("topologyType", "Unknown")
                    else:
                        topo_name = raw_tp.get("name", "Unknown")
                        topo_type = raw_tp.get("type", "FTDS2SVpn")
                        topo_subtype = raw_tp.get("topologyType", "Unknown")
                    
                    # Count peers from endpoints
                    eps = raw_tp.get("endpoints")
                    if isinstance(eps, list):
                        peer_count = len(eps)
                    elif isinstance(eps, dict) and isinstance(eps.get("items"), list):
                        peer_count = len(eps.get("items", []))
                    
                    # Update tracker with actual values
                    status_tracker["name"] = topo_name
                    status_tracker["type"] = topo_type
                    status_tracker["subtype"] = topo_subtype
                    status_tracker["peers"] = peer_count
            except Exception:
                pass
            
            try:
                # Resolve IKE policy and IPSec proposal references before processing
                if isinstance(raw_tp, dict):
                    _resolve_vpn_policy_references(raw_tp)
                    
                    # Track objects resolution
                    if raw_tp.get("objects") or any(
                        ep.get("protectedNetworks") 
                        for ep in (raw_tp.get("endpoints") or []) 
                        if isinstance(ep, dict)
                    ):
                        try:
                            _resolve_protected_network_objects(raw_tp)
                            status_tracker["objects"] = "SUCCESS"
                        except Exception as obj_ex:
                            status_tracker["objects"] = "FAILED"
                            error_msg = f"Objects: {str(obj_ex)}"
                            status_tracker["error_details"].append(error_msg)
                            logger.warning(f"[VPN] Objects resolution failed: {obj_ex}")
                    else:
                        status_tracker["objects"] = "SKIPPED"
                
                endpoints = []
                tp_body = {}
                if isinstance(raw_tp, dict) and ("summary" in raw_tp):
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
                        elif isinstance(eps, dict) and isinstance(eps.get("items"), list):
                            endpoints = eps.get("items")
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
                        # Log response description
                        tp_name = created_tp.get("name", "Unknown")
                        tp_type = created_tp.get("type", "Unknown")
                        logger.info(f"[VPN] POST Topology Response: name='{tp_name}', type={tp_type}, id={vpn_id}")
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
                                    error_desc = f"Existing topology '{name}' not found when resolving ID after create error: {create_ex}"
                                    errors.append(error_desc)
                                    status_tracker["description"] = error_desc
                                    topology_summary.append(status_tracker)
                                    continue
                            except Exception as resolve_ex:
                                error_desc = f"Failed to resolve existing topology '{name}': {resolve_ex}"
                                errors.append(error_desc)
                                status_tracker["description"] = error_desc
                                topology_summary.append(status_tracker)
                                continue
                        else:
                            error_desc = f"Topology create failed: {create_ex}"
                            errors.append(error_desc)
                            status_tracker["description"] = error_desc
                            topology_summary.append(status_tracker)
                            continue

                # Resolve placeholder UUIDs after topology creation and before settings/endpoints are applied
                if vpn_id:
                    try:
                        # Update endpoint placeholders (using caches defined at outer scope)
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
                                    
                                    # Always resolve device UUID by name from destination FMC
                                    # (UUIDs differ between FMCs, so we must resolve by name)
                                    dev_type = "Device"  # Default
                                    if dev_name:
                                        dev_uuid = _get_device_uuid_by_name(dev_name)
                                        if dev_uuid and isinstance(dev, dict):
                                            # Get the device type from cache
                                            container_uuid = dev_uuid
                                            if dev_name in device_uuid_cache:
                                                dev_type = device_uuid_cache[dev_name][1]
                                            
                                            # For HA pairs and clusters, use primary/control device UUID in endpoint payload
                                            if dev_type in ("DeviceHAPair", "DeviceCluster"):
                                                actual_dev_uuid = _get_actual_device_uuid(dev_uuid, dev_type)
                                                dev["id"] = actual_dev_uuid
                                                dev["type"] = "Device"  # Primary/control device is always type "Device"
                                                dev_uuid = actual_dev_uuid  # Use actual device UUID for interface loading
                                                logger.info(f"[VPN] Resolved device '{dev_name}' ({dev_type}) -> using primary/control device UUID: {actual_dev_uuid}")
                                            else:
                                                dev["id"] = dev_uuid
                                                dev["type"] = dev_type
                                                logger.info(f"[VPN] Resolved device '{dev_name}' -> UUID: {dev_uuid}, Type: {dev_type}")
                                    
                                    # Load interfaces for this device (use resolved actual device UUID for HA/clusters)
                                    iface_items = _load_ifaces_for_device(dev_uuid, "Device") if dev_uuid else []

                                    # interface - always resolve by name from destination FMC
                                    iface = ep.get("interface") if isinstance(ep, dict) else None
                                    if isinstance(iface, dict):
                                        iname = iface.get("name")
                                        itype = iface.get("type")
                                        if iname:
                                            iid = _match_iface_id(iface_items, itype, iname)
                                            if iid:
                                                iface["id"] = iid
                                                logger.info(f"[VPN] Resolved interface UUID for '{iname}' ({itype}) on device '{dev_name}' -> {iid}")

                                    # tunnelSourceInterface - always resolve by name from destination FMC
                                    ts = ep.get("tunnelSourceInterface") if isinstance(ep, dict) else None
                                    if isinstance(ts, dict):
                                        tname = ts.get("name")
                                        ttype = ts.get("type")
                                        if tname:
                                            tid = _match_iface_id(iface_items, ttype, tname)
                                            if tid:
                                                ts["id"] = tid
                                                logger.info(f"[VPN] Resolved tunnel source UUID for '{tname}' ({ttype}) on device '{dev_name}' -> {tid}")
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

                def _strip_metadata_and_links(obj: Any) -> Any:
                    """Recursively strip metadata and links fields from objects."""
                    if isinstance(obj, dict):
                        return {k: _strip_metadata_and_links(v) for k, v in obj.items() if k not in ("metadata", "links")}
                    elif isinstance(obj, list):
                        return [_strip_metadata_and_links(item) for item in obj]
                    return obj

                if vpn_id and isinstance(raw_tp, dict):
                    ike_val = raw_tp.get("ikeSettings")
                    ike_obj = (ike_val[0] if isinstance(ike_val, list) and ike_val else ike_val) if isinstance(ike_val, (list, dict)) else None
                    if isinstance(ike_obj, dict) and ike_obj.get("id"):
                        # Strip metadata and links before sending
                        ike_obj = _strip_metadata_and_links(ike_obj)
                        ike_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/ikesettings/{ike_obj.get('id')}"
                        try:
                            logger.info(f"[VPN] PUT {ike_url}\nPayload: {json.dumps(ike_obj, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] PUT {ike_url} (payload logged as JSON failed)")
                        ike_resp = fmc.fmc_put(ike_url, ike_obj)
                        if ike_resp and ike_resp.status_code in [200, 201]:
                            ike_data = ike_resp.json() if ike_resp.text else {}
                            ike_type = ike_data.get("type", "Unknown")
                            ike_id = ike_data.get("id", ike_obj.get("id"))
                            logger.info(f"[VPN] PUT IKE Settings Response: type={ike_type}, id={ike_id}, status={ike_resp.status_code}")
                            status_tracker["ike_settings"] = "SUCCESS"
                        else:
                            error_desc = _extract_error_description(ike_resp)
                            logger.warning(f"[VPN] PUT IKE Settings failed with status {ike_resp.status_code if ike_resp else 'None'}: {error_desc}")
                            status_tracker["ike_settings"] = "FAILED"
                            error_msg = f"IKE Settings: {error_desc}"
                            status_tracker["error_details"].append(error_msg)
                    ipsec_val = raw_tp.get("ipsecSettings")
                    ipsec_obj = (ipsec_val[0] if isinstance(ipsec_val, list) and ipsec_val else ipsec_val) if isinstance(ipsec_val, (list, dict)) else None
                    if isinstance(ipsec_obj, dict) and ipsec_obj.get("id"):
                        # Strip metadata and links before sending
                        ipsec_obj = _strip_metadata_and_links(ipsec_obj)
                        ipsec_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/ipsecsettings/{ipsec_obj.get('id')}"
                        try:
                            logger.info(f"[VPN] PUT {ipsec_url}\nPayload: {json.dumps(ipsec_obj, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] PUT {ipsec_url} (payload logged as JSON failed)")
                        ipsec_resp = fmc.fmc_put(ipsec_url, ipsec_obj)
                        if ipsec_resp and ipsec_resp.status_code in [200, 201]:
                            ipsec_data = ipsec_resp.json() if ipsec_resp.text else {}
                            ipsec_type = ipsec_data.get("type", "Unknown")
                            ipsec_id = ipsec_data.get("id", ipsec_obj.get("id"))
                            logger.info(f"[VPN] PUT IPSec Settings Response: type={ipsec_type}, id={ipsec_id}, status={ipsec_resp.status_code}")
                            status_tracker["ipsec_settings"] = "SUCCESS"
                        else:
                            error_desc = _extract_error_description(ipsec_resp)
                            logger.warning(f"[VPN] PUT IPSec Settings failed with status {ipsec_resp.status_code if ipsec_resp else 'None'}: {error_desc}")
                            status_tracker["ipsec_settings"] = "FAILED"
                            error_msg = f"IPSec Settings: {error_desc}"
                            status_tracker["error_details"].append(error_msg)
                    adv_val = raw_tp.get("advancedSettings")
                    adv_obj = (adv_val[0] if isinstance(adv_val, list) and adv_val else adv_val) if isinstance(adv_val, (list, dict)) else None
                    if isinstance(adv_obj, dict) and adv_obj.get("id"):
                        # Strip metadata and links before sending
                        adv_obj = _strip_metadata_and_links(adv_obj)
                        adv_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/advancedsettings/{adv_obj.get('id')}"
                        try:
                            logger.info(f"[VPN] PUT {adv_url}\nPayload: {json.dumps(adv_obj, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] PUT {adv_url} (payload logged as JSON failed)")
                        adv_resp = fmc.fmc_put(adv_url, adv_obj)
                        if adv_resp and adv_resp.status_code in [200, 201]:
                            adv_data = adv_resp.json() if adv_resp.text else {}
                            adv_type = adv_data.get("type", "Unknown")
                            adv_id = adv_data.get("id", adv_obj.get("id"))
                            logger.info(f"[VPN] PUT Advanced Settings Response: type={adv_type}, id={adv_id}, status={adv_resp.status_code}")
                            status_tracker["advanced_settings"] = "SUCCESS"
                        else:
                            error_desc = _extract_error_description(adv_resp)
                            logger.warning(f"[VPN] PUT Advanced Settings failed with status {adv_resp.status_code if adv_resp else 'None'}: {error_desc}")
                            status_tracker["advanced_settings"] = "FAILED"
                            error_msg = f"Advanced Settings: {error_desc}"
                            status_tracker["error_details"].append(error_msg)

                if vpn_id and isinstance(endpoints, list) and endpoints:
                    # Fetch existing endpoints to avoid duplicates
                    existing_endpoints = []
                    existing_names = set()
                    try:
                        logger.info(f"[VPN] Fetching existing endpoints for VPN {vpn_id} to check for duplicates...")
                        existing_endpoints = fmc.get_vpn_endpoints(fmc_ip, headers, domain_uuid, vpn_id, tp_body.get('name'))
                        if isinstance(existing_endpoints, list):
                            existing_names = {ep.get("name") for ep in existing_endpoints if ep.get("name")}
                    except Exception as fetch_ex:
                        logger.warning(f"[VPN] Failed to fetch existing endpoints: {fetch_ex}. Will attempt to create all endpoints.")
                    
                    # Filter out endpoints that already exist
                    new_endpoints = []
                    skipped_count = 0
                    for ep in endpoints:
                        ep_name = ep.get("name")
                        if ep_name and ep_name in existing_names:
                            skipped_count += 1
                        else:
                            new_endpoints.append(ep)
                    
                    if skipped_count > 0:
                        logger.info(f"[VPN] Skipping {skipped_count} endpoint(s) that already exist in the topology")
                    
                    if new_endpoints:
                        logger.info(f"[VPN] Creating {len(new_endpoints)} new endpoint(s)")
                        bulk_payloads = [ _sanitize(ep) for ep in new_endpoints ]
                        bulk_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints?bulk=true"
                        try:
                            logger.info(f"[VPN] POST {bulk_url}\nPayload: {json.dumps(bulk_payloads, indent=2)}")
                        except Exception:
                            logger.info(f"[VPN] POST {bulk_url} (payload logged as JSON failed)")
                        try:
                            bulk_resp = post_vpn_endpoints_bulk(fmc_ip, headers, domain_uuid, vpn_id, bulk_payloads)
                            endpoints_created += len(bulk_payloads)
                            status_tracker["endpoints"] = "SUCCESS"
                            # Log bulk endpoint creation response
                            if isinstance(bulk_resp, dict):
                                items = bulk_resp.get("items", [])
                                logger.info(f"[VPN] POST Endpoints Bulk Response: {len(items)} endpoint(s) created")
                                for idx, ep_data in enumerate(items[:5]):  # Log first 5 to avoid spam
                                    ep_name = ep_data.get("name", "Unknown")
                                    ep_id = ep_data.get("id", "Unknown")
                                    ep_type = ep_data.get("type", "Unknown")
                                    logger.info(f"[VPN]   - Endpoint {idx+1}: name='{ep_name}', type={ep_type}, id={ep_id}")
                                if len(items) > 5:
                                    logger.info(f"[VPN]   - ... and {len(items) - 5} more endpoint(s)")
                        except Exception as bulk_ex:
                            try:
                                logger.error(f"[VPN] Bulk endpoint create failed for {tp_body.get('name')}: {bulk_ex}")
                            except Exception:
                                pass
                            errors.append(f"Bulk endpoint create failed for {tp_body.get('name')}: {bulk_ex}")
                            status_tracker["endpoints"] = "FAILED"
                            # Extract error description from the exception
                            endpoint_error = str(bulk_ex)
                            if hasattr(bulk_ex, 'response') and bulk_ex.response is not None:
                                endpoint_error = _extract_error_description(bulk_ex.response)
                            error_msg = f"Endpoints: {endpoint_error}"
                            status_tracker["error_details"].append(error_msg)
                    else:
                        logger.info(f"[VPN] No new endpoints to create (all {len(endpoints)} endpoint(s) already exist)")
                        status_tracker["endpoints"] = "SKIPPED"
                else:
                    # No endpoints to create
                    status_tracker["endpoints"] = "SKIPPED"
                
                # Topology processed - set description based on errors
                if status_tracker["error_details"]:
                    # Join all error messages with semicolons
                    status_tracker["description"] = "; ".join(status_tracker["error_details"])
                else:
                    status_tracker["description"] = "Success"
                topology_summary.append(status_tracker)
                
            except Exception as ex:
                # Track failed topology with error description
                error_desc = str(ex)
                # Try to extract more meaningful error from FMC response if available
                try:
                    if hasattr(ex, 'response') and ex.response is not None:
                        error_desc = _extract_error_description(ex.response)
                except Exception:
                    pass
                
                # Update status tracker with failure info
                status_tracker["description"] = error_desc
                topology_summary.append(status_tracker)
                
                error_msg = f"Failed to process topology '{topo_name}': {error_desc}"
                errors.append(error_msg)
                logger.error(f"[VPN] {error_msg}")
                logger.info(f"[VPN] Skipping topology '{topo_name}' and continuing with remaining topologies...")

        # Create comprehensive summary table
        def _create_table(headers: List[str], rows: List[List[str]], title: str) -> str:
            """Create a simple ASCII table with borders."""
            if not rows:
                return f"\n{title}\n{'=' * len(title)}\nNo entries\n"
            
            # Calculate column widths
            col_widths = [len(h) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
            
            # Create separator line
            separator = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
            
            # Build table
            table_lines = [f"\n{title}", "=" * len(title), separator]
            
            # Header row
            header_row = "|" + "|".join([f" {headers[i]:<{col_widths[i]}} " for i in range(len(headers))]) + "|"
            table_lines.append(header_row)
            table_lines.append(separator)
            
            # Data rows
            for row in rows:
                data_row = "|" + "|".join([f" {str(row[i]):<{col_widths[i]}} " for i in range(len(row))]) + "|"
                table_lines.append(data_row)
            
            table_lines.append(separator)
            return "\n".join(table_lines) + "\n"
        
        # Generate unified topology summary table
        summary_table = ""
        if topology_summary:
            headers = [
                "Topology Name", 
                "Topology Type", 
                "Sub Type", 
                "Peers", 
                "IKE Settings", 
                "IPSec Settings", 
                "Advanced Settings", 
                "Objects",
                "Endpoints", 
                "Description"
            ]
            rows = [
                [
                    t["name"], 
                    t["type"], 
                    t["subtype"], 
                    str(t["peers"]),
                    t["ike_settings"],
                    t["ipsec_settings"],
                    t["advanced_settings"],
                    t["objects"],
                    t["endpoints"],
                    t["description"]
                ] 
                for t in topology_summary
            ]
            summary_table = _create_table(headers, rows, "VPN Topology Summary")
            logger.info(summary_table)
        
        # Summary message
        summary_msg = f"VPN apply completed: {created} topology/topologies created, {endpoints_created} endpoint(s) created"
        if errors:
            summary_msg += f", {len(errors)} error(s) encountered"
            logger.warning(f"[VPN] {summary_msg}")
        else:
            logger.info(f"[VPN] {summary_msg}")
        
        # Build summary_tables for frontend display and clean up internal tracking fields
        applied_rows = []
        failed_rows = []
        cleaned_topology_summary = []
        
        for t in topology_summary:
            # Create a clean copy without error_details
            clean_t = {k: v for k, v in t.items() if k != "error_details"}
            cleaned_topology_summary.append(clean_t)
            
            if t["description"] == "Success":
                # Applied row: [Type, Name, Peers count]
                applied_rows.append([
                    "VPN Topology",
                    t["name"],
                    str(t["peers"])
                ])
            else:
                # Failed row: [Type, Name, Error]
                failed_rows.append([
                    "VPN Topology",
                    t["name"],
                    t["description"]
                ])
        
        return {
            "success": True,
            "created": created,
            "endpoints_created": endpoints_created,
            "errors": errors,
            "summary_tables": {
                "applied": applied_rows,
                "failed": failed_rows,
            },
            "message": summary_msg
        }
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"VPN apply error: {e}")
        return {"success": False, "message": str(e)}

@app.post("/api/fmc-config/vpn/delete")
async def fmc_vpn_delete(payload: Dict[str, Any], http_request: Request):
    """Delete selected VPN topologies from FMC."""
    try:
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _vpn_delete_sync(payload))
        return result
    except Exception as e:
        logger.error(f"VPN delete error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _vpn_delete_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Delete VPN topologies from FMC by name."""
    _apply_debug_flag(payload)
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

        # Fetch existing VPN topologies from FMC to get their IDs
        logger.info("[VPN Delete] Fetching existing VPN topologies from FMC...")
        existing_topologies = fmc.get_vpn_topologies(fmc_ip, headers, domain_uuid) or []
        existing_by_name = {t.get("name"): t for t in existing_topologies if t.get("name")}
        logger.info(f"[VPN Delete] Found {len(existing_topologies)} existing topologies on FMC")

        deleted = 0
        errors: List[str] = []
        deleted_names: List[str] = []

        for topo in topo_list:
            topo_name = topo.get("name") if isinstance(topo, dict) else None
            if not topo_name:
                errors.append("Topology has no name, skipping")
                continue

            # Find the topology in FMC by name
            existing = existing_by_name.get(topo_name)
            if not existing:
                error_msg = f"Topology '{topo_name}' not found on FMC"
                logger.warning(f"[VPN Delete] {error_msg}")
                errors.append(error_msg)
                continue

            vpn_id = existing.get("id")
            if not vpn_id:
                error_msg = f"Topology '{topo_name}' found but has no ID"
                logger.warning(f"[VPN Delete] {error_msg}")
                errors.append(error_msg)
                continue

            # Delete the topology
            try:
                logger.info(f"[VPN Delete] Deleting topology '{topo_name}' (ID: {vpn_id})...")
                fmc.delete_vpn_topology(fmc_ip, headers, domain_uuid, vpn_id, topo_name)
                deleted += 1
                deleted_names.append(topo_name)
                logger.info(f"[VPN Delete] Successfully deleted topology '{topo_name}'")
            except Exception as ex:
                error_msg = f"Failed to delete topology '{topo_name}': {ex}"
                logger.error(f"[VPN Delete] {error_msg}")
                errors.append(error_msg)

        # Summary
        summary_msg = f"VPN delete completed: {deleted} topology(ies) deleted"
        if errors:
            summary_msg += f", {len(errors)} error(s) encountered"
            logger.warning(f"[VPN Delete] {summary_msg}")
        else:
            logger.info(f"[VPN Delete] {summary_msg}")

        return {
            "success": True,
            "deleted": deleted,
            "deleted_names": deleted_names,
            "errors": errors,
            "message": summary_msg
        }
    except Exception as e:
        logger.error(f"VPN delete error: {e}")
        return {"success": False, "message": str(e)}


@app.post("/api/fmc-config/vpn/replace-endpoints")
async def fmc_vpn_replace_endpoints(payload: Dict[str, Any], http_request: Request):
    """Replace VPN endpoints: swap source device for destination device across all VPN topologies."""
    try:
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _vpn_replace_endpoints_sync(payload, username))
        return result
    except Exception as e:
        logger.error(f"VPN replace-endpoints error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _vpn_replace_endpoints_sync(payload: Dict[str, Any], username: str) -> Dict[str, Any]:
    """Replace all VPN endpoints of source device with destination device."""
    _apply_debug_flag(payload)
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        fmc_user = (payload.get("username") or "").strip()
        fmc_pass = payload.get("password") or ""
        src_device_id = (payload.get("src_device_id") or "").strip()
        dst_device_id = (payload.get("dst_device_id") or "").strip()

        if not fmc_ip or not fmc_user or not fmc_pass:
            return {"success": False, "message": "Missing fmc_ip, username or password"}
        if not src_device_id or not dst_device_id:
            return {"success": False, "message": "Missing source or destination device ID"}

        sel_domain = (payload.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, fmc_user, fmc_pass)
        domain_uuid = sel_domain or auth_domain

        # Resolve device names from IDs
        source_name = get_ftd_name_by_id(fmc_ip, headers, domain_uuid, src_device_id)
        dest_name = get_ftd_name_by_id(fmc_ip, headers, domain_uuid, dst_device_id)
        logger.info(f"[VPN Replace] Source: {source_name} ({src_device_id}) -> Dest: {dest_name} ({dst_device_id})")

        # Fetch all VPN topologies and their endpoints
        vpn_topologies = get_vpn_topologies(fmc_ip, headers, domain_uuid)
        vpn_configs = []
        for vpn in vpn_topologies:
            vpn_id = vpn.get("id")
            vpn_name = vpn.get("name")
            endpoints = get_vpn_endpoints(fmc_ip, headers, domain_uuid, vpn_id, vpn_name=vpn_name)
            vpn_copy = dict(vpn)
            vpn_copy["endpoints"] = endpoints
            vpn_configs.append(vpn_copy)

        logger.info(f"[VPN Replace] Found {len(vpn_configs)} VPN topologies, replacing endpoints...")

        # Replace VPN endpoints
        replace_vpn_endpoint(fmc_ip, headers, domain_uuid, source_name, dest_name, vpn_configs)

        record_activity(username, "vpn_replace_endpoints", {"source": source_name, "destination": dest_name, "topologies": len(vpn_configs)})

        return {
            "success": True,
            "message": f"Successfully replaced VPN endpoints from {source_name} to {dest_name} across {len(vpn_configs)} topologies",
            "source": source_name,
            "destination": dest_name,
            "topologies_checked": len(vpn_configs),
        }
    except Exception as e:
        logger.error(f"VPN replace-endpoints error: {e}")
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
        reset_progress(username)
        _start_user_operation(username, "config-apply")
        _attach_user_log_handlers(username)
        # Add app username to payload for progress tracking
        payload["app_username"] = username
        # Execute heavy operation in thread to allow /api/logs polling concurrently
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _apply_config_multi(payload))
        _finish_user_operation(username, bool(result.get("success", False)), result.get("message", "Config apply completed"))
        return result
    except InterruptedError:
        try:
            _finish_user_operation(username, False, "Operation stopped by user")
        except Exception:
            pass
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"FMC config apply error: {e}")
        try:
            _finish_user_operation(username, False, f"Config apply error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _apply_config_multi(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Multi-device wrapper. Iterates selected device_ids sequentially and aggregates results.

    Returns { success: True, results: [ { device_id, device_name, applied, errors, success }... ], applied: <totals>, errors: <all_errors> }
    Falls back to single-device behavior if only device_id is provided.
    """
    _apply_debug_flag(payload)
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
        aggregated_applied_rows = []
        aggregated_skipped_rows = []
        aggregated_failed_rows = []

        for did in device_ids:
            _check_stop_requested(payload.get("app_username") or username)
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
            
            # Aggregate summary tables from each device
            summary_tables = res.get("summary_tables") or {}
            for row in (summary_tables.get("applied") or []):
                aggregated_applied_rows.append(row)
            for row in (summary_tables.get("skipped") or []):
                aggregated_skipped_rows.append(row)
            for row in (summary_tables.get("failed") or []):
                aggregated_failed_rows.append(row)

        return {
            "success": True, 
            "results": results, 
            "applied": total_applied, 
            "errors": all_errors,
            "summary_tables": {
                "applied": aggregated_applied_rows,
                "skipped": aggregated_skipped_rows,
                "failed": aggregated_failed_rows
            }
        }
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def _unpack_selected_types(payload: Dict[str, Any], prefix: str = "apply") -> None:
    """Translate React frontend selected_types dict into legacy flat keys on payload.

    For 'apply' prefix: selected_types keys → apply_* keys (used by _apply_config_sync)
    For 'delete' prefix: selected_types keys → delete_* keys (used by _delete_config_sync / _delete_objects_sync)
    """
    sel_types: Dict[str, bool] = payload.get("selected_types") or {}
    if not sel_types:
        return
    # Map from React UI checkbox key → legacy backend suffix (prefixed with apply_/delete_)
    _SUFFIX_MAP = {
        # Interfaces
        "loopback_interfaces": "loopbacks",
        "physical_interfaces": "physicals",
        "etherchannel_interfaces": "etherchannels",
        "subinterfaces": "subinterfaces",
        "vti_interfaces": "vtis",
        "inline_sets": "inline_sets",
        "bridge_group_interfaces": "bridge_group_interfaces",
        # Routing
        "routing_bgp_general_settings": "routing_bgp_general_settings",
        "routing_bgp_policies": "routing_bgp_policies",
        "routing_bfd_policies": "routing_bfd_policies",
        "routing_ospfv2_policies": "routing_ospfv2_policies",
        "routing_ospfv2_interfaces": "routing_ospfv2_interfaces",
        "routing_ospfv3_policies": "routing_ospfv3_policies",
        "routing_ospfv3_interfaces": "routing_ospfv3_interfaces",
        "routing_eigrp_policies": "routing_eigrp_policies",
        "routing_pbr_policies": "routing_pbr_policies",
        "routing_ipv4_static_routes": "routing_ipv4_static_routes",
        "routing_ipv6_static_routes": "routing_ipv6_static_routes",
        "routing_ecmp_zones": "routing_ecmp_zones",
        "routing_vrfs": "routing_vrfs",
        # Objects > Interface
        "objects_interface_security_zones": "obj_if_security_zones",
        # Objects > Network
        "objects_network_hosts": "obj_net_host",
        "objects_network_ranges": "obj_net_range",
        "objects_network_networks": "obj_net_network",
        "objects_network_fqdns": "obj_net_fqdn",
        "objects_network_groups": "obj_net_group",
        # Objects > Port
        "objects_port_objects": "obj_port_objects",
        # Objects > Routing Templates & Lists
        "objects_bfd_templates": "obj_bfd_templates",
        "objects_as_path_lists": "obj_as_path_lists",
        "objects_key_chains": "obj_key_chains",
        "objects_sla_monitors": "obj_sla_monitors",
        "objects_community_lists_community": "obj_community_lists_community",
        "objects_community_lists_extended": "obj_community_lists_extended",
        "objects_prefix_lists_ipv4": "obj_prefix_lists_ipv4",
        "objects_prefix_lists_ipv6": "obj_prefix_lists_ipv6",
        "objects_access_lists_extended": "obj_access_lists_extended",
        "objects_access_lists_standard": "obj_access_lists_standard",
        "objects_route_maps": "obj_route_maps",
        # Objects > Address Pools
        "objects_address_pools_ipv4": "obj_address_pools_ipv4",
        "objects_address_pools_ipv6": "obj_address_pools_ipv6",
        "objects_address_pools_mac": "obj_address_pools_mac",
    }
    for ui_key, suffix in _SUFFIX_MAP.items():
        if ui_key in sel_types:
            payload[f"{prefix}_{suffix}"] = bool(sel_types[ui_key])


def _apply_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    _apply_debug_flag(payload)
    _unpack_selected_types(payload, prefix="apply")

    fmc_ip = (payload.get("fmc_ip") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    app_username = payload.get("app_username") or username  # For progress tracking
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

    apply_bulk = bool(payload.get("apply_bulk", payload.get("bulk", True)))
    batch_size = int(payload.get("batch_size") or 25)
    if batch_size <= 0:
        batch_size = 25

    # Build interface maps for the destination device
    from utils.fmc_api import get_physical_interfaces, get_etherchannel_interfaces, get_subinterfaces, get_vti_interfaces
    from utils.fmc_api import get_loopback_interfaces, get_bridge_group_interfaces, get_inline_sets
    from utils.fmc_api import create_loopback_interface, put_physical_interface, post_etherchannel_interface, post_subinterface, post_vti_interface
    from utils.fmc_api import put_loopback_interface, put_etherchannel_interface, put_subinterface, put_vti_interface
    from utils.fmc_api import post_inline_set, post_bridge_group_interface
    from utils.fmc_api import put_inline_set, put_bridge_group_interface
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
        post_vrfs_bulk,
        # PUT functions for updating routing protocols with redistribution
        put_bgp_policy,
        put_ospfv2_policy,
        put_ospfv3_policy,
        put_eigrp_policy,
        put_bfd_policy,
        # Helper functions for redistribution handling
        has_redistribute_protocols,
        strip_redistribute_protocols,
        restore_redistribute_protocols,
    )

    dest_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    phys_map = { (item.get('name') or item.get('ifname')): item.get('id') for item in dest_phys if item.get('id') }
    dest_eth = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    eth_map = { item.get('name'): item.get('id') for item in dest_eth if item.get('id') }

    # Build additional interface maps for existing-check (PUT vs POST)
    dest_loops = get_loopback_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    loop_map = {}
    for it in dest_loops:
        for k in [it.get("ifname"), it.get("name")]:
            if it.get("id") and k:
                loop_map[str(k).strip()] = it["id"]

    dest_subs = get_subinterfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    sub_map = {}
    for it in dest_subs:
        sid = it.get("id")
        if not sid:
            continue
        # Index by ifname when available
        ifn = (it.get("ifname") or "").strip()
        if ifn:
            sub_map[ifn] = sid
        # Primary composite key: name.subIntfId  (name = parent interface name in GET response)
        sub_name = (it.get("name") or "").strip()
        sub_intf_id = it.get("subIntfId")
        if sub_name and sub_intf_id is not None:
            sub_map[f"{sub_name}.{sub_intf_id}"] = sid
        # Also try parentInterface.name.subIntfId if parentInterface is populated
        try:
            parent = (it.get("parentInterface") or {}).get("name", "").strip()
        except Exception:
            parent = ""
        if parent and sub_intf_id is not None and parent != sub_name:
            sub_map[f"{parent}.{sub_intf_id}"] = sid

    dest_vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    vti_map = {}
    for it in dest_vtis:
        for k in [it.get("name"), it.get("ifname")]:
            if it.get("id") and k:
                vti_map[str(k).strip()] = it["id"]

    dest_bridges = get_bridge_group_interfaces(fmc_ip, headers, domain_uuid, device_id, device_name)
    bridge_map = { str(it.get("name")): it.get("id") for it in dest_bridges if it.get("id") and it.get("name") }

    dest_inlines = get_inline_sets(fmc_ip, headers, domain_uuid, device_id, device_name)
    inline_map = { str(it.get("name")): it.get("id") for it in dest_inlines if it.get("id") and it.get("name") }

    # Prime resolver for interfaces and security zones
    resolver = DependencyResolver(fmc_ip, headers, domain_uuid, device_id)
    resolver.prime_device_interfaces(device_name)
    resolver.prime_security_zones()
    resolver.prime_object_maps()

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
    # Track created security zones for reporting (defined early to be accessible later)
    created_security_zones_count = 0
    
    if needed_zones and bool(payload.get("apply_obj_if_security_zones", False)):
        logger.info(f"[Objects > Interface] Ensuring SecurityZones exist for: {sorted(list(needed_zones))}")
        created_zones = resolver.ensure_security_zones(sec_zone_defs, needed_zones, batch_size=batch_size)
        created_security_zones_count = len(created_zones or [])
        if created_zones:
            logger.info(f"Created {len(created_zones)} SecurityZone(s): {[z.get('name') for z in created_zones]}")
        else:
            logger.info("All referenced SecurityZones already exist; none created")

    try:
        src_index = {}
        def _idx_add(items):
            for it in (items or []):
                try:
                    t = str(it.get("type") or "")
                    oid = str(it.get("id") or "")
                    nm = (it.get("name") or "").strip()
                    if t and oid and nm:
                        src_index.setdefault(t, {})[oid] = nm
                except Exception:
                    continue
        if isinstance(cfg_objects, dict):
            net = cfg_objects.get("network") or {}
            _idx_add(net.get("hosts"))
            _idx_add(net.get("ranges"))
            _idx_add(net.get("networks"))
            _idx_add(net.get("fqdns"))
            _idx_add(net.get("groups"))
            prt = cfg_objects.get("port") or {}
            _idx_add(prt.get("objects"))
            _idx_add(cfg_objects.get("bfd_templates"))
            _idx_add(cfg_objects.get("as_path_lists"))
            _idx_add(cfg_objects.get("key_chains"))
            _idx_add(cfg_objects.get("sla_monitors"))
            comm = cfg_objects.get("community_lists") or {}
            _idx_add(comm.get("community"))
            _idx_add(comm.get("extended"))
            pref = cfg_objects.get("prefix_lists") or {}
            _idx_add(pref.get("ipv4"))
            _idx_add(pref.get("ipv6"))
            acls = cfg_objects.get("access_lists") or {}
            _idx_add(acls.get("extended"))
            _idx_add(acls.get("standard"))
            _idx_add(cfg_objects.get("route_maps"))
            pools = cfg_objects.get("address_pools") or {}
            _idx_add(pools.get("ipv4"))
            _idx_add(pools.get("ipv6"))
            _idx_add(pools.get("mac"))
        if src_index:
            resolver.set_source_object_index(src_index)
    except Exception:
        pass

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
    skipped: List[str] = []  # Track skipped configurations with format "type name: reason"

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    # 0) Objects — always apply first if selected
    try:
        _check_stop_requested(app_username)
        obj = (cfg.get("objects") or {}) if isinstance(cfg, dict) else {}
        
        # Build validation set from already-cached object maps (avoids 20 extra API calls)
        logger.info("Building existing objects for validation from cached object maps...")
        existing_objects: Dict[str, Set[str]] = {}  # type -> set of names
        try:
            for type_name, name_id_map in (resolver._obj_maps or {}).items():
                existing_objects[type_name] = set(name_id_map.keys())
            logger.info(f"Loaded existing objects for validation: {sum(len(v) for v in existing_objects.values())} objects across {len(existing_objects)} types")
        except Exception as ex:
            logger.warning(f"Failed to build validation data from cached maps: {ex}")
        
        # Helper to log object processing summary blocks
        def _obj_status(items, is_enabled: bool) -> str:
            if not is_enabled:
                return "Not Selected"
            if not items or len(items) == 0:
                return "No Objects"
            return f"Selected ({len(items)})"

        def _log_object_block(title: str, entries: List[Tuple[str, str]]) -> None:
            from datetime import datetime

            ts = datetime.now().strftime("%H:%M:%S")
            logger.info(f"[{ts}] INFO  {title}")
            if not entries:
                logger.info("            └─ No Objects....................... Not Selected")
                return
            dot_width = 32
            for idx, (label, status) in enumerate(entries):
                branch = "└─" if idx == len(entries) - 1 else "├─"
                dots = "." * max(2, dot_width - len(label))
                logger.info(f"            {branch} {label}{dots} {status}")

        def _log_object_block_end(refresh_note: str = "Refreshing maps...") -> None:
            suffix = f" | {refresh_note}" if refresh_note else ""
            logger.info(f"            ✔ Completed{suffix}")
        
        # Helper to post a list of objects with a callable, checking if they already exist
        def _post_list(items, func, applied_key: str, object_type: str = None, bulk_func=None):
            """Post items individually or in bulk. If bulk_func is provided and apply_bulk is True, uses bulk API."""
            if not items:
                return
            _check_stop_requested(app_username)
            
            # Filter out items that already exist
            filtered_items = []
            for it in items:
                name = str((it or {}).get("name") or (it or {}).get("value") or "<unnamed>")
                if object_type and object_type in existing_objects:
                    if name in existing_objects[object_type]:
                        skipped.append(f"{applied_key} {name}: Object already exists")
                        continue
                filtered_items.append(it)
            
            if not filtered_items:
                return
            
            # Use bulk API if available and enabled
            if bulk_func and apply_bulk:
                for group in chunks(filtered_items, batch_size):
                    try:
                        payloads = []
                        for it in group:
                            p = dict(it or {})
                            # strip api-only fields
                            if str(p.get("type") or "") == "RouteMap":
                                for k in ("links","metadata"):
                                    p.pop(k, None)
                            else:
                                for k in ("id","links","metadata"):
                                    p.pop(k, None)
                            resolver.resolve_all_in_payload(p)
                            fmc.normalize_reference_objects(p)
                            payloads.append(p)
                        
                        # Call bulk function
                        bulk_func(fmc_ip, headers, domain_uuid, payloads)
                        applied[applied_key] += len(payloads)
                    except Exception as ex:
                        # On bulk failure, log error for the batch
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        batch_names = [str((it or {}).get("name") or "<unnamed>") for it in group]
                        errors.append(f"{applied_key} bulk ({', '.join(batch_names[:3])}{'...' if len(batch_names) > 3 else ''}): {desc}")
            else:
                # Fall back to individual POSTs
                for it in filtered_items:
                    name = str((it or {}).get("name") or (it or {}).get("value") or "<unnamed>")
                    try:
                        p = dict(it or {})
                        # strip api-only fields
                        if str(p.get("type") or "") == "RouteMap":
                            for k in ("links","metadata"):
                                p.pop(k, None)
                        else:
                            for k in ("id","links","metadata"):
                                p.pop(k, None)
                        resolver.resolve_all_in_payload(p)
                        fmc.normalize_reference_objects(p)
                        func(fmc_ip, headers, domain_uuid, p)
                        applied[applied_key] += 1
                    except Exception as ex:
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        errors.append(f"{applied_key} {name}: {desc}")
        # Phase 1: Objects (Level 1 & 2)
        set_progress(app_username, 5, "Phase 1: Objects (Level 1 & 2)")
        logger.info("=" * 80)
        logger.info("📤 Starting Phase 1: Objects (Level 1 & 2) [PROGRESS: 5%]")
        logger.info("=" * 80)
        level_1_entries = [
            ("Host Objects", _obj_status((obj.get("network") or {}).get("hosts"), payload.get("apply_obj_net_host"))),
            ("Range Objects", _obj_status((obj.get("network") or {}).get("ranges"), payload.get("apply_obj_net_range"))),
            ("Network Objects", _obj_status((obj.get("network") or {}).get("networks"), payload.get("apply_obj_net_network"))),
            ("FQDN Objects", _obj_status((obj.get("network") or {}).get("fqdns"), payload.get("apply_obj_net_fqdn"))),
            ("Port Objects", _obj_status((obj.get("port") or {}).get("objects"), payload.get("apply_obj_port_objects"))),
            ("BFD Templates", _obj_status(obj.get("bfd_templates"), payload.get("apply_obj_bfd_templates"))),
            ("AS Path Lists", _obj_status(obj.get("as_path_lists"), payload.get("apply_obj_as_path_lists"))),
            ("Key Chains", _obj_status(obj.get("key_chains"), payload.get("apply_obj_key_chains"))),
            ("Community Lists (Community)", _obj_status((obj.get("community_lists") or {}).get("community"), payload.get("apply_obj_community_lists_community"))),
            ("Community Lists (Extended)", _obj_status((obj.get("community_lists") or {}).get("extended"), payload.get("apply_obj_community_lists_extended"))),
            ("IPv4 Prefix Lists", _obj_status((obj.get("prefix_lists") or {}).get("ipv4"), payload.get("apply_obj_prefix_lists_ipv4"))),
            ("IPv6 Prefix Lists", _obj_status((obj.get("prefix_lists") or {}).get("ipv6"), payload.get("apply_obj_prefix_lists_ipv6"))),
            ("IPv4 Address Pools", _obj_status((obj.get("address_pools") or {}).get("ipv4"), payload.get("apply_obj_address_pools_ipv4"))),
            ("IPv6 Address Pools", _obj_status((obj.get("address_pools") or {}).get("ipv6"), payload.get("apply_obj_address_pools_ipv6"))),
            ("MAC Address Pools", _obj_status((obj.get("address_pools") or {}).get("mac"), payload.get("apply_obj_address_pools_mac"))),
        ]
        _log_object_block("Level 1 Objects", level_1_entries)
        
        # Network objects
        net = obj.get("network") or {}
        if payload.get("apply_obj_net_host"): _post_list(net.get("hosts"), fmc.post_host_object, "objects_network_hosts", "Host", bulk_func=fmc.post_host_object_bulk)
        if payload.get("apply_obj_net_range"): _post_list(net.get("ranges"), fmc.post_range_object, "objects_network_ranges", "Range", bulk_func=fmc.post_range_object_bulk)
        if payload.get("apply_obj_net_network"): _post_list(net.get("networks"), fmc.post_network_object, "objects_network_networks", "Network", bulk_func=fmc.post_network_object_bulk)
        if payload.get("apply_obj_net_fqdn"): _post_list(net.get("fqdns"), fmc.post_fqdn_object, "objects_network_fqdns", "FQDN", bulk_func=fmc.post_fqdn_object_bulk)
        # Port objects
        prt = obj.get("port") or {}
        if payload.get("apply_obj_port_objects"):
            _post_list(prt.get("objects"), fmc.post_port_object, "objects_port_objects", "ProtocolPortObject", bulk_func=fmc.post_port_object_bulk)
        # BFD templates need UI auth overrides
        if payload.get("apply_obj_bfd_templates"):
            for it in (obj.get("bfd_templates") or []):
                nm = str((it or {}).get("name") or "<unnamed>")
                # Check if BFD template already exists
                if "BFDTemplate" in existing_objects and nm in existing_objects["BFDTemplate"]:
                    skipped.append(f"objects_bfd_templates {nm}: Object already exists")
                    continue
                try:
                    p = dict(it or {})
                    for k in ("id","links","metadata"): p.pop(k, None)
                    resolver.resolve_all_in_payload(p)
                    fmc.normalize_reference_objects(p)
                    fmc.post_bfd_template(fmc_ip, headers, domain_uuid, p, ui_auth_values=ui_auth_values)
                    applied["objects_bfd_templates"] += 1
                except Exception as ex:
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"objects_bfd_templates {nm}: {desc}")
        if payload.get("apply_obj_as_path_lists"): _post_list(obj.get("as_path_lists"), fmc.post_as_path_list, "objects_as_path_lists", "ASPathList")
        if payload.get("apply_obj_key_chains"): _post_list(obj.get("key_chains"), fmc.post_key_chain, "objects_key_chains", "KeyChain", bulk_func=fmc.post_key_chain_bulk)
        comm = obj.get("community_lists") or {}
        if payload.get("apply_obj_community_lists_community"): _post_list(comm.get("community"), fmc.post_community_list, "objects_community_lists_community", "CommunityList")
        if payload.get("apply_obj_community_lists_extended"): _post_list(comm.get("extended"), fmc.post_extended_community_list, "objects_community_lists_extended", "ExtendedCommunityList")
        pref = obj.get("prefix_lists") or {}
        if payload.get("apply_obj_prefix_lists_ipv4"): _post_list(pref.get("ipv4"), fmc.post_ipv4_prefix_list, "objects_prefix_lists_ipv4", "IPv4PrefixList")
        if payload.get("apply_obj_prefix_lists_ipv6"): _post_list(pref.get("ipv6"), fmc.post_ipv6_prefix_list, "objects_prefix_lists_ipv6", "IPv6PrefixList")
        pools = obj.get("address_pools") or {}
        if payload.get("apply_obj_address_pools_ipv4"): _post_list(pools.get("ipv4"), fmc.post_ipv4_address_pool, "objects_address_pools_ipv4", "IPv4AddressPool")
        if payload.get("apply_obj_address_pools_ipv6"): _post_list(pools.get("ipv6"), fmc.post_ipv6_address_pool, "objects_address_pools_ipv6", "IPv6AddressPool")
        if payload.get("apply_obj_address_pools_mac"): _post_list(pools.get("mac"), fmc.post_mac_address_pool, "objects_address_pools_mac", "MacAddressPool")
        _log_object_block_end("Refreshing maps...")
        
        # Refresh object maps after Level 1 so Level 2 can reference them (skip if nothing was selected)
        _level_1_selected = any([
            payload.get("apply_obj_net_host"), payload.get("apply_obj_net_range"),
            payload.get("apply_obj_net_network"), payload.get("apply_obj_net_fqdn"),
            payload.get("apply_obj_port_objects"), payload.get("apply_obj_bfd_templates"),
            payload.get("apply_obj_as_path_lists"), payload.get("apply_obj_key_chains"),
            payload.get("apply_obj_community_lists_community"), payload.get("apply_obj_community_lists_extended"),
            payload.get("apply_obj_prefix_lists_ipv4"), payload.get("apply_obj_prefix_lists_ipv6"),
            payload.get("apply_obj_address_pools_ipv4"), payload.get("apply_obj_address_pools_ipv6"),
            payload.get("apply_obj_address_pools_mac"),
        ])
        if _level_1_selected:
            resolver.prime_object_maps()
        
        # Level 2: Objects that depend on Level 1
        level_2_entries = [
            ("Network Groups", _obj_status(net.get("groups"), payload.get("apply_obj_net_group"))),
            ("SLA Monitors", _obj_status(obj.get("sla_monitors"), payload.get("apply_obj_sla_monitors"))),
        ]
        _log_object_block("Level 2 Objects", level_2_entries)
        if payload.get("apply_obj_net_group"): _post_list(net.get("groups"), fmc.post_network_group, "objects_network_groups", "NetworkGroup", bulk_func=fmc.post_network_group_bulk)
        if payload.get("apply_obj_sla_monitors"): _post_list(obj.get("sla_monitors"), fmc.post_sla_monitor, "objects_sla_monitors", "SLAMonitor", bulk_func=fmc.post_sla_monitor_bulk)
        _log_object_block_end("Refreshing maps...")
        
        # Refresh object maps after Level 2 (skip if nothing was selected in Level 1 or 2)
        _level_2_selected = any([payload.get("apply_obj_net_group"), payload.get("apply_obj_sla_monitors")])
        if _level_1_selected or _level_2_selected:
            resolver.prime_object_maps()
        
        # NOTE: Level 3 (Access Lists) and Level 4 (Route Maps) moved to AFTER interface creation
        # to allow them to reference network objects created from interface IPs
        
        logger.info("=" * 80)
        logger.info("✅ Finished Phase 1: Objects (Level 1 & 2)")
        logger.info("=" * 80)
        
        # Update applied count for security zones (created earlier, before object levels)
        applied["objects_interface_security_zones"] += created_security_zones_count
    except Exception as e:
        errors.append(f"Objects phase: {e}")

    # Phase 2: Interfaces
    set_progress(app_username, 25, "Phase 2: Interfaces")
    logger.info("=" * 80)
    logger.info("📤 Starting Phase 2: Interfaces [PROGRESS: 25%]")
    logger.info("=" * 80)

    # 1) Loopback interfaces (no bulk API -> process in batches, item-by-item)
    if payload.get("apply_loopbacks") and loops:
        set_progress(app_username, 27, "Section 2.1: Loopback Interfaces")
        # Split into existing (PUT) vs new (POST)
        loops_to_update = []
        loops_to_create = []
        for lb in loops:
            name = lb.get('ifname') or lb.get('name') or ''
            existing_id = loop_map.get(name.strip())
            if existing_id:
                loops_to_update.append((lb, existing_id))
            else:
                loops_to_create.append(lb)
        logger.info(f"  Starting Section 2.1: Loopback Interfaces ({len(loops)} to apply: {len(loops_to_update)} existing→PUT, {len(loops_to_create)} new→POST) [PROGRESS: 27%]")
        # PUT existing loopbacks
        for lb, obj_id in loops_to_update:
            _check_stop_requested(app_username)
            try:
                p = dict(lb)
                if not p.get("type"): p["type"] = "LoopbackInterface"
                p["id"] = obj_id
                resolver.resolve_all_in_payload(p)
                put_loopback_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                applied["loopbacks"] += 1
            except Exception as ex:
                name = lb.get('ifname') or lb.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Loopback {name}: {desc}")
        # POST new loopbacks
        for lb in loops_to_create:
            _check_stop_requested(app_username)
            try:
                if not lb.get("type"): lb["type"] = "LoopbackInterface"
                resolver.resolve_all_in_payload(lb)
                create_loopback_interface(fmc_ip, headers, domain_uuid, device_id, lb)
                applied["loopbacks"] += 1
            except Exception as ex:
                name = lb.get('ifname') or lb.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Loopback {name}: {desc}")
        logger.info(f"  Finished Section 2.1: Loopback Interfaces ({applied['loopbacks']} applied)")
        # Refresh interface caches so subsequent steps (e.g., VTI borrowIPfrom) can resolve newly created loopbacks
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Loopback creation: {e}")


    # 2) Physical interfaces (update; no bulk -> in batches)
    if payload.get("apply_physicals") and phys:
        set_progress(app_username, 30, "Section 2.2: Physical Interfaces")
        logger.info(f"  Starting Section 2.2: Physical Interfaces ({len(phys)} to apply) [PROGRESS: 30%]")
        logger.info(f"  Applying {len(phys)} physical interface(s)")
        for group in (chunks(phys, batch_size) if apply_bulk else [phys]):
            _check_stop_requested(app_username)
            for ph in group:
                _check_stop_requested(app_username)
                try:
                    nm = ph.get("name") or ph.get("ifname")
                    obj_id = phys_map.get(nm)
                    if not obj_id:
                        raise Exception(f"Physical interface '{nm}' not found on device")
                    ph_payload = dict(ph)
                    ph_payload["id"] = obj_id
                    # Resolve SecurityZone and dependent objects by name (and any nested interface refs)
                    resolver.resolve_all_in_payload(ph_payload)
                    put_physical_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, ph_payload)
                    logger.info(f"Updated PhysicalInterface {nm} (id={obj_id})")
                    applied["physicals"] += 1
                except Exception as ex:
                    name = ph.get('name') or ph.get('ifname')
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"Physical {name}: {desc}")
        logger.info(f"  Finished Section 2.2: Physical Interfaces ({applied['physicals']} applied)")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Physical Interface creation: {e}")


    # 3) EtherChannel interfaces (PUT existing / POST new; no bulk)
    if payload.get("apply_etherchannels") and eths:
        set_progress(app_username, 35, "Section 2.3: EtherChannel Interfaces")
        # Split into existing (PUT) vs new (POST)
        eths_to_update = []
        eths_to_create = []
        for ec in eths:
            ec_name = ec.get('name') or ''
            existing_id = eth_map.get(ec_name.strip())
            if existing_id:
                eths_to_update.append((ec, existing_id))
            else:
                eths_to_create.append(ec)
        logger.info(f"  Starting Section 2.3: EtherChannel Interfaces ({len(eths)} to apply: {len(eths_to_update)} existing→PUT, {len(eths_to_create)} new→POST) [PROGRESS: 35%]")

        def _prepare_etherchannel(ec_item):
            p = dict(ec_item)
            p.setdefault("type", "EtherChannelInterface")
            members = []
            for m in (ec_item.get("members") or []):
                mname = m.get("name")
                mid = phys_map.get(mname)
                if not mid:
                    raise Exception(f"Member interface '{mname}' not found on device")
                members.append({"id": mid, "type": "PhysicalInterface", "name": mname})
            if members:
                p["memberInterfaces"] = members
            resolver.resolve_all_in_payload(p)
            return p

        # PUT existing etherchannels
        for ec, obj_id in eths_to_update:
            _check_stop_requested(app_username)
            try:
                p = _prepare_etherchannel(ec)
                p["id"] = obj_id
                put_etherchannel_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                applied["etherchannels"] += 1
            except Exception as ex:
                name = ec.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"EtherChannel {name}: {desc}")
        # POST new etherchannels
        for ec in eths_to_create:
            _check_stop_requested(app_username)
            try:
                p = _prepare_etherchannel(ec)
                post_etherchannel_interface(fmc_ip, headers, domain_uuid, device_id, p)
                applied["etherchannels"] += 1
            except Exception as ex:
                name = ec.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"EtherChannel {name}: {desc}")
        logger.info(f"  Finished Section 2.3: EtherChannel Interfaces ({applied['etherchannels']} applied)")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Ethernet Interface creation: {e}")

    # 4) Subinterfaces (PUT existing / POST new; new supports bulk)
    if payload.get("apply_subinterfaces") and subs:
        set_progress(app_username, 40, "Section 2.4: Subinterfaces")
        # Split into existing (PUT) vs new (POST)
        subs_to_update = []
        subs_to_create = []
        for si in subs:
            si_name = (si.get("name") or "").strip()
            si_ifname = (si.get("ifname") or "").strip()
            si_sub_id = si.get("subIntfId")
            # Try multiple keys: parentName.subIntfId, name, ifname
            existing_id = None
            if si_name and si_sub_id is not None:
                existing_id = sub_map.get(f"{si_name}.{si_sub_id}")
            if not existing_id and si_ifname:
                existing_id = sub_map.get(si_ifname)
            if not existing_id and si_name:
                existing_id = sub_map.get(si_name)
            if existing_id:
                subs_to_update.append((si, existing_id))
            else:
                subs_to_create.append(si)
        logger.info(f"  Starting Section 2.4: Subinterfaces ({len(subs)} to apply: {len(subs_to_update)} existing→PUT, {len(subs_to_create)} new→POST) [PROGRESS: 40%]")

        # PUT existing subinterfaces (always individual)
        for si, obj_id in subs_to_update:
            _check_stop_requested(app_username)
            try:
                p = dict(si)
                p.setdefault("type", "SubInterface")
                p["id"] = obj_id
                resolver.resolve_all_in_payload(p)
                put_subinterface(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                applied["subinterfaces"] += 1
            except Exception as ex:
                name = f"{si.get('name')}.{si.get('subIntfId')}"
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Subinterface {name}: {desc}")

        # POST new subinterfaces (bulk if enabled)
        if subs_to_create:
            if apply_bulk:
                for group in chunks(subs_to_create, batch_size):
                    _check_stop_requested(app_username)
                    try:
                        out_payload = []
                        for si in group:
                            _check_stop_requested(app_username)
                            p = dict(si)
                            p.setdefault("type", "SubInterface")
                            resolver.resolve_all_in_payload(p)
                            out_payload.append(p)
                        if out_payload:
                            post_subinterface(fmc_ip, headers, domain_uuid, device_id, out_payload, bulk=True)
                            logger.info(f"Posted {len(out_payload)} new SubInterface(s) in bulk")
                            applied["subinterfaces"] += len(out_payload)
                    except Exception as ex:
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        errors.append(f"Subinterface batch: {desc}")
            else:
                for si in subs_to_create:
                    _check_stop_requested(app_username)
                    try:
                        p = dict(si)
                        p.setdefault("type", "SubInterface")
                        resolver.resolve_all_in_payload(p)
                        post_subinterface(fmc_ip, headers, domain_uuid, device_id, p, bulk=False)
                        logger.info(f"Created SubInterface {p.get('name')}.{p.get('subIntfId')}")
                        applied["subinterfaces"] += 1
                    except Exception as ex:
                        name = si.get('subIntfId')
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        errors.append(f"Subinterface {name}: {desc}")

        logger.info(f"  Finished Section 2.4: Subinterfaces ({applied['subinterfaces']} applied)")
        # Refresh interface caches so subsequent steps can resolve newly created subinterfaces
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Subinterface creation: {e}")


    # 5) VTI interfaces (PUT existing / POST new; new supports bulk)
    if payload.get("apply_vtis") and vtis:
        set_progress(app_username, 43, "Section 2.5: VTI Interfaces")
        # Split into existing (PUT) vs new (POST)
        vtis_to_update = []
        vtis_to_create = []
        for vt in vtis:
            vt_name = (vt.get("name") or "").strip()
            vt_ifname = (vt.get("ifname") or "").strip()
            existing_id = vti_map.get(vt_name) or vti_map.get(vt_ifname)
            if existing_id:
                vtis_to_update.append((vt, existing_id))
            else:
                vtis_to_create.append(vt)
        logger.info(f"  Starting Section 2.5: VTI Interfaces ({len(vtis)} to apply: {len(vtis_to_update)} existing→PUT, {len(vtis_to_create)} new→POST) [PROGRESS: 43%]")

        # PUT existing VTIs (always individual)
        for vt, obj_id in vtis_to_update:
            _check_stop_requested(app_username)
            try:
                p = dict(vt)
                p.setdefault("type", "VTIInterface")
                p["id"] = obj_id
                resolver.resolve_all_in_payload(p)
                put_vti_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                applied["vtis"] += 1
            except Exception as ex:
                name = vt.get('name') or vt.get('ifname')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"VTI {name}: {desc}")

        # POST new VTIs (bulk if enabled)
        if vtis_to_create:
            if apply_bulk:
                for group in chunks(vtis_to_create, batch_size):
                    _check_stop_requested(app_username)
                    try:
                        out_payload = []
                        for vi in group:
                            _check_stop_requested(app_username)
                            p = dict(vi)
                            p.setdefault("type", "VTIInterface")
                            resolver.resolve_all_in_payload(p)
                            out_payload.append(p)
                        if out_payload:
                            post_vti_interface(fmc_ip, headers, domain_uuid, device_id, out_payload if len(out_payload) > 1 else out_payload[0], bulk=(len(out_payload) > 1))
                            logger.info(f"Posted {len(out_payload)} new VTI Interface(s) in {'bulk' if len(out_payload) > 1 else 'single'} mode")
                            applied["vtis"] += len(out_payload)
                    except Exception as ex:
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        errors.append(f"VTI batch: {desc}")
            else:
                for vt in vtis_to_create:
                    _check_stop_requested(app_username)
                    try:
                        p = dict(vt)
                        p.setdefault("type", "VTIInterface")
                        resolver.resolve_all_in_payload(p)
                        post_vti_interface(fmc_ip, headers, domain_uuid, device_id, p, bulk=False)
                        logger.info(f"Created VTIInterface {p.get('name') or p.get('ifname')}")
                        applied["vtis"] += 1
                    except Exception as ex:
                        name = vt.get('name') or vt.get('ifname')
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        errors.append(f"VTI {name}: {desc}")
        logger.info(f"  Finished Section 2.5: VTI Interfaces ({applied['vtis']} applied)")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after VTI creation: {e}")

    # 6) Inline Sets (PUT existing / POST new; no bulk endpoint)
    if payload.get("apply_inline_sets") and inline_sets:
        set_progress(app_username, 46, "Section 2.6: Inline Sets")
        # Split into existing (PUT) vs new (POST)
        inlines_to_update = []
        inlines_to_create = []
        for item in inline_sets:
            iname = (item.get('name') or '').strip()
            existing_id = inline_map.get(iname)
            if existing_id:
                inlines_to_update.append((item, existing_id))
            else:
                inlines_to_create.append(item)
        logger.info(f"  Starting Section 2.6: Inline Sets ({len(inline_sets)} to apply: {len(inlines_to_update)} existing→PUT, {len(inlines_to_create)} new→POST) [PROGRESS: 46%]")
        # PUT existing inline sets
        for item, obj_id in inlines_to_update:
            _check_stop_requested(app_username)
            try:
                p = dict(item)
                p["id"] = obj_id
                resolver.resolve_all_in_payload(p)
                put_inline_set(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                applied["inline_sets"] += 1
            except Exception as ex:
                name = item.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Inline Set {name}: {desc}")
        # POST new inline sets
        for item in inlines_to_create:
            _check_stop_requested(app_username)
            try:
                p = dict(item)
                resolver.resolve_all_in_payload(p)
                post_inline_set(fmc_ip, headers, domain_uuid, device_id, p)
                applied["inline_sets"] += 1
            except Exception as ex:
                name = item.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Inline Set {name}: {desc}")
        logger.info(f"  Finished Section 2.6: Inline Sets ({applied['inline_sets']} applied)")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Inline Set creation: {e}")

    # 7) Bridge Group Interfaces (PUT existing / POST new; no bulk endpoint)
    if payload.get("apply_bridge_group_interfaces") and bridge_groups:
        set_progress(app_username, 48, "Section 2.7: Bridge Group Interfaces")
        # Split into existing (PUT) vs new (POST)
        bgs_to_update = []
        bgs_to_create = []
        for item in bridge_groups:
            bg_name = (item.get('name') or '').strip()
            existing_id = bridge_map.get(bg_name)
            if existing_id:
                bgs_to_update.append((item, existing_id))
            else:
                bgs_to_create.append(item)
        logger.info(f"  Starting Section 2.7: Bridge Group Interfaces ({len(bridge_groups)} to apply: {len(bgs_to_update)} existing→PUT, {len(bgs_to_create)} new→POST) [PROGRESS: 48%]")
        # PUT existing bridge groups
        for item, obj_id in bgs_to_update:
            _check_stop_requested(app_username)
            try:
                p = dict(item)
                p["id"] = obj_id
                resolver.resolve_all_in_payload(p)
                put_bridge_group_interface(fmc_ip, headers, domain_uuid, device_id, obj_id, p)
                applied["bridge_group_interfaces"] += 1
            except Exception as ex:
                name = item.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Bridge Group Interface {name}: {desc}")
        # POST new bridge groups
        for item in bgs_to_create:
            _check_stop_requested(app_username)
            try:
                p = dict(item)
                resolver.resolve_all_in_payload(p)
                post_bridge_group_interface(fmc_ip, headers, domain_uuid, device_id, p)
                applied["bridge_group_interfaces"] += 1
            except Exception as ex:
                name = item.get('name')
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"Bridge Group Interface {name}: {desc}")
        logger.info(f"  Finished Section 2.7: Bridge Group Interfaces ({applied['bridge_group_interfaces']} applied)")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after Bridge Group creation: {e}")

    logger.info("=" * 80)
    logger.info("✅ Finished Phase 2: Interfaces")
    logger.info("=" * 80)

    # Phase 3: Objects (Level 3 & 4) - Access Lists and Route Maps
    set_progress(app_username, 50, "Phase 3: Objects (Level 3 & 4)")
    logger.info("=" * 80)
    logger.info("📤 Starting Phase 3: Objects (Level 3 & 4) [PROGRESS: 50%]")
    logger.info("=" * 80)
    
    # Track whether any interfaces were actually applied in Phase 2
    _any_interfaces_applied = any([
        applied.get("loopbacks", 0), applied.get("physicals", 0),
        applied.get("etherchannels", 0), applied.get("subinterfaces", 0),
        applied.get("vtis", 0), applied.get("inline_sets", 0),
        applied.get("bridge_group_interfaces", 0),
    ])
    _any_level34_selected = any([
        payload.get("apply_obj_access_lists_extended"),
        payload.get("apply_obj_access_lists_standard"),
        payload.get("apply_obj_route_maps"),
    ])
    try:
        # Refresh object maps to include interface-derived network objects
        refresh_entries = [
            ("Interface-derived network objects", "Refreshing" if (_any_interfaces_applied or _any_level34_selected) else "Skipped (no changes)"),
        ]
        _log_object_block("Refreshing object maps to include interface-derived network objects", refresh_entries)
        if _any_interfaces_applied or _any_level34_selected:
            resolver.prime_object_maps()
        _log_object_block_end("")
        
        # Level 3: Access Lists (depend on Level 1 & 2 objects + interface-derived objects)
        acls = obj.get("access_lists") or {}
        level_3_entries = [
            ("Extended ACLs", _obj_status(acls.get("extended"), payload.get("apply_obj_access_lists_extended"))),
            ("Standard ACLs", _obj_status(acls.get("standard"), payload.get("apply_obj_access_lists_standard"))),
        ]
        _log_object_block("Level 3 Objects", level_3_entries)
        if payload.get("apply_obj_access_lists_extended"):
            _check_stop_requested(app_username)
            _post_list(acls.get("extended"), fmc.post_extended_access_list, "objects_access_lists_extended", "ExtendedAccessList")
        if payload.get("apply_obj_access_lists_standard"):
            _check_stop_requested(app_username)
            _post_list(acls.get("standard"), fmc.post_standard_access_list, "objects_access_lists_standard", "StandardAccessList")
        _log_object_block_end("Refreshing maps...")
        
        # Refresh object maps after Level 3 so Level 4 (Route Maps) can reference Access Lists
        _level_3_selected = any([payload.get("apply_obj_access_lists_extended"), payload.get("apply_obj_access_lists_standard")])
        if _level_3_selected:
            resolver.prime_object_maps()
        
        # Level 4: Route Maps (depend on all previous levels including access lists)
        level_4_entries = [
            ("Route Maps", _obj_status(obj.get("route_maps"), payload.get("apply_obj_route_maps"))),
        ]
        _log_object_block("Level 4 Objects", level_4_entries)
        if payload.get("apply_obj_route_maps"):
            _check_stop_requested(app_username)
            _post_list(obj.get("route_maps"), fmc.post_route_map, "objects_route_maps", "RouteMap")
        _log_object_block_end("Refreshing maps...")
        
        # Refresh object maps after Level 4 so routing policies can reference Route Maps
        _level_4_selected = bool(payload.get("apply_obj_route_maps"))
        if _level_3_selected or _level_4_selected:
            resolver.prime_object_maps()
    except Exception as e:
        errors.append(f"Level 3/4 Objects phase: {e}")

    logger.info("=" * 80)
    logger.info("✅ Finished Phase 3: Objects (Level 3 & 4)")
    logger.info("=" * 80)

    # Phase 4: Routing
    set_progress(app_username, 65, "Phase 4: Routing")
    logger.info("=" * 80)
    logger.info("📤 Starting Phase 4: Routing (Two-Pass for Redistribution) [PROGRESS: 65%]")
    logger.info("=" * 80)

    # 9) Routing (two-pass approach to handle protocol redistribution dependencies)
    if isinstance(routing, dict):
        def chunks(lst, n):
            for i in range(0, len(lst), n):
                yield lst[i:i+n]

        # Storage for protocols that need redistribution updates (Pass 2)
        protocols_to_update = []
        
        # BGP General Settings (no redistribution)
        if payload.get("apply_routing_bgp_general_settings"):
            items = routing.get("bgp_general_settings") or []
            set_progress(app_username, 67, "BGP General Settings")
            logger.info(f"Applying {len(items)} BGP General Settings [PROGRESS: 67%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
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
        
        logger.info("=" * 80)
        logger.info("🔄 PASS 1: Applying Base Routing Protocols (without redistribution)")
        logger.info("=" * 80)

        # BFD Policies - Pass 1 (BFD typically doesn't redistribute, but handle it)
        if payload.get("apply_routing_bfd_policies"):
            items = routing.get("bfd_policies") or []
            set_progress(app_username, 69, "BFD Policies (Pass 1)")
            logger.info(f"Pass 1: Applying {len(items)} BFD Policies [PROGRESS: 69%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
                    # Check if has redistribution
                    if has_redistribute_protocols(p):
                        clean_p, redist_data = strip_redistribute_protocols(p)
                        result = post_bfd_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, ui_auth_values=ui_auth_values)
                        # Store POST response and redistribution data for Pass 2
                        protocols_to_update.append(("bfd", result.get("id"), result, redist_data, None, None, ui_auth_values))
                    else:
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
                    errors.append(f"BFD {nm} (Pass 1): {desc}")

        # OSPFv2 Policies - Pass 1
        if payload.get("apply_routing_ospfv2_policies"):
            items = routing.get("ospfv2_policies") or []
            set_progress(app_username, 71, "OSPFv2 Policies (Pass 1)")
            logger.info(f"Pass 1: Applying {len(items)} OSPFv2 Policies [PROGRESS: 71%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
                    # Check if has redistribution
                    if has_redistribute_protocols(p):
                        clean_p, redist_data = strip_redistribute_protocols(p)
                        result = post_ospfv2_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, ui_auth_values=ui_auth_values)
                        # Store POST response and redistribution data for Pass 2
                        protocols_to_update.append(("ospfv2", result.get("id"), result, redist_data, None, None, ui_auth_values))
                    else:
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
                    errors.append(f"OSPFv2 policy {nm} (Pass 1): {desc}")

        # OSPFv3 Policies - Pass 1
        if payload.get("apply_routing_ospfv3_policies"):
            items = routing.get("ospfv3_policies") or []
            set_progress(app_username, 73, "OSPFv3 Policies (Pass 1)")
            logger.info(f"Pass 1: Applying {len(items)} OSPFv3 Policies [PROGRESS: 73%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
                    # Check if has redistribution
                    if has_redistribute_protocols(p):
                        clean_p, redist_data = strip_redistribute_protocols(p)
                        result = post_ospfv3_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, ui_auth_values=ui_auth_values)
                        # Store POST response and redistribution data for Pass 2
                        protocols_to_update.append(("ospfv3", result.get("id"), result, redist_data, None, None, ui_auth_values))
                    else:
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
                    errors.append(f"OSPFv3 policy {nm} (Pass 1): {desc}")

        # EIGRP Policies - Pass 1
        if payload.get("apply_routing_eigrp_policies"):
            items = routing.get("eigrp_policies") or []
            set_progress(app_username, 75, "EIGRP Policies (Pass 1)")
            logger.info(f"Pass 1: Applying {len(items)} EIGRP Policies [PROGRESS: 75%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
                    # Check if has redistribution
                    if has_redistribute_protocols(p):
                        clean_p, redist_data = strip_redistribute_protocols(p)
                        result = post_eigrp_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, ui_auth_values=ui_auth_values)
                        # Store POST response and redistribution data for Pass 2
                        protocols_to_update.append(("eigrp", result.get("id"), result, redist_data, None, None, ui_auth_values))
                    else:
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
                    errors.append(f"EIGRP policy {nm} (Pass 1): {desc}")

        # BGP Policies - Pass 1 (applied after IGP protocols)
        if payload.get("apply_routing_bgp_policies"):
            items = routing.get("bgp_policies") or []
            set_progress(app_username, 77, "BGP Policies (Pass 1)")
            logger.info(f"Pass 1: Applying {len(items)} BGP Policies [PROGRESS: 77%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
                    # Check if has redistribution
                    if has_redistribute_protocols(p):
                        clean_p, redist_data = strip_redistribute_protocols(p)
                        result = post_bgp_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, ui_auth_values=ui_auth_values)
                        # Store POST response and redistribution data for Pass 2
                        protocols_to_update.append(("bgp", result.get("id"), result, redist_data, None, None, ui_auth_values))
                    else:
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
                    errors.append(f"BGP policy {nm} (Pass 1): {desc}")
        
        # Routing interfaces (no redistribution)
        if payload.get("apply_routing_ospfv2_interfaces"):
            items = routing.get("ospfv2_interfaces") or []
            set_progress(app_username, 79, "OSPFv2 Interfaces")
            logger.info(f"Applying {len(items)} OSPFv2 Interfaces [PROGRESS: 79%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
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

        if payload.get("apply_routing_ospfv3_interfaces"):
            items = routing.get("ospfv3_interfaces") or []
            set_progress(app_username, 81, "OSPFv3 Interfaces")
            logger.info(f"Applying {len(items)} OSPFv3 Interfaces [PROGRESS: 81%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
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

        # PBR Policies (supports bulk)
        if payload.get("apply_routing_pbr_policies"):
            items = routing.get("pbr_policies") or []
            logger.info(f"Applying {len(items)} PBR Policies in {'bulk' if apply_bulk else 'single'} mode")
            for group in (chunks(items, batch_size) if apply_bulk else [items]):
                _check_stop_requested(app_username)
                try:
                    out = []
                    for it in group:
                        _check_stop_requested(app_username)
                        p = dict(it)
                        resolver.resolve_all_in_payload(p)
                        out.append(p)
                    if out:
                        post_pbr_policy(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], bulk=(len(out) > 1))
                        applied["routing_pbr_policies"] += len(out)
                except Exception as ex:
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"PBR: {desc}")

        # ECMP Zones
        if payload.get("apply_routing_ecmp_zones"):
            items = routing.get("ecmp_zones") or []
            set_progress(app_username, 87, "ECMP Zones")
            logger.info(f"Applying {len(items)} ECMP Zones [PROGRESS: 87%]")
            for it in items:
                _check_stop_requested(app_username)
                try:
                    p = dict(it)
                    resolver.resolve_all_in_payload(p)
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

        # IPv4 Static Routes (supports bulk)
        if payload.get("apply_routing_ipv4_static_routes"):
            items = routing.get("ipv4_static_routes") or []
            set_progress(app_username, 88, "IPv4 Static Routes")
            logger.info(f"Applying {len(items)} IPv4 Static Routes in {'bulk' if apply_bulk else 'single'} mode [PROGRESS: 88%]")
            for group in (chunks(items, batch_size) if apply_bulk else [items]):
                _check_stop_requested(app_username)
                try:
                    out = []
                    for it in group:
                        _check_stop_requested(app_username)
                        p = dict(it)
                        resolver.resolve_all_in_payload(p)
                        out.append(p)
                    if out:
                        post_ipv4_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], bulk=(len(out) > 1))
                        applied["routing_ipv4_static_routes"] += len(out)
                except Exception as ex:
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"IPv4 static route: {desc}")

        # IPv6 Static Routes (supports bulk)
        if payload.get("apply_routing_ipv6_static_routes"):
            items = routing.get("ipv6_static_routes") or []
            set_progress(app_username, 89, "IPv6 Static Routes")
            logger.info(f"Applying {len(items)} IPv6 Static Routes in {'bulk' if apply_bulk else 'single'} mode [PROGRESS: 89%]")
            for group in (chunks(items, batch_size) if apply_bulk else [items]):
                _check_stop_requested(app_username)
                try:
                    out = []
                    for it in group:
                        _check_stop_requested(app_username)
                        p = dict(it)
                        resolver.resolve_all_in_payload(p)
                        out.append(p)
                    if out:
                        post_ipv6_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], bulk=(len(out) > 1))
                        applied["routing_ipv6_static_routes"] += len(out)
                except Exception as ex:
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"IPv6 static route: {desc}")

        # VRFs and VRF-specific
        if payload.get("apply_routing_vrfs"):
            vrfs = routing.get("vrfs") or []
            set_progress(app_username, 91, "VRFs")
            logger.info(f"Applying {len(vrfs)} VRF(s) [PROGRESS: 91%]")
            name_to_id: Dict[str, str] = {}
            
            # Filter out Global VRF and prepare payloads
            vrf_payloads = []
            for vrf in vrfs:
                p = dict(vrf)
                vrf_name = (p.get("name") or "").strip()
                if vrf_name and vrf_name.lower() == "global":
                    logger.info("Skipping VRF 'Global' (default)")
                    continue
                resolver.resolve_all_in_payload(p)
                vrf_payloads.append(p)
            
            # Use bulk if multiple VRFs, otherwise single POST
            if len(vrf_payloads) > 1:
                _check_stop_requested(app_username)
                try:
                    logger.info(f"Creating {len(vrf_payloads)} VRFs using bulk API")
                    result = post_vrfs_bulk(fmc_ip, headers, domain_uuid, device_id, vrf_payloads)
                    items = result.get("items", [])
                    for item in items:
                        vid = item.get("id")
                        vname = item.get("name")
                        if vid and vname:
                            name_to_id[str(vname)] = vid
                        applied["routing_vrfs"] += 1
                except Exception as ex:
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"VRFs (bulk): {desc}")
            else:
                # Single VRF - use individual POST
                for p in vrf_payloads:
                    _check_stop_requested(app_username)
                    try:
                        res = post_vrf(fmc_ip, headers, domain_uuid, device_id, p)
                        vid = res.get("id")
                        if vid and p.get("name"):
                            name_to_id[str(p["name"])] = vid
                        applied["routing_vrfs"] += 1
                    except Exception as ex:
                        name = p.get('name')
                        try:
                            import requests as _rq
                            if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                                desc = fmc.extract_error_description(ex.response) or str(ex)
                            else:
                                desc = str(ex)
                        except Exception:
                            desc = str(ex)
                        errors.append(f"VRF {name}: {desc}")
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
                set_progress(app_username, 91, "VRF-specific routing (Pass 1)")
                logger.info("Pass 1: Applying VRF-specific routing configs [PROGRESS: 91%]")
                for vrf_name, sections in vrf_spec.items():
                    _check_stop_requested(app_username)
                    vid = name_to_id.get(vrf_name)
                    if not vid:
                        errors.append(f"VRF-specific skipped for '{vrf_name}' (VRF not found)")
                        continue
                    
                    # BFD policies in VRF - Pass 1
                    for it in ((sections or {}).get("bfd_policies") or []):
                        _check_stop_requested(app_username)
                        try:
                            p = dict(it)
                            resolver.resolve_all_in_payload(p)
                            if has_redistribute_protocols(p):
                                clean_p, redist_data = strip_redistribute_protocols(p)
                                result = post_bfd_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                                # Store POST response and redistribution data for Pass 2
                                protocols_to_update.append(("bfd", result.get("id"), result, redist_data, vid, vrf_name, ui_auth_values))
                            else:
                                post_bfd_policy(fmc_ip, headers, domain_uuid, device_id, p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                        except Exception as ex2:
                            try:
                                import requests as _rq
                                if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                    desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                else:
                                    desc = str(ex2)
                            except Exception:
                                desc = str(ex2)
                            errors.append(f"VRF {vrf_name} BFD (Pass 1): {desc}")
                    
                    # OSPFv2 policies in VRF - Pass 1
                    for it in ((sections or {}).get("ospfv2_policies") or []):
                        _check_stop_requested(app_username)
                        try:
                            p = dict(it)
                            resolver.resolve_all_in_payload(p)
                            if has_redistribute_protocols(p):
                                clean_p, redist_data = strip_redistribute_protocols(p)
                                result = post_ospfv2_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                                # Store POST response and redistribution data for Pass 2
                                protocols_to_update.append(("ospfv2", result.get("id"), result, redist_data, vid, vrf_name, ui_auth_values))
                            else:
                                post_ospfv2_policy(fmc_ip, headers, domain_uuid, device_id, p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                        except Exception as ex2:
                            try:
                                import requests as _rq
                                if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                    desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                else:
                                    desc = str(ex2)
                            except Exception:
                                desc = str(ex2)
                            errors.append(f"VRF {vrf_name} OSPFv2 (Pass 1): {desc}")
                    
                    # BGP policies in VRF - Pass 1
                    for it in ((sections or {}).get("bgp_policies") or []):
                        _check_stop_requested(app_username)
                        try:
                            p = dict(it)
                            resolver.resolve_all_in_payload(p)
                            if has_redistribute_protocols(p):
                                clean_p, redist_data = strip_redistribute_protocols(p)
                                result = post_bgp_policy(fmc_ip, headers, domain_uuid, device_id, clean_p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                                # Store POST response and redistribution data for Pass 2
                                protocols_to_update.append(("bgp", result.get("id"), result, redist_data, vid, vrf_name, ui_auth_values))
                            else:
                                post_bgp_policy(fmc_ip, headers, domain_uuid, device_id, p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                        except Exception as ex2:
                            try:
                                import requests as _rq
                                if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                    desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                else:
                                    desc = str(ex2)
                            except Exception:
                                desc = str(ex2)
                            errors.append(f"VRF {vrf_name} BGP (Pass 1): {desc}")
                    
                    # OSPFv2 interfaces in VRF (no redistribution)
                    for it in ((sections or {}).get("ospfv2_interfaces") or []):
                        _check_stop_requested(app_username)
                        try:
                            p = dict(it)
                            resolver.resolve_all_in_payload(p)
                            post_ospfv2_interface(fmc_ip, headers, domain_uuid, device_id, p, vrf_id=vid, vrf_name=vrf_name, ui_auth_values=ui_auth_values)
                        except Exception as ex2:
                            try:
                                import requests as _rq
                                if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                    desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                else:
                                    desc = str(ex2)
                            except Exception:
                                desc = str(ex2)
                            errors.append(f"VRF {vrf_name} OSPFv2 interface: {desc}")
                    # Bulk for static routes
                    ipv4s = (sections or {}).get("ipv4_static_routes") or []
                    if ipv4s:
                        for group in (chunks(ipv4s, batch_size) if apply_bulk else [ipv4s]):
                            _check_stop_requested(app_username)
                            try:
                                out = []
                                for it in group:
                                    _check_stop_requested(app_username)
                                    p = dict(it)
                                    resolver.resolve_all_in_payload(p)
                                    out.append(p)
                                if out:
                                    post_ipv4_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], vrf_id=vid, vrf_name=vrf_name, bulk=(len(out) > 1))
                            except Exception as ex2:
                                try:
                                    import requests as _rq
                                    if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                        desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                    else:
                                        desc = str(ex2)
                                except Exception:
                                    desc = str(ex2)
                                errors.append(f"VRF {vrf_name} ipv4_static_routes: {desc}")
                    ipv6s = (sections or {}).get("ipv6_static_routes") or []
                    if ipv6s:
                        for group in (chunks(ipv6s, batch_size) if apply_bulk else [ipv6s]):
                            _check_stop_requested(app_username)
                            try:
                                out = []
                                for it in group:
                                    _check_stop_requested(app_username)
                                    p = dict(it)
                                    resolver.resolve_all_in_payload(p)
                                    out.append(p)
                                if out:
                                    post_ipv6_static_route(fmc_ip, headers, domain_uuid, device_id, out if len(out) > 1 else out[0], vrf_id=vid, vrf_name=vrf_name, bulk=(len(out) > 1))
                            except Exception as ex2:
                                try:
                                    import requests as _rq
                                    if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                        desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                    else:
                                        desc = str(ex2)
                                except Exception:
                                    desc = str(ex2)
                                errors.append(f"VRF {vrf_name} ipv6_static_routes: {desc}")
                    
                    # ECMP zones in VRF (no redistribution)
                    for it in ((sections or {}).get("ecmp_zones") or []):
                        _check_stop_requested(app_username)
                        try:
                            p = dict(it)
                            resolver.resolve_all_in_payload(p)
                            post_ecmp_zone(fmc_ip, headers, domain_uuid, device_id, p)
                        except Exception as ex2:
                            try:
                                import requests as _rq
                                if isinstance(ex2, _rq.exceptions.RequestException) and getattr(ex2, "response", None) is not None:
                                    desc = fmc.extract_error_description(ex2.response) or str(ex2)
                                else:
                                    desc = str(ex2)
                            except Exception:
                                desc = str(ex2)
                            errors.append(f"VRF {vrf_name} ECMP zone: {desc}")
        
        # ========== PASS 2: Update protocols with redistribution ==========
        if protocols_to_update:
            logger.info("=" * 80)
            logger.info(f"🔄 PASS 2: Updating {len(protocols_to_update)} Routing Protocols with Redistribution")
            logger.info("=" * 80)
            set_progress(app_username, 93, "Applying Redistribution (Pass 2)")
            
            for idx, (protocol_type, obj_id, post_response, redist_data, vrf_id, vrf_name, ui_auth) in enumerate(protocols_to_update, 1):
                _check_stop_requested(app_username)
                try:
                    # Use POST response as base (has correct FMC-assigned IDs)
                    # and restore redistributeProtocols into it
                    p = dict(post_response)
                    p = restore_redistribute_protocols(p, redist_data)
                    
                    # Resolve any object references in the redistribution config
                    resolver.resolve_all_in_payload(p)
                    
                    if protocol_type == "bgp":
                        put_bgp_policy(fmc_ip, headers, domain_uuid, device_id, obj_id, p, vrf_id=vrf_id, vrf_name=vrf_name, ui_auth_values=ui_auth)
                        nm = str(p.get("name") or "<unnamed>")
                        logger.info(f"  [{idx}/{len(protocols_to_update)}] Updated BGP policy {nm} with redistribution")
                    elif protocol_type == "ospfv2":
                        put_ospfv2_policy(fmc_ip, headers, domain_uuid, device_id, obj_id, p, vrf_id=vrf_id, vrf_name=vrf_name, ui_auth_values=ui_auth)
                        nm = str(p.get("name") or p.get("processId") or "<unnamed>")
                        logger.info(f"  [{idx}/{len(protocols_to_update)}] Updated OSPFv2 policy {nm} with redistribution")
                    elif protocol_type == "ospfv3":
                        put_ospfv3_policy(fmc_ip, headers, domain_uuid, device_id, obj_id, p, ui_auth_values=ui_auth)
                        nm = str(p.get("name") or p.get("processId") or "<unnamed>")
                        logger.info(f"  [{idx}/{len(protocols_to_update)}] Updated OSPFv3 policy {nm} with redistribution")
                    elif protocol_type == "eigrp":
                        put_eigrp_policy(fmc_ip, headers, domain_uuid, device_id, obj_id, p, ui_auth_values=ui_auth)
                        nm = str(p.get("name") or "<unnamed>")
                        logger.info(f"  [{idx}/{len(protocols_to_update)}] Updated EIGRP policy {nm} with redistribution")
                    elif protocol_type == "bfd":
                        put_bfd_policy(fmc_ip, headers, domain_uuid, device_id, obj_id, p, vrf_id=vrf_id, vrf_name=vrf_name, ui_auth_values=ui_auth)
                        nm = str(p.get("name") or "<unnamed>")
                        logger.info(f"  [{idx}/{len(protocols_to_update)}] Updated BFD policy {nm} with redistribution")
                        
                except Exception as ex:
                    protocol_name = f"{protocol_type} {obj_id}"
                    if vrf_name:
                        protocol_name = f"VRF {vrf_name} {protocol_name}"
                    try:
                        import requests as _rq
                        if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                            desc = fmc.extract_error_description(ex.response) or str(ex)
                        else:
                            desc = str(ex)
                    except Exception:
                        desc = str(ex)
                    errors.append(f"{protocol_name} (Pass 2 redistribution): {desc}")
                    logger.error(f"  [{idx}/{len(protocols_to_update)}] Failed to update {protocol_name}: {desc}")

    set_progress(app_username, 95, "Finishing up...")
    logger.info("=" * 80)
    logger.info("✅ Finished Phase 4: Routing [PROGRESS: 95%]")
    logger.info("=" * 80)

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
        elif type_key == "routing_bfd_policies":
            # BFD policies: show template name
            for it in (items or []):
                try:
                    template_name = ((it.get("template") or {}).get("name") or "").strip()
                except Exception:
                    template_name = ""
                names.append(template_name or "<unnamed>")
        elif type_key == "routing_eigrp_policies":
            # EIGRP policies: show AS number
            for it in (items or []):
                asn = it.get("asNumber")
                names.append(f"AS {asn}" if asn else "<unnamed>")
        elif type_key in ("routing_ipv4_static_routes", "routing_ipv6_static_routes"):
            # Static routes: show "interfaceName via gateway.literal.value"
            for it in (items or []):
                try:
                    iface = (it.get("interfaceName") or "").strip()
                    gateway = ((it.get("gateway") or {}).get("literal") or {}).get("value") or ""
                    if iface and gateway:
                        names.append(f"{iface} via {gateway}")
                    elif iface:
                        names.append(iface)
                    else:
                        names.append("<unnamed>")
                except Exception:
                    names.append("<unnamed>")
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

    # Build skipped rows: one row per skipped item
    skipped_rows = []
    if skipped:
        for s in skipped:
            try:
                prefix, sep, msg = str(s).partition(": ")
                type_and_name = prefix.strip()  # e.g., "objects_network_networks sgt_server_nw"
                if " " in type_and_name:
                    t_full, name_val = type_and_name.split(" ", 1)
                else:
                    t_full = type_and_name
                    name_val = type_and_name
                t_disp = _display_name_for_type(t_full)
                skipped_rows.append([t_disp, name_val.strip(), msg.strip()])
            except Exception:
                skipped_rows.append(["<unknown>", "<unknown>", str(s)])
        skipped_table = _format_table(["Type", "Name", "Reason"], skipped_rows)
        logger.info("\nConfigurations Skipped\n" + skipped_table)

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
                t_disp = _display_name_for_type(t_full)
                failed_rows.append([t_disp, name_val.strip(), msg.strip()])
            except Exception:
                failed_rows.append(["<unknown>", "<unknown>", str(e)])
        failed_table = _format_table(["Type", "Name", "Error"], failed_rows)
        logger.info("\nConfigurations Failed\n" + failed_table)

    set_progress(app_username, 100, "Complete!")
    return {
        "success": True, 
        "applied": applied, 
        "errors": errors, 
        "skipped": skipped,
        "summary_tables": {
            "applied": applied_rows,
            "skipped": skipped_rows,
            "failed": failed_rows
        }
    }

# -----------------------
# Chassis Configuration
# -----------------------

def _export_chassis_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a YAML export for chassis interfaces and logical devices."""
    _apply_debug_flag(payload)
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username
        device_ids: List[str] = payload.get("device_ids") or []
        if not fmc_ip or not username or not password or not device_ids:
            return {"success": False, "message": "Missing fmc_ip, username, password, or device_ids"}
        if len(device_ids) != 1:
            return {"success": False, "message": "Select exactly one chassis for Get Config export"}

        sel_domain = (payload.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain

        chassis_id = device_ids[0]

        # Try to resolve chassis name from device records for filename
        from utils.fmc_api import get_devicerecords
        records = get_devicerecords(fmc_ip, headers, domain_uuid, bulk=True) or []
        rec_map = {str(r.get("id")): r for r in records}
        dev_rec = rec_map.get(chassis_id) or {}
        chassis_name = (dev_rec.get("name") or dev_rec.get("hostName") or chassis_id).strip() or chassis_id

        logger.info(f"Exporting chassis configuration for {chassis_name} ({chassis_id})")

        from utils.fmc_api import get_chassis_interfaces, get_chassis_logical_devices

        admin_password = (payload.get("chassis_admin_password") or "").strip()

        # Phase 1: Interfaces (single API call)
        set_progress(app_username, 5, "Phase 1: Fetching Chassis Interfaces...")
        logger.info("=" * 80)
        logger.info("📥 Phase 1: Chassis Interfaces [PROGRESS: 5%]")
        logger.info("=" * 80)

        all_ifaces = get_chassis_interfaces(fmc_ip, domain_uuid, chassis_id) or []
        logger.info(f"  Fetched {len(all_ifaces)} total chassis interfaces")

        # Split by type
        raw_phys = [i for i in all_ifaces if i.get("type") == "PhysicalInterface"]
        raw_eth = [i for i in all_ifaces if i.get("type") == "EtherChannelInterface"]
        raw_sub = [i for i in all_ifaces if i.get("type") == "SubInterface"]

        # Strip non-portable keys
        def _strip_top(lst):
            out = []
            for it in (lst or []):
                p = dict(it)
                p.pop("links", None)
                p.pop("metadata", None)
                p.pop("id", None)
                out.append(p)
            return out

        phys_out = _strip_top(raw_phys)
        eth_out = _strip_top(raw_eth)
        sub_out = _strip_top(raw_sub)

        # Phase 1a: Physical Interfaces
        set_progress(app_username, 15, "Phase 1a: Physical Interfaces")
        logger.info("-" * 60)
        logger.info(f"  Phase 1a: Physical Interfaces ({len(phys_out)})")
        logger.info("-" * 60)
        try:
            fmc._log_pretty_table("Physical Interfaces", ["Name", "PortType", "AdminState"],
                [[str(i.get("name","")), str(i.get("portType","")), str(i.get("adminState",""))] for i in phys_out])
        except Exception:
            pass

        # Phase 1b: EtherChannel Interfaces
        set_progress(app_username, 25, "Phase 1b: EtherChannel Interfaces")
        logger.info("-" * 60)
        logger.info(f"  Phase 1b: EtherChannel Interfaces ({len(eth_out)})")
        logger.info("-" * 60)
        try:
            fmc._log_pretty_table("EtherChannel Interfaces", ["Name", "EthChannelId", "PortType"],
                [[str(i.get("name","")), str(i.get("etherChannelId","")), str(i.get("portType",""))] for i in eth_out])
        except Exception:
            pass

        # Phase 1c: Subinterfaces
        set_progress(app_username, 35, "Phase 1c: Subinterfaces")
        logger.info("-" * 60)
        logger.info(f"  Phase 1c: Subinterfaces ({len(sub_out)})")
        logger.info("-" * 60)
        try:
            fmc._log_pretty_table("Subinterfaces", ["Name", "SubIntfId", "VlanId"],
                [[str(i.get("name","")), str(i.get("subIntfId","")), str(i.get("vlanId",""))] for i in sub_out])
        except Exception:
            pass

        set_progress(app_username, 45, "Phase 1: Chassis Interfaces Complete")
        logger.info("=" * 80)
        logger.info("✅ Phase 1 Complete: Chassis Interfaces")
        logger.info("=" * 80)

        # Phase 2: Logical Devices
        set_progress(app_username, 50, "Phase 2: Fetching Logical Devices...")
        logger.info("=" * 80)
        logger.info("📥 Phase 2: Logical Devices [PROGRESS: 50%]")
        logger.info("=" * 80)

        raw_ld = get_chassis_logical_devices(fmc_ip, domain_uuid, chassis_id) or []
        logger.info(f"  Fetched {len(raw_ld)} logical device(s)")

        ld_out = []
        for it in (raw_ld or []):
            p = dict(it)
            p.pop("links", None)
            p.pop("metadata", None)
            p.pop("id", None)
            ld_out.append(p)

        # Replace adminPassword if provided
        if admin_password:
            for ld in ld_out:
                mb = ld.get("managementBootstrap")
                if isinstance(mb, dict):
                    mb["adminPassword"] = admin_password
                    logger.info(f"  Replaced adminPassword for logical device '{ld.get('name', '<unnamed>')}'")
        else:
            logger.info("  No admin password provided — adminPassword fields left as-is from FMC")

        # Phase 2a: Per-device details
        for idx, ld in enumerate(ld_out):
            ld_name = ld.get("name", f"App {idx+1}")
            set_progress(app_username, 55 + int(idx / max(len(ld_out), 1) * 15), f"Phase 2a: {ld_name}")
            logger.info("-" * 60)
            logger.info(f"  Logical Device: {ld_name}")
            logger.info("-" * 60)
            try:
                details = [
                    ["FTD Version", str(ld.get("ftdApplicationVersion", ""))],
                    ["Admin State", str(ld.get("adminState", ""))],
                    ["Resource Profile", str(ld.get("resourceProfileName", ""))],
                ]
                ext_ports = [str(p.get("name", "")) for p in (ld.get("externalPortLink") or [])]
                if ext_ports:
                    details.append(["External Ports", ", ".join(ext_ports)])
                mb = ld.get("managementBootstrap") or {}
                if mb.get("managementInterface"):
                    details.append(["Mgmt Interface", str(mb["managementInterface"])])
                if mb.get("managementIp"):
                    details.append(["Mgmt IP", str(mb["managementIp"])])
                pw_display = "***set***" if admin_password else str(mb.get("adminPassword", ""))
                details.append(["Admin Password", pw_display])
                fmc._log_pretty_table(f"Logical Device: {ld_name}", ["Property", "Value"], details)
            except Exception:
                pass

        set_progress(app_username, 75, "Phase 2: Logical Devices Complete")
        logger.info("=" * 80)
        logger.info("✅ Phase 2 Complete: Logical Devices")
        logger.info("=" * 80)

        cfg_out = {
            "chassis_interfaces": {
                "physicalinterfaces": phys_out,
                "etherchannelinterfaces": eth_out,
                "subinterfaces": sub_out,
            },
            "logical_devices": ld_out,
        }

        # Build filename
        def _safe(s: str) -> str:
            s = (s or "").strip()
            return "".join(c if c.isalnum() or c in ("-", "_") else "-" for c in s) or "unknown"

        meta = payload.get("device_meta") or {}
        name_override = str(meta.get("name") or "").strip()
        safe_name = _safe(name_override or chassis_name)
        dev_ver = str(meta.get("version") or dev_rec.get("sw_version") or dev_rec.get("softwareVersion") or "").strip()
        dev_model = str(meta.get("model") or dev_rec.get("model") or "").strip()
        ts = time.strftime("%Y%m%d_%H%M%S")
        filename = f"chassis_{_safe(safe_name)}_{_safe(dev_ver)}_{_safe(dev_model)}_{ts}.yaml"

        set_progress(app_username, 95, "Generating YAML...")
        content = yaml.safe_dump(cfg_out, sort_keys=False)
        set_progress(app_username, 100, "Complete!")
        return {"success": True, "filename": filename, "content": content}
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"Chassis export error: {e}")
        return {"success": False, "message": str(e)}


def _apply_chassis_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Apply chassis configuration (interfaces + logical devices) to one chassis device."""
    _apply_debug_flag(payload)
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username
        device_ids: List[str] = payload.get("device_ids") or []
        if not fmc_ip or not username or not password or not device_ids:
            return {"success": False, "message": "Missing fmc_ip, username, password, or device_ids"}
        if len(device_ids) != 1:
            return {"success": False, "message": "Select exactly one chassis for Push Config"}

        sel_domain = (payload.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain
        chassis_id = device_ids[0]

        from utils.fmc_api import (
            get_chassis_interfaces, get_chassis_logical_devices,
            put_chassis_physical_interface,
            post_chassis_etherchannel_interface, put_chassis_etherchannel_interface,
            post_chassis_subinterface, put_chassis_subinterface,
            post_chassis_logical_device, put_chassis_logical_device,
        )

        cfg = payload.get("config") or {}
        chassis_ifaces = cfg.get("chassis_interfaces") or {}
        src_phys = chassis_ifaces.get("physicalinterfaces") or []
        src_eth = chassis_ifaces.get("etherchannelinterfaces") or []
        src_sub = chassis_ifaces.get("subinterfaces") or []
        src_ld = cfg.get("logical_devices") or []

        # Support both legacy flat keys and new selected_types dict from React frontend
        sel = payload.get("selected_types") or {}
        apply_phys = bool(sel.get("chassis_interfaces.physicalinterfaces", payload.get("apply_chassis_physicalinterfaces", True)))
        apply_eth = bool(sel.get("chassis_interfaces.etherchannelinterfaces", payload.get("apply_chassis_etherchannelinterfaces", True)))
        apply_sub = bool(sel.get("chassis_interfaces.subinterfaces", payload.get("apply_chassis_subinterfaces", True)))

        # Logical devices: collect selected LD names from selected_types (keys like "logical_devices.myld")
        if sel:
            selected_ld_names = set()
            for k, v in sel.items():
                if k.startswith("logical_devices.") and v:
                    selected_ld_names.add(k.replace("logical_devices.", "", 1))
            apply_ld = len(selected_ld_names) > 0
        else:
            raw_apply_ld = payload.get("apply_chassis_logical_devices", True)
            if isinstance(raw_apply_ld, list):
                selected_ld_names = set(raw_apply_ld)
                apply_ld = len(selected_ld_names) > 0
            elif raw_apply_ld:
                selected_ld_names = None  # None means "all"
                apply_ld = True
            else:
                selected_ld_names = set()
                apply_ld = False

        admin_password = (payload.get("chassis_admin_password") or payload.get("admin_password") or "").strip()

        applied = {"physicalinterfaces": 0, "etherchannelinterfaces": 0, "subinterfaces": 0, "logical_devices": 0}
        applied_names: Dict[str, List[str]] = {"physicalinterfaces": [], "etherchannelinterfaces": [], "subinterfaces": [], "logical_devices": []}
        errors: List[str] = []
        skipped: List[str] = []

        # Build destination maps from target chassis
        logger.info("=" * 80)
        logger.info("📥 Building destination interface maps for target chassis")
        logger.info("=" * 80)
        set_progress(app_username, 5, "Building destination maps...")

        dest_all = get_chassis_interfaces(fmc_ip, domain_uuid, chassis_id) or []
        dest_phys_map = {i.get("name"): i.get("id") for i in dest_all if i.get("type") == "PhysicalInterface" and i.get("name") and i.get("id")}
        dest_eth_map = {i.get("name"): i.get("id") for i in dest_all if i.get("type") == "EtherChannelInterface" and i.get("name") and i.get("id")}
        dest_sub_map = {i.get("name"): i.get("id") for i in dest_all if i.get("type") == "SubInterface" and i.get("name") and i.get("id")}

        dest_ld_all = get_chassis_logical_devices(fmc_ip, domain_uuid, chassis_id) or []
        dest_ld_map = {i.get("name"): i.get("id") for i in dest_ld_all if i.get("name") and i.get("id")}

        logger.info(f"  Destination maps: phys={len(dest_phys_map)}, eth={len(dest_eth_map)}, sub={len(dest_sub_map)}, ld={len(dest_ld_map)}")

        def _remap_interface_ref(ref: dict, phys_m: dict, eth_m: dict, sub_m: dict):
            """Remap a single interface reference dict by name+type."""
            if not isinstance(ref, dict) or not ref.get("name"):
                return
            name = ref["name"]
            rtype = ref.get("type", "")
            new_id = None
            if rtype == "PhysicalInterface":
                new_id = phys_m.get(name)
            elif rtype == "EtherChannelInterface":
                new_id = eth_m.get(name)
            elif rtype == "SubInterface":
                new_id = sub_m.get(name)
            else:
                new_id = phys_m.get(name) or eth_m.get(name) or sub_m.get(name)
            if new_id:
                old_id = ref.get("id")
                ref["id"] = new_id
                if old_id and old_id != new_id:
                    logger.info(f"  Remap {rtype} '{name}': {old_id} -> {new_id}")

        # --- 1) Physical Interfaces (PUT only) ---
        if apply_phys and src_phys:
            set_progress(app_username, 15, "Phase 1: Physical Interfaces")
            logger.info("=" * 80)
            logger.info(f"📤 Phase 1: Physical Interfaces ({len(src_phys)} items) [PROGRESS: 15%]")
            logger.info("=" * 80)
            for item in src_phys:
                name = item.get("name", "<unnamed>")
                try:
                    dest_id = dest_phys_map.get(name)
                    if not dest_id:
                        skipped.append(f"physicalinterfaces {name}: No matching interface on target chassis")
                        continue
                    p = dict(item)
                    p.pop("links", None)
                    p.pop("metadata", None)
                    p.pop("channelGroupId", None)
                    p["id"] = dest_id
                    put_chassis_physical_interface(fmc_ip, domain_uuid, chassis_id, dest_id, p)
                    applied["physicalinterfaces"] += 1
                    applied_names["physicalinterfaces"].append(name)
                except Exception as ex:
                    desc = fmc.extract_error_description(getattr(ex, "response", None)) if hasattr(ex, "response") else str(ex)
                    errors.append(f"physicalinterfaces {name}: {desc}")
                    logger.error(f"  Failed to PUT physical interface {name}: {desc}")

        # --- 2) EtherChannel Interfaces (PUT existing / POST new) ---
        if apply_eth and src_eth:
            set_progress(app_username, 30, "Phase 2: EtherChannel Interfaces")
            logger.info("=" * 80)
            logger.info(f"📤 Phase 2: EtherChannel Interfaces ({len(src_eth)} items) [PROGRESS: 30%]")
            logger.info("=" * 80)
            for item in src_eth:
                name = item.get("name", "<unnamed>")
                try:
                    p = dict(item)
                    p.pop("links", None)
                    p.pop("metadata", None)
                    p.pop("id", None)
                    # Remap selectedInterfaces references
                    for ref in (p.get("selectedInterfaces") or []):
                        _remap_interface_ref(ref, dest_phys_map, dest_eth_map, dest_sub_map)
                    dest_id = dest_eth_map.get(name)
                    if dest_id:
                        p["id"] = dest_id
                        put_chassis_etherchannel_interface(fmc_ip, domain_uuid, chassis_id, dest_id, p)
                    else:
                        post_chassis_etherchannel_interface(fmc_ip, domain_uuid, chassis_id, p)
                    applied["etherchannelinterfaces"] += 1
                    applied_names["etherchannelinterfaces"].append(name)
                except Exception as ex:
                    desc = fmc.extract_error_description(getattr(ex, "response", None)) if hasattr(ex, "response") else str(ex)
                    errors.append(f"etherchannelinterfaces {name}: {desc}")
                    logger.error(f"  Failed etherchannel {name}: {desc}")

            # Refresh dest_eth_map after etherchannel creation
            try:
                refreshed = get_chassis_interfaces(fmc_ip, domain_uuid, chassis_id) or []
                dest_eth_map = {i.get("name"): i.get("id") for i in refreshed if i.get("type") == "EtherChannelInterface" and i.get("name") and i.get("id")}
                dest_sub_map = {i.get("name"): i.get("id") for i in refreshed if i.get("type") == "SubInterface" and i.get("name") and i.get("id")}
                logger.info(f"  Refreshed maps: eth={len(dest_eth_map)}, sub={len(dest_sub_map)}")
            except Exception:
                pass

        # --- 3) Subinterfaces (PUT existing / POST new) ---
        if apply_sub and src_sub:
            set_progress(app_username, 50, "Phase 3: Subinterfaces")
            logger.info("=" * 80)
            logger.info(f"📤 Phase 3: Subinterfaces ({len(src_sub)} items) [PROGRESS: 50%]")
            logger.info("=" * 80)
            for item in src_sub:
                name = item.get("name", "<unnamed>")
                try:
                    p = dict(item)
                    p.pop("links", None)
                    p.pop("metadata", None)
                    p.pop("id", None)
                    # Remap parentInterface reference
                    parent = p.get("parentInterface")
                    if isinstance(parent, dict):
                        _remap_interface_ref(parent, dest_phys_map, dest_eth_map, dest_sub_map)
                    dest_id = dest_sub_map.get(name)
                    if dest_id:
                        p["id"] = dest_id
                        put_chassis_subinterface(fmc_ip, domain_uuid, chassis_id, dest_id, p)
                    else:
                        post_chassis_subinterface(fmc_ip, domain_uuid, chassis_id, p)
                    applied["subinterfaces"] += 1
                    applied_names["subinterfaces"].append(name)
                except Exception as ex:
                    desc = fmc.extract_error_description(getattr(ex, "response", None)) if hasattr(ex, "response") else str(ex)
                    errors.append(f"subinterfaces {name}: {desc}")
                    logger.error(f"  Failed subinterface {name}: {desc}")

            # Refresh dest_sub_map after subinterface creation
            try:
                refreshed = get_chassis_interfaces(fmc_ip, domain_uuid, chassis_id) or []
                dest_sub_map = {i.get("name"): i.get("id") for i in refreshed if i.get("type") == "SubInterface" and i.get("name") and i.get("id")}
                # Also refresh etherchannel map in case any new ones appeared
                dest_eth_map = {i.get("name"): i.get("id") for i in refreshed if i.get("type") == "EtherChannelInterface" and i.get("name") and i.get("id")}
                logger.info(f"  Refreshed maps: eth={len(dest_eth_map)}, sub={len(dest_sub_map)}")
            except Exception:
                pass

        # --- 4) Logical Devices (PUT existing / POST new) ---
        if apply_ld and src_ld:
            # Filter by selected names if a list was provided
            if selected_ld_names is not None:
                filtered_ld = [ld for ld in src_ld if ld.get("name", "") in selected_ld_names]
            else:
                filtered_ld = list(src_ld)
            set_progress(app_username, 70, "Phase 4: Logical Devices")
            logger.info("=" * 80)
            logger.info(f"📤 Phase 4: Logical Devices ({len(filtered_ld)} selected) [PROGRESS: 70%]")
            logger.info("=" * 80)
            for item in filtered_ld:
                name = item.get("name", "<unnamed>")
                try:
                    p = dict(item)
                    p.pop("links", None)
                    p.pop("metadata", None)
                    p.pop("id", None)
                    # Remap externalPortLink references
                    for ref in (p.get("externalPortLink") or []):
                        _remap_interface_ref(ref, dest_phys_map, dest_eth_map, dest_sub_map)
                    # Inject adminPassword override if provided
                    if admin_password:
                        mb = p.get("managementBootstrap")
                        if isinstance(mb, dict):
                            mb["adminPassword"] = admin_password
                        else:
                            p["managementBootstrap"] = {"adminPassword": admin_password}
                    dest_id = dest_ld_map.get(name)
                    if dest_id:
                        p["id"] = dest_id
                        put_chassis_logical_device(fmc_ip, domain_uuid, chassis_id, dest_id, p)
                    else:
                        post_chassis_logical_device(fmc_ip, domain_uuid, chassis_id, p)
                    applied["logical_devices"] += 1
                    applied_names["logical_devices"].append(name)
                except Exception as ex:
                    desc = fmc.extract_error_description(getattr(ex, "response", None)) if hasattr(ex, "response") else str(ex)
                    errors.append(f"logical_devices {name}: {desc}")
                    logger.error(f"  Failed logical device {name}: {desc}")

        # Build summary tables
        _CHASSIS_TYPE_DISPLAY = {
            "physicalinterfaces": "Physical Interface",
            "etherchannelinterfaces": "EtherChannel Interface",
            "subinterfaces": "Subinterface",
            "logical_devices": "Logical Device",
        }

        def _format_table(hdrs, rows):
            if not rows:
                return "(none)"
            widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(hdrs)]
            sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
            def rr(vals):
                return "|" + "|".join(" " + str(v).ljust(w) + " " for v, w in zip(vals, widths)) + "|"
            return "\n".join([sep, rr(hdrs), sep] + [rr(r) for r in rows] + [sep])

        applied_rows = []
        for key, cnt in applied.items():
            if cnt <= 0:
                continue
            disp = _CHASSIS_TYPE_DISPLAY.get(key, key)
            names = applied_names.get(key) or []
            for i_idx, n in enumerate(names):
                applied_rows.append([disp if i_idx == 0 else "", n, str(cnt) if i_idx == 0 else ""])

        if applied_rows:
            logger.info("\nConfigurations Applied\n" + _format_table(["Type", "Name", "Count"], applied_rows))

        skipped_rows = []
        for s in skipped:
            try:
                prefix, _, msg = str(s).partition(": ")
                if " " in prefix:
                    t_full, name_val = prefix.split(" ", 1)
                else:
                    t_full, name_val = prefix, prefix
                skipped_rows.append([_CHASSIS_TYPE_DISPLAY.get(t_full, t_full), name_val.strip(), msg.strip()])
            except Exception:
                skipped_rows.append(["<unknown>", "<unknown>", str(s)])
        if skipped_rows:
            logger.info("\nConfigurations Skipped\n" + _format_table(["Type", "Name", "Reason"], skipped_rows))

        failed_rows = []
        for e in errors:
            try:
                prefix, _, msg = str(e).partition(": ")
                if " " in prefix:
                    t_full, name_val = prefix.split(" ", 1)
                else:
                    t_full, name_val = prefix, prefix
                failed_rows.append([_CHASSIS_TYPE_DISPLAY.get(t_full, t_full), name_val.strip(), msg.strip()])
            except Exception:
                failed_rows.append(["<unknown>", "<unknown>", str(e)])
        if failed_rows:
            logger.info("\nConfigurations Failed\n" + _format_table(["Type", "Name", "Error"], failed_rows))

        set_progress(app_username, 100, "Complete!")
        return {
            "success": True,
            "applied": applied,
            "errors": errors,
            "skipped": skipped,
            "summary_tables": {
                "applied": applied_rows,
                "skipped": skipped_rows,
                "failed": failed_rows,
            }
        }
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"Chassis apply error: {e}")
        return {"success": False, "message": str(e)}


def _export_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a YAML export for exactly one selected device and return in-memory content.

    Expected payload:
      { fmc_ip, username, password, domain_uuid?, device_ids: [singleId] }
    Returns: { success, filename, content }
    """
    _apply_debug_flag(payload)
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username  # For progress tracking
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
            fix_vrf_interface_types,
        )
        # Object getters (ID-based selective fetch)
        from utils.fmc_api import get_objects_by_type_and_ids

        records = get_devicerecords(fmc_ip, headers, domain_uuid, bulk=True) or []
        rec_map = {str(r.get("id")): r for r in records}

        dev_id = device_ids[0]
        dev_rec = rec_map.get(dev_id) or {}
        dev_name = (dev_rec.get("name") or dev_rec.get("hostName") or dev_id).strip() or dev_id
        logger.info(f"Exporting configuration for device {dev_name} ({dev_id})")
        
        # Phase 1: Interfaces
        set_progress(app_username, 5, "Phase 1: Interfaces")
        logger.info("=" * 80)
        logger.info("📥 Starting Phase 1: Interfaces [PROGRESS: 5%]")
        logger.info("=" * 80)
        
        set_progress(app_username, 8, "Section 1.1: Loopback Interfaces")
        logger.info("  Starting Section 1.1: Loopback Interfaces [PROGRESS: 8%]")
        loops = get_loopback_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.1: Loopback Interfaces ({len(loops)} found)")
        
        set_progress(app_username, 12, "Section 1.2: Physical Interfaces")
        logger.info("  Starting Section 1.2: Physical Interfaces [PROGRESS: 12%]")
        phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.2: Physical Interfaces ({len(phys)} found)")
        
        set_progress(app_username, 16, "Section 1.3: EtherChannel Interfaces")
        logger.info("  Starting Section 1.3: EtherChannel Interfaces [PROGRESS: 16%]")
        eths = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.3: EtherChannel Interfaces ({len(eths)} found)")
        
        set_progress(app_username, 20, "Section 1.4: Subinterfaces")
        logger.info("  Starting Section 1.4: Subinterfaces [PROGRESS: 20%]")
        subs = get_subinterfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.4: Subinterfaces ({len(subs)} found)")
        
        set_progress(app_username, 24, "Section 1.5: VTI Interfaces")
        logger.info("  Starting Section 1.5: VTI Interfaces [PROGRESS: 24%]")
        vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.5: VTI Interfaces ({len(vtis)} found)")
        
        set_progress(app_username, 28, "Section 1.6: Inline Sets")
        logger.info("  Starting Section 1.6: Inline Sets [PROGRESS: 28%]")
        inlines = get_inline_sets(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.6: Inline Sets ({len(inlines)} found)")
        
        set_progress(app_username, 31, "Section 1.7: Bridge Group Interfaces")
        logger.info("  Starting Section 1.7: Bridge Group Interfaces [PROGRESS: 31%]")
        bgis = get_bridge_group_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
        logger.info(f"  Finished Section 1.7: Bridge Group Interfaces ({len(bgis)} found)")

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
        
        logger.info("=" * 80)
        logger.info("✅ Finished Phase 1: Interfaces")
        logger.info("=" * 80)
        set_progress(app_username, 33, "Phase 1: Interfaces Complete")

        # Fill missing securityZone.name using securityZone.id before dependency scan
        try:
            # Collect all unique security zone IDs from all interface types
            sz_ids: Set[str] = set()
            for iface_list in (loops, phys, eths, subs, vtis, inlines, bgis):
                for iface in (iface_list or []):
                    try:
                        sz = iface.get("securityZone") or {}
                        sz_id = sz.get("id")
                        if sz_id and isinstance(sz_id, str):
                            sz_ids.add(sz_id)
                    except Exception:
                        continue
            
            # Fetch security zones and build ID->name map
            if sz_ids:
                from utils.fmc_api import get_security_zones
                all_zones = get_security_zones(fmc_ip, headers, domain_uuid) or []
                id_to_name = {str(z.get("id")): str(z.get("name") or "") for z in all_zones if z.get("id")}
                
                # Fill missing names in all interface items
                def _fill_zone_names(iface_list: List[Dict[str, Any]]):
                    for iface in (iface_list or []):
                        try:
                            sz = iface.get("securityZone")
                            if isinstance(sz, dict):
                                sz_id = sz.get("id")
                                sz_name = sz.get("name")
                                # Fill name if missing or empty but ID exists
                                if sz_id and (not sz_name or not str(sz_name).strip()):
                                    if sz_id in id_to_name:
                                        sz["name"] = id_to_name[sz_id]
                        except Exception:
                            continue
                
                _fill_zone_names(loops)
                _fill_zone_names(phys)
                _fill_zone_names(eths)
                _fill_zone_names(subs)
                _fill_zone_names(vtis)
                _fill_zone_names(inlines)
                _fill_zone_names(bgis)
                
                logger.info(f"Filled missing security zone names for {len(sz_ids)} zones")
        except Exception as ex:
            logger.warning(f"Failed to fill security zone names: {ex}")

        # Scan dependencies used by interface section only; do not fetch yet
        PHASE_OBJECT_TYPES = {
            "SecurityZone",
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

        def _infer_type_from_key_local(key_hint: str) -> List[str]:
            k = (key_hint or "").lower()
            out: List[str] = []
            # Route maps
            if "routemap" in k or ("route" in k and "map" in k) or ("route-map" in k):
                out.append("RouteMap")
            # Prefix lists
            if ("ipv4" in k and "prefix" in k) or "ipv4prefixlist" in k or ("prefix-list" in k and "ipv4" in k):
                out.append("IPv4PrefixList")
            if ("ipv6" in k and "prefix" in k) or "ipv6prefixlist" in k or ("prefix-list" in k and "ipv6" in k):
                out.append("IPv6PrefixList")
            if "prefixlist" in k and "ipv4" not in k and "ipv6" not in k:
                out.extend(["IPv4PrefixList", "IPv6PrefixList"])
            # Access lists
            if ("extended" in k and "access" in k) or "extendedaccesslist" in k:
                out.append("ExtendedAccessList")
            if ("standard" in k and "access" in k) or "standardaccesslist" in k:
                out.append("StandardAccessList")
            if "accesslist" in k or "acl" in k or "ipaccesslist" in k:
                if "ExtendedAccessList" not in out:
                    out.append("ExtendedAccessList")
                if "StandardAccessList" not in out:
                    out.append("StandardAccessList")
            # Network groups
            if "networkgroup" in k or ("network" in k and "group" in k):
                out.append("NetworkGroup")
            # Other lists
            if "communitylist" in k and "extended" not in k:
                out.append("CommunityList")
            if "extendedcommunitylist" in k or ("extended" in k and "community" in k):
                out.append("ExtendedCommunityList")
            if "aspath" in k:
                out.append("ASPathList")
            if "keychain" in k:
                out.append("KeyChain")
            if "slamonitor" in k or ("sla" in k and "monitor" in k):
                out.append("SLAMonitor")
            if "bfdtemplate" in k or ("bfd" in k and "template" in k):
                out.append("BFDTemplate")
            return out

        def _scan_deps_rows(obj: Any) -> List[List[str]]:
            seen: Set[Tuple[str, str, str]] = set()
            rows: List[List[str]] = []
            t_map = {"IPV4PrefixList": "IPv4PrefixList", "IPV6PrefixList": "IPv6PrefixList"}

            def _walk(o: Any, key_hint: str = ""):
                if isinstance(o, dict):
                    t_raw = o.get("type")
                    t = t_map.get(t_raw, t_raw)
                    oid = o.get("id")
                    name = o.get("name")
                    captured = False
                    if t in PHASE_OBJECT_TYPES:
                        key = (str(name or ""), str(t or ""), str(oid or ""))
                        if key not in seen:
                            seen.add(key)
                            rows.append([name or "", t or "", oid or ""])
                            captured = True
                    # If not captured by type, try key hint inference for dicts with name/id
                    if not captured and (name or oid):
                        for inferred_t in _infer_type_from_key_local(key_hint):
                            key = (str(name or ""), inferred_t, str(oid or ""))
                            if key not in seen:
                                seen.add(key)
                                rows.append([name or "", inferred_t, oid or ""])
                    for k, v in o.items():
                        _walk(v, k)
                elif isinstance(o, list):
                    for it in o:
                        _walk(it, key_hint)
                elif isinstance(o, str):
                    # name-only reference hinted by key
                    for t in _infer_type_from_key_local(key_hint):
                        key = (o.strip(), t, "")
                        if o.strip() and key not in seen:
                            seen.add(key)
                            rows.append([o.strip(), t, ""])

            _walk(obj)
            rows.sort(key=lambda r: (r[1], r[0], r[2]))
            return rows

        # Aggregate interface-only dependencies
        iface_rows: List[List[str]] = []
        for section in (loops, phys, eths, subs, vtis, inlines, bgis):
            iface_rows.extend(_scan_deps_rows(section))
        # Deduplicate rows across sections
        dedup_seen: Set[Tuple[str, str, str]] = set()
        dedup_rows: List[List[str]] = []
        for r in iface_rows:
            tup = (r[0], r[1], r[2])
            if tup not in dedup_seen:
                dedup_seen.add(tup)
                dedup_rows.append(r)

        # Prepare objects block holder (filled later by object sweeps)
        objects_block: Dict[str, Any] = {}
        # Aggregated dependent objects table across phases
        dep_rows_all: List[List[str]] = []
        dep_seen_all: Set[Tuple[str, str, str]] = set()
        dep_ids_by_type: Dict[str, Set[str]] = {}
        dep_names_by_type: Dict[str, Set[str]] = {}

        def _ingest_rows(rows: List[List[str]]):
            for row in (rows or []):
                try:
                    name, typ, oid = row[0], row[1], row[2]
                except Exception:
                    continue
                t = str(typ or "").strip()
                n = str(name or "").strip()
                i = str(oid or "").strip()
                key = (n, t, i)
                if key not in dep_seen_all:
                    dep_seen_all.add(key)
                    dep_rows_all.append([n, t, i])
                if t:
                    if i:
                        dep_ids_by_type.setdefault(t, set()).add(i)
                    if n:
                        dep_names_by_type.setdefault(t, set()).add(n)

        try:
            fmc._log_pretty_table("Dependent Objects (Phase 1: Interfaces)", ["Name", "Type", "UUID"], dedup_rows)
        except Exception:
            pass

        # Seed aggregated dependency table with Phase 1 rows
        _ingest_rows(dedup_rows)

        # Phase 2: Routing
        set_progress(app_username, 35, "Phase 2: Routing")
        logger.info("=" * 80)
        logger.info("📥 Starting Phase 2: Routing [PROGRESS: 35%]")
        logger.info("=" * 80)
        
        # Routing export (global lists; plus VRF-specific)
        # Each subsection is wrapped in its own try/except to continue on failure
        routing_block: Dict[str, Any] = {}
        
        set_progress(app_username, 38, "Section 2.1: BGP General Settings")
        logger.info("  Starting Section 2.1: BGP General Settings [PROGRESS: 38%]")
        try:
            bgp_general = get_bgp_general_settings(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["bgp_general_settings"] = _strip(bgp_general)
            logger.info(f"  Finished Section 2.1: BGP General Settings ({len(bgp_general)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.1: BGP General Settings: {ex}")
            routing_block["bgp_general_settings"] = []
        
        set_progress(app_username, 41, "Section 2.2: BGP Policies")
        logger.info("  Starting Section 2.2: BGP Policies [PROGRESS: 41%]")
        try:
            bgp_policies = get_bgp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["bgp_policies"] = _strip(bgp_policies)
            logger.info(f"  Finished Section 2.2: BGP Policies ({len(bgp_policies)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.2: BGP Policies: {ex}")
            routing_block["bgp_policies"] = []
        
        set_progress(app_username, 44, "Section 2.3: BFD Policies")
        logger.info("  Starting Section 2.3: BFD Policies [PROGRESS: 44%]")
        try:
            bfd_policies = get_bfd_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["bfd_policies"] = _strip(bfd_policies)
            logger.info(f"  Finished Section 2.3: BFD Policies ({len(bfd_policies)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.3: BFD Policies: {ex}")
            routing_block["bfd_policies"] = []
        
        set_progress(app_username, 47, "Section 2.4: OSPFv2 Policies")
        logger.info("  Starting Section 2.4: OSPFv2 Policies [PROGRESS: 47%]")
        try:
            ospfv2_policies = get_ospfv2_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ospfv2_policies"] = _strip(ospfv2_policies)
            logger.info(f"  Finished Section 2.4: OSPFv2 Policies ({len(ospfv2_policies)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.4: OSPFv2 Policies: {ex}")
            routing_block["ospfv2_policies"] = []
        
        set_progress(app_username, 50, "Section 2.5: OSPFv2 Interfaces")
        logger.info("  Starting Section 2.5: OSPFv2 Interfaces [PROGRESS: 50%]")
        try:
            ospfv2_interfaces = get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ospfv2_interfaces"] = _strip(ospfv2_interfaces)
            logger.info(f"  Finished Section 2.5: OSPFv2 Interfaces ({len(ospfv2_interfaces)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.5: OSPFv2 Interfaces: {ex}")
            routing_block["ospfv2_interfaces"] = []
        
        set_progress(app_username, 53, "Section 2.6: OSPFv3 Policies")
        logger.info("  Starting Section 2.6: OSPFv3 Policies [PROGRESS: 53%]")
        try:
            ospfv3_policies = get_ospfv3_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ospfv3_policies"] = _strip(ospfv3_policies)
            logger.info(f"  Finished Section 2.6: OSPFv3 Policies ({len(ospfv3_policies)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.6: OSPFv3 Policies: {ex}")
            routing_block["ospfv3_policies"] = []
        
        set_progress(app_username, 55, "Section 2.7: OSPFv3 Interfaces")
        logger.info("  Starting Section 2.7: OSPFv3 Interfaces [PROGRESS: 55%]")
        try:
            ospfv3_interfaces = get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ospfv3_interfaces"] = _strip(ospfv3_interfaces)
            logger.info(f"  Finished Section 2.7: OSPFv3 Interfaces ({len(ospfv3_interfaces)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.7: OSPFv3 Interfaces: {ex}")
            routing_block["ospfv3_interfaces"] = []
        
        set_progress(app_username, 57, "Section 2.8: EIGRP Policies")
        logger.info("  Starting Section 2.8: EIGRP Policies [PROGRESS: 57%]")
        try:
            eigrp_policies = get_eigrp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["eigrp_policies"] = _strip(eigrp_policies)
            logger.info(f"  Finished Section 2.8: EIGRP Policies ({len(eigrp_policies)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.8: EIGRP Policies: {ex}")
            routing_block["eigrp_policies"] = []
        
        set_progress(app_username, 59, "Section 2.9: PBR Policies")
        logger.info("  Starting Section 2.9: PBR Policies [PROGRESS: 59%]")
        try:
            pbr_policies = get_pbr_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["pbr_policies"] = _strip(pbr_policies)
            logger.info(f"  Finished Section 2.9: PBR Policies ({len(pbr_policies)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.9: PBR Policies: {ex}")
            routing_block["pbr_policies"] = []
        
        set_progress(app_username, 62, "Section 2.10: IPv4 Static Routes")
        logger.info("  Starting Section 2.10: IPv4 Static Routes [PROGRESS: 62%]")
        try:
            ipv4_static = get_ipv4_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ipv4_static_routes"] = _strip(ipv4_static)
            logger.info(f"  Finished Section 2.10: IPv4 Static Routes ({len(ipv4_static)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.10: IPv4 Static Routes: {ex}")
            routing_block["ipv4_static_routes"] = []
        
        set_progress(app_username, 65, "Section 2.11: IPv6 Static Routes")
        logger.info("  Starting Section 2.11: IPv6 Static Routes [PROGRESS: 65%]")
        try:
            ipv6_static = get_ipv6_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ipv6_static_routes"] = _strip(ipv6_static)
            logger.info(f"  Finished Section 2.11: IPv6 Static Routes ({len(ipv6_static)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.11: IPv6 Static Routes: {ex}")
            routing_block["ipv6_static_routes"] = []
        
        set_progress(app_username, 67, "Section 2.12: ECMP Zones")
        logger.info("  Starting Section 2.12: ECMP Zones [PROGRESS: 67%]")
        try:
            ecmp_zones = get_ecmp_zones(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            routing_block["ecmp_zones"] = _strip(ecmp_zones)
            logger.info(f"  Finished Section 2.12: ECMP Zones ({len(ecmp_zones)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.12: ECMP Zones: {ex}")
            routing_block["ecmp_zones"] = []
        
        set_progress(app_username, 69, "Section 2.13: VRFs")
        logger.info("  Starting Section 2.13: VRFs [PROGRESS: 69%]")
        try:
            vrfs = get_vrfs(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            # Fix VRF interface types (FMC API bug returns PixF1InterfaceTable instead of actual type)
            vrfs = fix_vrf_interface_types(
                vrfs,
                loopbacks=loops,
                vtis=vtis,
                physicals=phys,
                subinterfaces=subs,
                etherchannels=eths,
                bridge_groups=bgis,
            )
            routing_block["vrfs"] = _strip(vrfs)
            logger.info(f"  Finished Section 2.13: VRFs ({len(vrfs)} found)")
        except Exception as ex:
            logger.warning(f"  Failed Section 2.13: VRFs: {ex}")
            routing_block["vrfs"] = []
            vrfs = []
        
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

        logger.info("=" * 80)
        logger.info("✅ Finished Phase 2: Routing")
        logger.info("=" * 80)
        set_progress(app_username, 68, "Phase 2: Routing Complete")

        try:
            routing_rows = _scan_deps_rows(routing_block)
            # Deduplicate
            r_seen: Set[Tuple[str, str, str]] = set()
            r_out: List[List[str]] = []
            for r in routing_rows:
                tup = (r[0], r[1], r[2])
                if tup not in r_seen:
                    r_seen.add(tup)
                    r_out.append(r)
            # Append Phase 2 discoveries to aggregated table
            _ingest_rows(r_out)
            # Log aggregated dependent objects (Phase 1 + Phase 2)
            fmc._log_pretty_table("Dependent Objects (Phase 2: Routing)", ["Name", "Type", "UUID"], dep_rows_all)
        except Exception:
            pass

        # Phase 3: Objects fetching driven by dependent objects table
        set_progress(app_username, 70, "Phase 3: Objects")
        logger.info("=" * 80)
        logger.info("📥 Starting Phase 3: Objects [PROGRESS: 70%]")
        logger.info("=" * 80)
        
        try:

            # Helper to sanitize lists
            def _sanitize(lst: List[Dict[str, Any]], obj_type: str = None):
                out = []
                for it in (lst or []):
                    d = dict(it)
                    d.pop("links", None)
                    d.pop("metadata", None)
                    # For SecurityZone, keep only name, type, interfaceMode
                    if obj_type == "SecurityZone":
                        d = {
                            "name": d.get("name"),
                            "type": d.get("type"),
                            "interfaceMode": d.get("interfaceMode")
                        }
                    out.append(d)
                return out

            # Mapping into YAML structure
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
                "SecurityZone": ("interface", "security_zones"),
            }

            TYPE_TO_LIST_FUNC = {
                "Host": fmc.get_hosts,
                "Range": fmc.get_ranges,
                "Network": fmc.get_networks,
                "FQDN": fmc.get_fqdns,
                "NetworkGroup": fmc.get_network_groups,
                "ProtocolPortObject": fmc.get_port_objects,
                "BFDTemplate": fmc.get_bfd_templates,
                "ASPathList": fmc.get_as_path_lists,
                "KeyChain": fmc.get_key_chains,
                "SLAMonitor": fmc.get_sla_monitors,
                "CommunityList": fmc.get_community_lists,
                "ExtendedCommunityList": fmc.get_extended_community_lists,
                "IPv4PrefixList": fmc.get_ipv4_prefix_lists,
                "IPv6PrefixList": fmc.get_ipv6_prefix_lists,
                "ExtendedAccessList": fmc.get_extended_access_lists,
                "StandardAccessList": fmc.get_standard_access_lists,
                "RouteMap": fmc.get_route_maps,
                "IPv4AddressPool": fmc.get_ipv4_address_pools,
                "IPv6AddressPool": fmc.get_ipv6_address_pools,
                "MacAddressPool": fmc.get_mac_address_pools,
                "SecurityZone": fmc.get_security_zones,
            }

            TYPE_TITLE = {
                "Host": "Network Hosts",
                "Range": "Network Ranges",
                "Network": "Network Networks",
                "FQDN": "FQDNs",
                "NetworkGroup": "Network Groups",
                "ProtocolPortObject": "Port Objects",
                "BFDTemplate": "BFD Templates",
                "ASPathList": "AS Path Lists",
                "KeyChain": "Key Chains",
                "SLAMonitor": "SLA Monitors",
                "CommunityList": "Community Lists (Community)",
                "ExtendedCommunityList": "Community Lists (Extended)",
                "IPv4PrefixList": "IPv4 Prefix Lists",
                "IPv6PrefixList": "IPv6 Prefix Lists",
                "ExtendedAccessList": "Extended Access Lists",
                "StandardAccessList": "Standard Access Lists",
                "RouteMap": "Route Maps",
                "IPv4AddressPool": "IPv4 Address Pools",
                "IPv6AddressPool": "IPv6 Address Pools",
                "MacAddressPool": "MAC Address Pools",
                "SecurityZone": "Security Zones",
            }

            def _merge_items(t: str, items: list[Dict[str, Any]]):
                if not items:
                    return
                top, sub = TYPE_TO_PATH.get(t, (None, None))
                if not top:
                    return
                if sub is None:
                    cur = list(objects_block.get(top) or [])
                    # dedupe by id
                    seen = {str(x.get("id")) for x in cur if isinstance(x, dict) and x.get("id")}
                    for it in items:
                        oid = str((it or {}).get("id") or "")
                        if oid and oid in seen:
                            continue
                        cur.append(it)
                        if oid:
                            seen.add(oid)
                    objects_block[top] = cur
                else:
                    group = dict(objects_block.get(top) or {})
                    lst = list(group.get(sub) or [])
                    seen = {str(x.get("id")) for x in lst if isinstance(x, dict) and x.get("id")}
                    for it in items:
                        oid = str((it or {}).get("id") or "")
                        if oid and oid in seen:
                            continue
                        lst.append(it)
                        if oid:
                            seen.add(oid)
                    group[sub] = lst
                    objects_block[top] = group

            def _rows(items: list[Dict[str, Any]]):
                out = []
                for it in (items or []):
                    out.append([str((it or {}).get("name") or ""), str((it or {}).get("id") or "")])
                return out

            # Normalize FMC API type names to internal type names
            # FMC API returns IPV4PrefixList/IPV6PrefixList but we use IPv4PrefixList/IPv6PrefixList
            TYPE_NORMALIZE = {
                "IPV4PrefixList": "IPv4PrefixList",
                "IPV6PrefixList": "IPv6PrefixList",
            }

            def _fetch_for_type(t: str):
                # Fetch by IDs from aggregated dependency table
                items_by_id: list[Dict[str, Any]] = []
                idset = set(dep_ids_by_type.get(t) or set())
                if idset:
                    raw_items = get_objects_by_type_and_ids(fmc_ip, headers, domain_uuid, t, idset)
                    # Group fetched items by their actual type (may differ from requested type due to fallback)
                    # e.g., requesting "Network" may return Host, Range, FQDN, or NetworkGroup objects
                    items_by_actual_type: Dict[str, list] = {}
                    for it in (raw_items or []):
                        raw_type = (it or {}).get("type") or t
                        actual_type = TYPE_NORMALIZE.get(raw_type, raw_type)  # Normalize type
                        items_by_actual_type.setdefault(actual_type, []).append(it)
                    
                    # Merge items into correct sections based on actual type
                    for actual_type, type_items in items_by_actual_type.items():
                        sanitized = _sanitize(type_items, actual_type)
                        _merge_items(actual_type, sanitized)
                        items_by_id.extend(sanitized)
                    
                    if items_by_id:
                        try:
                            title = TYPE_TITLE.get(t, t)
                            fmc.logger.info(f"Fetching {title} for FTD: {dev_name}")
                            fmc._log_pretty_table(f"{title} for {dev_name}", ["Name","UUID"], _rows(items_by_id))
                        except Exception:
                            pass

                # Fetch by Names from aggregated dependency table (misses only)
                names = set(dep_names_by_type.get(t) or set())
                have_names = set([row[0] for row in _rows(items_by_id)]) if items_by_id else set()
                miss_names = names - have_names
                items_by_name: list[Dict[str, Any]] = []
                if miss_names:
                    list_func = TYPE_TO_LIST_FUNC.get(t)
                    all_items = []
                    if list_func:
                        try:
                            all_items = list_func(fmc_ip, headers, domain_uuid) or []
                        except Exception:
                            all_items = []
                    selected = [it for it in all_items if (it or {}).get("name") in miss_names]
                    # Group by actual type for correct placement
                    items_by_actual_type_name: Dict[str, list] = {}
                    for it in selected:
                        raw_type = (it or {}).get("type") or t
                        actual_type = TYPE_NORMALIZE.get(raw_type, raw_type)  # Normalize type
                        items_by_actual_type_name.setdefault(actual_type, []).append(it)
                    
                    for actual_type, type_items in items_by_actual_type_name.items():
                        sanitized = _sanitize(type_items, actual_type)
                        _merge_items(actual_type, sanitized)
                        items_by_name.extend(sanitized)
                    
                    if items_by_name:
                        try:
                            title = TYPE_TITLE.get(t, t)
                            fmc.logger.info(f"Fetching {title} for FTD: {dev_name}")
                            fmc._log_pretty_table(f"{title} for {dev_name}", ["Name","UUID"], _rows(items_by_name))
                        except Exception:
                            pass
                    for it in items_by_name:
                        iid = str((it or {}).get("id") or "")
                        if iid:
                            raw_type = (it or {}).get("type") or t
                            actual_type = TYPE_NORMALIZE.get(raw_type, raw_type)  # Normalize type
                            dep_ids_by_type.setdefault(actual_type, set()).add(iid)

                # Update aggregated dependency table with fetched objects (ensure UUIDs are recorded)
                fetched = (items_by_id or []) + (items_by_name or [])
                for it in fetched:
                    raw_type = (it or {}).get("type") or t
                    actual_type = TYPE_NORMALIZE.get(raw_type, raw_type)  # Normalize type
                    _ingest_rows([[str((it or {}).get("name") or ""), actual_type, str((it or {}).get("id") or "")]])

            section_num = 1
            # Phase 3 spans from 70% to 95%, with ~21 sections = ~1.2% per section
            # Calculate progress: 70 + (section_num * 1.2)
            
            def _log_section(obj_type: str):
                nonlocal section_num
                title = TYPE_TITLE.get(obj_type, obj_type)
                progress_pct = min(70 + int(section_num * 1.2), 94)  # Cap at 94% (Finished goes to 95%)
                logger.info(f"  Starting Section 3.{section_num}: {title} [PROGRESS: {progress_pct}%]")
                
            def _log_section_done(obj_type: str, count: int):
                nonlocal section_num
                title = TYPE_TITLE.get(obj_type, obj_type)
                logger.info(f"  Finished Section 3.{section_num}: {title} ({count} found)")
                section_num += 1

            # Level 4
            logger.info("  Fetching Level 4 Objects (Route Maps)")
            _log_section("RouteMap")
            _fetch_for_type("RouteMap")
            rm_count = len([r for r in dep_rows_all if r[1] == "RouteMap"])
            _log_section_done("RouteMap", rm_count)
            # Rescan newly fetched objects to discover nested dependencies
            try:
                new_deps = _scan_deps_rows(objects_block)
                _ingest_rows(new_deps)
            except Exception:
                pass
            try:
                fmc._log_pretty_table("Dependent Objects (Phase 3: after Level 4)", ["Name", "Type", "UUID"], dep_rows_all)
            except Exception:
                pass

            # Level 3
            logger.info("  Fetching Level 3 Objects (Access Lists)")
            for t in ["ExtendedAccessList", "StandardAccessList"]:
                _log_section(t)
                _fetch_for_type(t)
                count = len([r for r in dep_rows_all if r[1] == t])
                _log_section_done(t, count)
            # Rescan newly fetched objects to discover nested dependencies
            try:
                new_deps = _scan_deps_rows(objects_block)
                _ingest_rows(new_deps)
            except Exception:
                pass
            try:
                fmc._log_pretty_table("Dependent Objects (Phase 3: after Level 3)", ["Name", "Type", "UUID"], dep_rows_all)
            except Exception:
                pass

            # Level 2
            logger.info("  Fetching Level 2 Objects (Network Groups, SLA Monitors)")
            for t in ["NetworkGroup", "SLAMonitor"]:
                _log_section(t)
                _fetch_for_type(t)
                count = len([r for r in dep_rows_all if r[1] == t])
                _log_section_done(t, count)
            # Rescan newly fetched objects to discover nested dependencies
            try:
                new_deps = _scan_deps_rows(objects_block)
                _ingest_rows(new_deps)
            except Exception:
                pass
            try:
                fmc._log_pretty_table("Dependent Objects (Phase 3: after Level 2)", ["Name", "Type", "UUID"], dep_rows_all)
            except Exception:
                pass

            # Level 1
            logger.info("  Fetching Level 1 Objects (Base Objects)")
            for t in [
                "SecurityZone", "Host", "Range", "Network", "FQDN", "ProtocolPortObject",
                "BFDTemplate", "ASPathList", "KeyChain", "CommunityList", "ExtendedCommunityList",
                "IPv4PrefixList", "IPv6PrefixList", "IPv4AddressPool", "IPv6AddressPool", "MacAddressPool",
            ]:
                _log_section(t)
                _fetch_for_type(t)
                count = len([r for r in dep_rows_all if r[1] == t])
                _log_section_done(t, count)
            # Rescan newly fetched objects to discover nested dependencies
            try:
                new_deps = _scan_deps_rows(objects_block)
                _ingest_rows(new_deps)
            except Exception:
                pass
            try:
                fmc._log_pretty_table("Dependent Objects (Phase 3: after Level 1)", ["Name", "Type", "UUID"], dep_rows_all)
            except Exception:
                pass
        except Exception as ex:
            logger.warning(f"Selective Objects export failed partially: {ex}")
        
        set_progress(app_username, 95, "Finalizing...")
        logger.info("=" * 80)
        logger.info("✅ Finished Phase 3: Objects [PROGRESS: 95%]")
        logger.info("=" * 80)

        # Detailed per-type logs with Name/UUID tables (logger: utils.fmc_api)
        try:
            def _rows(items: list[Dict[str, Any]]):
                out = []
                for it in (items or []):
                    try:
                        out.append([str(it.get("name") or ""), str(it.get("id") or "")])
                    except Exception:
                        continue
                return out

            # Network
            net = objects_block.get("network") or {}
            if (net.get("hosts") or []):
                fmc.logger.info(f"Fetching Network Hosts for FTD: {dev_name}")
                fmc._log_pretty_table(f"Network Hosts for {dev_name}", ["Name","UUID"], _rows(net.get("hosts")))
            if (net.get("ranges") or []):
                fmc.logger.info(f"Fetching Network Ranges for FTD: {dev_name}")
                fmc._log_pretty_table(f"Network Ranges for {dev_name}", ["Name","UUID"], _rows(net.get("ranges")))
            if (net.get("networks") or []):
                fmc.logger.info(f"Fetching Network Networks for FTD: {dev_name}")
                fmc._log_pretty_table(f"Network Networks for {dev_name}", ["Name","UUID"], _rows(net.get("networks")))
            if (net.get("fqdns") or []):
                fmc.logger.info(f"Fetching FQDNs for FTD: {dev_name}")
                fmc._log_pretty_table(f"FQDNs for {dev_name}", ["Name","UUID"], _rows(net.get("fqdns")))
            if (net.get("groups") or []):
                fmc.logger.info(f"Fetching Network Groups for FTD: {dev_name}")
                fmc._log_pretty_table(f"Network Groups for {dev_name}", ["Name","UUID"], _rows(net.get("groups")))

            # Port objects
            prt = objects_block.get("port") or {}
            if (prt.get("objects") or []):
                fmc.logger.info(f"Fetching Port Objects for FTD: {dev_name}")
                fmc._log_pretty_table(f"Port Objects for {dev_name}", ["Name","UUID"], _rows(prt.get("objects")))

            # Templates & lists
            if (objects_block.get("bfd_templates") or []):
                fmc.logger.info(f"Fetching BFD Templates for FTD: {dev_name}")
                fmc._log_pretty_table(f"BFD Templates for {dev_name}", ["Name","UUID"], _rows(objects_block.get("bfd_templates")))
            if (objects_block.get("as_path_lists") or []):
                fmc.logger.info(f"Fetching AS Path Lists for FTD: {dev_name}")
                fmc._log_pretty_table(f"AS Path Lists for {dev_name}", ["Name","UUID"], _rows(objects_block.get("as_path_lists")))
            if (objects_block.get("key_chains") or []):
                fmc.logger.info(f"Fetching Key Chains for FTD: {dev_name}")
                fmc._log_pretty_table(f"Key Chains for {dev_name}", ["Name","UUID"], _rows(objects_block.get("key_chains")))
            if (objects_block.get("sla_monitors") or []):
                fmc.logger.info(f"Fetching SLA Monitors for FTD: {dev_name}")
                fmc._log_pretty_table(f"SLA Monitors for {dev_name}", ["Name","UUID"], _rows(objects_block.get("sla_monitors")))

            comm = objects_block.get("community_lists") or {}
            if (comm.get("community") or []):
                fmc.logger.info(f"Fetching Community Lists (Community) for FTD: {dev_name}")
                fmc._log_pretty_table(f"Community Lists (Community) for {dev_name}", ["Name","UUID"], _rows(comm.get("community")))
            if (comm.get("extended") or []):
                fmc.logger.info(f"Fetching Community Lists (Extended) for FTD: {dev_name}")
                fmc._log_pretty_table(f"Community Lists (Extended) for {dev_name}", ["Name","UUID"], _rows(comm.get("extended")))

            pref = objects_block.get("prefix_lists") or {}
            if (pref.get("ipv4") or []):
                fmc.logger.info(f"Fetching IPv4 Prefix Lists for FTD: {dev_name}")
                fmc._log_pretty_table(f"IPv4 Prefix Lists for {dev_name}", ["Name","UUID"], _rows(pref.get("ipv4")))
            if (pref.get("ipv6") or []):
                fmc.logger.info(f"Fetching IPv6 Prefix Lists for FTD: {dev_name}")
                fmc._log_pretty_table(f"IPv6 Prefix Lists for {dev_name}", ["Name","UUID"], _rows(pref.get("ipv6")))

            acls = objects_block.get("access_lists") or {}
            if (acls.get("extended") or []):
                fmc.logger.info(f"Fetching Extended Access Lists for FTD: {dev_name}")
                fmc._log_pretty_table(f"Extended Access Lists for {dev_name}", ["Name","UUID"], _rows(acls.get("extended")))
            if (acls.get("standard") or []):
                fmc.logger.info(f"Fetching Standard Access Lists for FTD: {dev_name}")
                fmc._log_pretty_table(f"Standard Access Lists for {dev_name}", ["Name","UUID"], _rows(acls.get("standard")))

            if (objects_block.get("route_maps") or []):
                fmc.logger.info(f"Fetching Route Maps for FTD: {dev_name}")
                fmc._log_pretty_table(f"Route Maps for {dev_name}", ["Name","UUID"], _rows(objects_block.get("route_maps")))

            pools = objects_block.get("address_pools") or {}
            if (pools.get("ipv4") or []):
                fmc.logger.info(f"Fetching IPv4 Address Pools for FTD: {dev_name}")
                fmc._log_pretty_table(f"IPv4 Address Pools for {dev_name}", ["Name","UUID"], _rows(pools.get("ipv4")))
            if (pools.get("ipv6") or []):
                fmc.logger.info(f"Fetching IPv6 Address Pools for FTD: {dev_name}")
                fmc._log_pretty_table(f"IPv6 Address Pools for {dev_name}", ["Name","UUID"], _rows(pools.get("ipv6")))
            if (pools.get("mac") or []):
                fmc.logger.info(f"Fetching MAC Address Pools for FTD: {dev_name}")
                fmc._log_pretty_table(f"MAC Address Pools for {dev_name}", ["Name","UUID"], _rows(pools.get("mac")))
        except Exception as _ex_log:
            logger.warning(f"Failed to log exported objects per-type: {_ex_log}")

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
        def _safe(s: str) -> str:
            s = (s or "").strip()
            return "".join(c if c.isalnum() or c in ("-", "_") else "-" for c in s) or "unknown"

        # Prefer UI-provided device_meta (from Available Devices table) for name/version/model
        meta = payload.get("device_meta") or {}
        name_override = str(meta.get("name") or "").strip()
        safe_name = _safe(name_override or dev_name)
        # Version and model (UI override -> FMC record fallback)
        dev_ver = (
            str(meta.get("version")
                or dev_rec.get("sw_version")
                or dev_rec.get("version")
                or dev_rec.get("softwareVersion")
                or dev_rec.get("swVersion")
                or "").strip()
        )
        dev_model = str((meta.get("model") or dev_rec.get("model") or "")).strip()
        safe_ver = _safe(dev_ver)
        safe_model = _safe(dev_model)
        ts = time.strftime("%Y%m%d_%H%M%S")
        # Requested format: devicename_version_model_date_time.yaml
        filename = f"{safe_name}_{safe_ver}_{safe_model}_{ts}.yaml"
        set_progress(app_username, 98, "Generating YAML...")
        content = yaml.safe_dump(cfg_out, sort_keys=False)
        set_progress(app_username, 100, "Complete!")
        return {"success": True, "filename": filename, "content": content}
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"Export error: {e}")
        return {"success": False, "message": str(e)}

@app.post("/api/fmc-config/config/get")
async def fmc_config_get(payload: Dict[str, Any], http_request: Request):
    try:
        # Ensure logs from utils.fmc_api surface while exporting
        username = get_current_username(http_request)
        reset_progress(username)
        _start_user_operation(username, "config-get")
        _attach_user_log_handlers(username)
        # Add app username to payload for progress tracking
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _export_config_sync(payload))
        if not result.get("success"):
            _finish_user_operation(username, False, result.get("message", "Config export failed"))
            return JSONResponse(status_code=400, content=result)
        filename = result.get("filename") or "export.yaml"
        content = (result.get("content") or "").encode("utf-8", errors="ignore")
        _finish_user_operation(username, True, f"Exported {filename}")
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"FMC config get error: {e}")
        try:
            _finish_user_operation(username, False, f"Config get error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# -----------------------
# Chassis Configuration Routes
# -----------------------

@app.post("/api/fmc-config/chassis-config/get")
async def fmc_chassis_config_get(payload: Dict[str, Any], http_request: Request):
    try:
        username = get_current_username(http_request)
        reset_progress(username)
        _start_user_operation(username, "chassis-config-get")
        _attach_user_log_handlers(username)
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _export_chassis_config_sync(payload))
        if not result.get("success"):
            _finish_user_operation(username, False, result.get("message", "Chassis config export failed"))
            return JSONResponse(status_code=400, content=result)
        filename = result.get("filename") or "chassis_export.yaml"
        content = (result.get("content") or "").encode("utf-8", errors="ignore")
        _finish_user_operation(username, True, f"Exported {filename}")
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except Exception as e:
        logger.error(f"FMC chassis config get error: {e}")
        try:
            _finish_user_operation(username, False, f"Chassis config get error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/fmc-config/chassis-config/upload")
async def fmc_chassis_config_upload(file: UploadFile = File(...)):
    try:
        raw = await file.read()
        data = _yaml_safe_load(raw) or {}
        chassis_ifaces = data.get("chassis_interfaces") or {}
        logical_devs = data.get("logical_devices") or []
        cfg = {
            "chassis_interfaces": {
                "physicalinterfaces": chassis_ifaces.get("physicalinterfaces") or [],
                "etherchannelinterfaces": chassis_ifaces.get("etherchannelinterfaces") or [],
                "subinterfaces": chassis_ifaces.get("subinterfaces") or [],
            },
            "logical_devices": logical_devs,
        }
        counts = {
            "chassis_interfaces.physicalinterfaces": len(cfg["chassis_interfaces"]["physicalinterfaces"]),
            "chassis_interfaces.etherchannelinterfaces": len(cfg["chassis_interfaces"]["etherchannelinterfaces"]),
            "chassis_interfaces.subinterfaces": len(cfg["chassis_interfaces"]["subinterfaces"]),
        }
        # Add per-logical-device counts so frontend can build dynamic items
        for ld in logical_devs:
            if isinstance(ld, dict):
                ld_name = ld.get("name") or ld.get("baseName") or f"ld{logical_devs.index(ld)}"
                # Count meaningful sub-items in each LD
                ld_item_count = 0
                for k, v in ld.items():
                    if isinstance(v, list):
                        ld_item_count += len(v)
                    elif isinstance(v, dict):
                        ld_item_count += 1
                    elif v:
                        ld_item_count += 1
                counts[f"logical_devices.{ld_name}"] = ld_item_count
        return {
            "success": True,
            "config": cfg,
            "counts": counts,
            "filename": getattr(file, "filename", None),
        }
    except Exception as e:
        logger.error(f"Chassis config upload error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/fmc-config/chassis-config/apply")
async def fmc_chassis_config_apply(payload: Dict[str, Any], http_request: Request):
    try:
        username = get_current_username(http_request)
        reset_progress(username)
        _start_user_operation(username, "chassis-config-apply")
        _attach_user_log_handlers(username)
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _apply_chassis_config_sync(payload))
        _finish_user_operation(username, bool(result.get("success", False)), result.get("message", "Chassis config apply completed"))
        return result
    except Exception as e:
        logger.error(f"FMC chassis config apply error: {e}")
        try:
            _finish_user_operation(username, False, f"Chassis config apply error: {e}")
        except Exception:
            pass
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
        _start_user_operation(username, "config-delete")
        _attach_user_log_handlers(username)
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _delete_config_sync(payload))
        _finish_user_operation(username, bool(result.get("success", False)), result.get("message", "Config delete completed"))
        return result
    except Exception as e:
        logger.error(f"FMC config delete error: {e}")
        try:
            _finish_user_operation(username, False, f"Config delete error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _delete_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    _apply_debug_flag(payload)
    _unpack_selected_types(payload, prefix="delete")
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username
        # Support both device_id (legacy) and device_ids (React frontend)
        device_id = (payload.get("device_id") or "").strip()
        if not device_id:
            device_ids = payload.get("device_ids") or []
            if device_ids:
                device_id = str(device_ids[0]).strip()
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
            _check_stop_requested(app_username)
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
            _check_stop_requested(app_username)
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
            _check_stop_requested(app_username)
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
            _check_stop_requested(app_username)
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
            _check_stop_requested(app_username)
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
            _check_stop_requested(app_username)
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
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"FMC config delete error: {e}")
        return {"success": False, "message": str(e)}

@app.post("/api/fmc-config/objects/delete")
async def fmc_objects_delete(payload: Dict[str, Any], http_request: Request):
    """Delete FMC objects from YAML configuration (no device selection needed).
    
    Expects JSON with:
      fmc_ip, username, password, domain_uuid (optional),
      delete_obj_net_host, delete_obj_net_range, delete_obj_net_network, delete_obj_net_fqdn, delete_obj_net_group,
      delete_obj_port_objects,
      delete_obj_bfd_templates, delete_obj_as_path_lists, delete_obj_key_chains, delete_obj_sla_monitors,
      delete_obj_community_lists_community, delete_obj_community_lists_extended,
      delete_obj_prefix_lists_ipv4, delete_obj_prefix_lists_ipv6,
      delete_obj_access_lists_extended, delete_obj_access_lists_standard,
      delete_obj_route_maps,
      delete_obj_address_pools_ipv4, delete_obj_address_pools_ipv6, delete_obj_address_pools_mac,
      config: { objects: { network: {...}, port: {...}, ... } }
    """
    try:
        username = get_current_username(http_request)
        _attach_user_log_handlers(username)
        _start_user_operation(username, "objects-delete")
        payload["app_username"] = username
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _delete_objects_sync(payload))
        _finish_user_operation(username, bool(result.get("success", False)), result.get("message", "Objects delete completed"))
        return result
    except Exception as e:
        logger.error(f"FMC objects delete error: {e}")
        try:
            _finish_user_operation(username, False, f"Objects delete error: {e}")
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _delete_objects_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Delete FMC objects specified in YAML config."""
    _apply_debug_flag(payload)
    _unpack_selected_types(payload, prefix="delete")
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username
        if not fmc_ip or not username or not password:
            return {"success": False, "message": "Missing fmc_ip, username, or password"}

        sel_domain = (payload.get("domain_uuid") or "").strip()
        auth_domain, headers = authenticate(fmc_ip, username, password)
        domain_uuid = sel_domain or auth_domain

        cfg = payload.get("config") or {}
        obj = cfg.get("objects") or {}

        deleted_summary: Dict[str, int] = {
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
            "objects_interface_security_zones": 0,
        }
        errors: List[str] = []

        # Helper to delete objects by type from YAML
        def _delete_obj_list(items: List[Dict[str, Any]], object_type: str, key: str):
            if not items:
                return
            _check_stop_requested(app_username)
            # Get all existing objects of this type from FMC
            from utils.fmc_api import delete_objects_by_type
            try:
                # Build name->id map for this type
                type_func_map = {
                    "Host": fmc.get_hosts,
                    "Range": fmc.get_ranges,
                    "Network": fmc.get_networks,
                    "FQDN": fmc.get_fqdns,
                    "NetworkGroup": fmc.get_network_groups,
                    "ProtocolPortObject": fmc.get_port_objects,
                    "BFDTemplate": fmc.get_bfd_templates,
                    "ASPathList": fmc.get_as_path_lists,
                    "KeyChain": fmc.get_key_chains,
                    "SLAMonitor": fmc.get_sla_monitors,
                    "CommunityList": fmc.get_community_lists,
                    "ExtendedCommunityList": fmc.get_extended_community_lists,
                    "IPv4PrefixList": fmc.get_ipv4_prefix_lists,
                    "IPv6PrefixList": fmc.get_ipv6_prefix_lists,
                    "ExtendedAccessList": fmc.get_extended_access_lists,
                    "StandardAccessList": fmc.get_standard_access_lists,
                    "RouteMap": fmc.get_route_maps,
                    "IPv4AddressPool": fmc.get_ipv4_address_pools,
                    "IPv6AddressPool": fmc.get_ipv6_address_pools,
                    "MacAddressPool": fmc.get_mac_address_pools,
                }
                
                get_func = type_func_map.get(object_type)
                if not get_func:
                    logger.warning(f"No GET function for object type: {object_type}")
                    return
                
                existing_objs = get_func(fmc_ip, headers, domain_uuid) or []
                name_to_id = {str(o.get("name")): o.get("id") for o in existing_objs if o.get("name") and o.get("id")}
                
                # Find IDs for items in YAML
                ids_to_delete = []
                for item in items:
                    name = str((item or {}).get("name") or "")
                    if name in name_to_id:
                        ids_to_delete.append(name_to_id[name])
                    else:
                        errors.append(f"{object_type} not found on FMC: {name}")
                
                if ids_to_delete:
                    logger.info(f"Deleting {len(ids_to_delete)} {object_type} objects from FMC")
                    res = delete_objects_by_type(fmc_ip, headers, domain_uuid, object_type, ids_to_delete)
                    deleted_summary[key] = res.get("deleted", 0)
                    for er in res.get("errors", []):
                        errors.append(er)
            except Exception as ex:
                errors.append(f"Failed to delete {object_type}: {ex}")

        # Delete objects in reverse dependency order (Level 4 -> Level 1)
        # Level 4: Route Maps
        if payload.get("delete_obj_route_maps"):
            _check_stop_requested(app_username)
            _delete_obj_list(obj.get("route_maps"), "RouteMap", "objects_route_maps")

        # Level 3: Access Lists
        acls = obj.get("access_lists") or {}
        if payload.get("delete_obj_access_lists_extended"):
            _check_stop_requested(app_username)
            _delete_obj_list(acls.get("extended"), "ExtendedAccessList", "objects_access_lists_extended")
        if payload.get("delete_obj_access_lists_standard"):
            _check_stop_requested(app_username)
            _delete_obj_list(acls.get("standard"), "StandardAccessList", "objects_access_lists_standard")

        # Level 2: Network Groups, SLA Monitors
        net = obj.get("network") or {}
        if payload.get("delete_obj_net_group"):
            _check_stop_requested(app_username)
            _delete_obj_list(net.get("groups"), "NetworkGroup", "objects_network_groups")
        if payload.get("delete_obj_sla_monitors"):
            _check_stop_requested(app_username)
            _delete_obj_list(obj.get("sla_monitors"), "SLAMonitor", "objects_sla_monitors")

        # Level 1: Base objects
        if payload.get("delete_obj_net_host"):
            _check_stop_requested(app_username)
            _delete_obj_list(net.get("hosts"), "Host", "objects_network_hosts")
        if payload.get("delete_obj_net_range"):
            _check_stop_requested(app_username)
            _delete_obj_list(net.get("ranges"), "Range", "objects_network_ranges")
        if payload.get("delete_obj_net_network"):
            _check_stop_requested(app_username)
            _delete_obj_list(net.get("networks"), "Network", "objects_network_networks")
        if payload.get("delete_obj_net_fqdn"):
            _check_stop_requested(app_username)
            _delete_obj_list(net.get("fqdns"), "FQDN", "objects_network_fqdns")
        
        if payload.get("delete_obj_port_objects"):
            _check_stop_requested(app_username)
            prt = obj.get("port") or {}
            _delete_obj_list(prt.get("objects"), "ProtocolPortObject", "objects_port_objects")
        
        if payload.get("delete_obj_bfd_templates"):
            _check_stop_requested(app_username)
            _delete_obj_list(obj.get("bfd_templates"), "BFDTemplate", "objects_bfd_templates")
        if payload.get("delete_obj_as_path_lists"):
            _check_stop_requested(app_username)
            _delete_obj_list(obj.get("as_path_lists"), "ASPathList", "objects_as_path_lists")
        if payload.get("delete_obj_key_chains"):
            _check_stop_requested(app_username)
            _delete_obj_list(obj.get("key_chains"), "KeyChain", "objects_key_chains")
        
        comm = obj.get("community_lists") or {}
        if payload.get("delete_obj_community_lists_community"):
            _check_stop_requested(app_username)
            _delete_obj_list(comm.get("community"), "CommunityList", "objects_community_lists_community")
        if payload.get("delete_obj_community_lists_extended"):
            _check_stop_requested(app_username)
            _delete_obj_list(comm.get("extended"), "ExtendedCommunityList", "objects_community_lists_extended")
        
        pref = obj.get("prefix_lists") or {}
        if payload.get("delete_obj_prefix_lists_ipv4"):
            _check_stop_requested(app_username)
            _delete_obj_list(pref.get("ipv4"), "IPv4PrefixList", "objects_prefix_lists_ipv4")
        if payload.get("delete_obj_prefix_lists_ipv6"):
            _check_stop_requested(app_username)
            _delete_obj_list(pref.get("ipv6"), "IPv6PrefixList", "objects_prefix_lists_ipv6")
        
        pools = obj.get("address_pools") or {}
        if payload.get("delete_obj_address_pools_ipv4"):
            _check_stop_requested(app_username)
            _delete_obj_list(pools.get("ipv4"), "IPv4AddressPool", "objects_address_pools_ipv4")
        if payload.get("delete_obj_address_pools_ipv6"):
            _check_stop_requested(app_username)
            _delete_obj_list(pools.get("ipv6"), "IPv6AddressPool", "objects_address_pools_ipv6")
        if payload.get("delete_obj_address_pools_mac"):
            _check_stop_requested(app_username)
            _delete_obj_list(pools.get("mac"), "MacAddressPool", "objects_address_pools_mac")

        # SecurityZones (delete last - interfaces may still reference them)
        if payload.get("delete_obj_if_security_zones"):
            _check_stop_requested(app_username)
            iface_obj = obj.get("interface") or {}
            sec_zone_defs = iface_obj.get("security_zones") or []
            if sec_zone_defs:
                try:
                    existing_zones = fmc.get_security_zones(fmc_ip, headers, domain_uuid) or []
                    name_to_id = {str(z.get("name")): z.get("id") for z in existing_zones if z.get("name") and z.get("id")}
                    ids_to_delete = []
                    for zdef in sec_zone_defs:
                        zname = str((zdef or {}).get("name") or "")
                        if zname in name_to_id:
                            ids_to_delete.append(name_to_id[zname])
                        else:
                            errors.append(f"SecurityZone not found on FMC: {zname}")
                    if ids_to_delete:
                        logger.info(f"Deleting {len(ids_to_delete)} SecurityZone objects from FMC")
                        res = fmc.delete_security_zones(fmc_ip, headers, domain_uuid, list(set(ids_to_delete)))
                        deleted_summary["objects_interface_security_zones"] = res.get("deleted", 0)
                        for er in res.get("errors", []):
                            errors.append(f"SecurityZone delete failed: {er}")
                except Exception as ex:
                    errors.append(f"Failed to delete SecurityZones: {ex}")

        if errors:
            logger.info("Object delete completed with some errors. See terminal.")
        else:
            logger.info("Object delete completed successfully")
        return {"success": True, "deleted": deleted_summary, "errors": errors}
    except InterruptedError:
        return {"success": False, "message": "Operation stopped by user"}
    except Exception as e:
        logger.error(f"FMC objects delete error: {e}")
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
                config = _yaml_safe_load(f)
            
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

def _start_user_operation(username: str, operation: str) -> None:
    """Mark a per-user operation as running so stop controls apply."""
    ctx = get_user_ctx(username)
    ctx["stop_requested"] = False
    ctx["operation_status"]["running"] = True
    ctx["operation_status"]["operation"] = operation
    ctx["operation_status"]["start_time"] = time.time()
    ctx["operation_status"]["success"] = None
    ctx["operation_status"]["message"] = f"Running {operation}..."

def _finish_user_operation(username: str, success: bool, message: str = "") -> None:
    """Finalize per-user operation state."""
    ctx = get_user_ctx(username)
    ctx["operation_status"]["running"] = False
    ctx["operation_status"]["success"] = success
    if message:
        ctx["operation_status"]["message"] = message
    ctx["operation_status"]["end_time"] = time.time()

def _check_stop_requested(username: str) -> None:
    """Raise InterruptedError if a stop has been requested for the user."""
    ctx = get_user_ctx(username)
    if ctx.get("stop_requested"):
        raise InterruptedError("Operation stopped by user")

def set_progress(username: str, percent: int, label: str = ""):
    """Update progress for the current operation."""
    try:
        ctx = get_user_ctx(username)
        if ctx.get("stop_requested"):
            raise InterruptedError("Operation stopped by user")
        ctx["progress"]["percent"] = max(0, min(100, percent))
        ctx["progress"]["label"] = label
        ctx["progress"]["active"] = True
    except InterruptedError:
        raise
    except Exception:
        pass

def reset_progress(username: str):
    """Reset progress tracking."""
    try:
        ctx = get_user_ctx(username)
        ctx["progress"]["percent"] = 0
        ctx["progress"]["label"] = ""
        ctx["progress"]["active"] = False
    except Exception:
        pass

@app.get("/api/progress")
async def get_progress(http_request: Request):
    """Get current operation progress."""
    username = get_current_username(http_request)
    ctx = get_user_ctx(username)
    return ctx.get("progress", {"percent": 0, "label": "", "active": False})

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
            _yaml_safe_load(io.BytesIO(contents))
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

# ---------------- strongSwan APIs ----------------

# Per-user strongSwan SSH connection storage
strongswan_connections: Dict[str, Any] = {}

def parse_swanctl_list_sas(output: str) -> List[Dict[str, Any]]:
    """Parse the output of 'swanctl --list-sas' command into structured tunnel data.
    
    Example output format:
    ftd-tunnel-ipv6-150: #299, ESTABLISHED, IKEv2, cc32f9a86f0cb4c1_i* 2079bad8194a7250_r
      local  '30:16:150::1' @ 30:16:150::1[4500]
      remote '30:16::1' @ 30:16::1[4500]
      ipsec-ipv6-150: #41327, reqid 299, INSTALLED, TUNNEL, ESP:...
    """
    # Import re locally to avoid scope issues
    import re as regex
    tunnels = []
    current_tunnel = None
    
    lines = output.strip().split('\n')
    logger.info(f"Parsing swanctl output: {len(lines)} lines")
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        
        # Check for new IKE SA - line doesn't start with whitespace and contains IKEv1 or IKEv2
        # Format: "tunnel-name: #N, ESTABLISHED, IKEv2, ..."
        is_ike_sa = (
            not line.startswith(' ') and 
            not line.startswith('\t') and 
            ':' in stripped and 
            ('ikev1' in stripped.lower() or 'ikev2' in stripped.lower())
        )
        
        if is_ike_sa:
            # Save previous tunnel
            if current_tunnel:
                tunnels.append(current_tunnel)
            
            # Parse tunnel name (everything before first colon)
            parts = stripped.split(':')
            tunnel_name = parts[0].strip()
            rest = ':'.join(parts[1:]) if len(parts) > 1 else ''
            
            # Parse IKE state
            ike_state = 'UNKNOWN'
            for state in ['ESTABLISHED', 'CONNECTING', 'REKEYING', 'REAUTHENTICATING', 'DESTROYING', 'DELETING', 'FAILED', 'PASSIVE']:
                if state in rest.upper():
                    ike_state = state
                    break
            
            current_tunnel = {
                'name': tunnel_name,
                'ike_state': ike_state,
                'ipsec_state': None,
                'local_addr': None,
                'remote_addr': None,
                'local_port': None,
                'remote_port': None,
                'local_name': tunnel_name,
                'remote_name': None,
                'raw_output': stripped,
                'ike_crypto': None,
                'ipsec_crypto': None,
                'traffic_in': False,
                'traffic_in_bytes': '0',
                'traffic_in_packets': '0',
                'traffic_out_bytes': '0',
                'traffic_out_packets': '0',
                'has_if_id': False,
            }
            
        elif current_tunnel:
            lower_stripped = stripped.lower()
            
            # Parse local address: "local  '30:16:11::1' @ 30:16:11::1[4500]"
            if lower_stripped.startswith('local') and '@' in stripped:
                try:
                    # Extract identity from quoted value - this is the friendly name
                    id_match = regex.search(r"'([^']+)'", stripped)
                    if id_match:
                        current_tunnel['local_id'] = id_match.group(1)
                        # Update local_name only if it's the default value (tunnel name)
                        if current_tunnel['local_name'] == current_tunnel['name']:
                            current_tunnel['local_name'] = id_match.group(1)
                    
                    # Extract IP address part
                    addr_part = stripped.split('@')[-1].strip()
                    
                    # Handle IPv6 addresses which may contain multiple colons
                    if '[' in addr_part:
                        addr = addr_part.split('[')[0].strip()
                        port_match = regex.search(r'\[(\d+)\]', addr_part)
                        port = port_match.group(1) if port_match else None
                    else:
                        # No port specified
                        addr = addr_part.strip()
                        port = None
                        
                    if addr and not current_tunnel.get('local_addr'):
                        current_tunnel['local_addr'] = addr
                        current_tunnel['local_port'] = port
                        logger.debug(f"Parsed local addr: {addr}:{port}")
                except Exception as e:
                    logger.error(f"Error parsing local address: {e}")
                    pass
                    
            # Parse remote address: "remote '30:16::1' @ 30:16::1[4500]"
            elif lower_stripped.startswith('remote') and '@' in stripped:
                try:
                    # Extract identity from quoted value - this is the friendly name
                    id_match = regex.search(r"'([^']+)'", stripped)
                    if id_match:
                        remote_id = id_match.group(1)
                        # Always update remote_name with the identity value
                        current_tunnel['remote_name'] = remote_id
                        logger.debug(f"Parsed remote name: {remote_id}")
                    
                    # Extract IP address part
                    addr_part = stripped.split('@')[-1].strip()
                    
                    # Handle IPv6 addresses which may contain multiple colons
                    if '[' in addr_part:
                        addr = addr_part.split('[')[0].strip()
                        port_match = regex.search(r'\[(\d+)\]', addr_part)
                        port = port_match.group(1) if port_match else None
                    else:
                        # No port specified
                        addr = addr_part.strip()
                        port = None
                        
                    if addr and not current_tunnel.get('remote_addr'):
                        current_tunnel['remote_addr'] = addr
                        current_tunnel['remote_port'] = port
                        logger.debug(f"Parsed remote addr: {addr}:{port}")
                except Exception as e:
                    logger.error(f"Error parsing remote address: {e}")
                    pass
            
            # Parse IKE SA crypto params: "AES_CBC-256/HMAC_SHA2_512_256/PRF_HMAC_SHA2_512/ECP_384/KE1_..."
            # This line contains only slash-separated crypto params, no colon prefix
            elif '/' in stripped and not ':' in stripped and not stripped.startswith('local') and not stripped.startswith('remote') and not 'bytes' in lower_stripped and not 'established' in lower_stripped:
                if not current_tunnel.get('ike_crypto'):
                    current_tunnel['ike_crypto'] = stripped
            
            # Parse traffic data: "in  cd9c33a8,      0 bytes,     0 packets"
            elif lower_stripped.startswith('in ') and 'bytes' in lower_stripped and 'packets' in lower_stripped:
                try:
                    # Format: in  cd9c33a8,      0 bytes,     0 packets
                    match = regex.search(r'(\d+)\s*bytes.*?(\d+)\s*packets', stripped, regex.IGNORECASE)
                    if match:
                        current_tunnel['traffic_in'] = True
                        current_tunnel['traffic_in_bytes'] = match.group(1)
                        current_tunnel['traffic_in_packets'] = match.group(2)
                except Exception:
                    pass
            
            # Parse traffic data: "out 76a16a49,      0 bytes,     0 packets"
            elif lower_stripped.startswith('out ') and 'bytes' in lower_stripped and 'packets' in lower_stripped:
                try:
                    match = regex.search(r'(\d+)\s*bytes.*?(\d+)\s*packets', stripped, regex.IGNORECASE)
                    if match:
                        current_tunnel['traffic_in'] = True
                        current_tunnel['traffic_out_bytes'] = match.group(1)
                        current_tunnel['traffic_out_packets'] = match.group(2)
                except Exception:
                    pass
            
            # Detect route-based tunnel from SA output:
            # 1) Literal if_id_in / if_id_out / if-id-in / if-id-out text
            # 2) Traffic lines with non-zero hex if_id: "in  SPI (-|0x00000001),"
            #    Format: (direction_indicator|0xHEXVALUE) where hex > 0 means route-based
            if ('if_id_in' in lower_stripped or 'if_id_out' in lower_stripped
                    or 'if-id-in' in lower_stripped or 'if-id-out' in lower_stripped):
                current_tunnel['has_if_id'] = True
            elif ('|0x' in stripped) and not current_tunnel.get('has_if_id'):
                # Match pattern like (-|0x00000001) or (SPI|0xNNNNNNNN) where hex != 0
                hex_matches = re.findall(r'\|\s*0x([0-9a-fA-F]+)\)', stripped)
                for hx in hex_matches:
                    if int(hx, 16) != 0:
                        current_tunnel['has_if_id'] = True
                        break
            
            # Check for child SA (IPsec SA): "ipsec-name: #N, reqid X, INSTALLED, TUNNEL, ESP:AES_CBC-256/..."
            if '{' in stripped or ('reqid' in lower_stripped and ':' in stripped):
                for state in ['INSTALLED', 'REKEYING', 'ROUTED', 'CREATED', 'INSTALLING', 'UPDATING', 'DELETING', 'DESTROYING', 'FAILED']:
                    if state in stripped.upper() and current_tunnel['ipsec_state'] is None:
                        current_tunnel['ipsec_state'] = state
                        break
                # Extract IPsec crypto params from child SA line
                # Format: ... ESP:AES_CBC-256/HMAC_SHA2_512_256/ECP_521/KE1_...
                if 'ESP:' in stripped and not current_tunnel.get('ipsec_crypto'):
                    try:
                        esp_part = stripped.split('ESP:')[1].strip()
                        # Remove any trailing text after the crypto params
                        if ',' in esp_part:
                            esp_part = esp_part.split(',')[0].strip()
                        current_tunnel['ipsec_crypto'] = esp_part
                    except Exception:
                        pass
    
    # Don't forget the last tunnel
    if current_tunnel:
        tunnels.append(current_tunnel)
    
    logger.info(f"Parsed {len(tunnels)} tunnel(s) from swanctl output")
    return tunnels

def parse_swanctl_list_conns(output: str) -> Dict[str, str]:
    """Parse swanctl --list-conns output to get configured connection names and their VPN type.
    
    Returns a dict of {connection_name: vpn_type} where vpn_type is 'route' or 'policy'.
    Route-based connections are detected by the presence of if_id_in, if_id_out,
    if-id-in, or if-id-out in connection details.
    
    Example output format:
    ftd-tunnel-ipv6-150: IKEv2, no reauthentication, rekeying every 86400s
      local:  %any
      remote: 30:16::1
      ...
    """
    conn_info: Dict[str, str] = {}
    current_conn = None
    has_if_id = False
    lines = output.strip().split('\n')
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        
        # Connection lines start without whitespace and end with IKEv1 or IKEv2
        if not line.startswith(' ') and not line.startswith('\t') and ':' in stripped:
            if 'ikev1' in stripped.lower() or 'ikev2' in stripped.lower():
                # Save previous connection
                if current_conn:
                    conn_info[current_conn] = 'route' if has_if_id else 'policy'
                # Extract connection name (everything before first colon)
                conn_name = stripped.split(':')[0].strip()
                current_conn = conn_name if conn_name else None
                has_if_id = False
        elif current_conn:
            # Check for if_id_in or if_id_out (underscore or hyphen variants)
            lower = stripped.lower()
            if 'if_id_in' in lower or 'if_id_out' in lower or 'if-id-in' in lower or 'if-id-out' in lower:
                has_if_id = True
    
    # Don't forget last connection
    if current_conn:
        conn_info[current_conn] = 'route' if has_if_id else 'policy'
    
    logger.info(f"Parsed {len(conn_info)} connection(s) from swanctl --list-conns ({sum(1 for v in conn_info.values() if v == 'route')} route-based)")
    return conn_info

def _resolve_vpn_type(tunnel_name: str, conn_info: Dict[str, str]) -> str:
    """Resolve the vpn_type for a tunnel name using exact match first, then prefix match.
    
    SAs from --list-sas may have a numbered suffix (e.g., 'tunnel-1') while
    --list-conns shows the base connection name (e.g., 'tunnel-1'). Some configs
    use separate connection names per tunnel. Try exact match first, then check
    if the tunnel name starts with any known connection name (longest match wins).
    """
    # Exact match
    if tunnel_name in conn_info:
        return conn_info[tunnel_name]
    
    # Prefix match: find the longest connection name that is a prefix of the tunnel name
    best_match = ''
    best_type = 'policy'
    for conn_name, vpn_type in conn_info.items():
        if tunnel_name.startswith(conn_name) and len(conn_name) > len(best_match):
            best_match = conn_name
            best_type = vpn_type
    
    return best_type

def merge_sas_and_conns(sas_tunnels: List[Dict[str, Any]], conn_info: Dict[str, str]) -> List[Dict[str, Any]]:
    """Merge active SAs with configured connections to identify inactive tunnels.
    conn_info is a dict of {connection_name: vpn_type} where vpn_type is 'route' or 'policy'.
    """
    # Get names of active tunnels
    active_names = {t['name'] for t in sas_tunnels}
    
    # Tag active tunnels with vpn_type (exact + prefix matching, or SA-level if_id detection)
    merged = list(sas_tunnels)
    for t in merged:
        resolved = _resolve_vpn_type(t['name'], conn_info)
        # If conn_info didn't resolve as route, but the SA itself has if_id, mark as route
        if resolved == 'policy' and t.get('has_if_id'):
            resolved = 'route'
        t['vpn_type'] = resolved
    
    # Add inactive tunnels (in conns but not in sas)
    for conn_name, vpn_type in conn_info.items():
        if conn_name not in active_names:
            merged.append({
                'name': conn_name,
                'ike_state': 'INACTIVE',
                'ipsec_state': 'INACTIVE',
                'local_addr': None,
                'remote_addr': None,
                'local_name': conn_name,
                'remote_name': None,
                'is_inactive': True,
                'vpn_type': vpn_type,
                'raw_output': f'{conn_name}: INACTIVE (configured but not active)'
            })
    
    # Sort by name for consistent ordering
    merged.sort(key=lambda x: x['name'])
    return merged

@app.post("/api/strongswan/connect")
async def strongswan_connect(request: StrongSwanConnectionRequest, http_request: Request):
    """Connect to strongSwan server via SSH and fetch tunnel data."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        # Establish SSH connection
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=request.ip,
                port=request.port,
                username=request.username,
                password=request.password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
        except Exception as e:
            return JSONResponse(status_code=400, content={"success": False, "message": f"SSH connection failed: {str(e)}"})
        
        # Run swanctl --list-sas with sudo, using the SSH password for sudo authentication
        # Use sudo -S to read password from stdin
        swanctl_cmd = "sudo -S swanctl --list-sas"
        stdin, stdout, stderr = ssh.exec_command(swanctl_cmd, timeout=30, get_pty=True)
        # Send the password to sudo via stdin
        stdin.write(request.password + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        # Remove password echo, sudo prompts and warnings from output
        def clean_swanctl_output(raw_output, password):
            lines = raw_output.split('\n')
            cleaned = []
            for line in lines:
                # Skip empty lines at the start
                if not cleaned and not line.strip():
                    continue
                # Skip password echo
                if line.strip() == password:
                    continue
                # Skip sudo prompts and warnings
                if line.startswith('[sudo]') or line.startswith('sudo:'):
                    continue
                cleaned.append(line)
            return '\n'.join(cleaned)
        
        output = clean_swanctl_output(output, request.password)
        
        logger.info(f"swanctl --list-sas output length: {len(output)} chars, error length: {len(error)} chars")
        if output:
            logger.info(f"swanctl output first 500 chars: {output[:500]}")
        if error and 'password' not in error.lower():
            logger.warning(f"swanctl stderr: {error[:500]}")
        
        # Store connection info for later use
        strongswan_connections[username] = {
            'ip': request.ip,
            'port': request.port,
            'username': request.username,
            'password': request.password
        }
        
        # Also run swanctl --list-conns to get all configured connections
        conns_cmd = "sudo -S swanctl --list-conns"
        stdin2, stdout2, stderr2 = ssh.exec_command(conns_cmd, timeout=30, get_pty=True)
        stdin2.write(request.password + '\n')
        stdin2.flush()
        conns_output = stdout2.read().decode('utf-8', errors='replace')
        conns_output = clean_swanctl_output(conns_output, request.password)
        
        ssh.close()
        
        # Parse the outputs
        active_tunnels = parse_swanctl_list_sas(output)
        conn_info = parse_swanctl_list_conns(conns_output)
        
        # Merge to include inactive tunnels
        tunnels = merge_sas_and_conns(active_tunnels, conn_info)
        
        active_count = len(active_tunnels)
        inactive_count = len(tunnels) - active_count
        logger.info(f"Total tunnels: {len(tunnels)} (active: {active_count}, inactive: {inactive_count})")
        
        record_activity(username, "strongswan_connect", {"ip": request.ip, "tunnels": len(tunnels)})
        
        return {
            "success": True,
            "tunnels": tunnels,
            "active_count": active_count,
            "inactive_count": inactive_count,
            "raw_output": output,
            "error": error if error else None
        }
        
    except Exception as e:
        logger.error(f"strongSwan connect error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/refresh")
async def strongswan_refresh(http_request: Request):
    """Refresh tunnel data from the connected strongSwan server."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        # Re-establish SSH connection
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
        except Exception as e:
            return JSONResponse(status_code=400, content={"success": False, "message": f"SSH reconnection failed: {str(e)}"})
        
        # Run swanctl --list-sas with sudo, using stored password for sudo authentication
        swanctl_cmd = "sudo -S swanctl --list-sas"
        stdin, stdout, stderr = ssh.exec_command(swanctl_cmd, timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        # Remove password echo, sudo prompts and warnings from output
        def clean_swanctl_output(raw_output, password):
            lines = raw_output.split('\n')
            cleaned = []
            for line in lines:
                if not cleaned and not line.strip():
                    continue
                if line.strip() == password:
                    continue
                if line.startswith('[sudo]') or line.startswith('sudo:'):
                    continue
                cleaned.append(line)
            return '\n'.join(cleaned)
        
        output = clean_swanctl_output(output, conn_info['password'])
        
        # Also run swanctl --list-conns to get all configured connections
        conns_cmd = "sudo -S swanctl --list-conns"
        stdin2, stdout2, stderr2 = ssh.exec_command(conns_cmd, timeout=30, get_pty=True)
        stdin2.write(conn_info['password'] + '\n')
        stdin2.flush()
        conns_output = stdout2.read().decode('utf-8', errors='replace')
        conns_output = clean_swanctl_output(conns_output, conn_info['password'])
        
        ssh.close()
        
        # Parse the outputs
        active_tunnels = parse_swanctl_list_sas(output)
        conns_type_map = parse_swanctl_list_conns(conns_output)
        
        # Merge to include inactive tunnels
        tunnels = merge_sas_and_conns(active_tunnels, conns_type_map)
        
        active_count = len(active_tunnels)
        inactive_count = len(tunnels) - active_count
        
        return {
            "success": True,
            "tunnels": tunnels,
            "active_count": active_count,
            "inactive_count": inactive_count,
            "raw_output": output
        }
        
    except Exception as e:
        logger.error(f"strongSwan refresh error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-detail")
async def strongswan_tunnel_detail(request: StrongSwanTunnelDetailRequest, http_request: Request):
    """Get detailed information about a specific tunnel."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        # Re-establish SSH connection
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
        except Exception as e:
            return JSONResponse(status_code=400, content={"success": False, "message": f"SSH reconnection failed: {str(e)}"})
        
        # Run swanctl --list-sas --ike <tunnel_name> with sudo
        tunnel_name = request.tunnel_name
        swanctl_cmd = f'sudo -S swanctl --list-sas --ike "{tunnel_name}"'
        stdin, stdout, stderr = ssh.exec_command(swanctl_cmd, timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        # Remove password echo, sudo prompts and warnings from output
        def clean_swanctl_output(raw_output, password):
            lines = raw_output.split('\n')
            cleaned = []
            for line in lines:
                if not cleaned and not line.strip():
                    continue
                if line.strip() == password:
                    continue
                if line.startswith('[sudo]') or line.startswith('sudo:'):
                    continue
                cleaned.append(line)
            return '\n'.join(cleaned)
        
        output = clean_swanctl_output(output, conn_info['password'])
        
        ssh.close()
        
        return {
            "success": True,
            "output": output if output else error,
            "command": f'swanctl --list-sas --ike "{tunnel_name}"'
        }
        
    except Exception as e:
        logger.error(f"strongSwan tunnel detail error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/restart")
async def strongswan_restart(http_request: Request):
    """Restart the strongSwan service."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
        except Exception as e:
            return JSONResponse(status_code=400, content={"success": False, "message": f"SSH reconnection failed: {str(e)}"})
        
        # Restart strongSwan service
        restart_cmd = "sudo -S systemctl restart strongswan"
        stdin, stdout, stderr = ssh.exec_command(restart_cmd, timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        exit_status = stdout.channel.recv_exit_status()
        
        # Verify service is running
        verify_cmd = "sudo -S systemctl is-active strongswan"
        stdin2, stdout2, stderr2 = ssh.exec_command(verify_cmd, timeout=10, get_pty=True)
        stdin2.write(conn_info['password'] + '\n')
        stdin2.flush()
        status = stdout2.read().decode('utf-8', errors='replace').strip()
        
        ssh.close()
        
        # Check if restart was successful
        if exit_status == 0 or 'active' in status.lower():
            logger.info(f"strongSwan restarted successfully by {username}")
            record_activity(username, "strongswan_restart", {"ip": conn_info['ip'], "status": "success"})
            return {"success": True, "message": "strongSwan restarted successfully", "status": status}
        else:
            logger.warning(f"strongSwan restart may have failed: {error}")
            return JSONResponse(status_code=400, content={"success": False, "message": f"Restart may have failed: {error or 'Unknown error'}"})
        
    except Exception as e:
        logger.error(f"strongSwan restart error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Administration > Process: Service Management APIs
# ============================================================================

@app.get("/api/strongswan/service/status")
async def strongswan_service_status(http_request: Request):
    """Get strongSwan service status using systemctl is-active."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        # systemctl is-active does not need sudo — run without pty to avoid password leak
        stdin, stdout, stderr = ssh.exec_command("systemctl is-active strongswan", timeout=10)
        status = stdout.read().decode('utf-8', errors='replace').strip()
        ssh.close()
        
        # status will be one of: active, inactive, failed, activating, deactivating, unknown
        status = status.split('\n')[-1].strip()
        return {"success": True, "status": status}
    except Exception as e:
        logger.error(f"Service status error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/service/enable")
async def strongswan_service_enable(http_request: Request):
    """Enable strongSwan service."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("sudo -S systemctl enable strongswan && sudo -S systemctl start strongswan", timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        stdout.read()
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()
        
        if exit_status == 0:
            record_activity(username, "strongswan_enable", {"ip": conn_info['ip']})
            return {"success": True, "message": "strongSwan enabled and started"}
        else:
            return JSONResponse(status_code=400, content={"success": False, "message": "Enable failed"})
    except Exception as e:
        logger.error(f"Service enable error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/service/disable")
async def strongswan_service_disable(http_request: Request):
    """Disable strongSwan service."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("sudo -S systemctl stop strongswan && sudo -S systemctl disable strongswan", timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        stdout.read()
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()
        
        if exit_status == 0:
            record_activity(username, "strongswan_disable", {"ip": conn_info['ip']})
            return {"success": True, "message": "strongSwan stopped and disabled"}
        else:
            return JSONResponse(status_code=400, content={"success": False, "message": "Disable failed"})
    except Exception as e:
        logger.error(f"Service disable error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/service/restart")
async def strongswan_service_restart(http_request: Request):
    """Restart strongSwan service (new Administration endpoint)."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("sudo -S systemctl restart strongswan", timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        stdout.read()
        exit_status = stdout.channel.recv_exit_status()
        
        # Verify service is running
        stdin2, stdout2, _ = ssh.exec_command("sudo -S systemctl is-active strongswan", timeout=10, get_pty=True)
        stdin2.write(conn_info['password'] + '\n')
        stdin2.flush()
        status = stdout2.read().decode('utf-8', errors='replace').strip()
        ssh.close()
        
        for line in status.split('\n'):
            line = line.strip()
            if line and '[sudo]' not in line and 'password' not in line.lower():
                status = line
                break
        
        if exit_status == 0 or 'active' in status.lower():
            record_activity(username, "strongswan_restart", {"ip": conn_info['ip'], "status": "success"})
            return {"success": True, "message": "strongSwan restarted successfully", "status": status}
        else:
            return JSONResponse(status_code=400, content={"success": False, "message": "Restart may have failed"})
    except Exception as e:
        logger.error(f"Service restart error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Administration > Troubleshooting: swanctl --log Process APIs
# ============================================================================

@app.get("/api/strongswan/swanctl-log/status")
async def swanctl_log_status(http_request: Request):
    """Get status and PID of the swanctl --log process."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        # Use pgrep -a to list full command, then filter for the actual swanctl process
        # Exclude grep/pgrep itself by using pgrep -f with exact arg match
        stdin, stdout, stderr = ssh.exec_command("pgrep -a swanctl 2>/dev/null", timeout=10)
        pid_output = stdout.read().decode('utf-8', errors='replace').strip()
        ssh.close()
        
        pid = None
        for line in pid_output.split('\n'):
            line = line.strip()
            if 'swanctl --log' in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    pid = int(parts[0])
                    break
        
        return {"success": True, "status": "running" if pid else "stopped", "pid": pid}
    except Exception as e:
        logger.error(f"swanctl-log status error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/swanctl-log/start")
async def swanctl_log_start(http_request: Request):
    """Start the swanctl --log process with timestamps."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        
        # Check if already running using pgrep -a to get full command
        stdin_chk, stdout_chk, _ = ssh.exec_command("pgrep -a swanctl 2>/dev/null", timeout=10)
        chk_output = stdout_chk.read().decode('utf-8', errors='replace').strip()
        existing_pid = None
        for chk_line in chk_output.split('\n'):
            chk_line = chk_line.strip()
            if 'swanctl --log' in chk_line:
                parts = chk_line.split()
                if parts and parts[0].isdigit():
                    existing_pid = int(parts[0])
                    break
        if existing_pid:
            ssh.close()
            return {"success": True, "message": "swanctl --log already running", "pid": existing_pid}
        
        # Start the process - use sudo bash -c with proper escaping
        cmd = "nohup swanctl --log --debug 1 | ts '[%Y-%m-%d %H:%M:%S]' > /var/log/swanctl-syslog.log 2>&1 &"
        stdin, stdout, stderr = ssh.exec_command(f"sudo -S bash -c \"{cmd}\"", timeout=10, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        time.sleep(2)
        
        # Get PID using pgrep -a to match actual swanctl --log process
        stdin2, stdout2, _ = ssh.exec_command("pgrep -a swanctl 2>/dev/null", timeout=10)
        pid_output = stdout2.read().decode('utf-8', errors='replace').strip()
        ssh.close()
        
        pid = None
        for line in pid_output.split('\n'):
            line = line.strip()
            if 'swanctl --log' in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    pid = int(parts[0])
                    break
        
        record_activity(username, "swanctl_log_start", {"ip": conn_info['ip'], "pid": pid})
        return {"success": True, "message": f"swanctl --log started{' (PID: ' + str(pid) + ')' if pid else ''}", "pid": pid}
    except Exception as e:
        logger.error(f"swanctl-log start error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/swanctl-log/stop")
async def swanctl_log_stop(http_request: Request):
    """Kill the swanctl --log process."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("sudo -S pkill -f 'swanctl --log'", timeout=10, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        stdout.read()
        ssh.close()
        
        record_activity(username, "swanctl_log_stop", {"ip": conn_info['ip']})
        return {"success": True, "message": "swanctl --log process killed"}
    except Exception as e:
        logger.error(f"swanctl-log stop error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Administration > Troubleshooting: Syslog File Listing APIs
# ============================================================================

@app.get("/api/strongswan/syslog-files")
async def strongswan_syslog_files(http_request: Request):
    """List syslog files ending with syslog.log in /var/log on local server."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        source = http_request.query_params.get('source', '')
        if source == 'csc':
            conn_info = csc_connections.get(username)
        else:
            conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("ls -1 /var/log/*syslog.log 2>/dev/null", timeout=10)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        ssh.close()
        
        files = []
        for line in output.split('\n'):
            line = line.strip()
            if line and '/var/log/' in line:
                files.append(line.split('/')[-1])
        
        return {"success": True, "files": sorted(files)}
    except Exception as e:
        logger.error(f"Syslog files error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/syslog-files/remote")
async def strongswan_syslog_files_remote(http_request: Request):
    """List syslog files ending with syslog.log in /var/log on remote server."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        # Get remote connection info from session
        session = http_request.session
        remote_conn = session.get('remote_tt_connection')
        if not remote_conn:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to remote server"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=remote_conn['ip'], port=remote_conn.get('port', 22), username=remote_conn['username'],
                    password=remote_conn['password'], timeout=15, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command("ls -1 /var/log/*syslog.log 2>/dev/null", timeout=10)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        ssh.close()
        
        files = []
        for line in output.split('\n'):
            line = line.strip()
            if line and '/var/log/' in line:
                files.append(line.split('/')[-1])
        
        return {"success": True, "files": sorted(files)}
    except Exception as e:
        logger.error(f"Remote syslog files error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Administration > Troubleshooting: Monitoring Daemon APIs
# ============================================================================

REMOTE_MONITOR_DAEMON_PATH = "/var/tmp/remote_tunnel_monitor_daemon.py"
REMOTE_MONITOR_PID_FILE = "/var/run/tunnel-monitor-daemon.pid"
REMOTE_MONITOR_LOG = "/var/log/tunnel-monitor-daemon.log"
REMOTE_MONITOR_REPORT = "/var/log/tunnel-disconnect-syslog.log"
REMOTE_MONITOR_COUNT_FILE = "/var/run/tunnel-monitor-daemon.count"


def _upload_remote_monitor_daemon(ssh: SSHClient, sudo_password: str):
    daemon_path = os.path.join(BASE_DIR, "remote_tunnel_monitor_daemon.py")
    with open(daemon_path, 'r', encoding='utf-8') as handle:
        source = handle.read()
    temp_remote_path = f"/tmp/remote_tunnel_monitor_daemon_{int(time.time() * 1000)}.py"
    sftp = ssh.open_sftp()
    try:
        with sftp.file(temp_remote_path, 'w') as remote_file:
            remote_file.write(source)
    finally:
        sftp.close()

    install_cmd = (
        f"sudo -S bash -c 'mv \"{temp_remote_path}\" \"{REMOTE_MONITOR_DAEMON_PATH}\" && "
        f"chown root:root \"{REMOTE_MONITOR_DAEMON_PATH}\" && chmod 755 \"{REMOTE_MONITOR_DAEMON_PATH}\"'"
    )
    stdin_i, stdout_i, stderr_i = ssh.exec_command(install_cmd, timeout=15, get_pty=True)
    stdin_i.write(sudo_password + '\n')
    stdin_i.flush()
    stdout_i.read()
    install_err = stderr_i.read().decode('utf-8', errors='replace')
    install_status = stdout_i.channel.recv_exit_status()
    if install_status != 0:
        raise RuntimeError(f"Failed to install monitoring daemon: {install_err}")


def _download_remote_report(conn_info: dict) -> Optional[str]:
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)

        def _sudo_output(cmd: str, timeout: int = 30) -> str:
            stdin, stdout, _ = ssh.exec_command(cmd, timeout=timeout, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            output = stdout.read().decode('utf-8', errors='replace')
            password = conn_info.get('password', '')
            clean_lines = []
            for line in output.split('\n'):
                stripped = line.strip()
                if '[sudo]' in stripped:
                    continue
                if password and stripped == password:
                    continue
                clean_lines.append(line)
            return '\n'.join(clean_lines)

        list_cmd = f"sudo -S -p '' bash -c 'ls -1 {REMOTE_MONITOR_REPORT}* 2>/dev/null | sort -V'"
        files_output = _sudo_output(list_cmd, timeout=15).strip()
        report_files = [line.strip() for line in files_output.split('\n') if line.strip()]

        if not report_files:
            return None

        contents = []
        for path in report_files:
            if path.endswith('.gz'):
                cat_cmd = f"sudo -S -p '' zcat {path} 2>/dev/null"
            else:
                cat_cmd = f"sudo -S -p '' cat {path} 2>/dev/null"
            contents.append(_sudo_output(cat_cmd, timeout=30))
        return ''.join(contents)
    finally:
        ssh.close()

class MonitoringStartRequest(BaseModel):
    local_log: str
    remote_log: str
    interval_seconds: int = 300
    leeway_seconds: int = 5

@app.post("/api/strongswan/monitoring/start")
async def monitoring_start(request: MonitoringStartRequest, http_request: Request):
    """Start the tunnel disconnect monitoring daemon.
    
    Also starts swanctl --log and clears local + remote logs for a fresh start.
    """
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        local_conn = strongswan_connections.get(username)
        if not local_conn:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to local server"})
        
        # Both local and remote logs are on the same server
        conn_info = local_conn
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
        
        # 1. Kill any existing monitoring daemon and swanctl --log processes
        stop_cmd = (
            f"pkill -f '{os.path.basename(REMOTE_MONITOR_DAEMON_PATH)}' 2>/dev/null || true; "
            f"sleep 1; "
            f"pkill -9 -f '{os.path.basename(REMOTE_MONITOR_DAEMON_PATH)}' 2>/dev/null || true; "
            f"if [ -f {REMOTE_MONITOR_PID_FILE} ]; then "
            f"pid=$(cat {REMOTE_MONITOR_PID_FILE}); "
            f"kill $pid 2>/dev/null || true; "
            f"sleep 1; kill -9 $pid 2>/dev/null || true; "
            f"rm -f {REMOTE_MONITOR_PID_FILE}; "
            f"fi; rm -f {REMOTE_MONITOR_COUNT_FILE}"
        )
        stdin_k, stdout_k, _ = ssh.exec_command(f"sudo -S bash -c \"{stop_cmd}\"", timeout=10, get_pty=True)
        stdin_k.write(conn_info['password'] + '\n')
        stdin_k.flush()
        stdout_k.read()

        stdin_sc, stdout_sc, _ = ssh.exec_command("sudo -S pkill -f 'swanctl --log' 2>/dev/null", timeout=10, get_pty=True)
        stdin_sc.write(conn_info['password'] + '\n')
        stdin_sc.flush()
        stdout_sc.read()
        time.sleep(1)

        # 2. Clear local log files and report for a fresh start (including rotated)
        local_log_base = f"/var/log/{request.local_log}"
        clear_local_cmd = (
            f"sudo -S bash -c 'rm -f {local_log_base}* && touch {local_log_base} && "
            f"rm -f {REMOTE_MONITOR_REPORT}* {REMOTE_MONITOR_COUNT_FILE} "
            f"{REMOTE_MONITOR_PID_FILE}'"
        )
        stdin_cl, stdout_cl, _ = ssh.exec_command(clear_local_cmd, timeout=15, get_pty=True)
        stdin_cl.write(conn_info['password'] + '\n')
        stdin_cl.flush()
        stdout_cl.read()
        logger.info(f"Cleared local log files: {local_log_base}* and report {REMOTE_MONITOR_REPORT}*")
        
        # 3. Start swanctl --log process
        swanctl_cmd = "nohup swanctl --log --debug 1 | ts '[%Y-%m-%d %H:%M:%S]' > /var/log/swanctl-syslog.log 2>&1 &"
        stdin_s, stdout_s, _ = ssh.exec_command(f"sudo -S bash -c \"{swanctl_cmd}\"", timeout=10, get_pty=True)
        stdin_s.write(conn_info['password'] + '\n')
        stdin_s.flush()
        time.sleep(2)
        
        # 4. Get swanctl --log PID
        stdin_p, stdout_p, _ = ssh.exec_command("pgrep -a swanctl 2>/dev/null", timeout=10)
        pid_output = stdout_p.read().decode('utf-8', errors='replace').strip()
        swanctl_pid = None
        for line in pid_output.split('\n'):
            line = line.strip()
            if 'swanctl --log' in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    swanctl_pid = int(parts[0])
                    break
        
        logger.info(f"Started swanctl --log with PID: {swanctl_pid}")
        
        # 5. Upload and start the monitoring daemon on the strongSwan/syslog server
        _upload_remote_monitor_daemon(ssh, conn_info['password'])
        daemon_cmd = (
            f"nohup python3 {REMOTE_MONITOR_DAEMON_PATH} "
            f"--local-log {request.local_log} "
            f"--remote-log {request.remote_log} "
            f"--interval {request.interval_seconds} "
            f"--leeway {request.leeway_seconds} "
            f"--report-file {REMOTE_MONITOR_REPORT} "
            f"--daemon-log {REMOTE_MONITOR_LOG} "
            f"--count-file {REMOTE_MONITOR_COUNT_FILE} "
            f"> /dev/null 2>&1 & echo $! > {REMOTE_MONITOR_PID_FILE}"
        )
        stdin_d, stdout_d, _ = ssh.exec_command(f"sudo -S bash -c \"{daemon_cmd}\"", timeout=15, get_pty=True)
        stdin_d.write(conn_info['password'] + '\n')
        stdin_d.flush()
        stdout_d.read()
        time.sleep(1)

        # Read daemon PID — try without pty first for clean output, fallback to pty
        daemon_pid = None
        try:
            stdin_pid, stdout_pid, _ = ssh.exec_command(f"cat {REMOTE_MONITOR_PID_FILE} 2>/dev/null", timeout=10)
            daemon_pid_raw = stdout_pid.read().decode('utf-8', errors='replace').strip()
            if daemon_pid_raw.isdigit():
                daemon_pid = int(daemon_pid_raw)
        except Exception:
            pass
        if daemon_pid is None:
            # Fallback: use sudo with pty and parse through noise
            try:
                stdin_pid, stdout_pid, _ = ssh.exec_command(f"sudo -S cat {REMOTE_MONITOR_PID_FILE} 2>/dev/null", timeout=10, get_pty=True)
                stdin_pid.write(conn_info['password'] + '\n')
                stdin_pid.flush()
                daemon_pid_raw = stdout_pid.read().decode('utf-8', errors='replace').strip()
                for line in reversed(daemon_pid_raw.split('\n')):
                    line = line.strip()
                    if line.isdigit():
                        daemon_pid = int(line)
                        break
                if daemon_pid is None:
                    m = re.search(r'\b(\d{3,})\b', daemon_pid_raw)
                    if m:
                        daemon_pid = int(m.group(1))
            except Exception:
                pass
        # Also try pgrep as ultimate fallback
        if daemon_pid is None:
            try:
                stdin_pg, stdout_pg, _ = ssh.exec_command("pgrep -f remote_tunnel_monitor_daemon.py 2>/dev/null", timeout=10)
                pg_output = stdout_pg.read().decode('utf-8', errors='replace').strip()
                for line in pg_output.split('\n'):
                    line = line.strip()
                    if line.isdigit():
                        daemon_pid = int(line)
                        break
            except Exception:
                pass
        ssh.close()

        result = {
            "success": True,
            "message": "Monitoring started",
            "pid": daemon_pid,
            "swanctl_pid": swanctl_pid,
            "disconnect_count": 0
        }
        
        record_activity(username, "monitoring_start", {
            "local_log": request.local_log,
            "remote_log": request.remote_log,
            "interval": request.interval_seconds,
            "leeway": request.leeway_seconds,
            "swanctl_pid": swanctl_pid,
            "daemon_pid": daemon_pid
        })
        
        return result
    except Exception as e:
        logger.error(f"Monitoring start error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/monitoring/stop")
async def monitoring_stop(http_request: Request):
    """Stop the tunnel disconnect monitoring daemon and kill swanctl --log."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        # Stop the monitoring daemon and swanctl --log process on the server
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})

        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                        password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)

            # Kill processes individually to avoid nested quoting issues
            kill_cmds = [
                "pkill -9 -f remote_tunnel_monitor_daemon.py",
                "pkill -9 -f 'swanctl --log'",
                "pkill -9 -f 'ts .%Y-%m-%d'",
                f"rm -f {REMOTE_MONITOR_PID_FILE} {REMOTE_MONITOR_COUNT_FILE}",
            ]
            for cmd in kill_cmds:
                try:
                    stdin_d, stdout_d, _ = ssh.exec_command(f"sudo -S {cmd} 2>/dev/null || true", timeout=10, get_pty=True)
                    stdin_d.write(conn_info['password'] + '\n')
                    stdin_d.flush()
                    stdout_d.read()
                except Exception:
                    pass

            ssh.close()
            logger.info("Stopped monitoring daemon and swanctl --log process")
        except Exception as kill_err:
            logger.warning(f"Error stopping monitoring: {kill_err}")
            return JSONResponse(status_code=500, content={"success": False, "message": str(kill_err)})
        
        record_activity(username, "monitoring_stop", {})
        return {"success": True, "message": "Monitoring stopped"}
    except Exception as e:
        logger.error(f"Monitoring stop error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/monitoring/status")
async def monitoring_status(http_request: Request):
    """Get the monitoring daemon status."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})

        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})

        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                    password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)

        stdin_pid, stdout_pid, _ = ssh.exec_command(
            f"sudo -S bash -c 'cat {REMOTE_MONITOR_PID_FILE} 2>/dev/null'",
            timeout=10,
            get_pty=True
        )
        stdin_pid.write(conn_info['password'] + '\n')
        stdin_pid.flush()
        pid_raw = stdout_pid.read().decode('utf-8', errors='replace').strip()

        daemon_pid = int(pid_raw) if pid_raw.isdigit() else None
        status = "stopped"
        if daemon_pid:
            stdin_ps, stdout_ps, _ = ssh.exec_command(f"ps -p {daemon_pid} -o pid=", timeout=10)
            ps_out = stdout_ps.read().decode('utf-8', errors='replace').strip()
            if ps_out:
                status = "running"
            else:
                daemon_pid = None

        if not daemon_pid:
            stdin_pg, stdout_pg, _ = ssh.exec_command(
                f"pgrep -f '{os.path.basename(REMOTE_MONITOR_DAEMON_PATH)}' | head -n 1",
                timeout=10
            )
            pg_out = stdout_pg.read().decode('utf-8', errors='replace').strip()
            if pg_out.isdigit():
                daemon_pid = int(pg_out)
                status = "running"

        count_value = 0
        try:
            stdin_count, stdout_count, _ = ssh.exec_command(
                f"sudo -S bash -c 'cat {REMOTE_MONITOR_COUNT_FILE} 2>/dev/null'",
                timeout=10,
                get_pty=True
            )
            stdin_count.write(conn_info['password'] + '\n')
            stdin_count.flush()
            count_raw = stdout_count.read().decode('utf-8', errors='replace').strip()
            if count_raw.isdigit():
                count_value = int(count_raw)
        except Exception:
            count_value = 0

        ssh.close()
        return {"success": True, "status": status, "pid": daemon_pid, "disconnect_count": count_value}
    except Exception as e:
        logger.error(f"Monitoring status error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/monitoring/download")
async def monitoring_download(http_request: Request):
    """Download the tunnel disconnect report file."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected"})
        
        content = _download_remote_report(conn_info)
        if content is None:
            return JSONResponse(status_code=404, content={"success": False, "message": "Report file not found"})
        
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=tunnel-disconnect-syslog.log"}
        )
    except Exception as e:
        logger.error(f"Report download error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/config-files")
async def strongswan_list_config_files(http_request: Request):
    """List configuration files from /etc/swanctl/conf.d."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
        except Exception as e:
            return JSONResponse(status_code=400, content={"success": False, "message": f"SSH reconnection failed: {str(e)}"})
        
        # List files in /etc/swanctl/conf.d
        # Use ls -la to include hidden files and ls with both explicit patterns to catch both hidden and normal .conf files
        list_cmd = "ls -la /etc/swanctl/conf.d/*.conf /etc/swanctl/conf.d/.*.conf 2>/dev/null || ls -la /etc/swanctl/conf.d/ 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(list_cmd, timeout=15)
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        # Detect route-based files by checking for if_id_in / if_id_out in each file
        grep_cmd = "grep -rl 'if_id_in\\|if_id_out' /etc/swanctl/conf.d/ 2>/dev/null"
        stdin2, stdout2, stderr2 = ssh.exec_command(grep_cmd, timeout=15)
        route_files_output = stdout2.read().decode('utf-8', errors='replace')
        route_based_files = set()
        for line in route_files_output.strip().split('\n'):
            if line.strip():
                route_based_files.add(os.path.basename(line.strip()))
        
        ssh.close()
        
        # Parse ls output to extract file info
        files = []
        seen_files = set()  # Track filenames we've already processed
        for line in output.strip().split('\n'):
            if not line or line.startswith('total'):
                continue
            parts = line.split()
            if len(parts) >= 9:
                # Format: -rw-r--r-- 1 root root 145804 Feb  5 07:52 /etc/swanctl/conf.d/filename.conf
                size = int(parts[4]) if parts[4].isdigit() else 0
                filepath = parts[-1]
                # Extract just the filename from the full path
                filename = os.path.basename(filepath)
                if (filename.endswith('.conf') or (filename.startswith('.') and filename.endswith('.conf'))) and filename not in seen_files:
                    seen_files.add(filename)
                    vpn_type = 'route' if filename in route_based_files else 'policy'
                    files.append({"name": filename, "size": size, "vpnType": vpn_type})
        
        return {"success": True, "files": files}
        
    except Exception as e:
        logger.error(f"strongSwan list config files error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

class StrongSwanConfigFileRequest(BaseModel):
    filename: str

class StrongSwanToggleFileVisibilityRequest(BaseModel):
    filename: str
    newFilename: str

class StrongSwanConfigFileSaveRequest(BaseModel):
    filename: str
    content: str

@app.post("/api/strongswan/config-file-content")
async def strongswan_get_config_file_content(request: StrongSwanConfigFileRequest, http_request: Request):
    """Get the content of a specific configuration file."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        
        # Validate filename to prevent path traversal
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        
        ssh = _ssh_connect(conn_info)
        
        # Read file content
        cat_cmd = f'sudo -S cat "/etc/swanctl/conf.d/{filename}"'
        output, error, _ = _ssh_sudo_exec(ssh, cat_cmd, conn_info['password'], timeout=10)
        
        ssh.close()
        
        content = output
        
        if 'No such file' in error or 'Permission denied' in error:
            return JSONResponse(status_code=404, content={"success": False, "message": f"File not found or access denied: {filename}"})
        
        return {"success": True, "content": content, "filename": filename}
        
    except Exception as e:
        logger.error(f"strongSwan get config file content error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/config-file-toggle-visibility")
async def strongswan_toggle_config_file_visibility(request: StrongSwanToggleFileVisibilityRequest, http_request: Request):
    """Toggle visibility of a configuration file by renaming it with a dot prefix."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        
        # Validate filename to prevent path traversal
        filename = request.filename
        newFilename = request.newFilename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        if '/' in newFilename or '\\' in newFilename or '..' in newFilename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid new filename"})
        
        ssh = _ssh_connect(conn_info)
        
        # Rename file
        rename_cmd = f'sudo -S mv "/etc/swanctl/conf.d/{filename}" "/etc/swanctl/conf.d/{newFilename}"'
        _, error, exit_status = _ssh_sudo_exec(ssh, rename_cmd, conn_info['password'], timeout=10)
        
        ssh.close()
        
        if exit_status != 0:
            if 'No such file' in error:
                return JSONResponse(status_code=404, content={"success": False, "message": f"File not found: {filename}"})
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to rename file: {error}"})
        
        logger.info(f"Config file {filename} renamed to {newFilename} by {username}")
        record_activity(username, "strongswan_config_rename", {"filename": filename, "newFilename": newFilename})
        
        return {"success": True, "message": f"File {filename} renamed to {newFilename} successfully"}
        
    except Exception as e:
        logger.error(f"strongSwan toggle config file visibility error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/config-file-save")
async def strongswan_save_config_file(request: StrongSwanConfigFileSaveRequest, http_request: Request):
    """Save (create or update) a configuration file."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        
        # Validate filename
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        if not filename.endswith('.conf'):
            return JSONResponse(status_code=400, content={"success": False, "message": "Filename must end with .conf"})
        
        ssh = _ssh_connect(conn_info)
        
        # Write file content - use SFTP to avoid argument list too long issues
        try:
            sftp = ssh.open_sftp()
            temp_path = f"/tmp/swanctl_temp_{filename}"
            
            # Normalize line endings to Unix style (LF only)
            normalized_content = request.content.replace('\r\n', '\n').replace('\r', '\n')
            
            # Write content to temp file with Unix line endings
            with sftp.file(temp_path, 'w') as f:
                f.write(normalized_content)
            
            sftp.close()
            
            # Move temp file to destination with sudo
            move_cmd = f'sudo -S mv "{temp_path}" "/etc/swanctl/conf.d/{filename}" && sudo -S chown root:root "/etc/swanctl/conf.d/{filename}" && sudo -S chmod 644 "/etc/swanctl/conf.d/{filename}"'
            
            stdin, stdout, stderr = ssh.exec_command(move_cmd, timeout=30, get_pty=True)
            # Send password twice (once for mv, potentially once for chown/chmod if sudo cache expires, though unlikely in one line)
            # Actually, sudo -S reads from stdin. We can just feed the password.
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            output = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')
            exit_status = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            if exit_status != 0:
                if 'Permission denied' in error:
                    return JSONResponse(status_code=400, content={"success": False, "message": "Permission denied writing file"})
                return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to save file (exit {exit_status}): {error}"})
                
            logger.info(f"Config file {filename} saved by {username}")
            record_activity(username, "strongswan_config_save", {"filename": filename})
            
            return {"success": True, "message": f"File {filename} saved successfully"}
            
        except Exception as e:
            ssh.close()
            raise e
        
    except Exception as e:
        logger.error(f"strongSwan save config file error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/config-file-delete")
async def strongswan_delete_config_file(request: StrongSwanConfigFileRequest, http_request: Request):
    """Delete a configuration file."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        
        # Validate filename
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        
        ssh = _ssh_connect(conn_info)
        
        # Delete file
        delete_cmd = f'sudo -S rm "/etc/swanctl/conf.d/{filename}"'
        _, error, exit_status = _ssh_sudo_exec(ssh, delete_cmd, conn_info['password'], timeout=10)
        
        ssh.close()
        
        if exit_status != 0:
            if 'No such file' in error:
                return JSONResponse(status_code=404, content={"success": False, "message": f"File not found: {filename}"})
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to delete file: {error}"})
        
        logger.info(f"Config file {filename} deleted by {username}")
        record_activity(username, "strongswan_config_delete", {"filename": filename})
        
        return {"success": True, "message": f"File {filename} deleted successfully"}
        
    except Exception as e:
        logger.error(f"strongSwan delete config file error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Netplan Configuration Endpoints
# ============================================================================

class NetplanFileRequest(BaseModel):
    filename: str

class NetplanFileSaveRequest(BaseModel):
    filename: str
    content: str

class NetplanToggleVisibilityRequest(BaseModel):
    filename: str
    newFilename: str

def _get_swan_ssh(http_request: Request):
    """Helper to get SSH connection for strongSwan server."""
    username = get_current_username(http_request)
    if not username:
        return None, None, JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
    conn_info = strongswan_connections.get(username)
    if not conn_info:
        return None, None, JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
    return username, conn_info, None

def _ssh_connect(conn_info):
    """Create and return an SSH connection."""
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(
        hostname=conn_info['ip'],
        port=conn_info['port'],
        username=conn_info['username'],
        password=conn_info['password'],
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
        allow_agent=False,
        look_for_keys=False
    )
    return ssh

def _ssh_sudo_exec(ssh, cmd, password, timeout=30):
    """Execute a sudo command over SSH, return (output, error, exit_status)."""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout, get_pty=True)
    stdin.write(password + '\n')
    stdin.flush()
    output = stdout.read().decode('utf-8', errors='replace')
    error = stderr.read().decode('utf-8', errors='replace')
    exit_status = stdout.channel.recv_exit_status()
    # Clean sudo artifacts from output
    lines = output.split('\n')
    clean_lines = [l for l in lines if not l.startswith('[sudo]') and not l.startswith('sudo:') and password not in l]
    clean_output = '\n'.join(clean_lines).strip()
    return clean_output, error, exit_status


# ── XFRM Interface Management (for route-based VPN tunnels) ──

class XfrmCreateRequest(BaseModel):
    if_id: int
    phys_dev: Optional[str] = None

class XfrmDeleteRequest(BaseModel):
    name: str

@app.get("/api/strongswan/interfaces")
async def strongswan_list_xfrm_interfaces(http_request: Request):
    """List XFRM interfaces on the connected strongSwan server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, "sudo -S ip -d link show type xfrm", conn_info['password'])
        
        # Also fetch IP addresses for all interfaces
        addr_output, _, _ = _ssh_sudo_exec(ssh, "sudo -S ip -o addr show", conn_info['password'])
        ssh.close()

        # Build a map of interface name -> list of IP addresses
        import re as _re
        addr_map: dict = {}
        for aline in addr_output.split('\n'):
            aline = aline.strip()
            if not aline:
                continue
            amatch = _re.match(r'^\d+:\s+(\S+)\s+inet6?\s+(\S+)', aline)
            if amatch:
                iname = amatch.group(1)
                addr = amatch.group(2)
                addr_map.setdefault(iname, []).append(addr)

        interfaces = []
        current = None
        for line in output.split('\n'):
            line = line.rstrip()
            if not line:
                continue
            iface_match = _re.match(r'^\d+:\s+(\S+?)(?:@(\S+))?:\s+<([^>]*)>\s+mtu\s+(\d+)', line)
            if iface_match:
                if current:
                    current['addresses'] = addr_map.get(current['name'], [])
                    interfaces.append(current)
                name = iface_match.group(1)
                phys_dev = iface_match.group(2)
                flags = iface_match.group(3)
                mtu = int(iface_match.group(4))
                state = 'UP' if 'UP' in flags else 'DOWN'
                current = {"name": name, "ifId": 0, "state": state, "mtu": mtu, "physDev": phys_dev}
            if current and 'xfrm' in line and 'if_id' in line:
                id_match = _re.search(r'if_id\s+(0x[0-9a-fA-F]+|\d+)', line)
                if id_match:
                    val = id_match.group(1)
                    current['ifId'] = int(val, 16) if val.startswith('0x') else int(val)
        if current:
            current['addresses'] = addr_map.get(current['name'], [])
            interfaces.append(current)

        return {"success": True, "interfaces": interfaces}
    except Exception as e:
        logger.error(f"List XFRM interfaces error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/strongswan/interfaces/create")
async def strongswan_create_xfrm_interface(request: XfrmCreateRequest, http_request: Request):
    """Create an XFRM interface on the connected strongSwan server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err

        name = f"xfrm{request.if_id}"
        cmd = f"sudo -S ip link add {name} type xfrm if_id {request.if_id}"
        if request.phys_dev:
            import re as _re
            if not _re.match(r'^[a-zA-Z0-9_.-]+$', request.phys_dev):
                return JSONResponse(status_code=400, content={"success": False, "message": "Invalid physical device name"})
            cmd += f" dev {request.phys_dev}"
        cmd += f" && sudo -S ip link set {name} up"

        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, cmd, conn_info['password'])
        ssh.close()

        if exit_status == 0:
            record_activity(username, "xfrm_create", {"name": name, "if_id": request.if_id})
            return {"success": True, "message": f"Interface {name} created and brought up"}
        return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to create {name}: {error or output}"})
    except Exception as e:
        logger.error(f"Create XFRM interface error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/strongswan/interfaces/delete")
async def strongswan_delete_xfrm_interface(request: XfrmDeleteRequest, http_request: Request):
    """Delete an XFRM interface on the connected strongSwan server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err

        import re as _re
        if not _re.match(r'^xfrm\d+$', request.name):
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid interface name"})

        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(
            ssh, f"sudo -S ip link del {request.name}", conn_info['password'])
        ssh.close()

        if exit_status == 0:
            record_activity(username, "xfrm_delete", {"name": request.name})
            return {"success": True, "message": f"Interface {request.name} deleted"}
        return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to delete {request.name}: {error or output}"})
    except Exception as e:
        logger.error(f"Delete XFRM interface error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


class XfrmBatchCreateRequest(BaseModel):
    interfaces: List[Dict[str, Any]]  # [{if_id: int, addresses: [str] (optional), address: str (optional), phys_dev: str (optional)}]

@app.post("/api/strongswan/interfaces/batch-create")
async def strongswan_batch_create_xfrm(request: XfrmBatchCreateRequest, http_request: Request):
    """Batch create XFRM interfaces with optional IP addresses."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        
        ssh = _ssh_connect(conn_info)
        results = []
        errors = []
        import re as _re
        
        for intf in request.interfaces:
            if_id = intf.get('if_id')
            # Support both 'addresses' (list) and legacy 'address' (string)
            addresses = intf.get('addresses', [])
            if not addresses:
                legacy = intf.get('address', '')
                if legacy:
                    addresses = [legacy]
            phys_dev = intf.get('phys_dev', '')
            
            if not if_id or not isinstance(if_id, int) or if_id < 0:
                errors.append(f"Invalid if_id: {if_id}")
                continue
            
            name = f"xfrm{if_id}"
            cmd = f"sudo -S ip link add {name} type xfrm if_id {if_id}"
            if phys_dev:
                if not _re.match(r'^[a-zA-Z0-9_.-]+$', phys_dev):
                    errors.append(f"Invalid phys_dev for {name}: {phys_dev}")
                    continue
                cmd += f" dev {phys_dev}"
            cmd += f" && sudo -S ip link set {name} up"
            
            for addr in addresses:
                if addr:
                    cmd += f" && sudo -S ip addr add {addr} dev {name}"
            
            output, error, exit_status = _ssh_sudo_exec(ssh, cmd, conn_info['password'])
            if exit_status == 0:
                addr_str = ', '.join(addresses) if addresses else ''
                results.append(f"{name} created" + (f" with {addr_str}" if addr_str else ""))
            else:
                errors.append(f"{name}: {error or output}")
        
        ssh.close()
        record_activity(username, "xfrm_batch_create", {"count": len(results)})
        return {
            "success": len(errors) == 0,
            "message": f"Created {len(results)} interface(s)" + (f", {len(errors)} failed" if errors else ""),
            "results": results,
            "errors": errors
        }
    except Exception as e:
        logger.error(f"Batch create XFRM interfaces error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


class OverlayRoutingRequest(BaseModel):
    type: str  # 'static', 'bgpv4', 'bgpv6', 'ospfv2', 'ospfv3', 'eigrpv4', 'eigrpv6'
    routes: Optional[List[Dict[str, str]]] = None  # for static: [{dest, via, dev}]
    # BGP fields
    local_as: Optional[str] = None
    router_id: Optional[str] = None
    neighbor_addr: Optional[str] = None
    neighbor_as: Optional[str] = None
    networks: Optional[List[str]] = None
    bgp_neighbors: Optional[List[Dict[str, Any]]] = None  # per-neighbor BGP commands [{addr, remote_as, password, ...}]
    bgp_ebgp_requires_policy: Optional[bool] = None  # if False/None, apply 'no bgp ebgp-requires-policy'
    bgp_default_ipv4_unicast: Optional[bool] = None  # if False/None, apply 'no bgp default ipv4-unicast'
    # OSPF fields
    ospf_area: Optional[str] = None          # e.g. '0' or '0.0.0.0'
    ospf_networks: Optional[List[Dict[str, str]]] = None  # [{network, area}]
    ospf_passive_interfaces: Optional[List[str]] = None
    ospf_hello_interval: Optional[str] = None
    ospf_dead_interval: Optional[str] = None
    ospf_interface: Optional[str] = None     # interface to enable OSPF on (e.g. xfrm1)
    ospf_interface_cmds: Optional[List[Dict[str, Any]]] = None  # per-interface OSPF commands [{name, area, cost, ...}]
    # EIGRP fields
    eigrp_as: Optional[str] = None           # EIGRP AS number
    eigrp_networks: Optional[List[str]] = None  # networks to advertise
    eigrp_router_id: Optional[str] = None

def _ensure_frr_available(ssh, password, daemons_needed: List[str], results: List[str], errors: List[str]):
    """Ensure FRR is installed and required daemons are enabled and running. Returns False on failure."""
    check_output, _, check_exit = _ssh_sudo_exec(ssh, "which vtysh", password)
    if check_exit != 0 or not (check_output or '').strip():
        results.append("FRR/vtysh not found. Installing FRR...")
        _ssh_sudo_exec(ssh, "sudo -S killall -q apt-get apt dpkg 2>/dev/null || true", password)
        _ssh_sudo_exec(ssh, "sudo -S rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend", password)
        _ssh_sudo_exec(ssh, "sudo -S dpkg --configure -a", password, timeout=60)
        install_cmds = [
            "sudo -S apt-get update -qq -o DPkg::Lock::Timeout=30",
            "sudo -S apt-get install -y -qq -o DPkg::Lock::Timeout=60 frr frr-pythontools",
        ]
        for icmd in install_cmds:
            o, e, s = _ssh_sudo_exec(ssh, icmd, password, timeout=180)
            if s != 0:
                errors.append(f"FRR install step failed: {(e or o or '').strip()}")
                return False
        results.append("FRR installed successfully")

    # Read daemons file and check each needed daemon
    daemons_out, _, _ = _ssh_sudo_exec(ssh, "sudo -S cat /etc/frr/daemons", password)
    daemons_content = daemons_out or ''
    restart_needed = False

    for daemon in daemons_needed:
        # Check if daemon is currently enabled — match any variation: daemon=yes, daemon = yes, etc.
        # A daemon is NOT enabled if the line reads daemon=no, or if there's no daemon=yes line at all
        enabled = bool(re.search(rf'^\s*{daemon}\s*=\s*yes', daemons_content, re.MULTILINE))
        if not enabled:
            # Try to flip daemon=no to daemon=yes
            has_no_line = bool(re.search(rf'^\s*{daemon}\s*=\s*no', daemons_content, re.MULTILINE))
            if has_no_line:
                _ssh_sudo_exec(ssh, f"sudo -S sed -i -E 's/^(\\s*){daemon}(\\s*)=(\\s*)no/{daemon}=yes/' /etc/frr/daemons", password)
            else:
                # No line exists at all — append it
                _ssh_sudo_exec(ssh, f"sudo -S bash -c 'echo \"{daemon}=yes\" >> /etc/frr/daemons'", password)
            restart_needed = True
            results.append(f"Enabled {daemon} in FRR daemons")

    if restart_needed:
        _ssh_sudo_exec(ssh, "sudo -S systemctl restart frr", password)
        time.sleep(4)
        results.append("Restarted FRR to activate daemons")

    # Verify each required daemon is actually running
    for daemon in daemons_needed:
        ps_out, _, ps_exit = _ssh_sudo_exec(ssh, f"sudo -S pgrep -x {daemon}", password)
        if ps_exit != 0 or not (ps_out or '').strip():
            # Daemon not running — try one more restart
            if not restart_needed:
                _ssh_sudo_exec(ssh, "sudo -S systemctl restart frr", password)
                time.sleep(4)
            # Check again
            ps_out2, _, ps_exit2 = _ssh_sudo_exec(ssh, f"sudo -S pgrep -x {daemon}", password)
            if ps_exit2 != 0 or not (ps_out2 or '').strip():
                errors.append(f"FRR daemon '{daemon}' is not running after enable+restart. Check /etc/frr/daemons manually.")
                return False
            results.append(f"Daemon {daemon} is now running (pid: {(ps_out2 or '').strip()})")
        else:
            results.append(f"Daemon {daemon} confirmed running (pid: {(ps_out or '').strip()})")

    # Final vtysh sanity check
    verify_out, _, verify_exit = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show version'", password)
    if verify_exit != 0:
        errors.append(f"vtysh not working: {(verify_out or '').strip()}")
        return False
    return True

def _run_vtysh(ssh, password, vtysh_parts: List[str]):
    """Run a vtysh command chain via sudo. Returns (output, error, exit_status).
    Splits 'write memory' into a separate invocation for reliability.
    Batches large command sets to avoid hitting command-line length limits."""
    # Separate write memory from config commands
    has_write = False
    config_parts = []
    for p in vtysh_parts:
        if p.lower().strip() in ('write memory', 'write', 'wr'):
            has_write = True
        else:
            config_parts.append(p)

    # Batch config commands to avoid exceeding command-line length limits.
    # Identify preamble (configure terminal, router ospf, etc.) and body commands.
    # We keep the preamble under ~50 -c flags per batch to stay well under limits.
    MAX_FLAGS_PER_BATCH = 50
    all_output, all_error = '', ''
    exit_status = 0

    if len(config_parts) <= MAX_FLAGS_PER_BATCH:
        # Small enough to run in one shot
        c_flags = ' '.join(f"-c '{p}'" for p in config_parts)
        cmd = f"sudo -S vtysh {c_flags}"
        all_output, all_error, exit_status = _ssh_sudo_exec(ssh, cmd, password)
    else:
        # Find preamble: everything up to and including 'router-id' (if present), then bulk commands are body
        preamble = []
        body = []
        in_body = False
        for p in config_parts:
            lp = p.lower().strip()
            if not in_body:
                preamble.append(p)
                # Once we've seen the router context + router-id, everything after is body
                if lp.startswith('router ') or lp.startswith('address-family'):
                    in_body = True
            elif 'router-id' in lp or lp.startswith('ospf router-id') or lp.startswith('ospf6 router-id') or lp.startswith('bgp router-id'):
                # router-id belongs in preamble, not body
                preamble.append(p)
            else:
                # 'exit' / 'end' are postamble — skip them from body, we'll add them per batch
                if lp in ('exit', 'end'):
                    continue
                body.append(p)
        # If we never entered body mode, just run preamble as-is
        if not body:
            c_flags = ' '.join(f"-c '{p}'" for p in config_parts)
            cmd = f"sudo -S vtysh {c_flags}"
            all_output, all_error, exit_status = _ssh_sudo_exec(ssh, cmd, password)
        else:
            # Run body commands in batches, each wrapped with preamble + exit/end
            for i in range(0, len(body), MAX_FLAGS_PER_BATCH):
                batch = body[i:i + MAX_FLAGS_PER_BATCH]
                batch_parts = preamble + batch + ["exit", "end"]
                c_flags = ' '.join(f"-c '{p}'" for p in batch_parts)
                cmd = f"sudo -S vtysh {c_flags}"
                o, e, s = _ssh_sudo_exec(ssh, cmd, password)
                if o:
                    all_output += o + '\n'
                if e:
                    all_error += e + '\n'
                if s != 0:
                    exit_status = s
                    break
            logger.info(f"vtysh: ran {len(body)} commands in {((len(body) - 1) // MAX_FLAGS_PER_BATCH) + 1} batch(es)")

    # Run write memory separately to ensure it executes
    if has_write and exit_status == 0:
        _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'write memory'", password)

    return all_output.strip(), all_error.strip(), exit_status

@app.post("/api/strongswan/overlay-routing/apply")
async def strongswan_overlay_routing_apply(request: OverlayRoutingRequest, http_request: Request):
    """Apply overlay routing configuration (static, BGP, OSPF, or EIGRP via FRR/vtysh)."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        results = []
        errors = []

        if request.type == 'static':
            for route in (request.routes or []):
                dest = route.get('dest', '')
                via = route.get('via', '')
                dev = route.get('dev', '')
                if not dest:
                    continue
                cmd = f"sudo -S ip route add {dest}"
                if via:
                    cmd += f" via {via}"
                if dev:
                    cmd += f" dev {dev}"
                output, error, exit_status = _ssh_sudo_exec(ssh, cmd, conn_info['password'])
                if exit_status == 0:
                    results.append(f"Route {dest} added")
                else:
                    errors.append(f"Route {dest}: {error or output}")

        elif request.type in ('bgpv4', 'bgpv6'):
            af = 'ipv4' if request.type == 'bgpv4' else 'ipv6'
            if not _ensure_frr_available(ssh, conn_info['password'], ['bgpd'], results, errors):
                ssh.close()
                return {"success": False, "message": "FRR setup failed: " + "; ".join(errors), "results": results, "errors": errors}

            # Build neighbor list: new format (bgp_neighbors) or legacy single neighbor
            neighbors: List[Dict[str, Any]] = []
            if request.bgp_neighbors:
                neighbors = request.bgp_neighbors
            elif request.neighbor_addr and request.neighbor_as:
                neighbors = [{'addr': request.neighbor_addr, 'remote_as': request.neighbor_as}]

            new_neighbor_addrs = {nb.get('addr', '') for nb in neighbors if nb.get('addr')}

            # ── Merge strategy: preserve existing BGP process, only clean stale
            # neighbors for THIS address family so BGPv4 and BGPv6 can coexist ──
            run_out, _, _ = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show running-config'", conn_info['password'])
            running = run_out or ''
            old_bgp = re.search(r'router bgp (\d+)', running)

            if old_bgp and old_bgp.group(1) != request.local_as:
                # AS changed — must remove old BGP entirely
                _run_vtysh(ssh, conn_info['password'], ["configure terminal", f"no router bgp {old_bgp.group(1)}", "end", "write memory"])
                logger.info(f"BGP: AS changed ({old_bgp.group(1)} -> {request.local_as}), removed old config")
            elif old_bgp:
                # Same AS — remove only stale neighbors for THIS address family
                # Parse neighbors that were activated in the current AF
                af_block = re.search(
                    rf'address-family {af} unicast\s*\n(.*?)exit-address-family',
                    running, re.DOTALL
                )
                if af_block:
                    old_af_neighbors = re.findall(r'neighbor (\S+) activate', af_block.group(1))
                    stale = [n for n in old_af_neighbors if n not in new_neighbor_addrs]
                    if stale:
                        cleanup_parts = ["configure terminal", f"router bgp {request.local_as}",
                                         f"address-family {af} unicast"]
                        for addr in stale:
                            cleanup_parts.append(f"no neighbor {addr} activate")
                        cleanup_parts.extend(["exit-address-family"])
                        # Also remove stale neighbors at router level if they are not in any other AF
                        other_af = 'ipv6' if af == 'ipv4' else 'ipv4'
                        other_af_block = re.search(
                            rf'address-family {other_af} unicast\s*\n(.*?)exit-address-family',
                            running, re.DOTALL
                        )
                        other_af_neighbors = set()
                        if other_af_block:
                            other_af_neighbors = set(re.findall(r'neighbor (\S+) activate', other_af_block.group(1)))
                        for addr in stale:
                            if addr not in other_af_neighbors:
                                cleanup_parts.append(f"no neighbor {addr} remote-as")
                        cleanup_parts.extend(["exit", "end", "write memory"])
                        _run_vtysh(ssh, conn_info['password'], cleanup_parts)
                        logger.info(f"BGP ({af}): removed {len(stale)} stale neighbor(s): {stale}")

            # ── Phase 1: Router-level config (BGP globals + neighbor declarations) ──
            # Build router-level commands as individual items to batch safely
            router_cmds: List[str] = []
            if request.router_id:
                router_cmds.append(f"bgp router-id {request.router_id}")
            if not request.bgp_ebgp_requires_policy:
                router_cmds.append("no bgp ebgp-requires-policy")
            if not request.bgp_default_ipv4_unicast:
                router_cmds.append("no bgp default ipv4-unicast")

            # Declare all neighbors at router-level
            for nb in neighbors:
                addr = nb.get('addr', '')
                remote_as = nb.get('remote_as', '')
                if addr and remote_as:
                    router_cmds.append(f"neighbor {addr} remote-as {remote_as}")

            # Per-neighbor router-level commands (outside address-family)
            for nb in neighbors:
                addr = nb.get('addr', '')
                if not addr:
                    continue
                if nb.get('password'):
                    router_cmds.append(f"neighbor {addr} password {nb['password']}")
                if nb.get('ebgpMultihop'):
                    router_cmds.append(f"neighbor {addr} ebgp-multihop {nb['ebgpMultihop']}")
                if nb.get('updateSource'):
                    router_cmds.append(f"neighbor {addr} update-source {nb['updateSource']}")
                if nb.get('bfd'):
                    router_cmds.append(f"neighbor {addr} bfd")
                if nb.get('keepAlive') or nb.get('holdTime'):
                    ka = nb.get('keepAlive') or '60'
                    ht = nb.get('holdTime') or '180'
                    router_cmds.append(f"neighbor {addr} timers {ka} {ht}")

            # Run router-level commands in batches (preamble = configure terminal + router bgp)
            bgp_preamble = ["configure terminal", f"router bgp {request.local_as}"]
            BATCH_SIZE = 40
            exit_status = 0
            all_output, all_error = '', ''

            for i in range(0, max(len(router_cmds), 1), BATCH_SIZE):
                batch = router_cmds[i:i + BATCH_SIZE]
                parts = bgp_preamble + batch + ["exit", "end"]
                o, e, s = _run_vtysh(ssh, conn_info['password'], parts)
                if o: all_output += o + '\n'
                if e: all_error += e + '\n'
                if s != 0:
                    exit_status = s
                    break
            if len(router_cmds) > BATCH_SIZE:
                logger.info(f"BGP ({af}): router-level cmds sent in {((len(router_cmds) - 1) // BATCH_SIZE) + 1} batch(es)")

            # ── Phase 2: Address-family config (activate + per-neighbor AF cmds + networks) ──
            if exit_status == 0:
                af_cmds: List[str] = []
                for nb in neighbors:
                    addr = nb.get('addr', '')
                    if not addr:
                        continue
                    af_cmds.append(f"neighbor {addr} activate")
                    if nb.get('nextHopSelf'):
                        af_cmds.append(f"neighbor {addr} next-hop-self")
                    if nb.get('defaultOriginate'):
                        af_cmds.append(f"neighbor {addr} default-originate")
                    if nb.get('softReconfigInbound'):
                        af_cmds.append(f"neighbor {addr} soft-reconfiguration inbound")
                    if nb.get('weight'):
                        af_cmds.append(f"neighbor {addr} weight {nb['weight']}")
                    if nb.get('allowasIn'):
                        af_cmds.append(f"neighbor {addr} allowas-in {nb['allowasIn']}")
                    if nb.get('routeMapIn'):
                        af_cmds.append(f"neighbor {addr} route-map {nb['routeMapIn']} in")
                    if nb.get('routeMapOut'):
                        af_cmds.append(f"neighbor {addr} route-map {nb['routeMapOut']} out")
                    if nb.get('prefixListIn'):
                        af_cmds.append(f"neighbor {addr} prefix-list {nb['prefixListIn']} in")
                    if nb.get('prefixListOut'):
                        af_cmds.append(f"neighbor {addr} prefix-list {nb['prefixListOut']} out")

                for net in (request.networks or []):
                    if net:
                        af_cmds.append(f"network {net}")

                # Run AF commands in batches (preamble = conf t + router bgp + address-family)
                af_preamble = ["configure terminal", f"router bgp {request.local_as}",
                               f"address-family {af} unicast"]
                for i in range(0, max(len(af_cmds), 1), BATCH_SIZE):
                    batch = af_cmds[i:i + BATCH_SIZE]
                    parts = af_preamble + batch + ["exit-address-family", "exit", "end"]
                    o, e, s = _run_vtysh(ssh, conn_info['password'], parts)
                    if o: all_output += o + '\n'
                    if e: all_error += e + '\n'
                    if s != 0:
                        exit_status = s
                        break
                if len(af_cmds) > BATCH_SIZE:
                    logger.info(f"BGP ({af}): address-family cmds sent in {((len(af_cmds) - 1) // BATCH_SIZE) + 1} batch(es)")

            # Write memory
            if exit_status == 0:
                _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'write memory'", conn_info['password'])

            if exit_status == 0:
                results.append(f"BGP ({af}) configuration applied successfully ({len(neighbors)} neighbor(s), {len([n for n in (request.networks or []) if n])} network(s))")
            else:
                errors.append(f"vtysh failed: {(all_error or all_output or 'unknown error').strip()}")

        elif request.type == 'ospfv2':
            if not _ensure_frr_available(ssh, conn_info['password'], ['ospfd'], results, errors):
                ssh.close()
                return {"success": False, "message": "FRR setup failed: " + "; ".join(errors), "results": results, "errors": errors}
            has_interface_config = bool(request.ospf_interface)
            has_networks = any(e.get('network') for e in (request.ospf_networks or []))

            # Before applying, remove all existing 'ip ospf' commands from interfaces
            # to prevent stale settings and to avoid conflict between network cmds and ip ospf area
            run_out, _, _ = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show running-config'", conn_info['password'])
            old_ospf_cmds: Dict[str, list] = {}  # {iface_name: [cmd_lines]}
            current_iface = None
            for line in (run_out or '').splitlines():
                line_s = line.strip()
                m_if = re.match(r'^interface (\S+)', line_s)
                if m_if:
                    current_iface = m_if.group(1)
                elif current_iface and line_s.startswith('ip ospf'):
                    old_ospf_cmds.setdefault(current_iface, []).append(line_s)
                elif line_s in ('exit', '!'):
                    current_iface = None if line_s == '!' else current_iface
            if old_ospf_cmds:
                logger.info(f"OSPFv2: removing old ip ospf commands from {len(old_ospf_cmds)} interface(s) before applying")
                remove_parts = ["configure terminal"]
                for if_name, cmds in old_ospf_cmds.items():
                    remove_parts.append(f"interface {if_name}")
                    for cmd in cmds:
                        remove_parts.append(f"no {cmd}")
                    remove_parts.append("exit")
                remove_parts.extend(["end", "write memory"])
                _run_vtysh(ssh, conn_info['password'], remove_parts)

            # Build router-level OSPF config
            vtysh_parts = ["configure terminal", "router ospf"]
            if request.router_id:
                vtysh_parts.append(f"ospf router-id {request.router_id}")
            # Add 'network ... area' commands
            net_count = 0
            for net_entry in (request.ospf_networks or []):
                network = net_entry.get('network', '')
                area = net_entry.get('area', '0')
                if network:
                    vtysh_parts.append(f"network {network} area {area}")
                    net_count += 1
            logger.info(f"OSPFv2: {net_count} network command(s), interface={request.ospf_interface or 'none'}")
            for iface in (request.ospf_passive_interfaces or []):
                if iface:
                    vtysh_parts.append(f"passive-interface {iface}")
            vtysh_parts.extend(["exit", "end", "write memory"])
            output, error, exit_status = _run_vtysh(ssh, conn_info['password'], vtysh_parts)
            if exit_status == 0:
                results.append(f"OSPFv2 configuration applied successfully ({net_count} network(s))")
            else:
                # If interface-level config follows, a router-level failure is non-fatal
                msg = (error or output or 'unknown error').strip()
                if has_interface_config:
                    logger.warning(f"OSPFv2 router-level vtysh returned non-zero (non-fatal, interface config follows): {msg}")
                else:
                    errors.append(f"vtysh config failed: {msg}")
            # Apply interface-level OSPF settings using per-interface commands
            # Skip 'ip ospf area' when network commands are used — they conflict in FRR
            if has_interface_config:
                # Build a lookup from interface name to its commands
                cmds_by_name: Dict[str, Dict[str, Any]] = {}
                for cmd_entry in (request.ospf_interface_cmds or []):
                    cmds_by_name[cmd_entry.get('name', '')] = cmd_entry
                iface_list = [iface.strip() for iface in request.ospf_interface.split(',') if iface.strip()]
                for iface_name in iface_list:
                    ic = cmds_by_name.get(iface_name, {})
                    intf_parts = ["configure terminal", f"interface {iface_name}"]
                    # Area (skip when network commands are used — they conflict)
                    if not has_networks:
                        intf_parts.append(f"ip ospf area {ic.get('area') or request.ospf_area or '0'}")
                    # Cost
                    if ic.get('cost'):
                        intf_parts.append(f"ip ospf cost {ic['cost']}")
                    # Intervals
                    hello = ic.get('helloInterval') or request.ospf_hello_interval
                    dead = ic.get('deadInterval') or request.ospf_dead_interval
                    if hello:
                        intf_parts.append(f"ip ospf hello-interval {hello}")
                    if dead:
                        intf_parts.append(f"ip ospf dead-interval {dead}")
                    if ic.get('retransmitInterval'):
                        intf_parts.append(f"ip ospf retransmit-interval {ic['retransmitInterval']}")
                    if ic.get('transmitDelay'):
                        intf_parts.append(f"ip ospf transmit-delay {ic['transmitDelay']}")
                    # Priority
                    if ic.get('priority'):
                        intf_parts.append(f"ip ospf priority {ic['priority']}")
                    # Network type
                    if ic.get('networkType'):
                        intf_parts.append(f"ip ospf network {ic['networkType']}")
                    # MTU ignore
                    if ic.get('mtuIgnore'):
                        intf_parts.append("ip ospf mtu-ignore")
                    # BFD
                    if ic.get('bfd'):
                        intf_parts.append("ip ospf bfd")
                    # Authentication
                    auth_type = ic.get('authType', '')
                    if auth_type == 'null':
                        intf_parts.append("ip ospf authentication")
                        if ic.get('authKey'):
                            intf_parts.append(f"ip ospf authentication-key {ic['authKey']}")
                    elif auth_type == 'message-digest':
                        intf_parts.append("ip ospf authentication message-digest")
                        if ic.get('mdKeyId') and ic.get('mdKey'):
                            intf_parts.append(f"ip ospf message-digest-key {ic['mdKeyId']} md5 {ic['mdKey']}")
                    intf_parts.extend(["exit", "end", "write memory"])
                    # Only run if there are actual interface commands beyond the wrapper
                    if len(intf_parts) > 4:  # more than just: conf t, interface X, exit, end, wr
                        o, e, s = _run_vtysh(ssh, conn_info['password'], intf_parts)
                        if s == 0:
                            results.append(f"OSPF interface config applied on {iface_name}")
                        else:
                            errors.append(f"OSPF interface config failed on {iface_name}: {(e or o or '').strip()}")
            # Verify OSPF took effect — informational only, not a hard error
            verify_out, _, _ = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show ip ospf interface'", conn_info['password'])
            if verify_out and 'ospf' in verify_out.lower():
                results.append("OSPF verified active on interface(s)")

        elif request.type == 'ospfv3':
            if not _ensure_frr_available(ssh, conn_info['password'], ['ospf6d'], results, errors):
                ssh.close()
                return {"success": False, "message": "FRR setup failed: " + "; ".join(errors), "results": results, "errors": errors}
            vtysh_parts = ["configure terminal", "router ospf6"]
            if request.router_id:
                vtysh_parts.append(f"ospf6 router-id {request.router_id}")
            for iface in (request.ospf_passive_interfaces or []):
                if iface:
                    vtysh_parts.append(f"passive-interface {iface}")
            vtysh_parts.extend(["exit"])
            # OSPFv3 uses interface-level area assignment — support comma-separated interfaces
            if request.ospf_interface:
                cmds_by_name: Dict[str, Dict[str, Any]] = {}
                for cmd_entry in (request.ospf_interface_cmds or []):
                    cmds_by_name[cmd_entry.get('name', '')] = cmd_entry
                iface_list = [iface.strip() for iface in request.ospf_interface.split(',') if iface.strip()]
                for iface_name in iface_list:
                    ic = cmds_by_name.get(iface_name, {})
                    vtysh_parts.append(f"interface {iface_name}")
                    vtysh_parts.append(f"ipv6 ospf6 area {ic.get('area') or request.ospf_area or '0'}")
                    # Cost
                    if ic.get('cost'):
                        vtysh_parts.append(f"ipv6 ospf6 cost {ic['cost']}")
                    # Intervals
                    hello = ic.get('helloInterval') or request.ospf_hello_interval
                    dead = ic.get('deadInterval') or request.ospf_dead_interval
                    if hello:
                        vtysh_parts.append(f"ipv6 ospf6 hello-interval {hello}")
                    if dead:
                        vtysh_parts.append(f"ipv6 ospf6 dead-interval {dead}")
                    if ic.get('retransmitInterval'):
                        vtysh_parts.append(f"ipv6 ospf6 retransmit-interval {ic['retransmitInterval']}")
                    if ic.get('transmitDelay'):
                        vtysh_parts.append(f"ipv6 ospf6 transmit-delay {ic['transmitDelay']}")
                    # Priority
                    if ic.get('priority'):
                        vtysh_parts.append(f"ipv6 ospf6 priority {ic['priority']}")
                    # Network type
                    if ic.get('networkType'):
                        vtysh_parts.append(f"ipv6 ospf6 network {ic['networkType']}")
                    # MTU ignore
                    if ic.get('mtuIgnore'):
                        vtysh_parts.append("ipv6 ospf6 mtu-ignore")
                    # Interface MTU
                    if ic.get('ifmtu'):
                        vtysh_parts.append(f"ipv6 ospf6 ifmtu {ic['ifmtu']}")
                    # BFD
                    if ic.get('bfd'):
                        vtysh_parts.append("ipv6 ospf6 bfd")
                    vtysh_parts.append("exit")
            vtysh_parts.extend(["end", "write memory"])
            output, error, exit_status = _run_vtysh(ssh, conn_info['password'], vtysh_parts)
            if exit_status == 0:
                results.append("OSPFv3 configuration applied successfully")
            else:
                errors.append(f"vtysh failed: {(error or output or 'unknown error').strip()}")

        elif request.type == 'eigrpv4':
            if not _ensure_frr_available(ssh, conn_info['password'], ['eigrpd'], results, errors):
                ssh.close()
                return {"success": False, "message": "FRR setup failed: " + "; ".join(errors), "results": results, "errors": errors}
            eigrp_as = request.eigrp_as or '100'
            vtysh_parts = ["configure terminal", f"router eigrp {eigrp_as}"]
            if request.eigrp_router_id:
                vtysh_parts.append(f"eigrp router-id {request.eigrp_router_id}")
            for net in (request.eigrp_networks or []):
                if net:
                    vtysh_parts.append(f"network {net}")
            for iface in (request.ospf_passive_interfaces or []):
                if iface:
                    vtysh_parts.append(f"passive-interface {iface}")
            vtysh_parts.extend(["exit", "end", "write memory"])
            output, error, exit_status = _run_vtysh(ssh, conn_info['password'], vtysh_parts)
            if exit_status == 0:
                results.append(f"EIGRPv4 (AS {eigrp_as}) configuration applied successfully")
            else:
                errors.append(f"vtysh failed: {(error or output or 'unknown error').strip()}")

        elif request.type == 'eigrpv6':
            if not _ensure_frr_available(ssh, conn_info['password'], ['eigrpd'], results, errors):
                ssh.close()
                return {"success": False, "message": "FRR setup failed: " + "; ".join(errors), "results": results, "errors": errors}
            eigrp_as = request.eigrp_as or '100'
            vtysh_parts = ["configure terminal", f"router eigrp {eigrp_as}"]
            if request.eigrp_router_id:
                vtysh_parts.append(f"eigrp router-id {request.eigrp_router_id}")
            for net in (request.eigrp_networks or []):
                if net:
                    vtysh_parts.append(f"network {net}")
            vtysh_parts.extend(["exit"])
            # EIGRPv6 needs interface-level activation
            if request.ospf_interface:
                vtysh_parts.append(f"interface {request.ospf_interface}")
                vtysh_parts.append(f"ipv6 eigrp {eigrp_as}")
                vtysh_parts.append("exit")
            vtysh_parts.extend(["end", "write memory"])
            output, error, exit_status = _run_vtysh(ssh, conn_info['password'], vtysh_parts)
            if exit_status == 0:
                results.append(f"EIGRPv6 (AS {eigrp_as}) configuration applied successfully")
            else:
                errors.append(f"vtysh failed: {(error or output or 'unknown error').strip()}")

        ssh.close()
        record_activity(username, "overlay_routing_apply", {"type": request.type})
        has_results = len(results) > 0
        has_errors = len(errors) > 0
        return {
            "success": has_results and not has_errors,
            "partial": has_results and has_errors,
            "message": "; ".join(results + ([f"(Warnings: {'; '.join(errors)})"] if has_errors and has_results else errors if has_errors else [])) if (has_results or has_errors) else "Applied",
            "results": results,
            "errors": errors,
        }
    except Exception as e:
        logger.error(f"Overlay routing apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


class OverlayRoutingDeleteRequest(BaseModel):
    type: str  # 'static', 'bgpv4', 'bgpv6', 'ospfv2', 'ospfv3', 'eigrpv4', 'eigrpv6'

@app.post("/api/strongswan/overlay-routing/delete")
async def strongswan_overlay_routing_delete(request: OverlayRoutingDeleteRequest, http_request: Request):
    """Remove overlay routing configuration."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        pw = conn_info['password']

        if request.type == 'static':
            route_v4, _, _ = _ssh_sudo_exec(ssh, "sudo -S ip route show", pw)
            route_v6, _, _ = _ssh_sudo_exec(ssh, "sudo -S ip -6 route show", pw)
            deleted = 0
            for line in (route_v4 or '').split('\n') + (route_v6 or '').split('\n'):
                if 'xfrm' in line.lower() and line.strip():
                    route_spec = line.strip().split('proto')[0].strip()
                    _ssh_sudo_exec(ssh, f"sudo -S ip route del {route_spec}", pw)
                    deleted += 1
            ssh.close()
            return {"success": True, "message": f"Removed {deleted} static route(s) through XFRM interfaces"}

        # All dynamic protocols need vtysh
        check_out, _, check_exit = _ssh_sudo_exec(ssh, "which vtysh", pw)
        if check_exit != 0 or not (check_out or '').strip():
            ssh.close()
            return {"success": False, "message": "FRR/vtysh is not installed — no routing configuration to remove"}

        output, _, _ = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show running-config'", pw)
        running = output or ''

        if request.type in ('bgpv4', 'bgpv6'):
            af = 'ipv4' if request.type == 'bgpv4' else 'ipv6'
            other_af = 'ipv6' if af == 'ipv4' else 'ipv4'
            as_match = re.search(r'router bgp (\d+)', running)
            if not as_match:
                ssh.close()
                return {"success": True, "message": "No BGP configuration found to remove"}
            bgp_as = as_match.group(1)
            # Check if the other AF has neighbors — if so, only remove this AF
            other_af_block = re.search(
                rf'address-family {other_af} unicast\s*\n(.*?)exit-address-family',
                running, re.DOTALL
            )
            other_has_neighbors = bool(other_af_block and re.search(r'neighbor \S+ activate', other_af_block.group(1)))
            if other_has_neighbors:
                # Only remove this AF's neighbors and address-family block
                af_block = re.search(
                    rf'address-family {af} unicast\s*\n(.*?)exit-address-family',
                    running, re.DOTALL
                )
                del_parts = ["configure terminal", f"router bgp {bgp_as}"]
                af_neighbors = []
                if af_block:
                    af_neighbors = re.findall(r'neighbor (\S+) activate', af_block.group(1))
                    del_parts.append(f"address-family {af} unicast")
                    for addr in af_neighbors:
                        del_parts.append(f"no neighbor {addr} activate")
                    # Remove networks in this AF
                    af_networks = re.findall(r'network (\S+)', af_block.group(1))
                    for net in af_networks:
                        del_parts.append(f"no network {net}")
                    del_parts.append("exit-address-family")
                # Remove router-level neighbor declarations that aren't in the other AF
                other_af_neighbors = set()
                if other_af_block:
                    other_af_neighbors = set(re.findall(r'neighbor (\S+) activate', other_af_block.group(1)))
                for addr in af_neighbors:
                    if addr not in other_af_neighbors:
                        del_parts.append(f"no neighbor {addr} remote-as")
                del_parts.extend(["exit", "end", "write memory"])
                _run_vtysh(ssh, pw, del_parts)
                ssh.close()
                return {"success": True, "message": f"BGP {af} address-family configuration removed (other AF preserved)"}
            else:
                # No other AF — remove entire BGP process
                _run_vtysh(ssh, pw, ["configure terminal", f"no router bgp {bgp_as}", "end", "write memory"])
                ssh.close()
                return {"success": True, "message": f"BGP AS {bgp_as} configuration removed"}

        elif request.type == 'ospfv2':
            removed_parts = []
            # Collect every 'ip ospf ...' command per interface so we can negate them all
            ospf_iface_cmds: Dict[str, list] = {}  # {iface_name: [cmd_lines]}
            current_iface = None
            for line in running.splitlines():
                line_s = line.strip()
                m = re.match(r'^interface (\S+)', line_s)
                if m:
                    current_iface = m.group(1)
                elif current_iface and line_s.startswith('ip ospf'):
                    ospf_iface_cmds.setdefault(current_iface, []).append(line_s)
                elif line_s in ('exit', '!'):
                    current_iface = None if line_s == '!' else current_iface
            if ospf_iface_cmds:
                iface_parts = ["configure terminal"]
                for if_name, cmds in ospf_iface_cmds.items():
                    iface_parts.append(f"interface {if_name}")
                    for cmd in cmds:
                        iface_parts.append(f"no {cmd}")
                    iface_parts.append("exit")
                iface_parts.extend(["end", "write memory"])
                _run_vtysh(ssh, pw, iface_parts)
                removed_parts.append(f"ip ospf from {len(ospf_iface_cmds)} interface(s)")
            # Remove router ospf
            if re.search(r'router ospf\b(?!6)', running):
                _run_vtysh(ssh, pw, ["configure terminal", "no router ospf", "end", "write memory"])
                removed_parts.append("router ospf")
            if removed_parts:
                ssh.close()
                return {"success": True, "message": f"OSPFv2 configuration removed: {', '.join(removed_parts)}"}
            ssh.close()
            return {"success": True, "message": "No OSPF configuration found to remove"}

        elif request.type == 'ospfv3':
            removed_parts = []
            # Collect every 'ipv6 ospf6 ...' command per interface so we can negate them all
            ospf6_iface_cmds: Dict[str, list] = {}  # {iface_name: [cmd_lines]}
            current_iface = None
            for line in running.splitlines():
                line_s = line.strip()
                m = re.match(r'^interface (\S+)', line_s)
                if m:
                    current_iface = m.group(1)
                elif current_iface and line_s.startswith('ipv6 ospf6'):
                    ospf6_iface_cmds.setdefault(current_iface, []).append(line_s)
                elif line_s in ('exit', '!'):
                    current_iface = None if line_s == '!' else current_iface
            if ospf6_iface_cmds:
                iface_parts = ["configure terminal"]
                for if_name, cmds in ospf6_iface_cmds.items():
                    iface_parts.append(f"interface {if_name}")
                    for cmd in cmds:
                        iface_parts.append(f"no {cmd}")
                    iface_parts.append("exit")
                iface_parts.extend(["end", "write memory"])
                _run_vtysh(ssh, pw, iface_parts)
                removed_parts.append(f"ipv6 ospf6 from {len(ospf6_iface_cmds)} interface(s)")
            # Remove router ospf6
            if 'router ospf6' in running:
                _run_vtysh(ssh, pw, ["configure terminal", "no router ospf6", "end", "write memory"])
                removed_parts.append("router ospf6")
            if removed_parts:
                ssh.close()
                return {"success": True, "message": f"OSPFv3 configuration removed: {', '.join(removed_parts)}"}
            ssh.close()
            return {"success": True, "message": "No OSPFv3 configuration found to remove"}

        elif request.type in ('eigrpv4', 'eigrpv6'):
            eigrp_match = re.search(r'router eigrp (\d+)', running)
            if eigrp_match:
                _run_vtysh(ssh, pw, ["configure terminal", f"no router eigrp {eigrp_match.group(1)}", "end", "write memory"])
                ssh.close()
                return {"success": True, "message": f"EIGRP AS {eigrp_match.group(1)} configuration removed"}
            ssh.close()
            return {"success": True, "message": "No EIGRP configuration found to remove"}

        ssh.close()
        return {"success": False, "message": f"Unknown routing type: {request.type}"}
    except Exception as e:
        logger.error(f"Overlay routing delete error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/strongswan/overlay-routing/status")
async def strongswan_overlay_routing_status(http_request: Request):
    """Get overlay routing status: config, protocol neighbors, and route table for XFRM interfaces."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        pw = conn_info['password']

        # Get routes through xfrm interfaces (legacy)
        route_v4, _, _ = _ssh_sudo_exec(ssh, "sudo -S ip route show", pw)
        route_v6, _, _ = _ssh_sudo_exec(ssh, "sudo -S ip -6 route show", pw)
        xfrm_routes = []
        for line in (route_v4 or '').split('\n') + (route_v6 or '').split('\n'):
            if 'xfrm' in line.lower():
                xfrm_routes.append(line.strip())
        route_output = '\n'.join(xfrm_routes)

        # Get per-protocol routes via vtysh
        route_sections = {}
        route_cmds = {
            'static_v4': "show ip route static",
            'static_v6': "show ipv6 route static",
            'bgp_v4': "show ip route bgp",
            'bgp_v6': "show ipv6 route bgp",
            'ospf_v4': "show ip route ospf",
            'ospf_v6': "show ipv6 route ospf6",
            'eigrp_v4': "show ip route eigrp",
            'eigrp_v6': "show ipv6 route eigrp",
        }
        for key, cmd in route_cmds.items():
            try:
                out, _, s = _ssh_sudo_exec(ssh, f"sudo -S vtysh -c '{cmd}'", pw, timeout=10)
                if s == 0 and out and out.strip():
                    route_sections[key] = out.strip()
            except Exception:
                pass

        # Try to get FRR/vtysh config
        config_output, _, config_status = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show running-config'", pw)
        if config_status != 0:
            config_output = "FRR/vtysh not available or not configured"

        running = config_output or ''

        # Gather protocol-specific neighbor/status info
        protocol_info = {}

        # BGP
        if 'router bgp' in running:
            bgp_out, _, s = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show bgp summary'", pw)
            if s == 0 and bgp_out:
                protocol_info['bgp'] = bgp_out.strip()

        # OSPFv2 (match 'router ospf' but not 'router ospf6')
        if re.search(r'router ospf\b(?!6)', running):
            ospf_out, _, s = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show ip ospf neighbor'", pw)
            if s == 0 and ospf_out:
                protocol_info['ospfv2_neighbors'] = ospf_out.strip()
            ospf_int, _, s2 = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show ip ospf interface'", pw)
            if s2 == 0 and ospf_int:
                protocol_info['ospfv2_interfaces'] = ospf_int.strip()

        # OSPFv3
        if 'router ospf6' in running:
            ospf6_out, _, s = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show ipv6 ospf6 neighbor'", pw)
            if s == 0 and ospf6_out:
                protocol_info['ospfv3_neighbors'] = ospf6_out.strip()

        # EIGRP
        if 'router eigrp' in running:
            eigrp_out, _, s = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show ip eigrp neighbor'", pw)
            if s == 0 and eigrp_out:
                protocol_info['eigrp_neighbors'] = eigrp_out.strip()
            eigrp_topo, _, s2 = _ssh_sudo_exec(ssh, "sudo -S vtysh -c 'show ip eigrp topology'", pw)
            if s2 == 0 and eigrp_topo:
                protocol_info['eigrp_topology'] = eigrp_topo.strip()

        ssh.close()
        return {
            "success": True,
            "config": config_output.strip() if config_output else "No overlay routing configured",
            "route_table": route_output.strip() if route_output else "No XFRM routes found",
            "bgp_neighbors": protocol_info.get('bgp', ''),
            "protocol_info": protocol_info,
            "route_sections": route_sections,
        }
    except Exception as e:
        logger.error(f"Overlay routing status error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/strongswan/netplan/files")
async def netplan_list_files(http_request: Request):
    """List netplan configuration files from /etc/netplan/."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        list_cmd = "ls -la /etc/netplan/*.yaml /etc/netplan/*.yml /etc/netplan/.*.yaml /etc/netplan/.*.yml 2>/dev/null || ls -la /etc/netplan/ 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(list_cmd, timeout=15)
        output = stdout.read().decode('utf-8', errors='replace')
        ssh.close()
        files = []
        seen = set()
        for line in output.strip().split('\n'):
            if not line or line.startswith('total'):
                continue
            parts = line.split()
            if len(parts) >= 9:
                size = int(parts[4]) if parts[4].isdigit() else 0
                filepath = parts[-1]
                filename = os.path.basename(filepath)
                if (filename.endswith('.yaml') or filename.endswith('.yml')) and filename not in seen:
                    seen.add(filename)
                    files.append({"name": filename, "size": size})
        return {"success": True, "files": files}
    except Exception as e:
        logger.error(f"Netplan list files error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/netplan/file-content")
async def netplan_get_file_content(request: NetplanFileRequest, http_request: Request):
    """Get the content of a specific netplan configuration file."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S cat "/etc/netplan/{filename}"', conn_info['password'])
        ssh.close()
        if 'No such file' in error or 'Permission denied' in error:
            return JSONResponse(status_code=404, content={"success": False, "message": f"File not found or access denied: {filename}"})
        return {"success": True, "content": output, "filename": filename}
    except Exception as e:
        logger.error(f"Netplan get file content error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/netplan/file-save")
async def netplan_save_file(request: NetplanFileSaveRequest, http_request: Request):
    """Save (create or update) a netplan configuration file."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        if not filename.endswith('.yaml') and not filename.endswith('.yml'):
            return JSONResponse(status_code=400, content={"success": False, "message": "Filename must end with .yaml or .yml"})
        ssh = _ssh_connect(conn_info)
        sftp = ssh.open_sftp()
        temp_path = f"/tmp/netplan_temp_{filename}"
        normalized_content = request.content.replace('\r\n', '\n').replace('\r', '\n')
        with sftp.file(temp_path, 'w') as f:
            f.write(normalized_content)
        sftp.close()
        move_cmd = f'sudo -S mv "{temp_path}" "/etc/netplan/{filename}" && sudo -S chown root:root "/etc/netplan/{filename}" && sudo -S chmod 600 "/etc/netplan/{filename}"'
        _, error, exit_status = _ssh_sudo_exec(ssh, move_cmd, conn_info['password'])
        ssh.close()
        if exit_status != 0:
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to save file: {error}"})
        logger.info(f"Netplan file {filename} saved by {username}")
        record_activity(username, "netplan_file_save", {"filename": filename})
        return {"success": True, "message": f"File {filename} saved successfully"}
    except Exception as e:
        logger.error(f"Netplan save file error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/netplan/file-delete")
async def netplan_delete_file(request: NetplanFileRequest, http_request: Request):
    """Delete a netplan configuration file."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _ssh_connect(conn_info)
        _, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S rm "/etc/netplan/{filename}"', conn_info['password'])
        ssh.close()
        if exit_status != 0:
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to delete file: {error}"})
        logger.info(f"Netplan file {filename} deleted by {username}")
        record_activity(username, "netplan_file_delete", {"filename": filename})
        return {"success": True, "message": f"File {filename} deleted successfully"}
    except Exception as e:
        logger.error(f"Netplan delete file error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/netplan/file-toggle-visibility")
async def netplan_toggle_file_visibility(request: NetplanToggleVisibilityRequest, http_request: Request):
    """Toggle visibility of a netplan config file by renaming with dot prefix."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        filename = request.filename
        newFilename = request.newFilename
        if '/' in filename or '\\' in filename or '..' in filename or '/' in newFilename or '\\' in newFilename or '..' in newFilename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _ssh_connect(conn_info)
        _, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S mv "/etc/netplan/{filename}" "/etc/netplan/{newFilename}"', conn_info['password'])
        ssh.close()
        if exit_status != 0:
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to rename file: {error}"})
        logger.info(f"Netplan file {filename} renamed to {newFilename} by {username}")
        record_activity(username, "netplan_file_rename", {"filename": filename, "newFilename": newFilename})
        return {"success": True, "message": f"File renamed successfully"}
    except Exception as e:
        logger.error(f"Netplan toggle visibility error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/netplan/apply")
async def netplan_apply(http_request: Request):
    """Execute 'netplan apply' on the connected server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, 'sudo -S netplan apply 2>&1', conn_info['password'], timeout=60)
        ssh.close()
        logger.info(f"Netplan apply executed by {username}, exit={exit_status}")
        record_activity(username, "netplan_apply", {"exit_status": exit_status})
        return {
            "success": exit_status == 0,
            "output": output or error or "(no output)",
            "message": "Netplan applied successfully" if exit_status == 0 else f"Netplan apply failed (exit {exit_status})"
        }
    except Exception as e:
        logger.error(f"Netplan apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/netplan/show-routes")
async def netplan_show_routes(http_request: Request):
    """Execute 'route -n' on the connected server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, 'route -n 2>&1', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "output": output or error or "(no output)"}
    except Exception as e:
        logger.error(f"Show routes error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# strongSwan Certificate Management Endpoints
# ============================================================================

class CertGenerateCARequest(BaseModel):
    key_type: str = "rsa"          # rsa, ecdsa, ed25519
    key_size: int = 4096           # RSA: 2048/3072/4096, ECDSA: 256/384/521
    lifetime: int = 3650           # days
    cn: str = "VPN Root CA"
    org: str = "Lab VPN"
    country: str = ""
    ca_name: str = "vpn-ca"       # base filename without extension

class CertGeneratePeerRequest(BaseModel):
    ca_name: str = "vpn-ca"       # which CA to sign with
    key_type: str = "rsa"
    key_size: int = 3072
    lifetime: int = 1825
    cn: str                        # e.g. "30.16.1.1"
    org: str = "Lab VPN"
    country: str = ""
    san: str = ""                  # Subject Alternative Name (IP or DNS)
    cert_name: str = ""            # output filename base (defaults to cn)
    server_auth: bool = True
    client_auth: bool = True

class CertDeleteRequest(BaseModel):
    filenames: List[str]           # list of filenames to delete
    cert_type: str                 # "x509ca", "x509", "private"

@app.get("/api/strongswan/certs/list")
async def strongswan_list_certs(http_request: Request):
    """List all certificates in /etc/swanctl/{x509ca,x509,private}."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)

        result = {"x509ca": [], "x509": [], "private": []}
        for folder in ["x509ca", "x509", "private"]:
            cmd = f'ls -la /etc/swanctl/{folder}/ 2>/dev/null'
            stdin_ch, stdout_ch, stderr_ch = ssh.exec_command(cmd, timeout=15)
            output = stdout_ch.read().decode('utf-8', errors='replace')
            for line in output.strip().split('\n'):
                if not line or line.startswith('total'):
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    fname = parts[-1]
                    if fname in ('.', '..'):
                        continue
                    size = int(parts[4]) if parts[4].isdigit() else 0
                    result[folder].append({"name": fname, "size": size})

        # Also list working dir certs (generated but not yet installed)
        work_cmd = 'ls -la /tmp/swanctl_pki/ 2>/dev/null'
        stdin_ch, stdout_ch, stderr_ch = ssh.exec_command(work_cmd, timeout=15)
        work_output = stdout_ch.read().decode('utf-8', errors='replace')
        staging = []
        for line in work_output.strip().split('\n'):
            if not line or line.startswith('total'):
                continue
            parts = line.split()
            if len(parts) >= 9:
                fname = parts[-1]
                if fname in ('.', '..'):
                    continue
                size = int(parts[4]) if parts[4].isdigit() else 0
                staging.append({"name": fname, "size": size})
        result["staging"] = staging

        ssh.close()
        return {"success": True, "certs": result}
    except Exception as e:
        logger.error(f"strongSwan list certs error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/certs/generate-ca")
async def strongswan_generate_ca(request: CertGenerateCARequest, http_request: Request):
    """Generate a CA key + self-signed certificate using strongSwan pki."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err

        ca_name = request.ca_name.strip()
        if not ca_name or '/' in ca_name or '..' in ca_name:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid CA name"})

        # Build DN string
        dn_parts = []
        if request.cn:
            dn_parts.append(f"CN={request.cn}")
        if request.org:
            dn_parts.append(f"O={request.org}")
        if request.country:
            dn_parts.append(f"C={request.country}")
        dn = ", ".join(dn_parts) if dn_parts else f"CN={ca_name}"

        ssh = _ssh_connect(conn_info)

        # Create working directory
        _ssh_sudo_exec(ssh, 'sudo -S mkdir -p /tmp/swanctl_pki', conn_info['password'])

        # Generate CA key (bash -c handles shell redirection over SSH)
        gen_cmd = f'sudo -S bash -c \'pki --gen --type {request.key_type}{" --size " + str(request.key_size) if request.key_type != "ed25519" else ""} --outform pem > /tmp/swanctl_pki/{ca_name}.key.pem\''
        output, error, exit_status = _ssh_sudo_exec(ssh, gen_cmd, conn_info['password'])
        if exit_status != 0:
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"CA key generation failed: {error or output}"})

        # Generate self-signed CA cert
        self_cmd = f'sudo -S bash -c \'pki --self --ca --lifetime {request.lifetime} --in /tmp/swanctl_pki/{ca_name}.key.pem --type {request.key_type} --dn "{dn}" --outform pem > /tmp/swanctl_pki/{ca_name}.crt.pem\''
        output, error, exit_status = _ssh_sudo_exec(ssh, self_cmd, conn_info['password'])
        if exit_status != 0:
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"CA cert generation failed: {error or output}"})

        # Install CA cert and key
        install_cmds = [
            f'sudo -S cp /tmp/swanctl_pki/{ca_name}.crt.pem /etc/swanctl/x509ca/{ca_name}.crt.pem',
            f'sudo -S chown root:root /etc/swanctl/x509ca/{ca_name}.crt.pem',
            f'sudo -S chmod 644 /etc/swanctl/x509ca/{ca_name}.crt.pem',
        ]
        for cmd in install_cmds:
            _, err_out, es = _ssh_sudo_exec(ssh, cmd, conn_info['password'])
            if es != 0:
                ssh.close()
                return JSONResponse(status_code=400, content={"success": False, "message": f"CA install failed: {err_out}"})

        ssh.close()
        logger.info(f"CA '{ca_name}' generated by {username}")
        record_activity(username, "strongswan_cert_generate_ca", {"ca_name": ca_name})
        return {"success": True, "message": f"CA '{ca_name}' generated and installed successfully", "ca_name": ca_name}

    except Exception as e:
        logger.error(f"strongSwan generate CA error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/certs/generate-peer")
async def strongswan_generate_peer(request: CertGeneratePeerRequest, http_request: Request):
    """Generate a peer key + certificate signed by an existing CA."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err

        ca_name = request.ca_name.strip()
        cn = request.cn.strip()
        cert_name = (request.cert_name.strip() or cn).replace(' ', '_')
        san = request.san.strip() or cn

        if not cn:
            return JSONResponse(status_code=400, content={"success": False, "message": "CN (Common Name) is required"})
        if '/' in cert_name or '..' in cert_name:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid cert name"})

        # Build DN
        dn_parts = [f"CN={cn}"]
        if request.org:
            dn_parts.append(f"O={request.org}")
        if request.country:
            dn_parts.append(f"C={request.country}")
        dn = ", ".join(dn_parts)

        # Build flags
        flags = []
        if request.server_auth:
            flags.append('--flag serverAuth')
        if request.client_auth:
            flags.append('--flag clientAuth')
        flag_str = ' '.join(flags)

        # Build SAN arguments — support multiple SANs comma-separated
        san_args = []
        for s in san.split(','):
            s = s.strip()
            if s:
                san_args.append(f'--san {s}')
        san_str = ' '.join(san_args)

        ssh = _ssh_connect(conn_info)

        # Ensure working directory exists
        _ssh_sudo_exec(ssh, 'sudo -S mkdir -p /tmp/swanctl_pki', conn_info['password'])

        # Check CA files exist
        check_cmd = f'test -f /tmp/swanctl_pki/{ca_name}.key.pem && test -f /tmp/swanctl_pki/{ca_name}.crt.pem && echo EXISTS'
        check_out, _, _ = _ssh_sudo_exec(ssh, check_cmd, conn_info['password'])
        if 'EXISTS' not in check_out:
            # Try installed CA cert + staging key
            check_cmd2 = f'test -f /tmp/swanctl_pki/{ca_name}.key.pem && test -f /etc/swanctl/x509ca/{ca_name}.crt.pem && echo EXISTS'
            check_out2, _, _ = _ssh_sudo_exec(ssh, check_cmd2, conn_info['password'])
            if 'EXISTS' not in check_out2:
                ssh.close()
                return JSONResponse(status_code=400, content={"success": False, "message": f"CA '{ca_name}' not found. Generate a CA first."})
            ca_cert_path = f'/etc/swanctl/x509ca/{ca_name}.crt.pem'
        else:
            ca_cert_path = f'/tmp/swanctl_pki/{ca_name}.crt.pem'

        ca_key_path = f'/tmp/swanctl_pki/{ca_name}.key.pem'

        # Generate peer key
        size_arg = f' --size {request.key_size}' if request.key_type != 'ed25519' else ''
        gen_cmd = f'sudo -S bash -c \'pki --gen --type {request.key_type}{size_arg} --outform pem > /tmp/swanctl_pki/{cert_name}.key.pem\''
        output, error, exit_status = _ssh_sudo_exec(ssh, gen_cmd, conn_info['password'])
        if exit_status != 0:
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"Peer key generation failed: {error or output}"})

        # Generate signed peer cert (pipe pki --pub into pki --issue)
        issue_cmd = f'sudo -S bash -c \'pki --pub --in /tmp/swanctl_pki/{cert_name}.key.pem --type {request.key_type} | pki --issue --lifetime {request.lifetime} --cacert {ca_cert_path} --cakey {ca_key_path} --dn "{dn}" {san_str} {flag_str} --outform pem > /tmp/swanctl_pki/{cert_name}.crt.pem\''
        output, error, exit_status = _ssh_sudo_exec(ssh, issue_cmd, conn_info['password'])
        if exit_status != 0:
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"Peer cert generation failed: {error or output}"})

        # Install cert and key to swanctl directories
        install_cmds = [
            f'sudo -S cp /tmp/swanctl_pki/{cert_name}.key.pem /etc/swanctl/private/{cert_name}.key.pem',
            f'sudo -S chown root:root /etc/swanctl/private/{cert_name}.key.pem',
            f'sudo -S chmod 600 /etc/swanctl/private/{cert_name}.key.pem',
            f'sudo -S cp /tmp/swanctl_pki/{cert_name}.crt.pem /etc/swanctl/x509/{cert_name}.crt.pem',
            f'sudo -S chown root:root /etc/swanctl/x509/{cert_name}.crt.pem',
            f'sudo -S chmod 644 /etc/swanctl/x509/{cert_name}.crt.pem',
        ]
        for cmd in install_cmds:
            _, err_out, es = _ssh_sudo_exec(ssh, cmd, conn_info['password'])
            if es != 0:
                ssh.close()
                return JSONResponse(status_code=400, content={"success": False, "message": f"Cert install failed: {err_out}"})

        ssh.close()
        logger.info(f"Peer cert '{cert_name}' generated by {username} (CA: {ca_name})")
        record_activity(username, "strongswan_cert_generate_peer", {"cert_name": cert_name, "ca_name": ca_name, "cn": cn})
        return {"success": True, "message": f"Peer certificate '{cert_name}' generated and installed", "cert_name": cert_name}

    except Exception as e:
        logger.error(f"strongSwan generate peer cert error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/certs/delete")
async def strongswan_delete_certs(request: CertDeleteRequest, http_request: Request):
    """Delete certificate/key files from swanctl directories."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err

        valid_types = {"x509ca", "x509", "private", "staging"}
        if request.cert_type not in valid_types:
            return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid cert_type. Must be one of: {valid_types}"})

        ssh = _ssh_connect(conn_info)

        deleted = []
        failed = []
        for fname in request.filenames:
            if '/' in fname or '..' in fname:
                failed.append(f"{fname}: invalid filename")
                continue

            if request.cert_type == "staging":
                path = f"/tmp/swanctl_pki/{fname}"
            else:
                path = f"/etc/swanctl/{request.cert_type}/{fname}"

            _, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S rm "{path}"', conn_info['password'])
            if exit_status == 0:
                deleted.append(fname)
            else:
                failed.append(f"{fname}: {error.strip()}")

        ssh.close()
        logger.info(f"Certs deleted by {username}: {deleted}")
        record_activity(username, "strongswan_cert_delete", {"deleted": deleted, "cert_type": request.cert_type})
        return {
            "success": len(failed) == 0,
            "deleted": deleted,
            "failed": failed,
            "message": f"Deleted {len(deleted)} file(s)" + (f", {len(failed)} failed" if failed else "")
        }
    except Exception as e:
        logger.error(f"strongSwan delete certs error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/certs/view/{cert_type}/{filename}")
async def strongswan_view_cert(cert_type: str, filename: str, http_request: Request):
    """View details of a certificate using pki --print or cat for keys."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err

        valid_types = {"x509ca", "x509", "private", "staging"}
        if cert_type not in valid_types:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid cert type"})
        if '/' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})

        if cert_type == "staging":
            path = f"/tmp/swanctl_pki/{filename}"
        else:
            path = f"/etc/swanctl/{cert_type}/{filename}"

        ssh = _ssh_connect(conn_info)

        if cert_type == "private":
            # For private keys, just confirm it exists and show type
            cmd = f'sudo -S pki --print --in "{path}" 2>&1 || sudo -S head -2 "{path}" 2>&1'
        else:
            cmd = f'sudo -S pki --print --in "{path}" 2>&1'

        output, error, exit_status = _ssh_sudo_exec(ssh, cmd, conn_info['password'])
        ssh.close()

        return {"success": True, "content": output or error, "filename": filename, "cert_type": cert_type}
    except Exception as e:
        logger.error(f"strongSwan view cert error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Traffic Control (tc) Endpoints
# ============================================================================

class TcCommandRequest(BaseModel):
    command: str

@app.post("/api/strongswan/tc/show")
async def tc_show(http_request: Request):
    """Show current tc configuration on all interfaces, excluding default rules."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, 'sudo -S bash -c \'tc qdisc show | grep -Ev "fq_codel|noqueue|mq"\' 2>&1', conn_info['password'])
        ssh.close()
        return {"success": True, "output": output or "(no non-default tc rules found)"}
    except Exception as e:
        logger.error(f"TC show error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tc/apply")
async def tc_apply(request: TcCommandRequest, http_request: Request):
    """Apply a tc command on the connected server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        raw_input = request.command.strip()
        # Support multi-line: split by newlines and execute each command
        commands = [c.strip() for c in raw_input.split('\n') if c.strip()]
        if not commands:
            return JSONResponse(status_code=400, content={"success": False, "message": "No commands provided"})
        # Validate every line
        for cmd in commands:
            if not cmd.startswith('tc '):
                return JSONResponse(status_code=400, content={"success": False, "message": f"Every line must start with 'tc ': {cmd}"})
            for bad in [';', '&&', '||', '|', '`', '$(', '>', '<']:
                if bad in cmd:
                    return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid character in command: {bad}"})
        ssh = _ssh_connect(conn_info)
        all_output = []
        all_success = True
        for cmd in commands:
            output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S {cmd} 2>&1', conn_info['password'])
            result_line = f"$ {cmd}\n{output or error or '(ok)'}" if exit_status == 0 else f"$ {cmd}\nFAILED: {output or error}"
            all_output.append(result_line)
            if exit_status != 0:
                all_success = False
            logger.info(f"TC command executed by {username}: {cmd}, exit={exit_status}")
        ssh.close()
        combined_output = '\n\n'.join(all_output)
        record_activity(username, "tc_apply", {"commands": commands, "success": all_success})
        return {
            "success": all_success,
            "output": combined_output,
            "message": f"All {len(commands)} command(s) executed successfully" if all_success else "One or more commands failed"
        }
    except Exception as e:
        logger.error(f"TC apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tc/remove")
async def tc_remove(http_request: Request):
    """Remove all tc rules from all interfaces (reset to default)."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        # Get all interfaces
        iface_output, _, _ = _ssh_sudo_exec(ssh, "ip -o link show | awk -F': ' '{print $2}' | grep -v lo", conn_info['password'])
        interfaces = [i.strip() for i in iface_output.split('\n') if i.strip()]
        removed = []
        for iface in interfaces[:20]:
            output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S tc qdisc del dev {iface} root 2>&1', conn_info['password'])
            if exit_status == 0:
                removed.append(iface)
        ssh.close()
        logger.info(f"TC rules removed by {username} on interfaces: {removed}")
        record_activity(username, "tc_remove", {"interfaces": removed})
        return {
            "success": True,
            "output": f"Removed tc rules from {len(removed)} interface(s): {', '.join(removed)}" if removed else "No tc rules to remove",
            "message": "TC rules removed successfully"
        }
    except Exception as e:
        logger.error(f"TC remove error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Tunnel Traffic Endpoints (Local Network = independent SSH, Remote Network = separate SSH)
# ============================================================================

TUNNEL_TRAFFIC_DIR = "/var/tmp/tunnel_traffic"

# Remote tunnel traffic SSH connections (separate from strongSwan)
remote_tunnel_connections: Dict[str, Dict[str, Any]] = {}
# Local tunnel traffic SSH connections (independent from strongSwan Server Connection)
local_tunnel_connections: Dict[str, Dict[str, Any]] = {}

class RemoteTunnelConnectRequest(BaseModel):
    ip: str
    port: int = 22
    username: str
    password: str

class TunnelTrafficFileRequest(BaseModel):
    filename: str

class TunnelTrafficFileSaveRequest(BaseModel):
    filename: str
    content: str

class TunnelTrafficToggleVisibilityRequest(BaseModel):
    filename: str
    newFilename: str

class ScriptExecRequest(BaseModel):
    filename: str

class ScriptKillRequest(BaseModel):
    filename: str
    pid: int

class TerminalCommandRequest(BaseModel):
    command: str

class GeneralCommandRequest(BaseModel):
    command: str

def _list_tunnel_traffic_files(ssh, password):
    """List files in /var/tmp/tunnel_traffic via SSH."""
    # Ensure dir exists
    _ssh_sudo_exec(ssh, f'sudo -S mkdir -p {TUNNEL_TRAFFIC_DIR}', password)
    output, error, _ = _ssh_sudo_exec(ssh, f'sudo -S ls -la {TUNNEL_TRAFFIC_DIR}/ 2>/dev/null', password)
    files = []
    seen = set()
    for line in output.strip().split('\n'):
        if not line or line.startswith('total'):
            continue
        parts = line.split()
        if len(parts) >= 9:
            filename = parts[-1]
            if filename in ('.', '..'):
                continue
            if filename not in seen:
                seen.add(filename)
                size = int(parts[4]) if parts[4].isdigit() else 0
                files.append({"name": filename, "size": size})
    return files

# --- Local Network (independent SSH server) ---

@app.post("/api/strongswan/tunnel-traffic/local/connect")
async def tunnel_traffic_local_connect(request: RemoteTunnelConnectRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=request.ip, port=request.port, username=request.username, password=request.password,
                    timeout=15, allow_agent=False, look_for_keys=False)
        ssh.close()
        local_tunnel_connections[username] = {
            'ip': request.ip, 'port': request.port,
            'username': request.username, 'password': request.password
        }
        return {"success": True, "message": f"Connected to {request.ip}:{request.port}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/strongswan/tunnel-traffic/local/disconnect")
async def tunnel_traffic_local_disconnect(http_request: Request):
    username = get_current_username(http_request)
    if username and username in local_tunnel_connections:
        del local_tunnel_connections[username]
    return {"success": True, "message": "Disconnected"}


@app.get("/api/strongswan/tunnel-traffic/local/status")
async def tunnel_traffic_local_status(http_request: Request):
    username = get_current_username(http_request)
    if not username:
        return {"connected": False}
    conn = local_tunnel_connections.get(username)
    if conn:
        return {"connected": True, "ip": conn['ip'], "port": conn['port']}
    return {"connected": False}


def _get_local_tt_conn(http_request: Request):
    username = get_current_username(http_request)
    if not username:
        return None, None, JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
    conn_info = local_tunnel_connections.get(username)
    if conn_info:
        return username, conn_info, None
    # If source=csc, fall back to CSC connection instead of strongSwan
    source = http_request.query_params.get('source', '')
    if source == 'csc':
        return _get_csc_ssh(http_request)
    return _get_swan_ssh(http_request)

# --- Local Network (tunnel traffic files) ---

@app.get("/api/strongswan/tunnel-traffic/local/files")
async def tunnel_traffic_local_list(http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        files = _list_tunnel_traffic_files(ssh, conn_info['password'])
        ssh.close()
        return {"success": True, "files": files}
    except Exception as e:
        logger.error(f"Tunnel traffic local list error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/file-content")
async def tunnel_traffic_local_content(request: TunnelTrafficFileRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S cat "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        ssh.close()
        return {"success": True, "filename": filename, "content": output}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/file-save")
async def tunnel_traffic_local_save(request: TunnelTrafficFileSaveRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        content = request.content.replace('\r\n', '\n').replace('\r', '\n')
        ssh = _ssh_connect(conn_info)
        _ssh_sudo_exec(ssh, f'sudo -S mkdir -p {TUNNEL_TRAFFIC_DIR}', conn_info['password'])
        sftp = ssh.open_sftp()
        temp_path = f"/tmp/tt_local_{filename}"
        with sftp.file(temp_path, 'w') as f:
            f.write(content)
        sftp.close()
        _ssh_sudo_exec(ssh, f'sudo -S mv "{temp_path}" "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        if filename.endswith('.sh'):
            _ssh_sudo_exec(ssh, f'sudo -S chmod +x "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        ssh.close()
        return {"success": True, "message": f"File '{filename}' saved"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/file-delete")
async def tunnel_traffic_local_delete(request: TunnelTrafficFileRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _ssh_connect(conn_info)
        _, _, exit_status = _ssh_sudo_exec(ssh, f'sudo -S rm "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "message": f"File '{filename}' deleted" if exit_status == 0 else "Delete failed"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/file-toggle-visibility")
async def tunnel_traffic_local_toggle(request: TunnelTrafficToggleVisibilityRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        _, _, exit_status = _ssh_sudo_exec(ssh, f'sudo -S mv "{TUNNEL_TRAFFIC_DIR}/{request.filename}" "{TUNNEL_TRAFFIC_DIR}/{request.newFilename}"', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "message": "Visibility toggled"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/execute")
async def tunnel_traffic_local_execute(request: ScriptExecRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        filename = request.filename
        if not filename.endswith('.sh') or '/' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Only .sh files can be executed"})
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(
            ssh, f'sudo -S bash -c \'nohup bash "{TUNNEL_TRAFFIC_DIR}/{filename}" > /tmp/tt_{filename}.log 2>&1 & echo $!\'',
            conn_info['password'], timeout=10
        )
        ssh.close()
        pid = None
        for line in output.strip().split('\n'):
            if line.strip().isdigit():
                pid = int(line.strip())
                break
        return {"success": pid is not None, "pid": pid, "message": f"Script started with PID {pid}" if pid else "Failed to start script"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/kill")
async def tunnel_traffic_local_kill(request: ScriptKillRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        ssh = _ssh_connect(conn_info)
        _, _, exit_status = _ssh_sudo_exec(ssh, f'sudo -S kill {request.pid} 2>&1', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "pid": request.pid, "message": f"PID {request.pid} killed" if exit_status == 0 else f"Failed to kill PID {request.pid}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/local/execute-command")
async def tunnel_traffic_local_terminal(request: TerminalCommandRequest, http_request: Request):
    try:
        username, conn_info, err = _get_local_tt_conn(http_request)
        if err:
            return err
        command = request.command.strip()
        if not command:
            return {"success": False, "message": "No command provided"}
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S bash -c \'{command}\' 2>&1', conn_info['password'], timeout=30)
        ssh.close()
        return {"success": True, "output": output or error or "(no output)", "exit_status": exit_status}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# --- Remote Network (separate SSH server) ---

@app.post("/api/strongswan/tunnel-traffic/remote/connect")
async def tunnel_traffic_remote_connect(request: RemoteTunnelConnectRequest, http_request: Request):
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=request.ip, port=request.port, username=request.username, password=request.password,
                    timeout=15, allow_agent=False, look_for_keys=False)
        ssh.close()
        remote_tunnel_connections[username] = {
            'ip': request.ip, 'port': request.port,
            'username': request.username, 'password': request.password
        }
        return {"success": True, "message": f"Connected to {request.ip}:{request.port}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/disconnect")
async def tunnel_traffic_remote_disconnect(http_request: Request):
    username = get_current_username(http_request)
    if username and username in remote_tunnel_connections:
        del remote_tunnel_connections[username]
    return {"success": True, "message": "Disconnected"}

def _get_remote_conn(http_request: Request):
    username = get_current_username(http_request)
    if not username:
        return None, None, JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
    conn_info = remote_tunnel_connections.get(username)
    if not conn_info:
        return None, None, JSONResponse(status_code=400, content={"success": False, "message": "Not connected to remote server"})
    return username, conn_info, None

def _remote_ssh_connect(conn_info):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(hostname=conn_info['ip'], port=conn_info['port'], username=conn_info['username'],
                password=conn_info['password'], timeout=15, allow_agent=False, look_for_keys=False)
    return ssh

@app.get("/api/strongswan/tunnel-traffic/remote/files")
async def tunnel_traffic_remote_list(http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        ssh = _remote_ssh_connect(conn_info)
        files = _list_tunnel_traffic_files(ssh, conn_info['password'])
        ssh.close()
        return {"success": True, "files": files}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/file-content")
async def tunnel_traffic_remote_content(request: TunnelTrafficFileRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _remote_ssh_connect(conn_info)
        output, error, _ = _ssh_sudo_exec(ssh, f'sudo -S cat "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        ssh.close()
        return {"success": True, "filename": filename, "content": output}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/file-save")
async def tunnel_traffic_remote_save(request: TunnelTrafficFileSaveRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        content = request.content.replace('\r\n', '\n').replace('\r', '\n')
        ssh = _remote_ssh_connect(conn_info)
        _ssh_sudo_exec(ssh, f'sudo -S mkdir -p {TUNNEL_TRAFFIC_DIR}', conn_info['password'])
        sftp = ssh.open_sftp()
        temp_path = f"/tmp/tt_remote_{filename}"
        with sftp.file(temp_path, 'w') as f:
            f.write(content)
        sftp.close()
        _ssh_sudo_exec(ssh, f'sudo -S mv "{temp_path}" "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        if filename.endswith('.sh'):
            _ssh_sudo_exec(ssh, f'sudo -S chmod +x "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        ssh.close()
        return {"success": True, "message": f"File '{filename}' saved"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/file-delete")
async def tunnel_traffic_remote_delete(request: TunnelTrafficFileRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _remote_ssh_connect(conn_info)
        _, _, exit_status = _ssh_sudo_exec(ssh, f'sudo -S rm "{TUNNEL_TRAFFIC_DIR}/{filename}"', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "message": f"File '{filename}' deleted" if exit_status == 0 else "Delete failed"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/file-toggle-visibility")
async def tunnel_traffic_remote_toggle(request: TunnelTrafficToggleVisibilityRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        ssh = _remote_ssh_connect(conn_info)
        _, _, exit_status = _ssh_sudo_exec(ssh, f'sudo -S mv "{TUNNEL_TRAFFIC_DIR}/{request.filename}" "{TUNNEL_TRAFFIC_DIR}/{request.newFilename}"', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "message": "Visibility toggled"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/execute")
async def tunnel_traffic_remote_execute(request: ScriptExecRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        filename = request.filename
        if not filename.endswith('.sh') or '/' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Only .sh files can be executed"})
        ssh = _remote_ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(
            ssh, f'sudo -S bash -c \'nohup bash "{TUNNEL_TRAFFIC_DIR}/{filename}" > /tmp/tt_{filename}.log 2>&1 & echo $!\'',
            conn_info['password'], timeout=10
        )
        ssh.close()
        pid = None
        for line in output.strip().split('\n'):
            if line.strip().isdigit():
                pid = int(line.strip())
                break
        return {"success": pid is not None, "pid": pid, "message": f"Script started with PID {pid}" if pid else "Failed to start script"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/kill")
async def tunnel_traffic_remote_kill(request: ScriptKillRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        ssh = _remote_ssh_connect(conn_info)
        _, _, exit_status = _ssh_sudo_exec(ssh, f'sudo -S kill {request.pid} 2>&1', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "pid": request.pid, "message": f"PID {request.pid} killed" if exit_status == 0 else f"Failed to kill PID {request.pid}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/tunnel-traffic/remote/execute-command")
async def tunnel_traffic_remote_terminal(request: TerminalCommandRequest, http_request: Request):
    try:
        username, conn_info, err = _get_remote_conn(http_request)
        if err:
            return err
        command = request.command.strip()
        if not command:
            return {"success": False, "message": "No command provided"}
        ssh = _remote_ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S bash -c \'{command}\' 2>&1', conn_info['password'], timeout=30)
        ssh.close()
        return {"success": True, "output": output or error or "(no output)", "exit_status": exit_status}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# --- General Command Execution (on strongSwan server) ---

@app.post("/api/strongswan/execute-command")
async def execute_general_command(request: GeneralCommandRequest, http_request: Request):
    """Execute a general command on the connected strongSwan server."""
    try:
        username, conn_info, err = _get_swan_ssh(http_request)
        if err:
            return err
        command = request.command.strip()
        if not command:
            return JSONResponse(status_code=400, content={"success": False, "message": "No command provided"})
        ssh = _ssh_connect(conn_info)
        output, error, exit_status = _ssh_sudo_exec(ssh, f'sudo -S bash -c \'{command}\' 2>&1', conn_info['password'], timeout=30)
        ssh.close()
        logger.info(f"General command executed by {username}: {command}, exit={exit_status}")
        record_activity(username, "execute_command", {"command": command, "exit_status": exit_status})
        return {
            "success": exit_status == 0,
            "output": output or error or "(no output)",
            "exit_status": exit_status,
            "message": "Command executed successfully" if exit_status == 0 else f"Command failed (exit {exit_status})"
        }
    except Exception as e:
        logger.error(f"Execute command error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/strongswan/tunnel-traffic/remote/status")
async def tunnel_traffic_remote_status(http_request: Request):
    username = get_current_username(http_request)
    if not username:
        return {"connected": False}
    conn = remote_tunnel_connections.get(username)
    if conn:
        return {"connected": True, "ip": conn['ip'], "port": conn['port']}
    return {"connected": False}

@app.get("/api/strongswan/presets")
async def strongswan_list_presets(http_request: Request):
    """List saved strongSwan connection presets."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        ud = _user_dir(username)
        presets = _read_json(os.path.join(ud, "strongswan_presets.json"), [])
        
        # Decrypt passwords
        cm = get_credential_manager()
        for p in presets:
            if p.get('password'):
                try:
                    p['password'] = decrypt_password(p['password'])
                except:
                    p['password'] = ''
        
        return {"success": True, "presets": presets}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/presets/save")
async def strongswan_save_preset(payload: Dict[str, Any], http_request: Request):
    """Save a strongSwan connection preset."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        ud = _user_dir(username)
        presets = _read_json(os.path.join(ud, "strongswan_presets.json"), [])
        
        # Encrypt password before saving
        encrypted_password = encrypt_password(payload.get('password', ''))
        
        preset = {
            "id": str(uuid.uuid4()),
            "name": payload.get('name', f"Preset {len(presets) + 1}"),
            "ip": payload.get('ip', ''),
            "port": payload.get('port', 22),
            "username": payload.get('username', ''),
            "password": encrypted_password
        }
        
        presets.append(preset)
        _write_json(os.path.join(ud, "strongswan_presets.json"), presets)
        
        # Return presets with decrypted passwords for UI
        cm = get_credential_manager()
        for p in presets:
            if p.get('password'):
                try:
                    p['password'] = decrypt_password(p['password'])
                except:
                    p['password'] = ''
        
        record_activity(username, "save_strongswan_preset", {"name": preset["name"]})
        return {"success": True, "preset": preset, "presets": presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/strongswan/presets/{preset_id}")
async def strongswan_delete_preset(preset_id: str, http_request: Request):
    """Delete a strongSwan connection preset."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        ud = _user_dir(username)
        presets = _read_json(os.path.join(ud, "strongswan_presets.json"), [])
        
        before = len(presets)
        presets = [p for p in presets if p.get('id') != preset_id]
        _write_json(os.path.join(ud, "strongswan_presets.json"), presets)
        
        # Return presets with decrypted passwords for UI
        cm = get_credential_manager()
        for p in presets:
            if p.get('password'):
                try:
                    p['password'] = decrypt_password(p['password'])
                except:
                    p['password'] = ''
        
        record_activity(username, "delete_strongswan_preset", {"id": preset_id})
        return {"success": True, "deleted": before - len(presets), "presets": presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

def _template_presets_file(user_dir: str, mode: str) -> str:
    """Return the presets JSON path for the given mode (policy or route)."""
    if mode == "route":
        return os.path.join(user_dir, "strongswan_template_presets_route.json")
    return os.path.join(user_dir, "strongswan_template_presets_policy.json")

@app.get("/api/strongswan/template-presets")
async def strongswan_list_template_presets(http_request: Request, mode: str = "policy"):
    """List saved strongSwan template builder presets for a given mode."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        ud = _user_dir(username)
        fpath = _template_presets_file(ud, mode)
        # Migrate: if mode-specific file doesn't exist but legacy file does, copy it
        legacy = os.path.join(ud, "strongswan_template_presets.json")
        if not os.path.exists(fpath) and os.path.exists(legacy):
            presets = _read_json(legacy, [])
            _write_json(fpath, presets)
        else:
            presets = _read_json(fpath, [])
        return {"success": True, "presets": presets}
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/strongswan/template-presets/save")
async def strongswan_save_template_preset(payload: Dict[str, Any], http_request: Request):
    """Save a strongSwan template builder preset (all form values)."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        ud = _user_dir(username)
        mode = payload.get("mode", "policy")
        fpath = _template_presets_file(ud, mode)
        presets = _read_json(fpath, [])
        preset = {
            "id": str(uuid.uuid4()),
            "name": payload.get("name", f"Template {len(presets) + 1}"),
            "data": payload.get("data", {}),
        }
        presets.append(preset)
        _write_json(fpath, presets)
        record_activity(username, "save_template_preset", {"name": preset["name"], "mode": mode})
        return {"success": True, "preset": preset, "presets": presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.delete("/api/strongswan/template-presets/{preset_id}")
async def strongswan_delete_template_preset(preset_id: str, http_request: Request, mode: str = "policy"):
    """Delete a strongSwan template builder preset."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        ud = _user_dir(username)
        fpath = _template_presets_file(ud, mode)
        presets = _read_json(fpath, [])
        presets = [p for p in presets if p.get("id") != preset_id]
        _write_json(fpath, presets)
        record_activity(username, "delete_template_preset", {"id": preset_id, "mode": mode})
        return {"success": True, "presets": presets}
    except Exception as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# ============================================================================
# AI Chat API Endpoints
# ============================================================================

from sse_starlette.sse import EventSourceResponse
from ai_service import (
    get_bridge_client, get_bedrock_client, get_rag_pipeline, get_fmc_rag, get_chat_storage,
    get_provider_config, ChatSession,
    SYSTEM_PROMPT_GENERAL, SYSTEM_PROMPT_STRONGSWAN, SYSTEM_PROMPT_FMC,
    BEDROCK_MODELS, CIRCUIT_MODELS,
)
from ai_tools import STRONGSWAN_TOOLS, NETPLAN_TOOLS, TC_TOOLS, GENERAL_CMD_TOOLS, TUNNEL_TRAFFIC_TOOLS, MONITORING_TOOLS, FMC_TOOLS, VPN_TOOLS, FMC_OPERATION_TOOLS, CSC_TOOLS, CSC_TOOL_NAMES, get_tool_executor, vpn_tool_executor, csc_tool_executor

class AIChatToolResult(BaseModel):
    """A single tool result."""
    tool_call_id: str
    content: str

class AIChatToolCall(BaseModel):
    """A single tool call from the assistant."""
    id: str
    type: str = "function"
    function: Dict[str, Any]

class AIChatRequest(BaseModel):
    """Request model for AI chat."""
    message: Optional[str] = None
    session_id: Optional[str] = None
    context_mode: Optional[str] = "general"  # 'general' or 'strongswan'
    stream: Optional[bool] = True
    provider: Optional[str] = "bedrock"  # 'circuit' or 'bedrock'
    model: Optional[str] = None  # model display name (e.g. 'claude-sonnet-4.6', 'gpt-4.1')
    tool_results: Optional[List[AIChatToolResult]] = None
    tool_calls: Optional[List[AIChatToolCall]] = None

class AIChatSessionCreate(BaseModel):
    """Request model for creating a chat session."""
    title: Optional[str] = "New Chat"
    context_mode: Optional[str] = "general"

@app.get("/api/ai/providers")
async def ai_providers():
    """Return available AI providers and their models for the frontend UI."""
    return {"success": True, "providers": get_provider_config()}

@app.post("/api/ai/sync-chassis-config")
async def ai_sync_chassis_config(http_request: Request):
    """Sync a manually-uploaded chassis config into the AI tool context so the AI can reference it."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        body = await http_request.json()
        config = body.get("config")
        config_yaml = body.get("config_yaml", "")
        filename = body.get("filename", "chassis_config.yaml")
        counts = body.get("counts", {})
        if not config:
            return JSONResponse(status_code=400, content={"success": False, "message": "config is required"})
        ctx = get_user_ctx(username)
        ctx["fmc_loaded_chassis_config"] = config
        ctx["fmc_loaded_chassis_config_yaml"] = config_yaml
        ctx["fmc_loaded_chassis_config_filename"] = filename
        ctx["fmc_loaded_chassis_config_counts"] = counts
        return {"success": True, "message": f"Chassis config '{filename}' synced to AI context."}
    except Exception as e:
        logger.error(f"Error syncing chassis config to AI context: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/ai/sessions")
async def ai_list_sessions(http_request: Request):
    """List all chat sessions for the current user."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        storage = get_chat_storage()
        sessions = storage.list_sessions(username)
        
        return {"success": True, "sessions": sessions}
    except Exception as e:
        logger.error(f"AI list sessions error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/ai/sessions")
async def ai_create_session(request: AIChatSessionCreate, http_request: Request):
    """Create a new chat session."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        storage = get_chat_storage()
        session = storage.create_session(username, request.title)
        session.context_mode = request.context_mode
        storage.update_session(session)
        
        record_activity(username, "ai_session_create", {"session_id": session.session_id})
        
        return {
            "success": True,
            "session": {
                "session_id": session.session_id,
                "title": session.title,
                "context_mode": session.context_mode,
                "created_at": session.created_at
            }
        }
    except Exception as e:
        logger.error(f"AI create session error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/ai/sessions/{session_id}")
async def ai_get_session(session_id: str, http_request: Request):
    """Get a specific chat session with full message history."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        storage = get_chat_storage()
        session = storage.get_session(username, session_id)
        
        if not session:
            return JSONResponse(status_code=404, content={"success": False, "message": "Session not found"})
        
        return {
            "success": True,
            "session": session.to_dict()
        }
    except Exception as e:
        logger.error(f"AI get session error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.delete("/api/ai/sessions/{session_id}")
async def ai_delete_session(session_id: str, http_request: Request):
    """Delete a chat session."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        storage = get_chat_storage()
        deleted = storage.delete_session(username, session_id)
        
        if deleted:
            record_activity(username, "ai_session_delete", {"session_id": session_id})
        
        return {"success": deleted}
    except Exception as e:
        logger.error(f"AI delete session error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.post("/api/ai/chat")
async def ai_chat(request: AIChatRequest, http_request: Request):
    """
    Send a message to the AI and get a response.
    Supports streaming via SSE.
    """
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        storage = get_chat_storage()
        rag_pipeline = get_rag_pipeline()
        
        # Select AI provider/client based on request
        ai_provider = request.provider or "bedrock"
        ai_model = request.model  # display name or None
        if ai_provider == "bedrock":
            ai_client = get_bedrock_client()
        else:
            ai_client = get_bridge_client()
        
        # Get or create session
        if request.session_id:
            session = storage.get_session(username, request.session_id)
            if not session:
                return JSONResponse(status_code=404, content={"success": False, "message": "Session not found"})
        else:
            session = storage.create_session(username)
        
        # Update context mode if changed
        if request.context_mode:
            session.context_mode = request.context_mode
        
        # Handle tool results continuation (AI called tools, frontend executed them, now feeding results back)
        is_tool_continuation = request.tool_results and request.tool_calls
        
        if is_tool_continuation:
            # The assistant tool_calls message was already stored by the streaming handler.
            # Only add the tool result messages here.
            for tr in request.tool_results:
                session.add_message("tool", tr.content, tool_call_id=tr.tool_call_id)
            storage.update_session(session)
        elif request.message:
            # Add user message to session
            session.add_message("user", request.message)
        else:
            return JSONResponse(status_code=400, content={"success": False, "message": "Either message or tool_results required"})
        
        # Build system prompt based on context mode
        if session.context_mode == "strongswan":
            system_prompt = SYSTEM_PROMPT_STRONGSWAN
            if not is_tool_continuation and request.message:
                rag_context = rag_pipeline.get_context_for_query(request.message)
                if rag_context:
                    system_prompt += f"\n\n{rag_context}"
                # Inject TC RAG for traffic control queries
                tc_keywords = ['tc ', 'traffic control', 'qdisc', 'netem', 'tbf', 'htb', 'pfifo', 'sfq', 'ingress', 'egress', 'traffic shaping', 'rate limit', 'bandwidth', 'latency', 'packet loss', 'delay']
                if any(kw in request.message.lower() for kw in tc_keywords):
                    tc_rag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "utils", "tc_manpage_rag.md")
                    if os.path.exists(tc_rag_path):
                        try:
                            with open(tc_rag_path, 'r') as f:
                                tc_content = f.read()
                            system_prompt += f"\n\n## Traffic Control (tc) Man Page Reference:\n\n{tc_content}"
                        except Exception as e:
                            logger.warning(f"Failed to load TC RAG: {e}")
                # Inject iperf3 RAG for iperf3-related queries
                iperf_keywords = ['iperf', 'iperf3', 'throughput', 'bandwidth test', 'network test', 'performance test']
                if any(kw in request.message.lower() for kw in iperf_keywords):
                    iperf_rag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "utils", "iperf3_manpage.md")
                    if os.path.exists(iperf_rag_path):
                        try:
                            with open(iperf_rag_path, 'r') as f:
                                iperf_content = f.read()
                            system_prompt += f"\n\n## iperf3 Man Page Reference:\n\n{iperf_content}"
                        except Exception as e:
                            logger.warning(f"Failed to load iperf3 RAG: {e}")
            tools = STRONGSWAN_TOOLS + NETPLAN_TOOLS + TC_TOOLS + GENERAL_CMD_TOOLS + TUNNEL_TRAFFIC_TOOLS + MONITORING_TOOLS + CSC_TOOLS
        elif session.context_mode == "fmc":
            system_prompt = SYSTEM_PROMPT_FMC
            if not is_tool_continuation and request.message:
                fmc_rag = get_fmc_rag()
                fmc_context = fmc_rag.get_context_for_query(request.message)
                if fmc_context:
                    system_prompt += f"\n\n{fmc_context}"
            tools = FMC_TOOLS + VPN_TOOLS + FMC_OPERATION_TOOLS
        else:
            system_prompt = SYSTEM_PROMPT_GENERAL
            if not is_tool_continuation and request.message and any(kw in request.message.lower() for kw in ['swanctl', 'strongswan', 'ipsec', 'vpn', 'ike']):
                rag_context = rag_pipeline.get_context_for_query(request.message)
                if rag_context:
                    system_prompt += f"\n\n{rag_context}"
            tools = None
        
        # Prepare messages for API
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(session.get_messages_for_api())
        
        if request.stream:
            async def generate_stream():
                """Generate SSE stream of AI response."""
                full_content = ""
                tool_calls_accumulated = []
                
                try:
                    async for chunk in ai_client.chat_completion(
                        messages=messages,
                        tools=tools,
                        stream=True,
                        model=ai_model,
                    ):
                        if "choices" in chunk and len(chunk["choices"]) > 0:
                            choice = chunk["choices"][0]
                            delta = choice.get("delta", {})
                            
                            # Handle content chunks
                            if "content" in delta and delta["content"]:
                                content = delta["content"]
                                full_content += content
                                yield {
                                    "event": "content",
                                    "data": json.dumps({"content": content})
                                }
                            
                            # Handle tool calls
                            if "tool_calls" in delta:
                                for tc in delta["tool_calls"]:
                                    # Accumulate tool call info
                                    idx = tc.get("index", 0)
                                    while len(tool_calls_accumulated) <= idx:
                                        # Include 'type' field - required by API when replaying messages
                                        tool_calls_accumulated.append({"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                                    
                                    if "id" in tc:
                                        tool_calls_accumulated[idx]["id"] = tc["id"]
                                    if "type" in tc:
                                        tool_calls_accumulated[idx]["type"] = tc["type"]
                                    if "function" in tc:
                                        if "name" in tc["function"]:
                                            tool_calls_accumulated[idx]["function"]["name"] = tc["function"]["name"]
                                        if "arguments" in tc["function"]:
                                            tool_calls_accumulated[idx]["function"]["arguments"] += tc["function"]["arguments"]
                            
                            # Check for finish
                            if choice.get("finish_reason"):
                                if choice["finish_reason"] == "tool_calls" and tool_calls_accumulated:
                                    # Process tool calls
                                    yield {
                                        "event": "tool_calls",
                                        "data": json.dumps({"tool_calls": tool_calls_accumulated})
                                    }
                                break
                    
                    # Save assistant message (handle content, tool_calls, or both)
                    if full_content or tool_calls_accumulated:
                        session.add_message(
                            "assistant", full_content,
                            tool_calls=tool_calls_accumulated if tool_calls_accumulated else None
                        )
                    
                    storage.update_session(session)
                    
                    yield {
                        "event": "done",
                        "data": json.dumps({
                            "session_id": session.session_id,
                            "message_count": len(session.messages)
                        })
                    }
                    
                except Exception as e:
                    logger.error(f"AI chat stream error: {e}")
                    yield {
                        "event": "error",
                        "data": json.dumps({"error": str(e)})
                    }
            
            return EventSourceResponse(generate_stream())
        
        else:
            # Non-streaming response
            full_content = ""
            async for response in ai_client.chat_completion(
                messages=messages,
                tools=tools,
                stream=False,
                model=ai_model,
            ):
                if "choices" in response and len(response["choices"]) > 0:
                    choice = response["choices"][0]
                    message = choice.get("message", {})
                    full_content = message.get("content", "")
                    
                    # Handle tool calls
                    if "tool_calls" in message:
                        session.add_message("assistant", full_content or "", tool_calls=message["tool_calls"])
                    else:
                        session.add_message("assistant", full_content)
            
            storage.update_session(session)
            
            return {
                "success": True,
                "session_id": session.session_id,
                "response": full_content,
                "message_count": len(session.messages)
            }
    
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# FMC AI Operation Handlers
# ============================================================================

FMC_OPERATION_TOOL_NAMES = {
    "fmc_connect", "fmc_get_device_config", "fmc_push_device_config",
    "fmc_delete_device", "fmc_delete_config",
    "fmc_get_vpn_topologies", "fmc_push_vpn_topologies", "fmc_replace_vpn_endpoints",
    "fmc_load_context_config", "fmc_load_context_vpn",
    "fmc_get_chassis_config", "fmc_push_chassis_config", "fmc_load_context_chassis_config"
}

def _ai_resolve_fmc_connection(ctx: Dict, fmc_ip: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Get an FMC connection from user context.

    If *fmc_ip* is provided, look it up in the multi-connection store.
    Otherwise return the most-recently-connected (active) connection.
    """
    if fmc_ip:
        fmc_ip = fmc_ip.strip()
        conns = ctx.get("fmc_connections") or {}
        # Try exact match first, then case-insensitive
        conn = conns.get(fmc_ip)
        if not conn:
            fmc_ip_lower = fmc_ip.lower()
            for key, val in conns.items():
                if key.lower() == fmc_ip_lower:
                    conn = val
                    break
        if conn and conn.get("fmc_ip") and conn.get("username") and conn.get("password"):
            return conn
        return None
    # Fallback: active (last-connected) connection
    conn = ctx.get("fmc_connection") or {}
    if conn.get("fmc_ip") and conn.get("username") and conn.get("password"):
        return conn
    return None

def _ai_resolve_device_id(ctx: Dict, device_name: str, fmc_ip: Optional[str] = None) -> tuple:
    """Resolve a device name to (device_id, matching_connection).

    Searches a specific FMC connection if *fmc_ip* is given, otherwise
    searches ALL stored FMC connections (most-recent first).
    Returns (device_id, conn_dict) or (None, None).
    """
    name_lower = device_name.strip().lower()

    def _search_conn(conn):
        for d in (conn.get("devices") or []):
            if (d.get("name") or "").strip().lower() == name_lower:
                return d.get("id")
            if (d.get("hostName") or "").strip().lower() == name_lower:
                return d.get("id")
        return None

    if fmc_ip:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=fmc_ip)
        if conn:
            did = _search_conn(conn)
            if did:
                return did, conn
        return None, None

    # Search all connections (active first, then others)
    active = ctx.get("fmc_connection") or {}
    if active.get("fmc_ip"):
        did = _search_conn(active)
        if did:
            return did, active
    for _ip, conn in (ctx.get("fmc_connections") or {}).items():
        if conn.get("fmc_ip") == active.get("fmc_ip"):
            continue  # already checked
        did = _search_conn(conn)
        if did:
            return did, conn
    return None, None

def _ai_resolve_domain_uuid(ctx: Dict, domain_name: Optional[str] = None, conn: Optional[Dict] = None) -> str:
    """Resolve domain name to UUID. Falls back to stored domain_uuid."""
    if conn is None:
        conn = ctx.get("fmc_connection") or {}
    if domain_name:
        domains = conn.get("domains") or []
        for d in domains:
            if (d.get("name") or "").strip().lower() == domain_name.strip().lower():
                return d.get("id") or d.get("uuid") or ""
    return conn.get("domain_uuid") or ctx.get("fmc_auth", {}).get("domain_uuid") or ""

async def _execute_fmc_operation(tool_name: str, arguments: Dict[str, Any], username: str) -> Dict[str, Any]:
    """Execute FMC operation tools that interact with the connected FMC."""
    ctx = get_user_ctx(username)
    _attach_user_log_handlers(username)
    loop = asyncio.get_running_loop()

    try:
        if tool_name == "fmc_connect":
            return await _ai_fmc_connect(arguments, ctx, username, loop)
        elif tool_name == "fmc_get_device_config":
            return await _ai_fmc_get_config(arguments, ctx, username, loop)
        elif tool_name == "fmc_push_device_config":
            return await _ai_fmc_push_config(arguments, ctx, username, loop)
        elif tool_name == "fmc_delete_device":
            return await _ai_fmc_delete_device(arguments, ctx, username, loop)
        elif tool_name == "fmc_delete_config":
            return await _ai_fmc_delete_config(arguments, ctx, username, loop)
        elif tool_name == "fmc_get_vpn_topologies":
            return await _ai_fmc_get_vpn(arguments, ctx, username, loop)
        elif tool_name == "fmc_push_vpn_topologies":
            return await _ai_fmc_push_vpn(arguments, ctx, username, loop)
        elif tool_name == "fmc_replace_vpn_endpoints":
            return _ai_fmc_replace_vpn_endpoints(arguments, ctx, username)
        elif tool_name == "fmc_load_context_config":
            return _ai_fmc_load_context_config(arguments, ctx, username)
        elif tool_name == "fmc_load_context_vpn":
            return _ai_fmc_load_context_vpn(arguments, ctx, username)
        elif tool_name == "fmc_get_chassis_config":
            return await _ai_fmc_get_chassis_config(arguments, ctx, username, loop)
        elif tool_name == "fmc_push_chassis_config":
            return await _ai_fmc_push_chassis_config(arguments, ctx, username, loop)
        elif tool_name == "fmc_load_context_chassis_config":
            return _ai_fmc_load_context_chassis_config(arguments, ctx, username)
        else:
            return {"success": False, "error": f"Unknown FMC operation: {tool_name}"}
    except Exception as e:
        logger.error(f"FMC AI operation '{tool_name}' error: {e}")
        return {"success": False, "error": str(e)}

async def _ai_fmc_connect(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Connect to FMC using preset or manual credentials."""
    preset_name = (args.get("preset_name") or "").strip()
    fmc_ip = (args.get("fmc_ip") or "").strip()
    fmc_user = (args.get("username") or "").strip()
    fmc_pass = args.get("password") or ""
    domain_name = (args.get("domain_name") or "").strip()

    # Resolve from preset
    if preset_name:
        presets = ctx.get("fmc_config_presets") or []
        matched = None
        for p in presets:
            if (p.get("name") or "").strip().lower() == preset_name.lower():
                matched = p
                break
        if not matched:
            available = [p.get("name") for p in presets if p.get("name")]
            return {"success": False, "error": f"Preset '{preset_name}' not found. Available presets: {', '.join(available) if available else 'none'}"}
        fmc_ip = matched.get("fmc_ip", "")
        fmc_user = matched.get("username", "")
        fmc_pass = matched.get("password", "")

    if not fmc_ip or not fmc_user or not fmc_pass:
        return {"success": False, "error": "Missing FMC IP, username, or password. Provide a preset_name or manual credentials."}

    def work():
        default_domain_uuid, headers = authenticate(fmc_ip, fmc_user, fmc_pass)
        domains = get_domains(fmc_ip, headers)

        selected_domain_uuid = default_domain_uuid
        if domain_name:
            for d in domains:
                if (d.get("name") or "").strip().lower() == domain_name.lower():
                    selected_domain_uuid = d.get("id") or d.get("uuid") or default_domain_uuid
                    break

        url = f"{fmc_ip}/api/fmc_config/v1/domain/{selected_domain_uuid}/devices/devicerecords?expanded=true&limit=1000"
        h = dict(headers)
        h["DOMAIN_UUID"] = selected_domain_uuid
        resp = requests.get(url, headers=h, verify=False)
        resp.raise_for_status()
        devices = resp.json().get("items", [])

        return {
            "default_domain_uuid": default_domain_uuid,
            "headers": headers,
            "domains": domains,
            "selected_domain_uuid": selected_domain_uuid,
            "devices": devices,
        }

    result = await loop.run_in_executor(None, work)

    # Store connection state (active + multi-connection store)
    conn_data = {
        "fmc_ip": fmc_ip,
        "username": fmc_user,
        "password": fmc_pass,
        "domain_uuid": result["selected_domain_uuid"],
        "domains": result["domains"],
        "devices": result["devices"],
        "headers": result["headers"],
    }
    ctx["fmc_connection"] = conn_data  # active (last-connected)
    if "fmc_connections" not in ctx:
        ctx["fmc_connections"] = {}
    ctx["fmc_connections"][fmc_ip] = conn_data  # multi-store keyed by FMC IP
    ctx["fmc_auth"]["domain_uuid"] = result["selected_domain_uuid"]
    ctx["fmc_auth"]["headers"] = result["headers"]

    # Build domain objects with id/name for renderDomainDropdown
    domain_objects = []
    for d in result["domains"]:
        domain_objects.append({
            "id": d.get("id") or d.get("uuid") or "",
            "name": d.get("name") or "",
        })

    record_activity(username, "ai_fmc_connect", {"devices": len(result["devices"])})

    # Parse host and port from fmc_ip URL for frontend field population
    import re as _re
    _m = _re.match(r'^https?://([^:/]+)(?::([0-9]+))?', fmc_ip)
    fmc_host = _m.group(1) if _m else fmc_ip
    fmc_port = int(_m.group(2)) if _m and _m.group(2) else 443

    return {
        "success": True,
        "action": "fmc_connected",
        "fmc_ip": fmc_ip,
        "fmc_host": fmc_host,
        "fmc_port": fmc_port,
        "fmc_username": fmc_user,
        "fmc_password": fmc_pass,
        "domain_uuid": result["selected_domain_uuid"],
        "domains": domain_objects,
        "devices": result["devices"],
        "message": f"Connected to FMC at {fmc_ip}. Found {len(result['devices'])} device(s) in domain '{domain_name or 'Global'}'.",
    }

async def _ai_fmc_get_config(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Get configuration from an FTD device."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None

    device_name = (args.get("device_name") or "").strip()
    if not device_name:
        return {"success": False, "error": "device_name is required"}

    # Search across all FMC connections for the device
    device_id, conn = _ai_resolve_device_id(ctx, device_name, fmc_ip=target_fmc_ip)
    if not conn:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}
    if not device_id:
        # Collect available devices from ALL connections for better error message
        all_available = []
        for _ip, c in (ctx.get("fmc_connections") or {}).items():
            for d in (c.get("devices") or []):
                dn = d.get("name")
                if dn:
                    all_available.append(f"{dn} (on {_ip})")
        return {"success": False, "error": f"Device '{device_name}' not found. Available: {', '.join(all_available) if all_available else 'none'}"}

    # Find full device record for filename metadata (version, model)
    device_meta = {}
    for d in (conn.get("devices") or []):
        if d.get("id") == device_id:
            device_meta = {
                "name": d.get("name") or "",
                "version": d.get("sw_version") or d.get("version") or d.get("softwareVersion") or d.get("swVersion") or "",
                "model": d.get("model") or "",
            }
            break

    domain_uuid = _ai_resolve_domain_uuid(ctx, args.get("domain_name"), conn=conn)

    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "domain_uuid": domain_uuid,
        "device_ids": [device_id],
        "app_username": username,
        "device_meta": device_meta,
    }

    reset_progress(username)
    result = await loop.run_in_executor(None, lambda: _export_config_sync(payload))

    if not result.get("success"):
        return {"success": False, "error": result.get("message", "Config export failed")}

    filename = result.get("filename") or "export.yaml"
    yaml_content = result.get("content") or ""

    # Parse YAML to get config dict and counts
    import yaml as yaml_lib
    try:
        config = _yaml_safe_load(yaml_content)
    except Exception:
        config = {}

    if not isinstance(config, dict):
        config = {}

    # Count config items
    from ai_tools import fmc_tool_executor
    counts = fmc_tool_executor._count_config_items(config)

    # Store loaded config in context
    ctx["fmc_loaded_config"] = config
    ctx["fmc_loaded_config_yaml"] = yaml_content

    # Build summary report
    non_zero = {k: v for k, v in counts.items() if v > 0}
    total_items = sum(non_zero.values())

    # Build detailed summary with individual item names for AI presentation
    def _extract_names(items_list, name_key="name"):
        """Extract name field from a list of dicts."""
        if not isinstance(items_list, list):
            return []
        names = []
        for item in items_list:
            if isinstance(item, dict):
                n = item.get(name_key) or item.get("ifname") or item.get("id") or ""
                if n:
                    names.append(str(n))
        return names

    routing = config.get("routing", {}) or {}
    objects = config.get("objects", {}) or {}

    detailed_summary = {}
    section_map = {
        "loopback_interfaces": (config, "loopback_interfaces"),
        "physical_interfaces": (config, "physical_interfaces"),
        "etherchannel_interfaces": (config, "etherchannel_interfaces"),
        "subinterfaces": (config, "subinterfaces"),
        "vti_interfaces": (config, "vti_interfaces"),
        "inline_sets": (config, "inline_sets"),
        "bridge_group_interfaces": (config, "bridge_group_interfaces"),
        "routing_bgp_general_settings": (routing, "bgp_general_settings"),
        "routing_bgp_policies": (routing, "bgp_policies"),
        "routing_bfd_policies": (routing, "bfd_policies"),
        "routing_ospfv2_policies": (routing, "ospfv2_policies"),
        "routing_ospfv2_interfaces": (routing, "ospfv2_interfaces"),
        "routing_ospfv3_policies": (routing, "ospfv3_policies"),
        "routing_ospfv3_interfaces": (routing, "ospfv3_interfaces"),
        "routing_eigrp_policies": (routing, "eigrp_policies"),
        "routing_pbr_policies": (routing, "pbr_policies"),
        "routing_ipv4_static_routes": (routing, "ipv4_static_routes"),
        "routing_ipv6_static_routes": (routing, "ipv6_static_routes"),
        "routing_ecmp_zones": (routing, "ecmp_zones"),
        "routing_vrfs": (routing, "vrfs"),
        "objects_security_zones": (objects.get("interface", {}) or {}, "security_zones"),
        "objects_network_hosts": (objects.get("network", {}) or {}, "hosts"),
        "objects_network_ranges": (objects.get("network", {}) or {}, "ranges"),
        "objects_network_networks": (objects.get("network", {}) or {}, "networks"),
        "objects_network_fqdns": (objects.get("network", {}) or {}, "fqdns"),
        "objects_network_groups": (objects.get("network", {}) or {}, "groups"),
        "objects_port_objects": (objects.get("port", {}) or {}, "objects"),
        "objects_bfd_templates": (objects, "bfd_templates"),
        "objects_as_path_lists": (objects, "as_path_lists"),
        "objects_key_chains": (objects, "key_chains"),
        "objects_sla_monitors": (objects, "sla_monitors"),
        "objects_access_lists_extended": (objects.get("access_lists", {}) or {}, "extended"),
        "objects_access_lists_standard": (objects.get("access_lists", {}) or {}, "standard"),
        "objects_route_maps": (objects, "route_maps"),
        "objects_address_pools_ipv4": (objects.get("address_pools", {}) or {}, "ipv4"),
        "objects_address_pools_ipv6": (objects.get("address_pools", {}) or {}, "ipv6"),
        "objects_address_pools_mac": (objects.get("address_pools", {}) or {}, "mac"),
    }

    for key, (parent, child_key) in section_map.items():
        items_list = parent.get(child_key) if isinstance(parent, dict) else None
        if isinstance(items_list, list) and len(items_list) > 0:
            names = _extract_names(items_list)
            detailed_summary[key] = {"count": len(items_list), "items": names}

    record_activity(username, "ai_fmc_get_config", {"device": device_name, "items": total_items})

    return {
        "success": True,
        "action": "config_fetched",
        "config": config,
        "counts": counts,
        "filename": filename,
        "config_yaml": yaml_content,
        "device_name": device_name,
        "summary": non_zero,
        "detailed_summary": detailed_summary,
        "total_items": total_items,
        "message": f"Retrieved configuration from '{device_name}': {total_items} total items across {len(non_zero)} config type(s). Use the detailed_summary field to show item names for each config type.",
    }

async def _ai_fmc_push_config(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Push loaded config to FTD device(s)."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None

    loaded_config = ctx.get("fmc_loaded_config")
    if not loaded_config:
        return {"success": False, "error": "No configuration loaded. Use fmc_get_device_config or load_config_to_ui first."}

    device_names = args.get("device_names") or []
    if not device_names:
        return {"success": False, "error": "device_names is required"}

    # Resolve device names to IDs (searching across all FMC connections)
    device_ids = []
    missing = []
    conn = None
    for dn in device_names:
        did, found_conn = _ai_resolve_device_id(ctx, dn, fmc_ip=target_fmc_ip)
        if did:
            device_ids.append(did)
            if conn is None:
                conn = found_conn
        else:
            missing.append(dn)

    if not conn:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}

    if missing:
        all_available = []
        for _ip, c in (ctx.get("fmc_connections") or {}).items():
            for d in (c.get("devices") or []):
                dn = d.get("name")
                if dn:
                    all_available.append(f"{dn} (on {_ip})")
        return {"success": False, "error": f"Device(s) not found: {', '.join(missing)}. Available: {', '.join(all_available) if all_available else 'none'}"}

    domain_uuid = _ai_resolve_domain_uuid(ctx, args.get("domain_name"), conn=conn)

    config = loaded_config
    routing = config.get("routing", {}) or {}
    objects = config.get("objects", {}) or {}

    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "domain_uuid": domain_uuid,
        "device_ids": device_ids,
        "config": config,
        "app_username": username,
        "apply_loopbacks": bool(config.get("loopback_interfaces")),
        "apply_physicals": bool(config.get("physical_interfaces")),
        "apply_etherchannels": bool(config.get("etherchannel_interfaces")),
        "apply_subinterfaces": bool(config.get("subinterfaces")),
        "apply_vtis": bool(config.get("vti_interfaces")),
        "apply_inline_sets": bool(config.get("inline_sets")),
        "apply_bridge_groups": bool(config.get("bridge_group_interfaces")),
        "apply_routing": bool(routing),
        "apply_objects": bool(objects),
    }

    reset_progress(username)
    result = await loop.run_in_executor(None, lambda: _apply_config_multi(payload))

    record_activity(username, "ai_fmc_push_config", {
        "devices": device_names,
        "success": result.get("success", False)
    })

    return {
        "success": result.get("success", False),
        "action": "config_pushed",
        "results": result.get("results"),
        "applied": result.get("applied"),
        "errors": result.get("errors"),
        "applied_rows": result.get("applied_rows"),
        "skipped_rows": result.get("skipped_rows"),
        "failed_rows": result.get("failed_rows"),
        "message": result.get("message") or (f"Configuration pushed to {len(device_names)} device(s)." if result.get("success") else "Push failed."),
    }

async def _ai_fmc_delete_device(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Delete/unregister devices from FMC."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None

    device_names = args.get("device_names") or []
    if not device_names:
        return {"success": False, "error": "device_names is required"}

    device_ids = []
    missing = []
    conn = None
    for dn in device_names:
        did, found_conn = _ai_resolve_device_id(ctx, dn, fmc_ip=target_fmc_ip)
        if did:
            device_ids.append(did)
            if conn is None:
                conn = found_conn
        else:
            missing.append(dn)

    if not conn:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}

    if missing:
        return {"success": False, "error": f"Device(s) not found: {', '.join(missing)}"}

    headers = conn.get("headers") or ctx.get("fmc_auth", {}).get("headers")
    domain_uuid = _ai_resolve_domain_uuid(ctx, conn=conn)

    if not headers:
        return {"success": False, "error": "FMC auth headers not available. Please reconnect."}

    def work():
        h = dict(headers)
        h["DOMAIN_UUID"] = domain_uuid
        return delete_devices_bulk(conn["fmc_ip"], h, domain_uuid, device_ids)

    result = await loop.run_in_executor(None, work)

    # Remove deleted devices from stored list
    deleted_set = set(device_ids)
    conn["devices"] = [d for d in (conn.get("devices") or []) if d.get("id") not in deleted_set]

    record_activity(username, "ai_fmc_delete_device", {"devices": device_names})

    return {
        "success": True,
        "action": "devices_deleted",
        "deleted_devices": device_names,
        "remaining_devices": [d.get("name") for d in conn.get("devices", []) if d.get("name")],
        "message": f"Deleted {len(device_names)} device(s) from FMC: {', '.join(device_names)}",
    }

async def _ai_fmc_delete_config(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Delete configuration from a device."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None

    device_name = (args.get("device_name") or "").strip()
    if not device_name:
        return {"success": False, "error": "device_name is required"}

    device_id, conn = _ai_resolve_device_id(ctx, device_name, fmc_ip=target_fmc_ip)
    if not conn:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}
    if not device_id:
        return {"success": False, "error": f"Device '{device_name}' not found"}

    config_types = args.get("config_types") or []
    domain_uuid = _ai_resolve_domain_uuid(ctx, conn=conn)
    loaded_config = ctx.get("fmc_loaded_config") or {}

    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "device_id": device_id,
        "domain_uuid": domain_uuid,
        "config": loaded_config,
        "delete_loopbacks": "loopback_interfaces" in config_types,
        "delete_physicals": "physical_interfaces" in config_types,
        "delete_etherchannels": "etherchannel_interfaces" in config_types,
        "delete_subinterfaces": "subinterfaces" in config_types,
        "delete_vtis": "vti_interfaces" in config_types,
        "delete_obj_if_security_zones": "security_zones" in config_types,
    }

    result = await loop.run_in_executor(None, lambda: _delete_config_sync(payload))

    record_activity(username, "ai_fmc_delete_config", {"device": device_name, "types": config_types})

    return {
        "success": result.get("success", False),
        "action": "config_deleted",
        "device_name": device_name,
        "deleted_types": config_types,
        "message": result.get("message") or f"Delete config operation completed for '{device_name}'.",
        "errors": result.get("errors"),
    }

async def _ai_fmc_get_vpn(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Get VPN topologies from FMC.
    Uses the exact same logic as the manual /api/fmc-config/vpn/list endpoint
    to fetch IKE/IPSec/Advanced settings, expand policy references, and fetch
    protected network objects. Then generates YAML via vpn/download logic.
    """
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None
    conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}

    domain_uuid = _ai_resolve_domain_uuid(ctx, args.get("domain_name"), conn=conn)

    # Reuse the exact same logic as fmc_vpn_list endpoint
    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "domain_uuid": domain_uuid,
    }

    def work():
        fmc_ip = payload["fmc_ip"]
        user = payload["username"]
        password = payload["password"]
        sel_domain = (payload.get("domain_uuid") or "").strip()

        logger.info("[VPN] Authenticating to FMC for VPN topology listing...")
        auth_domain, headers = authenticate(fmc_ip, user, password)
        du = sel_domain or auth_domain
        logger.info(f"[VPN] Using domain: {du}")

        # List topologies via summaries API
        summaries_base = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/policy/s2svpnsummaries"
        r = fmc.fmc_get(f"{summaries_base}?limit=1000&expanded=true")
        r.raise_for_status()
        items = (r.json() or {}).get("items", [])

        # Fetch full FTDS2SVpn objects
        ftds_map: Dict[str, Any] = {}
        try:
            logger.info("[VPN] Fetching FTDS2SVpn objects for domain...")
            all_vpn_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/policy/ftds2svpns?expanded=true&limit=1000"
            rv = fmc.fmc_get(all_vpn_url)
            rv.raise_for_status()
            for itx in (rv.json() or {}).get("items", []):
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

                # Fetch endpoints
                eps = []
                try:
                    logger.info(f"[VPN]  - Fetching endpoints for {name} via ftds2svpns/{vpn_id}/endpoints...")
                    endpoints_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/policy/ftds2svpns/{vpn_id}/endpoints?expanded=true&limit=1000"
                    re_ep = fmc.fmc_get(endpoints_url)
                    re_ep.raise_for_status()
                    eps = (re_ep.json() or {}).get('items', [])
                except Exception:
                    eps = []
                logger.info(f"[VPN]  - Endpoints fetched: {len(eps)} for {name}")

                # Fetch IKE settings
                ike_obj = None
                try:
                    ike_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/policy/ftds2svpns/{vpn_id}/ikesettings?expanded=true"
                    r_ike = fmc.fmc_get(ike_url)
                    rj = r_ike.json() if r_ike is not None else None
                    if isinstance(rj, dict):
                        ike_items = rj.get('items') if 'items' in rj else None
                        if isinstance(ike_items, list) and ike_items:
                            ike_obj = ike_items
                        elif rj and not ike_items:
                            ike_obj = [rj]
                except Exception as ex:
                    logger.warning(f"[VPN]  - Failed to fetch IKE settings for {name}: {ex}")

                # Fetch IPSec settings
                ipsec_obj = None
                try:
                    ipsec_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/policy/ftds2svpns/{vpn_id}/ipsecsettings?expanded=true"
                    r_ip = fmc.fmc_get(ipsec_url)
                    rj = r_ip.json() if r_ip is not None else None
                    if isinstance(rj, dict):
                        ipsec_items = rj.get('items') if 'items' in rj else None
                        if isinstance(ipsec_items, list) and ipsec_items:
                            ipsec_obj = ipsec_items
                        elif rj and not ipsec_items:
                            ipsec_obj = [rj]
                except Exception as ex:
                    logger.warning(f"[VPN]  - Failed to fetch IPSec settings for {name}: {ex}")

                # Fetch Advanced settings
                adv_obj = None
                try:
                    adv_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/policy/ftds2svpns/{vpn_id}/advancedsettings?expanded=true"
                    r_av = fmc.fmc_get(adv_url)
                    rj = r_av.json() if r_av is not None else None
                    if isinstance(rj, dict):
                        adv_items = rj.get('items') if 'items' in rj else None
                        if isinstance(adv_items, list) and adv_items:
                            adv_obj = adv_items
                        elif rj and not adv_items:
                            adv_obj = [rj]
                except Exception as ex:
                    logger.warning(f"[VPN]  - Failed to fetch Advanced settings for {name}: {ex}")

                # Expand IKE policy references
                if isinstance(ike_obj, list):
                    for ike_setting in ike_obj:
                        if not isinstance(ike_setting, dict):
                            continue
                        ikev2_settings = ike_setting.get("ikeV2Settings")
                        if isinstance(ikev2_settings, dict):
                            policies = ikev2_settings.get("policies")
                            if isinstance(policies, list):
                                expanded_policies = []
                                for policy_ref in policies:
                                    if isinstance(policy_ref, dict) and policy_ref.get("id"):
                                        try:
                                            policy_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/object/ikev2policies/{policy_ref['id']}"
                                            r_policy = fmc.fmc_get(policy_url)
                                            if r_policy and r_policy.status_code == 200:
                                                expanded_policies.append(r_policy.json())
                                            else:
                                                expanded_policies.append(policy_ref)
                                        except Exception:
                                            expanded_policies.append(policy_ref)
                                    else:
                                        expanded_policies.append(policy_ref)
                                ikev2_settings["policies"] = expanded_policies

                # Expand IPSec proposal references
                if isinstance(ipsec_obj, list):
                    for ipsec_setting in ipsec_obj:
                        if not isinstance(ipsec_setting, dict):
                            continue
                        proposals = ipsec_setting.get("ikeV2IpsecProposal")
                        if isinstance(proposals, list):
                            expanded_proposals = []
                            for proposal_ref in proposals:
                                if isinstance(proposal_ref, dict) and proposal_ref.get("id"):
                                    try:
                                        proposal_url = f"{fmc_ip}/api/fmc_config/v1/domain/{du}/object/ikev2ipsecproposals/{proposal_ref['id']}"
                                        r_proposal = fmc.fmc_get(proposal_url)
                                        if r_proposal and r_proposal.status_code == 200:
                                            expanded_proposals.append(r_proposal.json())
                                        else:
                                            expanded_proposals.append(proposal_ref)
                                    except Exception:
                                        expanded_proposals.append(proposal_ref)
                                else:
                                    expanded_proposals.append(proposal_ref)
                            ipsec_setting["ikeV2IpsecProposal"] = expanded_proposals

                # Collect and fetch protected network objects
                objects_section = {}
                try:
                    network_names = set()
                    accesslist_names = set()
                    for ep in eps or []:
                        prot_nets = ep.get('protectedNetworks')
                        if isinstance(prot_nets, dict):
                            nets = prot_nets.get('networks', [])
                            if isinstance(nets, list):
                                for net in nets:
                                    if isinstance(net, dict) and net.get('name'):
                                        network_names.add(net['name'])
                            acls = prot_nets.get('accessLists', [])
                            if isinstance(acls, list):
                                for acl in acls:
                                    if isinstance(acl, dict) and acl.get('name'):
                                        accesslist_names.add(acl['name'])
                    if network_names or accesslist_names:
                        logger.info(f"[VPN] Fetching {len(network_names)} networks and {len(accesslist_names)} access lists for topology {name}")
                        if network_names:
                            all_networks = get_all_network_objects(fmc_ip, headers, du)
                            network_objs = []
                            for net_name in network_names:
                                if net_name in all_networks:
                                    network_objs.append(all_networks[net_name])
                                    logger.info(f"[VPN]  - Found network: {net_name}")
                                else:
                                    logger.warning(f"[VPN]  - Network not found: {net_name}")
                            if network_objs:
                                objects_section['networks'] = network_objs
                        if accesslist_names:
                            all_accesslists = get_all_accesslist_objects(fmc_ip, headers, du)
                            acl_objs = []
                            for acl_name in accesslist_names:
                                if acl_name in all_accesslists:
                                    acl_objs.append(all_accesslists[acl_name])
                                    logger.info(f"[VPN]  - Found access list: {acl_name}")
                                else:
                                    logger.warning(f"[VPN]  - Access list not found: {acl_name}")
                            if acl_objs:
                                objects_section['accesslists'] = acl_objs
                except Exception as ex:
                    logger.warning(f"[VPN] Failed to fetch protected network objects for {name}: {ex}")

                raw = {
                    'summary': dict(it),
                    'endpoints': eps,
                    'ikeSettings': ike_obj,
                    'ipsecSettings': ipsec_obj,
                    'advancedSettings': adv_obj,
                    'ftds2svpn': ftds_map.get(vpn_id),
                }
                if objects_section:
                    raw['objects'] = objects_section

                # Peers for UI
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
                logger.warning(f"[VPN] Failed to expand VPN topology: {ex}")
                continue

        return out

    topologies = await loop.run_in_executor(None, work)

    # Store loaded VPN topologies (same format as manual flow)
    ctx["fmc_loaded_vpn_topologies"] = topologies

    # Generate YAML via the same download logic used by manual flow
    vpn_yaml = None
    vpn_filename = f"vpn-topologies-{int(time.time())}.yaml"
    try:
        raw_items = [t.get("raw", t) for t in topologies]
        # Use the same YAML generation logic as /api/fmc-config/vpn/download
        def _strip_keys_recursive_local(obj, keys={"metadata", "links"}):
            if isinstance(obj, dict):
                return {k: _strip_keys_recursive_local(v, keys) for k, v in obj.items() if k not in keys}
            if isinstance(obj, list):
                return [_strip_keys_recursive_local(x, keys) for x in obj]
            return obj

        def _limited_summary_local(src):
            return {
                'name': src.get('name'),
                'routeBased': bool(src.get('routeBased')) if src.get('routeBased') is not None else src.get('routeBased'),
                'ikeV1Enabled': bool(src.get('ikeV1Enabled')) if src.get('ikeV1Enabled') is not None else src.get('ikeV1Enabled'),
                'ikeV2Enabled': bool(src.get('ikeV2Enabled')) if src.get('ikeV2Enabled') is not None else src.get('ikeV2Enabled'),
                'topologyType': src.get('topologyType'),
            }

        vpn_items = []
        for raw in raw_items:
            raw_dict = dict(raw or {}) if isinstance(raw, dict) else {}
            if 'summary' in raw_dict:
                src_summary = dict(raw_dict.get('summary') or {})
                src_endpoints = list(raw_dict.get('endpoints') or [])
                src_ike = raw_dict.get('ikeSettings')
                src_ipsec = raw_dict.get('ipsecSettings')
                src_adv = raw_dict.get('advancedSettings')
                ftds = raw_dict.get('ftds2svpn')
                if isinstance(ftds, dict):
                    src_ike = src_ike or ftds.get('ikeSettings')
                    src_ipsec = src_ipsec or ftds.get('ipsecSettings')
                    src_adv = src_adv or ftds.get('advancedSettings')
            else:
                src_summary = raw_dict
                src_endpoints = list(raw_dict.get('endpoints') or [])
                src_ike = raw_dict.get('ikeSettings')
                src_ipsec = raw_dict.get('ipsecSettings')
                src_adv = raw_dict.get('advancedSettings')

            src_summary = _strip_keys_recursive_local(src_summary)
            src_endpoints = _strip_keys_recursive_local(src_endpoints)
            src_ike = _strip_keys_recursive_local(src_ike) if isinstance(src_ike, (dict, list)) else src_ike
            src_ipsec = _strip_keys_recursive_local(src_ipsec) if isinstance(src_ipsec, (dict, list)) else src_ipsec
            src_adv = _strip_keys_recursive_local(src_adv) if isinstance(src_adv, (dict, list)) else src_adv

            item = _limited_summary_local(src_summary)
            if src_endpoints:
                item['endpoints'] = src_endpoints
            if isinstance(src_ike, (dict, list)) and src_ike:
                item['ikeSettings'] = src_ike
            if isinstance(src_ipsec, (dict, list)) and src_ipsec:
                item['ipsecSettings'] = src_ipsec
            if isinstance(src_adv, (dict, list)) and src_adv:
                item['advancedSettings'] = src_adv
            src_objects = raw_dict.get('objects')
            if isinstance(src_objects, dict) and src_objects:
                item['objects'] = _strip_keys_recursive_local(src_objects)
            vpn_items.append(item)

        doc = {'vpn_topologies': vpn_items}
        vpn_yaml = yaml.safe_dump(doc, sort_keys=False)
        ctx["fmc_loaded_vpn_yaml"] = vpn_yaml
    except Exception as ex:
        logger.warning(f"[VPN] Failed to generate VPN YAML: {ex}")

    # Build UI-compatible topology objects
    ui_topologies = []
    summary_list = []
    for t in topologies:
        peers_info = t.get("peers", [])
        ep_names = [f"{p['name']} ({p.get('peerType') or ''})" if p.get('peerType') else p['name'] for p in peers_info]

        ui_topologies.append({
            "name": t["name"],
            "topologyType": t["topologyType"],
            "routeBased": t["routeBased"],
            "peers": peers_info,
            "raw": t.get("raw", t),
        })

        summary_list.append({
            "name": t["name"],
            "topologyType": t["topologyType"],
            "routeBased": t["routeBased"],
            "endpointCount": len(peers_info),
            "endpoints": ep_names,
        })

    record_activity(username, "ai_fmc_get_vpn", {"count": len(topologies)})

    return {
        "success": True,
        "action": "vpn_fetched",
        "topologies": summary_list,
        "vpn_topologies_for_ui": ui_topologies,
        "vpn_yaml": vpn_yaml,
        "vpn_filename": vpn_filename,
        "topology_count": len(topologies),
        "message": f"Retrieved {len(topologies)} VPN topology(ies) from FMC.",
    }

async def _ai_fmc_push_vpn(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Push VPN topologies to FMC."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None
    conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}

    loaded_vpn = ctx.get("fmc_loaded_vpn_topologies")
    loaded_vpn_yaml = ctx.get("fmc_loaded_vpn_yaml")

    if not loaded_vpn and not loaded_vpn_yaml:
        return {"success": False, "error": "No VPN topologies loaded. Use fmc_get_vpn_topologies or load_vpn_topology_to_ui first."}

    domain_uuid = _ai_resolve_domain_uuid(ctx, args.get("domain_name"), conn=conn)

    if loaded_vpn_yaml:
        import yaml as yaml_lib
        try:
            data = _yaml_safe_load(loaded_vpn_yaml)
        except Exception as e:
            return {"success": False, "error": f"Invalid VPN YAML: {e}"}

        def _as_list(x):
            return x if isinstance(x, list) else []
        candidates = [
            _as_list(data.get("vpn_topologies") if isinstance(data, dict) else None),
            _as_list((data.get("vpn") or {}).get("topologies") if isinstance(data, dict) else None),
            _as_list(data.get("topologies") if isinstance(data, dict) else None),
        ]
        topo_list = next((lst for lst in candidates if lst), [])
    else:
        topo_list = [t.get("raw", t) for t in loaded_vpn]

    if not topo_list:
        return {"success": False, "error": "No VPN topologies to push"}

    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "domain_uuid": domain_uuid,
        "topologies": topo_list,
    }

    result = await loop.run_in_executor(None, lambda: _vpn_apply_sync(payload))

    record_activity(username, "ai_fmc_push_vpn", {"success": result.get("success", False)})

    return {
        "success": result.get("success", False),
        "action": "vpn_pushed",
        "message": result.get("message") or "VPN push completed.",
        "created": result.get("created"),
        "endpoints_created": result.get("endpoints_created"),
        "errors": result.get("errors"),
        "topology_summary": result.get("topology_summary"),
    }

def _ai_fmc_replace_vpn_endpoints(args: Dict, ctx: Dict, username: str) -> Dict[str, Any]:
    """Replace VPN endpoints, swapping source device for target device."""
    source = (args.get("source_device") or "").strip()
    target = (args.get("target_device") or "").strip()

    if not source or not target:
        return {"success": False, "error": "Both source_device and target_device are required"}

    loaded_vpn = ctx.get("fmc_loaded_vpn_topologies")
    loaded_yaml = ctx.get("fmc_loaded_vpn_yaml")

    if not loaded_vpn and not loaded_yaml:
        return {"success": False, "error": "No VPN topologies loaded. Use fmc_get_vpn_topologies first."}

    # If we have YAML, do string replacement
    if loaded_yaml:
        new_yaml = loaded_yaml.replace(source, target)
        ctx["fmc_loaded_vpn_yaml"] = new_yaml

    # Update in-memory topologies
    replaced_count = 0
    if loaded_vpn:
        for topo in loaded_vpn:
            for ep in (topo.get("endpoints") or []):
                dev = ep.get("device") or {}
                if (dev.get("name") or "").strip().lower() == source.lower():
                    dev["name"] = target
                    replaced_count += 1
                if (ep.get("name") or "").strip().lower() == source.lower():
                    ep["name"] = target
                    replaced_count += 1
            raw = topo.get("raw") or {}
            for ep in (raw.get("endpoints") or []):
                dev = ep.get("device") or {}
                if (dev.get("name") or "").strip().lower() == source.lower():
                    dev["name"] = target
                    replaced_count += 1
                if (ep.get("name") or "").strip().lower() == source.lower():
                    ep["name"] = target
                    replaced_count += 1

    record_activity(username, "ai_fmc_replace_vpn_endpoints", {
        "source": source, "target": target, "replaced": replaced_count
    })

    return {
        "success": True,
        "action": "vpn_endpoints_replaced",
        "source_device": source,
        "target_device": target,
        "replaced_count": replaced_count,
        "message": f"Replaced {replaced_count} endpoint reference(s) from '{source}' to '{target}' in loaded VPN topologies.",
    }

def _ai_fmc_load_context_config(args: Dict, ctx: Dict, username: str) -> Dict[str, Any]:
    """Load the previously fetched/stored config from context into the Device Configuration UI."""
    config = ctx.get("fmc_loaded_config")
    config_yaml = ctx.get("fmc_loaded_config_yaml")

    if not config and not config_yaml:
        return {"success": False, "error": "No configuration in context. Use fmc_get_device_config to fetch config first, or upload a YAML file."}

    if not config and config_yaml:
        import yaml as yaml_lib
        try:
            config = _yaml_safe_load(config_yaml)
        except Exception as e:
            return {"success": False, "error": f"Failed to parse stored YAML: {e}"}
        if not isinstance(config, dict):
            config = {}

    from ai_tools import fmc_tool_executor
    counts = fmc_tool_executor._count_config_items(config)
    non_zero = {k: v for k, v in counts.items() if v > 0}
    total_items = sum(non_zero.values())

    record_activity(username, "ai_fmc_load_context_config", {"items": total_items})

    return {
        "success": True,
        "action": "context_config_loaded",
        "config": config,
        "counts": counts,
        "config_yaml": config_yaml or "",
        "filename": "loaded_config.yaml",
        "summary": non_zero,
        "total_items": total_items,
        "message": f"Configuration loaded into Device Configuration section: {total_items} items across {len(non_zero)} config type(s).",
    }

def _ai_fmc_load_context_vpn(args: Dict, ctx: Dict, username: str) -> Dict[str, Any]:
    """Load the previously fetched/stored VPN topologies from context into the VPN section UI."""
    loaded_vpn = ctx.get("fmc_loaded_vpn_topologies")

    if not loaded_vpn:
        return {"success": False, "error": "No VPN topologies in context. Use fmc_get_vpn_topologies to fetch them first."}

    # Build UI-compatible topology objects
    ui_topologies = []
    for t in loaded_vpn:
        peers_info = []
        for ep in (t.get("endpoints") or []):
            nm = (ep.get("device") or {}).get("name") or ep.get("name") or ""
            rl = (ep.get("role") or "").upper() if isinstance(ep.get("role"), str) else ""
            pt = (ep.get("peerType") or ep.get("role") or "").upper() if isinstance(ep.get("peerType") or ep.get("role"), str) else ""
            ex = bool(ep.get("extranet")) if isinstance(ep.get("extranet"), (bool, str, int)) else False
            if nm:
                peers_info.append({"name": str(nm), "role": rl or None, "peerType": pt or None, "extranet": ex})

        ui_topologies.append({
            "name": t.get("name", ""),
            "topologyType": t.get("topologyType", ""),
            "routeBased": t.get("routeBased", False),
            "peers": peers_info,
            "raw": t.get("raw", t),
        })

    record_activity(username, "ai_fmc_load_context_vpn", {"count": len(ui_topologies)})

    return {
        "success": True,
        "action": "vpn_fetched",
        "vpn_topologies_for_ui": ui_topologies,
        "topologies": [{"name": t["name"], "topologyType": t["topologyType"], "endpointCount": len(t.get("peers", []))} for t in ui_topologies],
        "topology_count": len(ui_topologies),
        "message": f"Loaded {len(ui_topologies)} VPN topology(ies) into the VPN section.",
    }

async def _ai_fmc_get_chassis_config(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Get chassis configuration from a chassis device."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None
    device_name = (args.get("device_name") or "").strip()
    if not device_name:
        return {"success": False, "error": "device_name is required"}

    device_id, conn = _ai_resolve_device_id(ctx, device_name, fmc_ip=target_fmc_ip)
    if not conn:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}
    if not device_id:
        all_available = []
        for _ip, c in (ctx.get("fmc_connections") or {}).items():
            for d in (c.get("devices") or []):
                dn = d.get("name")
                if dn:
                    all_available.append(f"{dn} (on {_ip})")
        return {"success": False, "error": f"Device '{device_name}' not found. Available: {', '.join(all_available) if all_available else 'none'}"}

    device_meta = {}
    for d in (conn.get("devices") or []):
        if d.get("id") == device_id:
            device_meta = {
                "name": d.get("name") or "",
                "version": d.get("sw_version") or d.get("version") or d.get("softwareVersion") or d.get("swVersion") or "",
                "model": d.get("model") or "",
            }
            break

    domain_uuid = _ai_resolve_domain_uuid(ctx, args.get("domain_name"), conn=conn)
    admin_password = (args.get("admin_password") or "").strip() or "Cisco@12"

    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "domain_uuid": domain_uuid,
        "device_ids": [device_id],
        "app_username": username,
        "device_meta": device_meta,
        "chassis_admin_password": admin_password,
    }

    reset_progress(username)
    result = await loop.run_in_executor(None, lambda: _export_chassis_config_sync(payload))

    if not result.get("success"):
        return {"success": False, "error": result.get("message", "Chassis config export failed")}

    filename = result.get("filename") or "chassis_export.yaml"
    yaml_content = result.get("content") or ""

    import yaml as yaml_lib
    try:
        config = _yaml_safe_load(yaml_content)
    except Exception:
        config = {}
    if not isinstance(config, dict):
        config = {}

    # Count chassis config items (keys match frontend CHASSIS_GROUPS items)
    chassis_ifaces = config.get("chassis_interfaces") or {}
    logical_devices = config.get("logical_devices") or []
    counts = {
        "chassis_interfaces.physicalinterfaces": len(chassis_ifaces.get("physicalinterfaces") or []),
        "chassis_interfaces.etherchannelinterfaces": len(chassis_ifaces.get("etherchannelinterfaces") or []),
        "chassis_interfaces.subinterfaces": len(chassis_ifaces.get("subinterfaces") or []),
    }
    for ld in logical_devices:
        if isinstance(ld, dict):
            ld_name = ld.get("name") or ld.get("baseName") or f"ld{logical_devices.index(ld)}"
            ld_item_count = 0
            for k, v in ld.items():
                if isinstance(v, list):
                    ld_item_count += len(v)
                elif isinstance(v, dict):
                    ld_item_count += 1
                elif v:
                    ld_item_count += 1
            counts[f"logical_devices.{ld_name}"] = ld_item_count

    # Store in context
    ctx["fmc_loaded_chassis_config"] = config
    ctx["fmc_loaded_chassis_config_yaml"] = yaml_content
    ctx["fmc_loaded_chassis_config_filename"] = filename
    ctx["fmc_loaded_chassis_config_counts"] = counts

    non_zero = {k: v for k, v in counts.items() if v > 0}
    total_items = sum(non_zero.values())

    # Build detailed summary
    detailed_summary = {}
    for section_key, items_list in [
        ("physical_interfaces", chassis_ifaces.get("physicalinterfaces") or []),
        ("etherchannel_interfaces", chassis_ifaces.get("etherchannelinterfaces") or []),
        ("subinterfaces", chassis_ifaces.get("subinterfaces") or []),
    ]:
        if items_list:
            names = [str(i.get("name", "")) for i in items_list if isinstance(i, dict) and i.get("name")]
            detailed_summary[section_key] = {"count": len(items_list), "items": names}
    if logical_devices:
        ld_names = [str(ld.get("name", "")) for ld in logical_devices if isinstance(ld, dict) and ld.get("name")]
        detailed_summary["logical_devices"] = {"count": len(logical_devices), "items": ld_names}

    record_activity(username, "ai_fmc_get_chassis_config", {"device": device_name, "items": total_items})

    return {
        "success": True,
        "action": "chassis_config_fetched",
        "config": config,
        "counts": counts,
        "filename": filename,
        "config_yaml": yaml_content,
        "device_name": device_name,
        "summary": non_zero,
        "detailed_summary": detailed_summary,
        "total_items": total_items,
        "message": f"Retrieved chassis configuration from '{device_name}': {total_items} total items. Use the detailed_summary field to show item names.",
    }

async def _ai_fmc_push_chassis_config(args: Dict, ctx: Dict, username: str, loop) -> Dict[str, Any]:
    """Push loaded chassis config to a chassis device."""
    target_fmc_ip = (args.get("fmc_ip") or "").strip() or None
    device_name = (args.get("device_name") or "").strip()
    if not device_name:
        return {"success": False, "error": "device_name is required"}

    config = ctx.get("fmc_loaded_chassis_config")
    if not config:
        return {"success": False, "error": "No chassis config loaded. Use fmc_get_chassis_config first."}

    device_id, conn = _ai_resolve_device_id(ctx, device_name, fmc_ip=target_fmc_ip)
    if not conn:
        conn = _ai_resolve_fmc_connection(ctx, fmc_ip=target_fmc_ip)
    if not conn:
        return {"success": False, "error": "Not connected to FMC. Use fmc_connect first."}
    if not device_id:
        return {"success": False, "error": f"Device '{device_name}' not found."}

    domain_uuid = _ai_resolve_domain_uuid(ctx, args.get("domain_name"), conn=conn)
    admin_password = (args.get("admin_password") or "").strip() or "Cisco@12"

    # Build apply flags
    ld_names = args.get("logical_device_names")  # None means all
    if ld_names is not None and not isinstance(ld_names, list):
        ld_names = None

    payload = {
        "fmc_ip": conn["fmc_ip"],
        "username": conn["username"],
        "password": conn["password"],
        "domain_uuid": domain_uuid,
        "device_ids": [device_id],
        "app_username": username,
        "config": config,
        "apply_chassis_physicalinterfaces": args.get("apply_physical_interfaces", True),
        "apply_chassis_etherchannelinterfaces": args.get("apply_etherchannel_interfaces", True),
        "apply_chassis_subinterfaces": args.get("apply_subinterfaces", True),
        "apply_chassis_logical_devices": ld_names if ld_names is not None else True,
        "chassis_admin_password": admin_password,
    }

    reset_progress(username)
    result = await loop.run_in_executor(None, lambda: _apply_chassis_config_sync(payload))

    record_activity(username, "ai_fmc_push_chassis_config", {"device": device_name, "success": result.get("success")})

    return {
        "success": result.get("success", False),
        "action": "chassis_config_pushed",
        "applied": result.get("applied"),
        "errors": result.get("errors"),
        "skipped": result.get("skipped"),
        "summary_tables": result.get("summary_tables"),
        "message": result.get("message") or (f"Chassis configuration pushed to '{device_name}'." if result.get("success") else "Chassis push failed."),
    }

def _ai_fmc_load_context_chassis_config(args: Dict, ctx: Dict, username: str) -> Dict[str, Any]:
    """Load the previously fetched chassis configuration from context into the Chassis Configuration UI."""
    config = ctx.get("fmc_loaded_chassis_config")
    config_yaml = ctx.get("fmc_loaded_chassis_config_yaml")
    filename = ctx.get("fmc_loaded_chassis_config_filename")
    counts = ctx.get("fmc_loaded_chassis_config_counts")

    if not config:
        return {"success": False, "error": "No chassis configuration in context. Use fmc_get_chassis_config to fetch one first."}

    record_activity(username, "ai_fmc_load_context_chassis_config", {})

    return {
        "success": True,
        "action": "chassis_config_fetched",
        "config": config,
        "counts": counts or {},
        "config_yaml": config_yaml or "",
        "filename": filename or "chassis_config.yaml",
        "message": "Chassis configuration loaded into Chassis Configuration section.",
    }

@app.post("/api/ai/tool-execute")
async def ai_execute_tool(http_request: Request):
    """Execute an AI tool call."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        body = await http_request.json()
        tool_name = body.get("tool_name")
        arguments = body.get("arguments", {})
        session_id = body.get("session_id")
        context_mode = body.get("context_mode", "strongswan")
        
        if not tool_name:
            return JSONResponse(status_code=400, content={"success": False, "message": "tool_name required"})
        
        # FMC operation tools (connect, get/push config, VPN ops)
        if tool_name in FMC_OPERATION_TOOL_NAMES:
            result = await _execute_fmc_operation(tool_name, arguments, username)
        # FMC schema/generation tools
        elif tool_name in {"lookup_fmc_schema", "validate_fmc_config", "load_config_to_ui", "load_chassis_config_to_ui"}:
            executor = get_tool_executor("fmc")
            result = executor.execute(tool_name, arguments, username)
            # Store loaded config in context
            if tool_name == "load_config_to_ui" and result.get("success") and result.get("config"):
                ctx = get_user_ctx(username)
                ctx["fmc_loaded_config"] = result["config"]
                ctx["fmc_loaded_config_yaml"] = result.get("config_yaml")
            elif tool_name == "load_chassis_config_to_ui" and result.get("success") and result.get("config"):
                ctx = get_user_ctx(username)
                ctx["fmc_loaded_chassis_config"] = result["config"]
                ctx["fmc_loaded_chassis_config_yaml"] = result.get("config_yaml")
                ctx["fmc_loaded_chassis_config_filename"] = result.get("filename")
                ctx["fmc_loaded_chassis_config_counts"] = result.get("counts")
        # VPN generation tools
        elif tool_name in {"generate_vpn_topology", "load_vpn_topology_to_ui"}:
            result = vpn_tool_executor.execute(tool_name, arguments, username)
            # Also store loaded VPN in context when load_vpn_topology_to_ui is used
            if tool_name == "load_vpn_topology_to_ui" and result.get("success") and result.get("vpn_yaml"):
                ctx = get_user_ctx(username)
                ctx["fmc_loaded_vpn_yaml"] = result["vpn_yaml"]
        # CSC (Cisco Secure Client) tools - use CSC SSH connection
        elif tool_name in CSC_TOOL_NAMES:
            csc_conn = csc_connections.get(username)
            if not csc_conn:
                return JSONResponse(status_code=400, content={
                    "success": False,
                    "message": "Not connected to Cisco Secure Client server. Please connect in the Cisco Secure Client section first."
                })
            result = await csc_tool_executor.execute_tool(tool_name, arguments, csc_conn, username)
        else:
            # Get strongSwan connection info
            conn_info = strongswan_connections.get(username)
            if not conn_info:
                return JSONResponse(status_code=400, content={
                    "success": False,
                    "message": "Not connected to strongSwan server. Please connect first."
                })
            executor = get_tool_executor("strongswan")
            result = await executor.execute_tool(tool_name, arguments, conn_info, username)
        
        # Note: Tool results are NOT stored in session here.
        # The frontend sends tool results back via /api/ai/chat with tool_results,
        # which handles adding both the assistant tool_calls and tool results to the session
        # in the correct order before continuing the conversation.
        
        record_activity(username, "ai_tool_execute", {"tool": tool_name, "success": result.get("success", False)})
        
        return result
    
    except Exception as e:
        logger.error(f"AI tool execute error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

@app.get("/api/ai/rag-search")
async def ai_rag_search(q: str, http_request: Request):
    """Search the RAG knowledge base."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        rag_pipeline = get_rag_pipeline()
        results = rag_pipeline.search(q, top_k=5)
        
        return {
            "success": True,
            "query": q,
            "results": results
        }
    except Exception as e:
        logger.error(f"AI RAG search error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

# ============================================================================
# Cisco Secure Client (CSC) APIs
# ============================================================================

csc_connections: Dict[str, Any] = {}

CSC_REMOTE_DIR = "/opt/cisco-secure-client-docker"
CSC_IMAGE_NAME = "cisco-secure-client"
CSC_CONTAINER_PREFIX = "csc-"

CSC_DOCKERFILE_TEMPLATE = """FROM ubuntu:22.04

RUN apt-get update && apt-get install -y net-tools iptables iproute2 expect && rm -rf /var/lib/apt/lists/*

ENV CSC_LOGGING_OUTPUT=STDOUT

ARG DEB_FILENAME
COPY ${DEB_FILENAME} /tmp/csc.deb
COPY entry.sh /entry.sh
RUN chmod +x /entry.sh

RUN cd /tmp && \\
    apt-get update && \\
    apt-get install -y ./csc.deb && \\
    rm -rf /tmp/csc.deb /var/lib/apt/lists/*

ENTRYPOINT ["/entry.sh"]
"""

CSC_ENTRY_SH = r"""#!/bin/bash

wait_forever() {
  while true; do
    sleep infinity &
    wait $!
  done
}

configure_cert_policy() {
  # Write AnyConnectLocalPolicy.xml to control BlockUntrustedServers.
  # The VPN agent reads this from /opt/cisco/secureclient/ at startup.
  # Must be written BEFORE the agent starts.
  if [ "$ACCEPT_UNTRUSTED_CERT" = "false" ]; then
    BLOCK_UNTRUSTED="true"
  else
    BLOCK_UNTRUSTED="false"
  fi
  POLICY_XML="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<AnyConnectLocalPolicy acversion=\"5.1.16\">
<FipsMode>false</FipsMode>
<BlockUntrustedServers>${BLOCK_UNTRUSTED}</BlockUntrustedServers>
<StrictCertificateTrust>false</StrictCertificateTrust>
</AnyConnectLocalPolicy>"
  # Write to all possible locations the agent may check
  echo "$POLICY_XML" > /opt/cisco/secureclient/AnyConnectLocalPolicy.xml
  mkdir -p /opt/cisco/secureclient/vpn
  echo "$POLICY_XML" > /opt/cisco/secureclient/vpn/AnyConnectLocalPolicy.xml
  echo "Wrote cert policy: BlockUntrustedServers=$BLOCK_UNTRUSTED"
}

configure_profile() {
  # Write AnyConnect client profile XML to configure connection preferences.
  # For IPSec-IKEv2: sets PrimaryProtocol to IPsec in the ServerList.
  # For SSL with DTLS disabled: prevents DTLS negotiation.
  # Profile must be written BEFORE the VPN agent starts.
  PROFILE_DIR="/opt/cisco/secureclient/vpn/profile"
  mkdir -p "$PROFILE_DIR"
  PROFILE_FILE="$PROFILE_DIR/csc_profile.xml"

  HOST_NAME="${VPN_GROUP:-${VPN_SERVER}}"
  USER_GROUP_TAG=""
  if [ -n "$VPN_GROUP" ]; then
    USER_GROUP_TAG="<UserGroup>${VPN_GROUP}</UserGroup>"
  fi

  if [ "$CONNECTION_TYPE" = "ipsec" ]; then
    if [ "$ENABLE_PQC" = "true" ]; then
      echo "Configuring AnyConnect profile for IPSec-IKEv2 with PQC..."
      PROTOCOL_TAG="<PrimaryProtocol>IPsec
        <AdditionalKeyExchange>1,2,3,4,5,6,7</AdditionalKeyExchange>
        <StandardAuthenticationOnly>false</StandardAuthenticationOnly>
      </PrimaryProtocol>"
    else
      echo "Configuring AnyConnect profile for IPSec-IKEv2..."
      PROTOCOL_TAG="<PrimaryProtocol>IPsec</PrimaryProtocol>"
    fi
  else
    echo "Configuring AnyConnect profile for SSL..."
    PROTOCOL_TAG="<PrimaryProtocol>SSL</PrimaryProtocol>"
  fi

  cat > "$PROFILE_FILE" <<PROFILE_EOF
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
  <ClientInitialization>
    <UseStartBeforeLogon UserControllable="true">false</UseStartBeforeLogon>
    <AutomaticCertSelection UserControllable="true">false</AutomaticCertSelection>
    <ShowPreConnectMessage>false</ShowPreConnectMessage>
    <CertificateStore>All</CertificateStore>
    <CertificateStoreOverride>false</CertificateStoreOverride>
    <ProxySettings>Native</ProxySettings>
    <AllowLocalProxyConnections>true</AllowLocalProxyConnections>
    <AuthenticationTimeout>12</AuthenticationTimeout>
    <AutoConnectOnStart UserControllable="true">false</AutoConnectOnStart>
    <MinimizeOnConnect UserControllable="true">true</MinimizeOnConnect>
    <LocalLanAccess UserControllable="true">false</LocalLanAccess>
    <ClearSmartcardPin UserControllable="true">true</ClearSmartcardPin>
    <AutoReconnect UserControllable="false">true
      <AutoReconnectBehavior UserControllable="false">DisconnectOnSuspend</AutoReconnectBehavior>
    </AutoReconnect>
    <AutoUpdate UserControllable="false">true</AutoUpdate>
    <RSASecurIDIntegration UserControllable="true">Automatic</RSASecurIDIntegration>
    <WindowsLogonEnforcement>SingleLocalLogon</WindowsLogonEnforcement>
    <WindowsVPNEstablishment>LocalUsersOnly</WindowsVPNEstablishment>
    <AutomaticVPNPolicy>false</AutomaticVPNPolicy>
    <PPPExclusion UserControllable="false">Disable
      <PPPExclusionServerIP UserControllable="false"></PPPExclusionServerIP>
    </PPPExclusion>
    <EnableScripting UserControllable="false">false</EnableScripting>
    <EnableAutomaticServerSelection UserControllable="false">false
      <AutoServerSelectionImprovement>20</AutoServerSelectionImprovement>
      <AutoServerSelectionSuspendTime>4</AutoServerSelectionSuspendTime>
    </EnableAutomaticServerSelection>
    <RetainVpnOnLogoff>false</RetainVpnOnLogoff>
  </ClientInitialization>
  <ServerList>
    <HostEntry>
      <HostName>${HOST_NAME}</HostName>
      <HostAddress>${VPN_SERVER}</HostAddress>
      ${USER_GROUP_TAG}
      ${PROTOCOL_TAG}
    </HostEntry>
  </ServerList>
</AnyConnectProfile>
PROFILE_EOF

  echo "Wrote AnyConnect profile to $PROFILE_FILE (connection_type=$CONNECTION_TYPE)"
}

start_service() {
  if [ -f /opt/cisco/secureclient/bin/vpnagentd ]; then
    echo "Starting VPN agent..."
    while true; do
      /opt/cisco/secureclient/bin/vpnagentd -execv_instance &
      SERVICE_PID=$!
      wait $SERVICE_PID
      echo "VPN agent exited. Restarting..."
      sleep 1
    done
  fi
}

connect_vpn() {
  if [ -n "$VPN_SERVER" ] && [ -n "$VPN_USER" ] && [ -n "$VPN_PASSWORD" ]; then
    sleep 3
    VPN_CLI="/opt/cisco/secureclient/bin/vpn"
    echo "Connecting to VPN server $VPN_SERVER (type=$CONNECTION_TYPE)..."

    if [ "$ACCEPT_UNTRUSTED_CERT" = "false" ]; then
      echo "Setting BlockUntrustedServers preference to enabled..."
      /opt/cisco/secureclient/bin/vpn block 1 2>&1 || true
    else
      echo "Setting BlockUntrustedServers preference to disabled..."
      /opt/cisco/secureclient/bin/vpn block 0 2>&1 || true
    fi
    sleep 1

    # For IPSec-IKEv2: connect using the profile HostName so the client
    # picks up PrimaryProtocol=IPsec from the installed profile.
    # For SSL: connect directly to VPN_SERVER address.
    if [ "$CONNECTION_TYPE" = "ipsec" ]; then
      CONNECT_TARGET="${VPN_GROUP:-${VPN_SERVER}}"
      echo "Using profile HostName '$CONNECT_TARGET' for IPSec-IKEv2 connection..."
    else
      CONNECT_TARGET="$VPN_SERVER"
    fi

    echo "Connecting with credentials..."
    export VPN_SERVER VPN_USER VPN_PASSWORD VPN_GROUP ACCEPT_UNTRUSTED_CERT CONNECTION_TYPE ENABLE_DTLS CONNECT_TARGET
    /usr/bin/expect <<'EXPECT_EOF'
set timeout 90
log_user 1

proc answer_prompts {} {
  expect {
    -re {Connect Anyway\? \[y/n\]:} {
      send "y\r"
      exp_continue
    }
    -re {Change the setting that blocks untrusted connections\? \[y/n\]:} {
      if {[info exists ::env(ACCEPT_UNTRUSTED_CERT)] && $::env(ACCEPT_UNTRUSTED_CERT) ne "false"} {
        send "y\r"
      } else {
        send "n\r"
      }
      exp_continue
    }
    -re {accept\? \[y/n\]:} {
      send "y\r"
      exp_continue
    }
    -re {\nGroup: $} {
      if {[info exists ::env(VPN_GROUP)] && $::env(VPN_GROUP) ne ""} {
        send "$::env(VPN_GROUP)\r"
      } else {
        send "\r"
      }
      exp_continue
    }
    -re {\nUsername: $} {
      send "$::env(VPN_USER)\r"
      exp_continue
    }
    -re {\nPassword: $} {
      send "$::env(VPN_PASSWORD)\r"
      exp_continue
    }
    -re {VPN>} {
      exp_continue
    }
    -re {>> Login failed} {
      puts "\nLogin failed - check credentials"
    }
    -re {>> state: Connected} {
      puts "\nVPN connected successfully"
    }
    eof
  }
}

spawn /opt/cisco/secureclient/bin/vpn connect $::env(CONNECT_TARGET)
answer_prompts
EXPECT_EOF
    echo "VPN connection attempt complete."
  fi
}

# 1. Configure certificate trust policy BEFORE agent starts
configure_cert_policy

# 2. Write AnyConnect client profile (IPSec/SSL preferences)
configure_profile

# 3. Start VPN agent daemon
start_service &

# 4. Attempt VPN connection
connect_vpn &

wait_forever
"""


def _get_csc_ssh(http_request: Request):
    """Helper to get CSC SSH connection info."""
    username = get_current_username(http_request)
    if not username:
        return None, None, JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
    conn_info = csc_connections.get(username)
    if not conn_info:
        return None, None, JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any CSC server"})
    return username, conn_info, None


def _csc_ssh_connect(conn_info):
    """Create and return an SSH connection for CSC server."""
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(
        hostname=conn_info['ip'],
        port=conn_info['port'],
        username=conn_info['username'],
        password=conn_info['password'],
        timeout=15,
        allow_agent=False,
        look_for_keys=False
    )
    return ssh


def _csc_sudo_exec(ssh, cmd, password, timeout=30):
    """Execute a sudo command over SSH for CSC, return (output, error, exit_status)."""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout, get_pty=True)
    stdin.write(password + '\n')
    stdin.flush()
    output = stdout.read().decode('utf-8', errors='replace')
    error = stderr.read().decode('utf-8', errors='replace')
    exit_status = stdout.channel.recv_exit_status()
    lines = output.split('\n')
    clean_lines = [l for l in lines if not l.startswith('[sudo]') and not l.startswith('sudo:') and password not in l]
    clean_output = '\n'.join(clean_lines).strip()
    return clean_output, error, exit_status


@app.post("/api/csc/connect")
async def csc_connect(request: CSCConnectionRequest, http_request: Request):
    """Connect to CSC server via SSH."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})

        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh.connect(
                hostname=request.ip,
                port=request.port,
                username=request.username,
                password=request.password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
        except Exception as e:
            return JSONResponse(status_code=400, content={"success": False, "message": f"SSH connection failed: {str(e)}"})

        ssh.close()

        csc_connections[username] = {
            'ip': request.ip,
            'port': request.port,
            'username': request.username,
            'password': request.password
        }
        record_activity(username, "csc_connect", {"ip": request.ip})
        return {"success": True, "message": f"Connected to {request.ip}"}
    except Exception as e:
        logger.error(f"CSC connect error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/upload-deb")
async def csc_upload_deb(http_request: Request, file: UploadFile = File(...)):
    """Upload a Cisco Secure Client .deb file and store locally."""
    try:
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})

        if not file.filename.endswith('.deb'):
            return JSONResponse(status_code=400, content={"success": False, "message": "File must be a .deb package"})

        user_dir = ensure_user_inputs_directory(username)
        csc_dir = os.path.join(user_dir, "csc")
        os.makedirs(csc_dir, exist_ok=True)
        # Store with original filename to preserve version info
        dest_path = os.path.join(csc_dir, file.filename)
        content = await file.read()
        # Remove any previous .deb files in the directory
        for old_file in os.listdir(csc_dir):
            if old_file.endswith('.deb'):
                os.remove(os.path.join(csc_dir, old_file))
        with open(dest_path, 'wb') as f:
            f.write(content)
        # Save filename metadata so install process knows which file to use
        with open(os.path.join(csc_dir, ".deb_filename"), 'w') as f:
            f.write(file.filename)
        logger.info(f"CSC .deb uploaded by {username}: {file.filename} ({len(content)} bytes)")
        return {"success": True, "message": f"Uploaded {file.filename} ({len(content)} bytes)", "filename": file.filename, "size": len(content)}
    except Exception as e:
        logger.error(f"CSC .deb upload error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/install")
def csc_install(request: CSCInstallRequest, http_request: Request):
    """Install Docker and build CSC image on the remote server."""
    username = None
    ssh = None
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ctx = get_user_ctx(username)
        _detach_user_log_handlers(username)
        ctx["log_stream"] = io.StringIO()
        ctx["stop_requested"] = False
        try:
            with open(os.path.join(_user_dir(username), "operation.log"), 'w', encoding='utf-8'):
                pass
        except Exception:
            pass
        reset_progress(username)
        _start_user_operation(username, "csc-install")
        ctx["operation_status"]["total_steps"] = 10
        ctx["operation_status"]["completed_steps"] = 0
        ctx["operation_status"]["current_step"] = "Starting CSC install"
        _attach_user_log_handlers(username)

        user_dir = ensure_user_inputs_directory(username)
        csc_dir = os.path.join(user_dir, "csc")
        # Find the uploaded .deb file (by metadata or by scanning)
        deb_filename = None
        meta_file = os.path.join(csc_dir, ".deb_filename")
        if os.path.exists(meta_file):
            with open(meta_file, 'r') as mf:
                deb_filename = mf.read().strip()
        if not deb_filename or not os.path.exists(os.path.join(csc_dir, deb_filename)):
            # Fallback: scan directory for any .deb file
            for fn in os.listdir(csc_dir) if os.path.isdir(csc_dir) else []:
                if fn.endswith('.deb'):
                    deb_filename = fn
                    break
        local_deb = os.path.join(csc_dir, deb_filename) if deb_filename else None
        if not local_deb or not os.path.exists(local_deb):
            message = "No .deb file uploaded. Please upload the Cisco Secure Client .deb package first."
            logger.error(f"CSC install: .deb not found in {csc_dir} for user {username}")
            _finish_user_operation(username, False, message)
            return JSONResponse(status_code=400, content={"success": False, "message": message})
        # Extract version from filename (e.g. cisco-secure-client-vpn-cli_5.1.16.194_amd64.deb)
        deb_version = None
        ver_match = re.search(r'_(\d+\.\d+\.\d+\.\d+)_', deb_filename)
        if ver_match:
            deb_version = ver_match.group(1)

        steps = []

        def append_step(message: str, percent: Optional[int] = None, level: str = "info"):
            steps.append(message)
            ctx["operation_status"]["current_step"] = message
            ctx["operation_status"]["completed_steps"] = len(steps)
            ctx["operation_status"]["message"] = message
            if percent is not None:
                set_progress(username, percent, message)
            if level == "error":
                logger.error(message)
            elif level == "warning":
                logger.warning(message)
            else:
                logger.info(message)

        def fail(message: str, status_code: int = 400):
            logger.error(message)
            ctx["operation_status"]["current_step"] = "Failed"
            ctx["operation_status"]["message"] = message
            _finish_user_operation(username, False, message)
            reset_progress(username)
            return JSONResponse(status_code=status_code, content={"success": False, "message": message, "steps": steps})

        append_step("Starting CSC install...", 1)
        ssh = _csc_ssh_connect(conn_info)

        # 1. Check Docker is present
        out, err_out, status = _csc_sudo_exec(ssh, "which docker", conn_info['password'], timeout=10)
        if status != 0:
            return fail("Docker is not installed. Please install Docker first using the 'Install Docker' button.")
        append_step("Docker detected.", 10)

        # 2. Create remote directory
        _csc_sudo_exec(ssh, f"sudo -S mkdir -p {CSC_REMOTE_DIR}", conn_info['password'], timeout=10)
        append_step(f"Created {CSC_REMOTE_DIR}", 20)

        # 3. Upload .deb via SFTP (preserve original filename)
        sftp = ssh.open_sftp()
        try:
            temp_deb = f"/tmp/csc_deb_{int(time.time())}.deb"
            sftp.put(local_deb, temp_deb)
        finally:
            sftp.close()
        remote_deb_name = deb_filename
        _csc_sudo_exec(ssh, f"sudo -S mv {temp_deb} {CSC_REMOTE_DIR}/{remote_deb_name}", conn_info['password'], timeout=15)
        append_step(f"Uploaded {remote_deb_name} to server.", 30)

        # 4. Write Dockerfile
        sftp = ssh.open_sftp()
        try:
            tmp_dockerfile = f"/tmp/csc_Dockerfile_{int(time.time())}"
            with sftp.file(tmp_dockerfile, 'w') as f:
                f.write(CSC_DOCKERFILE_TEMPLATE)
        finally:
            sftp.close()
        _csc_sudo_exec(ssh, f"sudo -S mv {tmp_dockerfile} {CSC_REMOTE_DIR}/Dockerfile", conn_info['password'], timeout=10)
        append_step("Wrote Dockerfile.", 40)

        # 5. Write entry.sh
        sftp = ssh.open_sftp()
        try:
            tmp_entry = f"/tmp/csc_entry_{int(time.time())}.sh"
            with sftp.file(tmp_entry, 'w') as f:
                f.write(CSC_ENTRY_SH)
        finally:
            sftp.close()
        _csc_sudo_exec(ssh, f"sudo -S mv {tmp_entry} {CSC_REMOTE_DIR}/entry.sh", conn_info['password'], timeout=10)
        _csc_sudo_exec(ssh, f"sudo -S chmod +x {CSC_REMOTE_DIR}/entry.sh", conn_info['password'], timeout=10)
        append_step("Wrote entry.sh.", 50)

        # 6. Configure Docker daemon proxy if provided
        has_proxy = request.http_proxy or request.https_proxy
        daemon_env = ""
        if has_proxy:
            env_lines = []
            if request.http_proxy:
                env_lines.append(f'"HTTP_PROXY={request.http_proxy}" "http_proxy={request.http_proxy}"')
            if request.https_proxy:
                env_lines.append(f'"HTTPS_PROXY={request.https_proxy}" "https_proxy={request.https_proxy}"')
            if request.no_proxy:
                env_lines.append(f'"NO_PROXY={request.no_proxy}" "no_proxy={request.no_proxy}"')
            proxy_conf = "[Service]\nEnvironment=" + " ".join(env_lines) + "\n"
            # Write via SFTP to /tmp then sudo mv (avoids shell escaping issues)
            tmp_proxy = f"/tmp/csc_docker_proxy_{int(time.time())}.conf"
            sftp = ssh.open_sftp()
            try:
                with sftp.file(tmp_proxy, 'w') as f:
                    f.write(proxy_conf)
            finally:
                sftp.close()
            _csc_sudo_exec(ssh, "sudo -S mkdir -p /etc/systemd/system/docker.service.d", conn_info['password'], timeout=10)
            _csc_sudo_exec(ssh, f"sudo -S mv {tmp_proxy} /etc/systemd/system/docker.service.d/http-proxy.conf", conn_info['password'], timeout=10)
            reload_out, reload_err, reload_status = _csc_sudo_exec(ssh, "sudo -S systemctl daemon-reload", conn_info['password'], timeout=15)
            if reload_status != 0:
                reload_output = (reload_out + '\n' + reload_err).strip()
                return fail(f"Failed to reload systemd after writing Docker proxy configuration.\n{reload_output[-1000:]}")
            restart_out, restart_err, restart_status = _csc_sudo_exec(ssh, "sudo -S systemctl restart docker", conn_info['password'], timeout=30)
            if restart_status != 0:
                restart_output = (restart_out + '\n' + restart_err).strip()
                return fail(f"Failed to restart Docker after writing proxy configuration.\n{restart_output[-1000:]}")
            verify_out, verify_err, verify_status = _csc_sudo_exec(ssh, "sudo -S systemctl show docker --property=Environment --no-pager", conn_info['password'], timeout=15)
            daemon_env = (verify_out + '\n' + verify_err).strip()
            append_step("Configured Docker daemon proxy settings.", 60)
            if verify_status == 0 and ("HTTP_PROXY=" in daemon_env or "HTTPS_PROXY=" in daemon_env):
                append_step("Verified Docker daemon proxy environment.", 65)
            else:
                append_step("Warning: Docker daemon proxy environment could not be verified.", 65, "warning")

        # 7. Pull base image before build
        append_step("Pulling ubuntu:22.04 base image...", 75)
        pull_out, pull_err, pull_status = _csc_sudo_exec(ssh, "sudo -S docker pull ubuntu:22.04", conn_info['password'], timeout=180)
        if pull_status != 0:
            pull_output = (pull_out + '\n' + pull_err).strip()
            proxy_hint = " Verify the Proxy Settings values and ensure the Docker daemon can reach Docker Hub through that proxy." if has_proxy else " If this server requires a proxy, fill in Proxy Settings and retry."
            detail = pull_output[-1000:]
            if daemon_env:
                detail = f"Docker daemon environment: {daemon_env[-400:]}\n\n{detail}"
            return fail(f"Failed to pull base image ubuntu:22.04 from Docker Hub.{proxy_hint}\n{detail}")
        append_step("Pulled ubuntu:22.04 base image.", 85)

        # 8. Build Docker image
        image_tag = f"{CSC_IMAGE_NAME}:{deb_version}" if deb_version else CSC_IMAGE_NAME
        append_step(f"Building Docker image {image_tag} (this may take a few minutes)...", 90)
        build_cmd = f"sudo -S docker build -t {shlex.quote(image_tag)}"
        if deb_version:
            build_cmd += f" -t {shlex.quote(CSC_IMAGE_NAME)}:latest"
        build_cmd += f" --build-arg {shlex.quote(f'DEB_FILENAME={remote_deb_name}')}"
        if request.http_proxy:
            build_cmd += f" --build-arg {shlex.quote(f'http_proxy={request.http_proxy}')} --build-arg {shlex.quote(f'HTTP_PROXY={request.http_proxy}')}"
        if request.https_proxy:
            build_cmd += f" --build-arg {shlex.quote(f'https_proxy={request.https_proxy}')} --build-arg {shlex.quote(f'HTTPS_PROXY={request.https_proxy}')}"
        if request.no_proxy:
            build_cmd += f" --build-arg {shlex.quote(f'no_proxy={request.no_proxy}')} --build-arg {shlex.quote(f'NO_PROXY={request.no_proxy}')}"
        build_cmd += f" {shlex.quote(CSC_REMOTE_DIR)}"
        # Stream build output line-by-line so the frontend can show progress
        build_cmd_with_progress = f'{build_cmd} 2>&1'
        stdin_b, stdout_b, stderr_b = ssh.exec_command(build_cmd_with_progress, timeout=1200, get_pty=True)
        stdin_b.write(conn_info['password'] + '\n')
        stdin_b.flush()
        build_lines = []
        for raw_line in stdout_b:
            line = raw_line.rstrip('\n\r')
            # Skip sudo password echo and empty lines
            if not line or line.startswith('[sudo]') or line.startswith('sudo:') or conn_info['password'] in line:
                continue
            build_lines.append(line)
            logger.info(f"[docker build] {line}")
        status = stdout_b.channel.recv_exit_status()
        if status != 0:
            build_output = '\n'.join(build_lines[-50:])
            return fail(f"Docker build failed:\n{build_output[-1000:]}")
        append_step("Docker image built successfully.", 100)
        record_activity(username, "csc_install", {"ip": conn_info['ip']})
        _finish_user_operation(username, True, "Cisco Secure Client Docker image installed successfully")
        reset_progress(username)
        return {"success": True, "message": "Cisco Secure Client Docker image installed successfully", "steps": steps}
    except Exception as e:
        logger.error(f"CSC install error: {e}")
        try:
            if username:
                _finish_user_operation(username, False, str(e))
        except Exception:
            pass
        if username:
            reset_progress(username)
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})
    finally:
        try:
            if ssh:
                ssh.close()
        except Exception:
            pass


@app.post("/api/csc/install/cancel")
async def csc_install_cancel(http_request: Request):
    """Cancel a running CSC image build by killing docker build on the remote server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ctx = get_user_ctx(username)
        ctx["stop_requested"] = True
        # Try to kill docker build on remote server
        try:
            ssh = _csc_ssh_connect(conn_info)
            _csc_sudo_exec(ssh, "sudo -S pkill -f 'docker build' 2>/dev/null; sudo -S docker buildx stop 2>/dev/null", conn_info['password'], timeout=10)
            ssh.close()
        except Exception:
            pass
        _finish_user_operation(username, False, "Build cancelled by user")
        reset_progress(username)
        return {"success": True, "message": "Build cancel requested"}
    except Exception as e:
        logger.error(f"CSC install cancel error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/install/status")
async def csc_install_status(http_request: Request):
    """Check if Docker and CSC image are present on the server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)

        # Check Docker
        out, _, docker_status = _csc_sudo_exec(ssh, "docker --version", conn_info['password'], timeout=10)
        docker_installed = docker_status == 0
        docker_version = out.strip() if docker_installed else None

        # Check image — get all CSC images with repo, tag, size
        fmt = '{{.Repository}}\t{{.Tag}}\t{{.Size}}'
        out, _, img_status = _csc_sudo_exec(
            ssh,
            f'sudo -S docker images --format "{fmt}" {CSC_IMAGE_NAME}',
            conn_info['password'], timeout=10
        )
        images = []
        image_built = False
        image_info = None
        if img_status == 0 and out.strip():
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 3 and parts[1] != '<none>':
                    images.append({"repo": parts[0], "tag": parts[1], "size": parts[2]})
            image_built = len(images) > 0
            if image_built:
                first = images[0]
                image_info = f"{first['repo']}:{first['tag']} ({first['size']})"

        # Check .deb present on server (any .deb file)
        out, _, deb_status = _csc_sudo_exec(ssh, f"ls {CSC_REMOTE_DIR}/*.deb 2>/dev/null", conn_info['password'], timeout=10)
        deb_present = deb_status == 0 and '.deb' in out

        ssh.close()
        return {
            "success": True,
            "docker_installed": docker_installed,
            "docker_version": docker_version,
            "image_built": image_built,
            "image_info": image_info,
            "images": images,
            "deb_present": deb_present
        }
    except Exception as e:
        logger.error(f"CSC install status error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/deploy")
async def csc_deploy(request: CSCDeployRequest, http_request: Request):
    """Deploy N Cisco Secure Client containers."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)

        # Determine image to use (image_tag may be full repo:tag or just a tag)
        if request.image_tag and ':' in request.image_tag:
            image_ref = request.image_tag
        elif request.image_tag:
            image_ref = f"{CSC_IMAGE_NAME}:{request.image_tag}"
        else:
            image_ref = CSC_IMAGE_NAME

        # Verify image exists
        out, _, status = _csc_sudo_exec(ssh, f"sudo -S docker images -q {image_ref}", conn_info['password'], timeout=10)
        if status != 0 or not out.strip():
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"CSC Docker image '{image_ref}' not found. Please install first."})

        # Compute IPs for each container based on octet/hextet increment
        def increment_ipv4(start_ip, index, octet):
            """Increment the specified octet (1-4) of an IPv4 address by index."""
            parts = start_ip.split('.')
            if len(parts) != 4:
                return start_ip
            octet_idx = octet - 1  # 0-indexed
            parts[octet_idx] = str(int(parts[octet_idx]) + index)
            return '.'.join(parts)

        def increment_ipv6(start_ip, index, hextet):
            """Increment the specified hextet (1-8) of an IPv6 address by index."""
            import ipaddress
            try:
                addr = ipaddress.IPv6Address(start_ip)
                # Convert to 8 hextets
                full = addr.exploded.split(':')
                hextet_idx = hextet - 1  # 0-indexed
                full[hextet_idx] = format(int(full[hextet_idx], 16) + index, '04x')
                return ':'.join(full)
            except Exception:
                return start_ip

        # Determine container name prefix based on protocol
        proto = request.protocol or 'v4'
        name_prefix = f"{CSC_CONTAINER_PREFIX}{proto}_"

        # Find next available index for this protocol
        out_existing, _, _ = _csc_sudo_exec(
            ssh,
            f'sudo -S docker ps -a --filter "name={name_prefix}" --format "{{{{.Names}}}}"',
            conn_info['password'], timeout=10
        )
        existing_indices = set()
        if out_existing.strip():
            for n in out_existing.strip().split('\n'):
                n = n.strip()
                if n.startswith(name_prefix):
                    try:
                        existing_indices.add(int(n[len(name_prefix):]))
                    except ValueError:
                        pass
        next_idx = max(existing_indices) + 1 if existing_indices else 0

        # For IPv6 deploys: ensure Docker has IPv6 enabled and create IPv6 network
        if proto == 'v6':
            # Check if IPv6 is already configured in daemon.json
            check_out, _, _ = _csc_sudo_exec(
                ssh, "sudo -S grep -c ipv6 /etc/docker/daemon.json 2>/dev/null || echo 0",
                conn_info['password'], timeout=10
            )
            if check_out.strip() == '0' or 'No such file' in check_out:
                # Use python3 on the remote to write valid JSON (avoids shell quoting issues)
                _csc_sudo_exec(ssh,
                    "sudo -S python3 -c \""
                    "import json; "
                    "d={}; "
                    "try: d=json.load(open('/etc/docker/daemon.json'))\n"
                    "except: pass\n"
                    "d['ipv6']=True; d['fixed-cidr-v6']='fd00:dead:beef::/48'; "
                    "json.dump(d,open('/etc/docker/daemon.json','w'),indent=2)\"",
                    conn_info['password'], timeout=15
                )
                _csc_sudo_exec(ssh, "sudo -S systemctl restart docker", conn_info['password'], timeout=60)
                # Wait for Docker to be ready
                _csc_sudo_exec(ssh, "sudo -S bash -c 'for i in 1 2 3 4 5; do docker info >/dev/null 2>&1 && break; sleep 2; done'",
                    conn_info['password'], timeout=30)

            # Always ensure the IPv6 network exists (separate from daemon.json check)
            net_check, _, net_status = _csc_sudo_exec(
                ssh, "sudo -S docker network inspect csc_ipv6_net >/dev/null 2>&1 && echo EXISTS || echo MISSING",
                conn_info['password'], timeout=10
            )
            logger.info(f"CSC IPv6 network check: status={net_status}, output='{net_check.strip()}'")
            if 'EXISTS' not in net_check:
                # Check if Docker is running first
                docker_check, _, docker_st = _csc_sudo_exec(
                    ssh, "sudo -S docker info >/dev/null 2>&1 && echo DOCKER_OK || echo DOCKER_DOWN",
                    conn_info['password'], timeout=10
                )
                logger.info(f"CSC Docker status: {docker_check.strip()}")
                if 'DOCKER_OK' not in docker_check:
                    ssh.close()
                    return JSONResponse(status_code=500, content={
                        "success": False,
                        "message": "Docker is not running. Please check Docker service on the server."
                    })
                net_out, net_err, net_st = _csc_sudo_exec(
                    ssh,
                    "sudo -S docker network create --ipv6 --subnet fd00:c5c0::/80 csc_ipv6_net",
                    conn_info['password'], timeout=15
                )
                logger.info(f"CSC IPv6 network create: status={net_st}, out='{net_out.strip()}', err='{net_err.strip()}'")
                if net_st != 0:
                    # With get_pty=True, error goes to stdout not stderr
                    error_msg = net_out.strip() or net_err.strip() or 'Unknown error'
                    ssh.close()
                    return JSONResponse(status_code=500, content={
                        "success": False,
                        "message": f"Failed to create IPv6 Docker network: {error_msg[:300]}"
                    })

        created = []
        errors = []
        for i in range(request.count):
            idx = next_idx + i
            name = f"{name_prefix}{idx}"
            # Stop and remove existing container with same name
            _csc_sudo_exec(ssh, f"sudo -S docker rm -f {name} 2>/dev/null", conn_info['password'], timeout=10)

            # Credential incrementing: 1-based (admin1, admin2, ... adminN)
            vpn_user = f"{request.vpn_user}{i + 1}" if request.vpn_user_increment else request.vpn_user
            vpn_pass = f"{request.vpn_password}{i + 1}" if request.vpn_password_increment else request.vpn_password

            cert_val = "true" if request.allow_untrusted_cert else "false"
            conn_type = request.connection_type or "ssl"
            dtls_val = "true" if request.enable_dtls else "false"
            # Wrap IPv6 headend in brackets so CSC agent doesn't treat colons as URL port separator
            headend = request.headend
            if ':' in headend and not headend.startswith('['):
                headend = f'[{headend}]'
            env_args = f'-e VPN_SERVER="{headend}" -e VPN_USER="{vpn_user}" -e VPN_PASSWORD="{vpn_pass}"'
            env_args += f' -e ACCEPT_UNTRUSTED_CERT="{cert_val}"'
            env_args += f' -e CONNECTION_TYPE="{conn_type}"'
            env_args += f' -e ENABLE_DTLS="{dtls_val}"'
            pqc_val = "true" if request.enable_pqc else "false"
            env_args += f' -e ENABLE_PQC="{pqc_val}"'
            if request.vpn_group:
                env_args += f' -e VPN_GROUP="{request.vpn_group}"'

            # Add computed local IPs based on protocol
            if proto == 'v4' and request.local_ipv4_start:
                ipv4 = increment_ipv4(request.local_ipv4_start, i, request.ipv4_increment_octet or 4)
                env_args += f' -e LOCAL_IPV4="{ipv4}"'
            if proto == 'v6' and request.local_ipv6_start:
                ipv6 = increment_ipv6(request.local_ipv6_start, i, request.ipv6_increment_hextet or 8)
                env_args += f' -e LOCAL_IPV6="{ipv6}"'
            # For IPv6 containers: use IPv6-enabled network and enable IPv6 sysctls
            network_args = ''
            if proto == 'v6':
                network_args = '--network csc_ipv6_net --sysctl net.ipv6.conf.all.disable_ipv6=0 '

            run_cmd = (
                f"sudo -S docker run -d --name {name} --cap-add NET_ADMIN --device /dev/net/tun "
                f"{network_args}{env_args} {image_ref}"
            )
            out, err_out, status = _csc_sudo_exec(ssh, run_cmd, conn_info['password'], timeout=30)
            if status == 0:
                created.append({"name": name, "id": out.strip()[:12]})
            else:
                errors.append({"name": name, "error": err_out[:200]})

        ssh.close()
        record_activity(username, "csc_deploy", {"count": request.count, "headend": request.headend, "created": len(created), "errors": len(errors)})
        return {"success": True, "created": created, "errors": errors, "message": f"Deployed {len(created)}/{request.count} containers"}
    except Exception as e:
        logger.error(f"CSC deploy error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/resources")
async def csc_resources(http_request: Request):
    """Get server and container resource utilization."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)

        # Server CPU usage (percentage used)
        out_cpu, _, _ = _csc_sudo_exec(ssh, "top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'", conn_info['password'], timeout=10)
        server_cpu = out_cpu.strip() + '%' if out_cpu.strip() else '--'

        # Server RAM (used/total)
        out_ram, _, _ = _csc_sudo_exec(ssh, "free -m | awk '/^Mem:/{printf \"%dMB / %dMB (%.0f%%)\", $3, $2, $3/$2*100}'", conn_info['password'], timeout=10)
        server_ram = out_ram.strip() if out_ram.strip() else '--'

        # Parse total RAM in MB for recommendation
        total_ram_mb = 0
        used_ram_mb = 0
        out_ram_raw, _, _ = _csc_sudo_exec(ssh, "free -m | awk '/^Mem:/{print $2, $3}'", conn_info['password'], timeout=10)
        if out_ram_raw.strip():
            ram_parts = out_ram_raw.strip().split()
            if len(ram_parts) >= 2:
                total_ram_mb = int(ram_parts[0])
                used_ram_mb = int(ram_parts[1])

        # Server Disk
        out_disk, _, _ = _csc_sudo_exec(ssh, "df -h / | awk 'NR==2{printf \"%s / %s (%s)\", $3, $2, $5}'", conn_info['password'], timeout=10)
        server_disk = out_disk.strip() if out_disk.strip() else '--'

        # CPU cores
        out_cores, _, _ = _csc_sudo_exec(ssh, "nproc", conn_info['password'], timeout=10)
        cpu_cores = int(out_cores.strip()) if out_cores.strip().isdigit() else 1

        # Get running CSC container names first, then pass to docker stats
        out_names, _, names_status = _csc_sudo_exec(
            ssh,
            f'sudo -S docker ps --filter "name={CSC_CONTAINER_PREFIX}" --filter "status=running" --format "{{{{.Names}}}}"',
            conn_info['password'], timeout=10
        )
        container_names = out_names.strip().split('\n') if names_status == 0 and out_names.strip() else []

        out_stats = ''
        stats_status = 1
        if container_names:
            names_arg = ' '.join(container_names)
            out_stats, _, stats_status = _csc_sudo_exec(
                ssh,
                f'sudo -S docker stats --no-stream --format "{{{{.CPUPerc}}}}\\t{{{{.MemUsage}}}}" {names_arg}',
                conn_info['password'], timeout=30
            )

        container_cpu_total = 0.0
        container_ram_total_mb = 0.0
        container_count = 0
        if stats_status == 0 and out_stats.strip():
            for line in out_stats.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    try:
                        cpu_val = float(parts[0].replace('%', ''))
                        container_cpu_total += cpu_val
                    except ValueError:
                        pass
                    try:
                        mem_str = parts[1].split('/')[0].strip()
                        if 'GiB' in mem_str:
                            container_ram_total_mb += float(mem_str.replace('GiB', '').strip()) * 1024
                        elif 'MiB' in mem_str:
                            container_ram_total_mb += float(mem_str.replace('MiB', '').strip())
                        elif 'KiB' in mem_str:
                            container_ram_total_mb += float(mem_str.replace('KiB', '').strip()) / 1024
                    except ValueError:
                        pass
                    container_count += 1

        container_cpu = f"{container_cpu_total:.1f}%"
        if container_ram_total_mb >= 1024:
            container_ram = f"{container_ram_total_mb/1024:.1f}GB"
        else:
            container_ram = f"{container_ram_total_mb:.0f}MB"
        container_avg = '--'
        if container_count > 0:
            avg_cpu = container_cpu_total / container_count
            avg_ram = container_ram_total_mb / container_count
            container_avg = f"{avg_cpu:.1f}% CPU, {avg_ram:.0f}MB RAM"

        # Recommendation: use multiple constraints and take the minimum
        # Each VPN container uses TUN devices, kernel resources, file descriptors, etc.
        # so pure RAM-based calculation is far too optimistic.
        recommended = '--'
        if container_count > 0 and total_ram_mb > 0:
            avg_ram_per = container_ram_total_mb / container_count
            avg_cpu_per = container_cpu_total / container_count
            # RAM constraint: leave 50% headroom for system + Docker overhead
            system_ram = used_ram_mb - container_ram_total_mb
            ram_budget = total_ram_mb * 0.5 - system_ram
            ram_limit = int(ram_budget / max(avg_ram_per, 50)) if avg_ram_per > 0 else 0
            # CPU constraint: max 80% total CPU utilization across all cores
            cpu_budget = cpu_cores * 80  # 80% per core
            cpu_limit = int(cpu_budget / max(avg_cpu_per, 0.5)) if avg_cpu_per > 0 else ram_limit
            # Kernel/FD constraint: each VPN container needs TUN devices, ~50 FDs, network namespaces
            # Empirical safe limit is roughly 15 per CPU core for VPN containers
            kernel_limit = cpu_cores * 15
            recommended = max(1, min(ram_limit, cpu_limit, kernel_limit))
        elif total_ram_mb > 0:
            # No containers running yet, conservative estimate
            available_ram = total_ram_mb * 0.5 - used_ram_mb
            ram_est = max(1, int(available_ram / 150))
            kernel_limit = cpu_cores * 15
            recommended = max(1, min(ram_est, kernel_limit))

        ssh.close()
        return {
            "success": True,
            "server_cpu": server_cpu,
            "server_ram": server_ram,
            "server_disk": server_disk,
            "cpu_cores": cpu_cores,
            "container_cpu": container_cpu,
            "container_ram": container_ram,
            "container_avg": container_avg,
            "container_count": container_count,
            "recommended_count": recommended
        }
    except Exception as e:
        logger.error(f"CSC resources error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/containers")
async def csc_containers(http_request: Request):
    """List all CSC containers with status."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)
        fmt = '{{.ID}}\\t{{.Names}}\\t{{.Status}}\\t{{.State}}'
        out, _, status = _csc_sudo_exec(
            ssh,
            f'sudo -S docker ps -a --filter "name={CSC_CONTAINER_PREFIX}" --format "{fmt}"',
            conn_info['password'], timeout=15
        )
        ssh.close()

        containers = []
        if out.strip():
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 4:
                    raw_state = parts[3].strip().lower()
                    # Normalise: 'created' and 'restarting' are transient, not errors
                    if raw_state in ('running', 'restarting', 'created'):
                        norm_state = 'running'
                    elif raw_state in ('exited', 'paused'):
                        norm_state = 'exited'
                    else:
                        norm_state = raw_state  # dead, removing → error
                    containers.append({
                        "id": parts[0],
                        "name": parts[1],
                        "status": parts[2],
                        "state": norm_state
                    })
        running = sum(1 for c in containers if c['state'] == 'running')
        stopped = sum(1 for c in containers if c['state'] == 'exited')
        error_count = sum(1 for c in containers if c['state'] not in ('running', 'exited'))
        return {"success": True, "containers": containers, "running": running, "stopped": stopped, "error": error_count, "total": len(containers)}
    except Exception as e:
        logger.error(f"CSC containers list error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/vpn-sessions")
async def csc_vpn_sessions(http_request: Request):
    """Get VPN session status from all running CSC containers for tunnel summary."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)

        # Get running container names
        fmt = '{{.Names}}\\t{{.State}}'
        out, _, status = _csc_sudo_exec(
            ssh,
            f'sudo -S docker ps -a --filter "name={CSC_CONTAINER_PREFIX}" --format "{fmt}"',
            conn_info['password'], timeout=15
        )

        tunnels = []
        if out.strip():
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                name = parts[0].strip()
                state = parts[1].strip().lower()

                # Determine protocol from container name
                vpn_proto = 'IPv4' if 'v4' in name else ('IPv6' if 'v6' in name else 'Unknown')

                if state != 'running':
                    tunnels.append({
                        "name": name,
                        "vpn_type": "ravpn",
                        "ike_state": "INACTIVE",
                        "ipsec_state": "INACTIVE",
                        "is_inactive": True,
                        "local_name": name,
                        "remote_name": "-",
                        "protocol": vpn_proto,
                    })
                    continue

                # Get VPN connection status from container logs (last 50 lines)
                log_out, _, _ = _csc_sudo_exec(
                    ssh,
                    f'sudo -S docker logs --tail 50 {name} 2>&1',
                    conn_info['password'], timeout=10
                )
                logs = log_out or ''

                # Parse connection status from logs
                connected = False
                vpn_server = ''
                vpn_user = ''
                tunnel_ip = ''
                dtls_status = ''

                for log_line in logs.split('\n'):
                    ll = log_line.strip().lower()
                    if 'vpn connected' in ll or 'state: connected' in ll or 'tunnel established' in ll:
                        connected = True
                    elif 'vpn disconnected' in ll or 'state: disconnected' in ll or 'connection terminated' in ll:
                        connected = False
                    if 'vpn_server=' in log_line or 'VPN_SERVER=' in log_line:
                        try:
                            vpn_server = log_line.split('=', 1)[1].strip().strip('"')
                        except Exception:
                            pass
                    if 'assigned address' in ll or 'tunnel ip' in ll:
                        # Try to extract IP from the line
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)', log_line.split('address')[-1] if 'address' in log_line else log_line)
                        if ip_match:
                            tunnel_ip = ip_match.group(1)
                    if 'dtls' in ll:
                        if 'dtls connected' in ll or 'dtls established' in ll:
                            dtls_status = 'DTLS'

                # Also try docker inspect for env vars
                env_out, _, _ = _csc_sudo_exec(
                    ssh,
                    f'sudo -S docker inspect --format "{{{{range .Config.Env}}}}{{{{println .}}}}{{{{end}}}}" {name}',
                    conn_info['password'], timeout=10
                )
                for env_line in (env_out or '').split('\n'):
                    if env_line.startswith('VPN_SERVER='):
                        vpn_server = env_line.split('=', 1)[1].strip()
                    elif env_line.startswith('VPN_USER='):
                        vpn_user = env_line.split('=', 1)[1].strip()

                tunnels.append({
                    "name": name,
                    "vpn_type": "ravpn",
                    "ike_state": "ESTABLISHED" if connected else "CONNECTING",
                    "ipsec_state": "INSTALLED" if connected else "CREATED",
                    "is_inactive": not connected and state != 'running',
                    "local_name": name,
                    "remote_name": vpn_server or '-',
                    "local_addr": tunnel_ip,
                    "remote_addr": vpn_server,
                    "protocol": vpn_proto,
                    "vpn_user": vpn_user,
                    "dtls": dtls_status,
                    "container_state": state,
                })

        ssh.close()
        return {"success": True, "tunnels": tunnels, "total": len(tunnels)}
    except Exception as e:
        logger.error(f"CSC VPN sessions error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/containers/stop")
async def csc_container_stop(request: CSCContainerActionRequest, http_request: Request):
    """Stop a specific CSC container."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        if not request.container_id:
            return JSONResponse(status_code=400, content={"success": False, "message": "container_id required"})

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(ssh, f"sudo -S docker stop {request.container_id}", conn_info['password'], timeout=30)
        ssh.close()
        if status == 0:
            return {"success": True, "message": f"Stopped {request.container_id}"}
        return JSONResponse(status_code=400, content={"success": False, "message": f"Stop failed: {err_out[:300]}"})
    except Exception as e:
        logger.error(f"CSC container stop error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/containers/restart")
async def csc_container_restart(request: CSCContainerActionRequest, http_request: Request):
    """Restart a specific CSC container."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        if not request.container_id:
            return JSONResponse(status_code=400, content={"success": False, "message": "container_id required"})

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(ssh, f"sudo -S docker restart {request.container_id}", conn_info['password'], timeout=30)
        ssh.close()
        if status == 0:
            return {"success": True, "message": f"Restarted {request.container_id}"}
        return JSONResponse(status_code=400, content={"success": False, "message": f"Restart failed: {err_out[:300]}"})
    except Exception as e:
        logger.error(f"CSC container restart error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/containers/stop-all")
async def csc_containers_stop_all(http_request: Request):
    """Stop all CSC containers, optionally filtered by protocol."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        body = {}
        try:
            body = await http_request.json()
        except Exception:
            pass
        proto = body.get('protocol')
        name_filter = f"{CSC_CONTAINER_PREFIX}{proto}_" if proto else CSC_CONTAINER_PREFIX

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(
            ssh,
            f'sudo -S bash -c \'ids=$(docker ps -q --filter "name={name_filter}"); if [ -n "$ids" ]; then docker stop -t 2 $ids; echo "STOPPED:$(echo $ids | wc -w)"; else echo "STOPPED:0"; fi\'',
            conn_info['password'], timeout=120
        )
        ssh.close()
        stopped = 0
        for line in out.split('\n'):
            if line.strip().startswith('STOPPED:'):
                try:
                    stopped = int(line.strip().split(':')[1])
                except (ValueError, IndexError):
                    pass
        label = f"{proto.upper()} " if proto else ""
        return {"success": True, "message": f"Stopped {stopped} {label}containers", "stopped": stopped}
    except Exception as e:
        logger.error(f"CSC stop all error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/containers/restart-all")
async def csc_containers_restart_all(http_request: Request):
    """Restart all CSC containers, optionally filtered by protocol."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        body = {}
        try:
            body = await http_request.json()
        except Exception:
            pass
        proto = body.get('protocol')
        name_filter = f"{CSC_CONTAINER_PREFIX}{proto}_" if proto else CSC_CONTAINER_PREFIX

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(
            ssh,
            f'sudo -S bash -c \'ids=$(docker ps -a -q --filter "name={name_filter}"); if [ -n "$ids" ]; then docker restart -t 2 $ids; echo "RESTARTED:$(echo $ids | wc -w)"; else echo "RESTARTED:0"; fi\'',
            conn_info['password'], timeout=120
        )
        ssh.close()
        restarted = 0
        for line in out.split('\n'):
            if line.strip().startswith('RESTARTED:'):
                try:
                    restarted = int(line.strip().split(':')[1])
                except (ValueError, IndexError):
                    pass
        label = f"{proto.upper()} " if proto else ""
        return {"success": True, "message": f"Restarted {restarted} {label}containers", "restarted": restarted}
    except Exception as e:
        logger.error(f"CSC restart all error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/containers/delete-all")
async def csc_containers_delete_all(http_request: Request):
    """Stop and remove all CSC containers, optionally filtered by protocol."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        body = {}
        try:
            body = await http_request.json()
        except Exception:
            pass
        proto = body.get('protocol')
        name_filter = f"{CSC_CONTAINER_PREFIX}{proto}_" if proto else CSC_CONTAINER_PREFIX

        ssh = _csc_ssh_connect(conn_info)
        # Get running container names to disconnect VPN sessions before deletion
        names_out, _, _ = _csc_sudo_exec(
            ssh,
            f'sudo -S docker ps -q --filter "name={name_filter}" --filter "status=running"',
            conn_info['password'], timeout=10
        )
        running_ids = [cid.strip() for cid in names_out.strip().split('\n') if cid.strip()]
        for cid in running_ids:
            _csc_sudo_exec(
                ssh,
                f'sudo -S docker exec {cid} /opt/cisco/secureclient/bin/vpn disconnect 2>/dev/null || true',
                conn_info['password'], timeout=10
            )
        # Now remove all containers (running + stopped)
        out, err_out, status = _csc_sudo_exec(
            ssh,
            f'sudo -S bash -c \'ids=$(docker ps -a -q --filter "name={name_filter}"); if [ -n "$ids" ]; then docker rm -f $ids; echo "DELETED:$(echo $ids | wc -w)"; else echo "DELETED:0"; fi\'',
            conn_info['password'], timeout=120
        )
        ssh.close()
        deleted = 0
        for line in out.split('\n'):
            if line.strip().startswith('DELETED:'):
                try:
                    deleted = int(line.strip().split(':')[1])
                except (ValueError, IndexError):
                    pass
        label = f"{proto.upper()} " if proto else ""
        return {"success": True, "message": f"Deleted {deleted} {label}containers", "deleted": deleted}
    except Exception as e:
        logger.error(f"CSC delete all error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/containers/{container_id}/logs")
async def csc_container_logs(container_id: str, http_request: Request):
    """Get logs for a specific CSC container."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(ssh, f"sudo -S docker logs --tail 200 {container_id}", conn_info['password'], timeout=15)
        ssh.close()
        return {"success": True, "logs": out, "container_id": container_id}
    except Exception as e:
        logger.error(f"CSC container logs error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/config-files")
async def csc_list_config_files(http_request: Request):
    """List host-side config files from /opt/cisco-secure-client-docker/."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)
        out, _, status = _csc_sudo_exec(ssh, f"sudo -S ls -la {CSC_REMOTE_DIR}/ 2>/dev/null", conn_info['password'], timeout=10)
        ssh.close()

        files = []
        if out.strip():
            for line in out.strip().split('\n'):
                if line.startswith('total') or line.startswith('d'):
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    size = int(parts[4]) if parts[4].isdigit() else 0
                    fname = parts[-1]
                    files.append({"name": fname, "size": size})
        return {"success": True, "files": files}
    except Exception as e:
        logger.error(f"CSC config files list error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/config-file")
async def csc_read_config_file(filename: str, http_request: Request):
    """Read a host-side config file."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(ssh, f'sudo -S cat "{CSC_REMOTE_DIR}/{filename}"', conn_info['password'], timeout=15)
        ssh.close()
        if status != 0:
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to read file: {err_out[:300]}"})
        return {"success": True, "content": out, "filename": filename}
    except Exception as e:
        logger.error(f"CSC config file read error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/config-file-save")
async def csc_save_config_file(request: CSCConfigFileSaveRequest, http_request: Request):
    """Save a host-side config file."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})

        ssh = _csc_ssh_connect(conn_info)
        sftp = ssh.open_sftp()
        try:
            temp_path = f"/tmp/csc_config_{int(time.time())}_{filename}"
            normalized = request.content.replace('\r\n', '\n').replace('\r', '\n')
            with sftp.file(temp_path, 'w') as f:
                f.write(normalized)
        finally:
            sftp.close()

        _csc_sudo_exec(ssh, f'sudo -S mv "{temp_path}" "{CSC_REMOTE_DIR}/{filename}"', conn_info['password'], timeout=15)
        _csc_sudo_exec(ssh, f'sudo -S chmod 644 "{CSC_REMOTE_DIR}/{filename}"', conn_info['password'], timeout=10)
        ssh.close()
        logger.info(f"CSC config file {filename} saved by {username}")
        return {"success": True, "message": f"Saved {filename}"}
    except Exception as e:
        logger.error(f"CSC config file save error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/image/delete")
async def csc_delete_image(request: CSCImageDeleteRequest, http_request: Request):
    """Delete a Docker image from the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        image_name = request.image.strip()
        if not image_name or any(c in image_name for c in [';', '&', '|', '$', '`', '\n']):
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid image name"})

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(
            ssh, f'sudo -S docker rmi {shlex.quote(image_name)}', conn_info['password'], timeout=30
        )
        ssh.close()
        if status != 0:
            detail = (out + '\n' + err_out).strip()
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to delete image: {detail[-500:]}"})
        logger.info(f"CSC image {image_name} deleted by {username}")
        record_activity(username, "csc_image_delete", {"image": image_name, "ip": conn_info['ip']})
        return {"success": True, "message": f"Image {image_name} deleted"}
    except Exception as e:
        logger.error(f"CSC image delete error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/config-file/delete")
async def csc_delete_config_file(request: CSCConfigFileDeleteRequest, http_request: Request):
    """Delete a config file from /opt/cisco-secure-client-docker/ on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        filename = request.filename.strip()
        if not filename or '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})

        protected = {'Dockerfile', 'entry.sh'}
        if filename in protected:
            return JSONResponse(status_code=400, content={"success": False, "message": f"Cannot delete protected file: {filename}"})

        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(
            ssh, f'sudo -S rm -f "{CSC_REMOTE_DIR}/{filename}"', conn_info['password'], timeout=10
        )
        ssh.close()
        if status != 0:
            detail = (out + '\n' + err_out).strip()
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to delete file: {detail[-500:]}"})
        logger.info(f"CSC config file {filename} deleted by {username}")
        record_activity(username, "csc_config_file_delete", {"filename": filename, "ip": conn_info['ip']})
        return {"success": True, "message": f"File {filename} deleted"}
    except Exception as e:
        logger.error(f"CSC config file delete error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/container-config")
async def csc_container_config(container_id: str, http_request: Request):
    """Read Secure Client config from inside a running container."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err

        ssh = _csc_ssh_connect(conn_info)
        # Only show relevant config files with descriptions
        config_files = [
            {
                "path": "/opt/cisco/secureclient/AnyConnectLocalPolicy.xml",
                "description": "Controls client-side security policies (e.g. BlockUntrustedServers, FIPS mode)"
            },
            {
                "path": "/opt/cisco/secureclient/vpn/profile/csc_profile.xml",
                "description": "AnyConnect client profile — defines connection type (SSL/IPSec), server list, and client preferences"
            },
        ]

        configs = []
        for cf in config_files:
            content_out, _, s = _csc_sudo_exec(
                ssh,
                f'sudo -S docker exec {container_id} cat "{cf["path"]}" 2>/dev/null',
                conn_info['password'], timeout=10
            )
            if s == 0 and content_out.strip():
                configs.append({"path": cf["path"], "content": content_out, "description": cf["description"]})

        ssh.close()
        return {"success": True, "container_id": container_id, "configs": configs}
    except Exception as e:
        logger.error(f"CSC container config error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ============================================================================
# CSC: Install Docker Only
# ============================================================================

@app.post("/api/csc/install-docker")
async def csc_install_docker(http_request: Request):
    """Install Docker on the CSC server without building any image."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ssh = _csc_ssh_connect(conn_info)
        out, err_out, status = _csc_sudo_exec(ssh, "which docker", conn_info['password'], timeout=10)
        if status == 0:
            version_out, _, _ = _csc_sudo_exec(ssh, "docker --version", conn_info['password'], timeout=10)
            ssh.close()
            return {"success": True, "message": f"Docker already installed: {version_out.strip()}"}

        # Step 1: apt-get update (non-fatal — may return non-zero due to repo warnings)
        out, err_out, status = _csc_sudo_exec(ssh, "sudo -S DEBIAN_FRONTEND=noninteractive apt-get update", conn_info['password'], timeout=120)
        if status != 0:
            logger.warning(f"CSC apt-get update returned non-zero ({status}), continuing with install anyway")

        # Step 2: install docker.io
        out, err_out, status = _csc_sudo_exec(ssh, "sudo -S DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io", conn_info['password'], timeout=180)
        if status != 0:
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to install Docker: {(out + err_out)[:500]}"})

        # Step 3: enable and start
        _csc_sudo_exec(ssh, "sudo -S systemctl enable --now docker", conn_info['password'], timeout=30)

        version_out, _, _ = _csc_sudo_exec(ssh, "docker --version", conn_info['password'], timeout=10)
        ssh.close()
        record_activity(username, "csc_install_docker", {"ip": conn_info['ip']})
        return {"success": True, "message": f"Docker installed: {version_out.strip()}"}
    except Exception as e:
        logger.error(f"CSC install Docker error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ============================================================================
# CSC: Netplan Endpoints
# ============================================================================

@app.get("/api/csc/netplan/files")
async def csc_netplan_list_files(http_request: Request):
    """List netplan configuration files from /etc/netplan/ on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ssh = _csc_ssh_connect(conn_info)
        list_cmd = "ls -la /etc/netplan/*.yaml /etc/netplan/*.yml /etc/netplan/.*.yaml /etc/netplan/.*.yml 2>/dev/null || ls -la /etc/netplan/ 2>/dev/null"
        out, _, status = _csc_sudo_exec(ssh, list_cmd, conn_info['password'], timeout=15)
        ssh.close()
        files = []
        seen = set()
        for line in out.strip().split('\n'):
            if not line or line.startswith('total'):
                continue
            parts = line.split()
            if len(parts) >= 9:
                size = int(parts[4]) if parts[4].isdigit() else 0
                filepath = parts[-1]
                filename = os.path.basename(filepath)
                if (filename.endswith('.yaml') or filename.endswith('.yml')) and filename not in seen:
                    seen.add(filename)
                    files.append({"name": filename, "size": size})
        return {"success": True, "files": files}
    except Exception as e:
        logger.error(f"CSC netplan list files error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/netplan/file-content")
async def csc_netplan_get_file_content(request: NetplanFileRequest, http_request: Request):
    """Get the content of a specific netplan file on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        ssh = _csc_ssh_connect(conn_info)
        output, error, exit_status = _csc_sudo_exec(ssh, f'sudo -S cat "/etc/netplan/{filename}"', conn_info['password'])
        ssh.close()
        if 'No such file' in error or 'Permission denied' in error:
            return JSONResponse(status_code=404, content={"success": False, "message": f"File not found or access denied: {filename}"})
        return {"success": True, "content": output, "filename": filename}
    except Exception as e:
        logger.error(f"CSC netplan get file content error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/netplan/file-save")
async def csc_netplan_save_file(request: NetplanFileSaveRequest, http_request: Request):
    """Save (create or update) a netplan configuration file on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        if not filename.endswith('.yaml') and not filename.endswith('.yml'):
            return JSONResponse(status_code=400, content={"success": False, "message": "Filename must end with .yaml or .yml"})
        ssh = _csc_ssh_connect(conn_info)
        sftp = ssh.open_sftp()
        temp_path = f"/tmp/netplan_temp_{filename}"
        normalized_content = request.content.replace('\r\n', '\n').replace('\r', '\n')
        with sftp.file(temp_path, 'w') as f:
            f.write(normalized_content)
        sftp.close()
        _, error, exit_status = _csc_sudo_exec(ssh, f'sudo -S mv "{temp_path}" "/etc/netplan/{filename}"', conn_info['password'])
        if exit_status != 0:
            ssh.close()
            return JSONResponse(status_code=400, content={"success": False, "message": f"Failed to save file: {error}"})
        _csc_sudo_exec(ssh, f'sudo -S chown root:root "/etc/netplan/{filename}"', conn_info['password'])
        _csc_sudo_exec(ssh, f'sudo -S chmod 600 "/etc/netplan/{filename}"', conn_info['password'])
        ssh.close()
        logger.info(f"CSC netplan file {filename} saved by {username}")
        record_activity(username, "csc_netplan_file_save", {"filename": filename})
        return {"success": True, "message": f"File {filename} saved successfully"}
    except Exception as e:
        logger.error(f"CSC netplan save file error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/netplan/apply")
async def csc_netplan_apply(http_request: Request):
    """Execute 'netplan apply' on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ssh = _csc_ssh_connect(conn_info)
        output, error, exit_status = _csc_sudo_exec(ssh, 'sudo -S netplan apply 2>&1', conn_info['password'], timeout=60)
        ssh.close()
        logger.info(f"CSC netplan apply executed by {username}, exit={exit_status}")
        record_activity(username, "csc_netplan_apply", {"exit_status": exit_status})
        return {
            "success": exit_status == 0,
            "output": output or error or "(no output)",
            "message": "Netplan applied successfully" if exit_status == 0 else f"Netplan apply failed (exit {exit_status})"
        }
    except Exception as e:
        logger.error(f"CSC netplan apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/csc/netplan/routes")
async def csc_netplan_show_routes(http_request: Request):
    """Execute 'route -n' on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ssh = _csc_ssh_connect(conn_info)
        output, error, exit_status = _csc_sudo_exec(ssh, 'route -n 2>&1', conn_info['password'])
        ssh.close()
        return {"success": exit_status == 0, "output": output or error or "(no output)"}
    except Exception as e:
        logger.error(f"CSC show routes error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ============================================================================
# CSC: Traffic Control Endpoints
# ============================================================================

@app.get("/api/csc/tc/show")
async def csc_tc_show(http_request: Request):
    """Show current tc configuration on all interfaces of the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ssh = _csc_ssh_connect(conn_info)
        output, error, exit_status = _csc_sudo_exec(ssh, 'sudo -S bash -c \'tc qdisc show | grep -Ev "fq_codel|noqueue|mq"\' 2>&1', conn_info['password'])
        ssh.close()
        return {"success": True, "output": output or "(no non-default tc rules found)"}
    except Exception as e:
        logger.error(f"CSC TC show error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/tc/apply")
async def csc_tc_apply(request: TcCommandRequest, http_request: Request):
    """Apply tc commands on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        raw_input = request.command.strip()
        commands = [c.strip() for c in raw_input.split('\n') if c.strip()]
        if not commands:
            return JSONResponse(status_code=400, content={"success": False, "message": "No commands provided"})
        for cmd in commands:
            if not cmd.startswith('tc '):
                return JSONResponse(status_code=400, content={"success": False, "message": f"Every line must start with 'tc ': {cmd}"})
            for bad in [';', '&&', '||', '|', '`', '$(', '>', '<']:
                if bad in cmd:
                    return JSONResponse(status_code=400, content={"success": False, "message": f"Invalid character in command: {bad}"})
        ssh = _csc_ssh_connect(conn_info)
        all_output = []
        all_success = True
        for cmd in commands:
            output, error, exit_status = _csc_sudo_exec(ssh, f'sudo -S {cmd} 2>&1', conn_info['password'])
            result_line = f"$ {cmd}\n{output or error or '(ok)'}" if exit_status == 0 else f"$ {cmd}\nFAILED: {output or error}"
            all_output.append(result_line)
            if exit_status != 0:
                all_success = False
            logger.info(f"CSC TC command executed by {username}: {cmd}, exit={exit_status}")
        ssh.close()
        combined_output = '\n\n'.join(all_output)
        record_activity(username, "csc_tc_apply", {"commands": commands, "success": all_success})
        return {
            "success": all_success,
            "output": combined_output,
            "message": f"All {len(commands)} command(s) executed successfully" if all_success else "One or more commands failed"
        }
    except Exception as e:
        logger.error(f"CSC TC apply error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.post("/api/csc/tc/remove")
async def csc_tc_remove(http_request: Request):
    """Remove all tc rules from all interfaces on the CSC server."""
    try:
        username, conn_info, err = _get_csc_ssh(http_request)
        if err:
            return err
        ssh = _csc_ssh_connect(conn_info)
        iface_output, _, _ = _csc_sudo_exec(ssh, "ip -o link show | awk -F': ' '{print $2}' | grep -v lo", conn_info['password'])
        interfaces = [i.strip() for i in iface_output.split('\n') if i.strip()]
        removed = []
        for iface in interfaces[:20]:
            output, error, exit_status = _csc_sudo_exec(ssh, f'sudo -S tc qdisc del dev {iface} root 2>&1', conn_info['password'])
            if exit_status == 0:
                removed.append(iface)
        ssh.close()
        logger.info(f"CSC TC rules removed by {username} on interfaces: {removed}")
        record_activity(username, "csc_tc_remove", {"interfaces": removed})
        return {
            "success": True,
            "output": f"Removed tc rules from {len(removed)} interface(s): {', '.join(removed)}" if removed else "No tc rules to remove",
            "message": "TC rules removed successfully"
        }
    except Exception as e:
        logger.error(f"CSC TC remove error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# Import SSH terminal WebSocket handler
from ssh_terminal import ssh_websocket_handler

@app.websocket("/api/terminal")
async def terminal_websocket(websocket: WebSocket):
    """WebSocket endpoint for SSH terminal sessions"""
    logger.info("WebSocket connection received to /api/terminal")
    await websocket.accept()
    logger.info("WebSocket connection accepted")
    
    try:
        # For testing, skip authentication
        # Get username from cookie
        cookies = websocket.cookies
        username = cookies.get("username") or "test_user"  # Default to test_user for testing
        logger.info(f"WebSocket terminal: Using username {username}")
        
        # Handle SSH terminal session
        logger.info("Calling SSH WebSocket handler")
        await ssh_websocket_handler(websocket)
    except Exception as e:
        logger.error(f"SSH terminal error: {e}")
    finally:
        try:
            await websocket.close()
        except:
            pass



# ─── React SPA routes (must be LAST) ─────────────────────────────────────────
# Serve the React SPA index.html for paths handled by the React frontend.
# All API, old Jinja2 page, and static file routes are matched above.
def _spa_response():
    spa_index = os.path.join(SPA_DIR, "index.html")
    if os.path.isfile(spa_index):
        return FileResponse(spa_index, media_type="text/html")
    return HTMLResponse("<h1>SPA not built</h1><p>Run: cd ../frontend &amp;&amp; npm run build</p>", status_code=503)

@app.get("/login")
async def spa_login():
    return _spa_response()

@app.get("/dashboard")
async def spa_dashboard():
    return _spa_response()

@app.get("/settings")
async def spa_settings():
    return _spa_response()

@app.get("/command-center")
async def spa_command_center():
    return _spa_response()

@app.get("/favicon.ico")
async def spa_favicon():
    fav = os.path.join(SPA_DIR, "favicon.ico")
    if os.path.isfile(fav):
        return FileResponse(fav)
    return Response(status_code=204)

@app.get("/favicon.svg")
async def spa_favicon_svg():
    fav = os.path.join(SPA_DIR, "favicon.svg")
    if os.path.isfile(fav):
        return FileResponse(fav, media_type="image/svg+xml")
    return Response(status_code=204)

# Catch-all: serve SPA index.html for any unmatched GET request (must be last)
@app.get("/{full_path:path}")
async def spa_catch_all(full_path: str):
    # Skip API and static paths (should already be matched above, but guard)
    if full_path.startswith(("api/", "static/", "assets/", "sso/")):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    return _spa_response()
