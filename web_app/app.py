import os
import sys
import re

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

import yaml
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
from utils.credential_manager import get_credential_manager, encrypt_password, decrypt_password

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
        # Helpers
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
            """Replace specific id values with placeholders and drop unknown ids.
            - In ikeSettings[*].id -> <IKE_SETTINGS_UUID> (direct child only, not nested)
            - In ipsecSettings[*].id -> <IPSEC_SETTINGS_UUID> (direct child only, not nested)
            - In advancedSettings[*].id -> <ADVANCED_SETTINGS_UUID> (direct child only, not nested)
            - In device.id -> <DEVICE_UUID>
            - In outsideInterface.id / interface.id -> <INTERFACE_UUID>
            - In tunnelSourceInterface.id / tunnelSource.id -> <TUNNEL_SOURCE_UUID>
            All other 'id' keys are removed to avoid leaking internal IDs.
            """
            try:
                if isinstance(obj, list):
                    return [_replace_ids(x, parent_key, key_path) for x in obj]
                if not isinstance(obj, dict):
                    return obj

                out: Dict[str, Any] = {}
                for k, v in obj.items():
                    kp = key_path + (k,)
                    # Recurse first
                    vv = _replace_ids(v, k, kp)

                    if k == 'id':
                        placeholder = None
                        # Only replace IDs at the direct child level of settings arrays
                        # key_path represents the path to the current dict, not including the 'id' key
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
                        # else: drop unknown id keys
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
            # Normalize to Option A-like source
            if 'summary' in raw_dict:
                src_summary = dict(raw_dict.get('summary') or {})
                src_endpoints = list(raw_dict.get('endpoints') or [])
                src_ike = raw_dict.get('ikeSettings')
                src_ipsec = raw_dict.get('ipsecSettings')
                src_adv = raw_dict.get('advancedSettings')
                # Fallback to FTDS2SVpn object (from FMC fetch) for settings if not directly present
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

            # Strip links/metadata everywhere first
            src_summary = _strip_keys_recursive(src_summary)
            src_endpoints = _strip_keys_recursive(src_endpoints)
            src_ike = _strip_keys_recursive(src_ike) if isinstance(src_ike, (dict, list)) else src_ike
            src_ipsec = _strip_keys_recursive(src_ipsec) if isinstance(src_ipsec, (dict, list)) else src_ipsec
            src_adv = _strip_keys_recursive(src_adv) if isinstance(src_adv, (dict, list)) else src_adv

            # Build limited summary and sanitize IDs in nested sections
            item: Dict[str, Any] = _limited_summary(src_summary)
            if src_endpoints:
                item['endpoints'] = _replace_ids(src_endpoints)
            # Handle both list and dict formats for settings (FMC API returns lists)
            # Pass key_path context so _replace_ids knows we're inside these settings
            if isinstance(src_ike, (dict, list)) and src_ike:
                item['ikeSettings'] = _replace_ids(src_ike, parent_key='', key_path=('ikeSettings',))
            if isinstance(src_ipsec, (dict, list)) and src_ipsec:
                item['ipsecSettings'] = _replace_ids(src_ipsec, parent_key='', key_path=('ipsecSettings',))
            if isinstance(src_adv, (dict, list)) and src_adv:
                item['advancedSettings'] = _replace_ids(src_adv, parent_key='', key_path=('advancedSettings',))
            
            # Include objects section if present (for protected networks)
            src_objects = raw_dict.get('objects')
            if isinstance(src_objects, dict) and src_objects:
                item['objects'] = _strip_keys_recursive(src_objects)

            vpn_items.append(item)

        doc = { 'vpn_topologies': vpn_items }
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

@app.get("/vpn-debugger", response_class=HTMLResponse)
async def vpn_debugger_page(request: Request):
    username = get_current_username(request)
    if not username:
        return RedirectResponse(url="/login?next=/vpn-debugger")
    return templates.TemplateResponse("strongswan.html", {"request": request, "active_page": "vpn_debugger", "username": username})

@app.get("/strongswan", response_class=HTMLResponse)
async def strongswan_page(request: Request):
    """Backwards-compatible redirect to VPN Debugger."""
    return RedirectResponse(url="/vpn-debugger")

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

def _apply_config_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
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
        logger.info(f"  Starting Section 2.1: Loopback Interfaces ({len(loops)} to apply) [PROGRESS: 27%]")
        logger.info(f"  Applying {len(loops)} loopback interface(s) in batches of {batch_size if apply_bulk else 1}")
        for group in (chunks(loops, batch_size) if apply_bulk else [loops]):
            _check_stop_requested(app_username)
            for lb in group:
                _check_stop_requested(app_username)
                try:
                    if not lb.get("type"): lb["type"] = "LoopbackInterface"
                    create_loopback_interface(fmc_ip, headers, domain_uuid, device_id, lb)
                    logger.info(f"Created loopback {lb.get('ifname') or lb.get('name')}")
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


    # 3) EtherChannel interfaces (create; no bulk -> in batches)
    if payload.get("apply_etherchannels") and eths:
        set_progress(app_username, 35, "Section 2.3: EtherChannel Interfaces")
        logger.info(f"  Starting Section 2.3: EtherChannel Interfaces ({len(eths)} to apply) [PROGRESS: 35%]")
        logger.info(f"  Applying {len(eths)} EtherChannel interface(s)")
        for group in (chunks(eths, batch_size) if apply_bulk else [eths]):
            _check_stop_requested(app_username)
            for ec in group:
                _check_stop_requested(app_username)
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
                    # Resolve SecurityZone and dependent objects by name
                    resolver.resolve_all_in_payload(p)
                    post_etherchannel_interface(fmc_ip, headers, domain_uuid, device_id, p)
                    logger.info(f"Created EtherChannel {ec.get('name')}")
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

    # 4) Subinterfaces (create; supports bulk) - pass payload as-is
    if payload.get("apply_subinterfaces") and subs:
        set_progress(app_username, 40, "Section 2.4: Subinterfaces")
        logger.info(f"  Starting Section 2.4: Subinterfaces ({len(subs)} to apply) [PROGRESS: 40%]")
        logger.info(f"  Applying {len(subs)} subinterface(s) in {'bulk' if apply_bulk else 'single'} mode")
        if apply_bulk:
            for group in chunks(subs, batch_size):
                _check_stop_requested(app_username)
                try:
                    out_payload = []
                    for si in group:
                        _check_stop_requested(app_username)
                        p = dict(si)
                        p.setdefault("type", "SubInterface")
                        # Resolve parentInterface/securityZone and dependent objects ids
                        resolver.resolve_all_in_payload(p)
                        out_payload.append(p)
                    if out_payload:
                        post_subinterface(fmc_ip, headers, domain_uuid, device_id, out_payload, bulk=True)
                        logger.info(f"Posted {len(out_payload)} SubInterface(s) in bulk")
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
            for si in subs:
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


    # 5) VTI interfaces (create; supports bulk) - pass payload as-is
    if payload.get("apply_vtis") and vtis:
        set_progress(app_username, 43, "Section 2.5: VTI Interfaces")
        logger.info(f"  Starting Section 2.5: VTI Interfaces ({len(vtis)} to apply) [PROGRESS: 43%]")
        logger.info(f"  Applying {len(vtis)} VTI interface(s) in {'bulk' if apply_bulk else 'single'} mode")
        if apply_bulk:
            for group in chunks(vtis, batch_size):
                _check_stop_requested(app_username)
                try:
                    out_payload = []
                    for vi in group:
                        _check_stop_requested(app_username)
                        p = dict(vi)
                        p.setdefault("type", "VTIInterface")
                        # Resolve tunnelSource/borrowIPfrom/securityZone and dependent objects
                        resolver.resolve_all_in_payload(p)
                        out_payload.append(p)
                    if out_payload:
                        post_vti_interface(fmc_ip, headers, domain_uuid, device_id, out_payload if len(out_payload) > 1 else out_payload[0], bulk=(len(out_payload) > 1))
                        logger.info(f"Posted {len(out_payload)} VTI Interface(s) in {'bulk' if len(out_payload) > 1 else 'single'} mode")
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
            try:
                for vt in vtis:
                    p = dict(vt)
                    p.setdefault("type", "VTIInterface")
                    resolver.resolve_all_in_payload(p)
                    post_vti_interface(fmc_ip, headers, domain_uuid, device_id, p, bulk=False)
                    logger.info(f"Created VTIInterface {p.get('name') or p.get('ifname')}")
                    applied["vtis"] += 1
            except Exception as ex:
                try:
                    import requests as _rq
                    if isinstance(ex, _rq.exceptions.RequestException) and getattr(ex, "response", None) is not None:
                        desc = fmc.extract_error_description(ex.response) or str(ex)
                    else:
                        desc = str(ex)
                except Exception:
                    desc = str(ex)
                errors.append(f"VTI: {desc}")
        logger.info(f"  Finished Section 2.5: VTI Interfaces ({applied['vtis']} applied)")
        try:
            resolver.prime_device_interfaces()
        except Exception as e:
            logger.warning(f"Failed to refresh device interfaces after VTI creation: {e}")

    # 6) Inline Sets (create; no bulk endpoint)
    if payload.get("apply_inline_sets") and inline_sets:
        set_progress(app_username, 46, "Section 2.6: Inline Sets")
        logger.info(f"  Starting Section 2.6: Inline Sets ({len(inline_sets)} to apply) [PROGRESS: 46%]")
        logger.info(f"  Applying {len(inline_sets)} Inline Set(s)")
        for item in inline_sets:
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

    # 7) Bridge Group Interfaces (create; no bulk endpoint)
    if payload.get("apply_bridge_group_interfaces") and bridge_groups:
        set_progress(app_username, 48, "Section 2.7: Bridge Group Interfaces")
        logger.info(f"  Starting Section 2.7: Bridge Group Interfaces ({len(bridge_groups)} to apply) [PROGRESS: 48%]")
        logger.info(f"  Applying {len(bridge_groups)} Bridge Group Interface(s)")
        for item in bridge_groups:
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
            for vrf in vrfs:
                _check_stop_requested(app_username)
                try:
                    p = dict(vrf)
                    # Skip creating the default Global VRF
                    vrf_name = (p.get("name") or "").strip()
                    if vrf_name and vrf_name.lower() == "global":
                        logger.info("Skipping VRF 'Global' (default)")
                        continue
                    resolver.resolve_all_in_payload(p)
                    res = post_vrf(fmc_ip, headers, domain_uuid, device_id, p)
                    vid = res.get("id")
                    if vid and p.get("name"):
                        name_to_id[str(p["name"])] = vid
                    applied["routing_vrfs"] += 1
                except Exception as ex:
                    name = vrf.get('name')
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

        apply_phys = bool(payload.get("apply_chassis_physicalinterfaces", True))
        apply_eth = bool(payload.get("apply_chassis_etherchannelinterfaces", True))
        apply_sub = bool(payload.get("apply_chassis_subinterfaces", True))
        # apply_chassis_logical_devices is now a list of selected LD names (or True/False for backward compat)
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

        admin_password = (payload.get("chassis_admin_password") or "").strip()

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
        data = yaml.safe_load(raw) or {}
        chassis_ifaces = data.get("chassis_interfaces") or {}
        cfg = {
            "chassis_interfaces": {
                "physicalinterfaces": chassis_ifaces.get("physicalinterfaces") or [],
                "etherchannelinterfaces": chassis_ifaces.get("etherchannelinterfaces") or [],
                "subinterfaces": chassis_ifaces.get("subinterfaces") or [],
            },
            "logical_devices": data.get("logical_devices") or [],
        }
        counts = {
            "chassis_physicalinterfaces": len(cfg["chassis_interfaces"]["physicalinterfaces"]),
            "chassis_etherchannelinterfaces": len(cfg["chassis_interfaces"]["etherchannelinterfaces"]),
            "chassis_subinterfaces": len(cfg["chassis_interfaces"]["subinterfaces"]),
            "chassis_logical_devices": len(cfg["logical_devices"]),
        }
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
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        app_username = payload.get("app_username") or username
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
                'traffic_out_packets': '0'
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

def parse_swanctl_list_conns(output: str) -> List[str]:
    """Parse swanctl --list-conns output to get list of configured connection names.
    
    Example output format:
    ftd-tunnel-ipv6-150: IKEv2, no reauthentication, rekeying every 86400s
      local:  %any
      remote: 30:16::1
      ...
    """
    conn_names = []
    lines = output.strip().split('\n')
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        
        # Connection lines start without whitespace and end with IKEv1 or IKEv2
        if not line.startswith(' ') and not line.startswith('\t') and ':' in stripped:
            if 'ikev1' in stripped.lower() or 'ikev2' in stripped.lower():
                # Extract connection name (everything before first colon)
                conn_name = stripped.split(':')[0].strip()
                if conn_name:
                    conn_names.append(conn_name)
    
    logger.info(f"Parsed {len(conn_names)} connection(s) from swanctl --list-conns")
    return conn_names

def merge_sas_and_conns(sas_tunnels: List[Dict[str, Any]], conn_names: List[str]) -> List[Dict[str, Any]]:
    """Merge active SAs with configured connections to identify inactive tunnels."""
    # Get names of active tunnels
    active_names = {t['name'] for t in sas_tunnels}
    
    # Add inactive tunnels (in conns but not in sas)
    merged = list(sas_tunnels)
    for conn_name in conn_names:
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
        conn_names = parse_swanctl_list_conns(conns_output)
        
        # Merge to include inactive tunnels
        tunnels = merge_sas_and_conns(active_tunnels, conn_names)
        
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
        conn_names = parse_swanctl_list_conns(conns_output)
        
        # Merge to include inactive tunnels
        tunnels = merge_sas_and_conns(active_tunnels, conn_names)
        
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
    interval_minutes: int = 5
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
            f"--interval {request.interval_minutes} "
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

        stdin_pid, stdout_pid, _ = ssh.exec_command(f"sudo -S cat {REMOTE_MONITOR_PID_FILE} 2>/dev/null", timeout=10, get_pty=True)
        stdin_pid.write(conn_info['password'] + '\n')
        stdin_pid.flush()
        daemon_pid_raw = stdout_pid.read().decode('utf-8', errors='replace').strip()
        daemon_pid = int(daemon_pid_raw) if daemon_pid_raw.isdigit() else None
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
            "interval": request.interval_minutes,
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

            stop_cmd = (
                "pkill -9 -f remote_tunnel_monitor_daemon.py 2>/dev/null || true; "
                "pkill -9 -f 'swanctl --log --debug 1' 2>/dev/null || true; "
                f"rm -f {REMOTE_MONITOR_PID_FILE} {REMOTE_MONITOR_COUNT_FILE}"
            )
            stdin_d, stdout_d, _ = ssh.exec_command(f"sudo -S bash -c \"{stop_cmd}\"", timeout=10, get_pty=True)
            stdin_d.write(conn_info['password'] + '\n')
            stdin_d.flush()
            stdout_d.read()

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
                    files.append({"name": filename, "size": size})
        
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
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        # Validate filename to prevent path traversal
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        
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
        
        # Read file content
        cat_cmd = f'sudo -S cat "/etc/swanctl/conf.d/{filename}"'
        stdin, stdout, stderr = ssh.exec_command(cat_cmd, timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        ssh.close()
        
        # Clean output (remove password echo and sudo prompts)
        lines = output.split('\n')
        cleaned = []
        for line in lines:
            if not cleaned and not line.strip():
                continue
            if line.strip() == conn_info['password']:
                continue
            if line.startswith('[sudo]') or line.startswith('sudo:'):
                continue
            cleaned.append(line)
        content = '\n'.join(cleaned)
        
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
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        # Validate filename to prevent path traversal
        filename = request.filename
        newFilename = request.newFilename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        if '/' in newFilename or '\\' in newFilename or '..' in newFilename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid new filename"})
        
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
        
        # Rename file
        rename_cmd = f'sudo -S mv "/etc/swanctl/conf.d/{filename}" "/etc/swanctl/conf.d/{newFilename}"'
        stdin, stdout, stderr = ssh.exec_command(rename_cmd, timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        exit_status = stdout.channel.recv_exit_status()
        
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
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        # Validate filename
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        if not filename.endswith('.conf'):
            return JSONResponse(status_code=400, content={"success": False, "message": "Filename must end with .conf"})
        
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
        username = get_current_username(http_request)
        if not username:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        conn_info = strongswan_connections.get(username)
        if not conn_info:
            return JSONResponse(status_code=400, content={"success": False, "message": "Not connected to any strongSwan server"})
        
        # Validate filename
        filename = request.filename
        if '/' in filename or '\\' in filename or '..' in filename:
            return JSONResponse(status_code=400, content={"success": False, "message": "Invalid filename"})
        
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
        
        # Delete file
        delete_cmd = f'sudo -S rm "/etc/swanctl/conf.d/{filename}"'
        stdin, stdout, stderr = ssh.exec_command(delete_cmd, timeout=30, get_pty=True)
        stdin.write(conn_info['password'] + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        exit_status = stdout.channel.recv_exit_status()
        
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
        timeout=15,
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
from ai_tools import STRONGSWAN_TOOLS, NETPLAN_TOOLS, TC_TOOLS, GENERAL_CMD_TOOLS, TUNNEL_TRAFFIC_TOOLS, MONITORING_TOOLS, FMC_TOOLS, VPN_TOOLS, FMC_OPERATION_TOOLS, get_tool_executor, vpn_tool_executor

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
            tools = STRONGSWAN_TOOLS + NETPLAN_TOOLS + TC_TOOLS + GENERAL_CMD_TOOLS + TUNNEL_TRAFFIC_TOOLS + MONITORING_TOOLS
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
        config = yaml_lib.safe_load(yaml_content)
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
            data = yaml_lib.safe_load(loaded_vpn_yaml)
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
            config = yaml_lib.safe_load(config_yaml)
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
        config = yaml_lib.safe_load(yaml_content)
    except Exception:
        config = {}
    if not isinstance(config, dict):
        config = {}

    # Count chassis config items
    chassis_ifaces = config.get("chassis_interfaces") or {}
    logical_devices = config.get("logical_devices") or []
    counts = {
        "chassis_physicalinterfaces": len(chassis_ifaces.get("physicalinterfaces") or []),
        "chassis_etherchannelinterfaces": len(chassis_ifaces.get("etherchannelinterfaces") or []),
        "chassis_subinterfaces": len(chassis_ifaces.get("subinterfaces") or []),
        "chassis_logical_devices": len(logical_devices),
    }

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
