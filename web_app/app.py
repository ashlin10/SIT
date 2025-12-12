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
    "adarsku3": "Cisco@123",
    "aleroyds": "Cisco@123",
    "ankkprak": "Cisco@123",
    "chetnsin": "Cisco@123",
    "hardivak": "Cisco@123",
    "harishk": "Cisco@123",
    "jazhagar": "Cisco@123",
    "laktata": "Cisco@123",
    "mohqures": "Cisco@123",
    "nitins5": "Cisco@123",
    "nishrima": "Cisco@123",
    "nivirman": "Cisco@123",
    "phaldika": "Cisco@123",
    "preddyn": "Cisco@123",
    "rajushri": "Cisco@123",
    "risrawat": "Cisco@123",
    "sapray": "Cisco@123",
    "sathiyag": "Cisco@123",
    "ssamarpa": "Cisco@123",
    "subriyer": "Cisco@123",
    "varajaya": "Cisco@123",
    "vigannam": "Cisco@123",
    "vivbalu": "Cisco@123",
    "vvantimu": "Cisco@123",
    "yabhavsa": "Cisco@123",
    "ykatager": "Cisco@123",
    "aakakulk": "Cisco@123",
    "nshelke": "Cisco@123"
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
        
        # Track all topologies for comprehensive summary table
        topology_summary: List[Dict[str, Any]] = []

        # Fetch IKE policies and IPSec proposals for reference resolution
        logger.info("[VPN] Fetching IKEv2 policies and IPSec proposals for reference resolution...")
        ikev2_policies = get_ikev2_policies(fmc_ip, headers, domain_uuid)
        ikev2_ipsec_proposals = get_ikev2_ipsec_proposals(fmc_ip, headers, domain_uuid)

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
                                            logger.info(f"[VPN] Resolved IKE policy '{policy_name}' -> {policy_id}")
                                        else:
                                            logger.warning(f"[VPN] IKE policy '{policy_name}' found but has no id")
                                    else:
                                        # Policy doesn't exist, create it
                                        try:
                                            logger.info(f"[VPN] IKE policy '{policy_name}' not found, creating it...")
                                            created_policy = post_ikev2_policy(fmc_ip, headers, domain_uuid, policy)
                                            policy_id = created_policy.get("id")
                                            if policy_id:
                                                policy["id"] = policy_id
                                                ikev2_policies[policy_name] = created_policy  # Cache it
                                                logger.info(f"[VPN] Created IKE policy '{policy_name}' -> {policy_id}")
                                            else:
                                                logger.warning(f"[VPN] Created IKE policy '{policy_name}' but got no id")
                                        except Exception as ex:
                                            logger.error(f"[VPN] Failed to create IKE policy '{policy_name}': {ex}")
            
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
                                        logger.info(f"[VPN] Resolved IPSec proposal '{proposal_name}' -> {proposal_id}")
                                    else:
                                        logger.warning(f"[VPN] IPSec proposal '{proposal_name}' found but has no id")
                                else:
                                    # Proposal doesn't exist, create it
                                    try:
                                        logger.info(f"[VPN] IPSec proposal '{proposal_name}' not found, creating it...")
                                        created_proposal = post_ikev2_ipsec_proposal(fmc_ip, headers, domain_uuid, proposal)
                                        proposal_id = created_proposal.get("id")
                                        if proposal_id:
                                            proposal["id"] = proposal_id
                                            ikev2_ipsec_proposals[proposal_name] = created_proposal  # Cache it
                                            logger.info(f"[VPN] Created IPSec proposal '{proposal_name}' -> {proposal_id}")
                                        else:
                                            logger.warning(f"[VPN] Created IPSec proposal '{proposal_name}' but got no id")
                                    except Exception as ex:
                                        logger.error(f"[VPN] Failed to create IPSec proposal '{proposal_name}': {ex}")

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
                        # Build caches to avoid repeated lookups
                        device_uuid_cache: Dict[str, Union[str, Tuple[str, str]]] = {}
                        iface_cache: Dict[str, List[Dict[str, Any]]] = {}

                        def _get_device_uuid_by_name(dev_name: str) -> Optional[str]:
                            dn = (dev_name or "").strip()
                            if not dn:
                                return None
                            if dn in device_uuid_cache:
                                cached = device_uuid_cache[dn]
                                # Return just the UUID from cached tuple
                                if isinstance(cached, tuple) and len(cached) == 2:
                                    return cached[0]
                                return cached
                            try:
                                du, dt = get_device_info(fmc_ip, headers, domain_uuid, dn)
                                device_uuid_cache[dn] = (du, dt)  # Cache both UUID and type
                                logger.info(f"[VPN] Resolved device '{dn}': UUID={du}, Type={dt}")
                                return du
                            except Exception as ex:
                                logger.warning(f"[VPN] Failed to resolve device UUID for '{dn}': {ex}")
                                return None

                        def _load_ifaces_for_device(dev_uuid: str, dev_type: str = "Device") -> List[Dict[str, Any]]:
                            if not dev_uuid:
                                return []
                            if dev_uuid in iface_cache:
                                return iface_cache[dev_uuid]
                            try:
                                items = fmc.get_all_interfaces(fmc_ip, headers, domain_uuid, dev_uuid, dev_type) or []
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
                                    
                                    # Always resolve device UUID by name from destination FMC
                                    # (UUIDs differ between FMCs, so we must resolve by name)
                                    dev_type = "Device"  # Default
                                    if dev_name:
                                        dev_uuid = _get_device_uuid_by_name(dev_name)
                                        if dev_uuid and isinstance(dev, dict):
                                            dev["id"] = dev_uuid
                                            # Also update device type if we have it cached
                                            if dev_name in device_uuid_cache:
                                                cached_info = device_uuid_cache[dev_name]
                                                if isinstance(cached_info, tuple) and len(cached_info) == 2:
                                                    dev["type"] = cached_info[1]
                                                    dev_type = cached_info[1]  # Store for interface loading
                                                    logger.info(f"[VPN] Resolved device '{dev_name}' -> UUID: {dev_uuid}, Type: {cached_info[1]}")
                                                else:
                                                    logger.info(f"[VPN] Resolved device UUID for '{dev_name}' -> {dev_uuid}")
                                            else:
                                                logger.info(f"[VPN] Resolved device UUID for '{dev_name}' -> {dev_uuid}")
                                    
                                    # Load interfaces for this device with device type
                                    iface_items = _load_ifaces_for_device(dev_uuid, dev_type) if dev_uuid else []

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
            "message": summary_msg,
            "topology_summary": cleaned_topology_summary,
            "summary_table": summary_table,
            "summary_tables": {
                "applied": applied_rows,
                "failed": failed_rows,
                "skipped": []
            }
        }
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
        reset_progress(username)
        _attach_user_log_handlers(username)
        # Add app username to payload for progress tracking
        payload["app_username"] = username
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
        aggregated_applied_rows = []
        aggregated_skipped_rows = []
        aggregated_failed_rows = []

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
        created_zones = resolver.ensure_security_zones(sec_zone_defs, needed_zones)
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
        obj = (cfg.get("objects") or {}) if isinstance(cfg, dict) else {}
        
        # Fetch all existing objects to validate before POSTing
        logger.info("Fetching existing objects from FMC for validation...")
        existing_objects: Dict[str, Set[str]] = {}  # type -> set of names
        try:
            existing_objects["Host"] = {str(o.get("name")) for o in (fmc.get_hosts(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["Range"] = {str(o.get("name")) for o in (fmc.get_ranges(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["Network"] = {str(o.get("name")) for o in (fmc.get_networks(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["FQDN"] = {str(o.get("name")) for o in (fmc.get_fqdns(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["NetworkGroup"] = {str(o.get("name")) for o in (fmc.get_network_groups(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["ProtocolPortObject"] = {str(o.get("name")) for o in (fmc.get_port_objects(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["BFDTemplate"] = {str(o.get("name")) for o in (fmc.get_bfd_templates(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["ASPathList"] = {str(o.get("name")) for o in (fmc.get_as_path_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["KeyChain"] = {str(o.get("name")) for o in (fmc.get_key_chains(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["SLAMonitor"] = {str(o.get("name")) for o in (fmc.get_sla_monitors(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["CommunityList"] = {str(o.get("name")) for o in (fmc.get_community_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["ExtendedCommunityList"] = {str(o.get("name")) for o in (fmc.get_extended_community_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["IPv4PrefixList"] = {str(o.get("name")) for o in (fmc.get_ipv4_prefix_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["IPv6PrefixList"] = {str(o.get("name")) for o in (fmc.get_ipv6_prefix_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["ExtendedAccessList"] = {str(o.get("name")) for o in (fmc.get_extended_access_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["StandardAccessList"] = {str(o.get("name")) for o in (fmc.get_standard_access_lists(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["RouteMap"] = {str(o.get("name")) for o in (fmc.get_route_maps(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["IPv4AddressPool"] = {str(o.get("name")) for o in (fmc.get_ipv4_address_pools(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["IPv6AddressPool"] = {str(o.get("name")) for o in (fmc.get_ipv6_address_pools(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            existing_objects["MacAddressPool"] = {str(o.get("name")) for o in (fmc.get_mac_address_pools(fmc_ip, headers, domain_uuid) or []) if o.get("name")}
            logger.info(f"Loaded existing objects for validation: {sum(len(v) for v in existing_objects.values())} objects across {len(existing_objects)} types")
        except Exception as ex:
            logger.warning(f"Failed to fetch existing objects for validation: {ex}")
        
        # Helper to log object processing start
        def _log_obj_start(obj_type_name: str, items, is_enabled: bool):
            """Log the start of object processing with count information"""
            if not is_enabled:
                logger.info(f"  {obj_type_name}: Not selected")
            elif not items or len(items) == 0:
                logger.info(f"  {obj_type_name}: No objects to create")
            else:
                logger.info(f"  {obj_type_name}: Processing {len(items)} object(s)")
        
        # Helper to post a list of objects with a callable, checking if they already exist
        def _post_list(items, func, applied_key: str, object_type: str = None, bulk_func=None):
            """Post items individually or in bulk. If bulk_func is provided and apply_bulk is True, uses bulk API."""
            if not items:
                return
            
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
        logger.info("  Level 1: Base objects (no dependencies)")
        
        # Network objects
        net = obj.get("network") or {}
        _log_obj_start("Host objects", net.get("hosts"), payload.get("apply_obj_net_host"))
        if payload.get("apply_obj_net_host"): _post_list(net.get("hosts"), fmc.post_host_object, "objects_network_hosts", "Host", bulk_func=fmc.post_host_object_bulk)
        _log_obj_start("Range objects", net.get("ranges"), payload.get("apply_obj_net_range"))
        if payload.get("apply_obj_net_range"): _post_list(net.get("ranges"), fmc.post_range_object, "objects_network_ranges", "Range", bulk_func=fmc.post_range_object_bulk)
        _log_obj_start("Network objects", net.get("networks"), payload.get("apply_obj_net_network"))
        if payload.get("apply_obj_net_network"): _post_list(net.get("networks"), fmc.post_network_object, "objects_network_networks", "Network", bulk_func=fmc.post_network_object_bulk)
        _log_obj_start("FQDN objects", net.get("fqdns"), payload.get("apply_obj_net_fqdn"))
        if payload.get("apply_obj_net_fqdn"): _post_list(net.get("fqdns"), fmc.post_fqdn_object, "objects_network_fqdns", "FQDN", bulk_func=fmc.post_fqdn_object_bulk)
        # Port objects
        prt = obj.get("port") or {}
        _log_obj_start("Port objects", prt.get("objects"), payload.get("apply_obj_port_objects"))
        if payload.get("apply_obj_port_objects"):
            _post_list(prt.get("objects"), fmc.post_port_object, "objects_port_objects", "ProtocolPortObject", bulk_func=fmc.post_port_object_bulk)
        # BFD templates need UI auth overrides
        _log_obj_start("BFD Templates", obj.get("bfd_templates"), payload.get("apply_obj_bfd_templates"))
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
        _log_obj_start("AS Path Lists", obj.get("as_path_lists"), payload.get("apply_obj_as_path_lists"))
        if payload.get("apply_obj_as_path_lists"): _post_list(obj.get("as_path_lists"), fmc.post_as_path_list, "objects_as_path_lists", "ASPathList")
        _log_obj_start("Key Chains", obj.get("key_chains"), payload.get("apply_obj_key_chains"))
        if payload.get("apply_obj_key_chains"): _post_list(obj.get("key_chains"), fmc.post_key_chain, "objects_key_chains", "KeyChain", bulk_func=fmc.post_key_chain_bulk)
        comm = obj.get("community_lists") or {}
        _log_obj_start("Community Lists (Community)", comm.get("community"), payload.get("apply_obj_community_lists_community"))
        if payload.get("apply_obj_community_lists_community"): _post_list(comm.get("community"), fmc.post_community_list, "objects_community_lists_community", "CommunityList")
        _log_obj_start("Community Lists (Extended)", comm.get("extended"), payload.get("apply_obj_community_lists_extended"))
        if payload.get("apply_obj_community_lists_extended"): _post_list(comm.get("extended"), fmc.post_extended_community_list, "objects_community_lists_extended", "ExtendedCommunityList")
        pref = obj.get("prefix_lists") or {}
        _log_obj_start("IPv4 Prefix Lists", pref.get("ipv4"), payload.get("apply_obj_prefix_lists_ipv4"))
        if payload.get("apply_obj_prefix_lists_ipv4"): _post_list(pref.get("ipv4"), fmc.post_ipv4_prefix_list, "objects_prefix_lists_ipv4", "IPv4PrefixList")
        _log_obj_start("IPv6 Prefix Lists", pref.get("ipv6"), payload.get("apply_obj_prefix_lists_ipv6"))
        if payload.get("apply_obj_prefix_lists_ipv6"): _post_list(pref.get("ipv6"), fmc.post_ipv6_prefix_list, "objects_prefix_lists_ipv6", "IPv6PrefixList")
        pools = obj.get("address_pools") or {}
        _log_obj_start("IPv4 Address Pools", pools.get("ipv4"), payload.get("apply_obj_address_pools_ipv4"))
        if payload.get("apply_obj_address_pools_ipv4"): _post_list(pools.get("ipv4"), fmc.post_ipv4_address_pool, "objects_address_pools_ipv4", "IPv4AddressPool")
        _log_obj_start("IPv6 Address Pools", pools.get("ipv6"), payload.get("apply_obj_address_pools_ipv6"))
        if payload.get("apply_obj_address_pools_ipv6"): _post_list(pools.get("ipv6"), fmc.post_ipv6_address_pool, "objects_address_pools_ipv6", "IPv6AddressPool")
        _log_obj_start("MAC Address Pools", pools.get("mac"), payload.get("apply_obj_address_pools_mac"))
        if payload.get("apply_obj_address_pools_mac"): _post_list(pools.get("mac"), fmc.post_mac_address_pool, "objects_address_pools_mac", "MacAddressPool")
        logger.info("  Finished Level 1 objects")
        
        # Refresh object maps after Level 1 so Level 2 can reference them
        logger.info("  Refreshing object maps...")
        resolver.prime_object_maps()
        
        # Level 2: Objects that depend on Level 1
        logger.info("  Level 2: Objects that depend on Level 1")
        _log_obj_start("Network Groups", net.get("groups"), payload.get("apply_obj_net_group"))
        if payload.get("apply_obj_net_group"): _post_list(net.get("groups"), fmc.post_network_group, "objects_network_groups", "NetworkGroup", bulk_func=fmc.post_network_group_bulk)
        _log_obj_start("SLA Monitors", obj.get("sla_monitors"), payload.get("apply_obj_sla_monitors"))
        if payload.get("apply_obj_sla_monitors"): _post_list(obj.get("sla_monitors"), fmc.post_sla_monitor, "objects_sla_monitors", "SLAMonitor", bulk_func=fmc.post_sla_monitor_bulk)
        logger.info("  Finished Level 2 objects")
        
        # Refresh object maps after Level 2
        logger.info("  Refreshing object maps...")
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
            for lb in group:
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
            for ph in group:
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
                try:
                    out_payload = []
                    for si in group:
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
                try:
                    out_payload = []
                    for vt in group:
                        p = dict(vt)
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
    
    try:
        # Refresh object maps to include interface-derived network objects
        logger.info("  Refreshing object maps to include interface-derived network objects")
        resolver.prime_object_maps()
        
        # Level 3: Access Lists (depend on Level 1 & 2 objects + interface-derived objects)
        logger.info("  Level 3: Access Lists (depend on interfaces)")
        acls = obj.get("access_lists") or {}
        _log_obj_start("Extended Access Lists", acls.get("extended"), payload.get("apply_obj_access_lists_extended"))
        if payload.get("apply_obj_access_lists_extended"): _post_list(acls.get("extended"), fmc.post_extended_access_list, "objects_access_lists_extended", "ExtendedAccessList")
        _log_obj_start("Standard Access Lists", acls.get("standard"), payload.get("apply_obj_access_lists_standard"))
        if payload.get("apply_obj_access_lists_standard"): _post_list(acls.get("standard"), fmc.post_standard_access_list, "objects_access_lists_standard", "StandardAccessList")
        logger.info("  Finished Level 3 objects")
        
        # Refresh object maps after Level 3 so Level 4 (Route Maps) can reference Access Lists
        logger.info("  Refreshing object maps...")
        resolver.prime_object_maps()
        
        # Level 4: Route Maps (depend on all previous levels including access lists)
        logger.info("  Level 4: Route Maps (depend on all previous levels)")
        _log_obj_start("Route Maps", obj.get("route_maps"), payload.get("apply_obj_route_maps"))
        if payload.get("apply_obj_route_maps"): _post_list(obj.get("route_maps"), fmc.post_route_map, "objects_route_maps", "RouteMap")
        logger.info("  Finished Level 4 objects")
        
        # Refresh object maps after Level 4 so routing policies can reference Route Maps
        logger.info("  Refreshing object maps...")
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
                try:
                    out = []
                    for it in group:
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
                try:
                    out = []
                    for it in group:
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
                try:
                    out = []
                    for it in group:
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
                    vid = name_to_id.get(vrf_name)
                    if not vid:
                        errors.append(f"VRF-specific skipped for '{vrf_name}' (VRF not found)")
                        continue
                    
                    # BFD policies in VRF - Pass 1
                    for it in ((sections or {}).get("bfd_policies") or []):
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
                            try:
                                out = []
                                for it in group:
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
                            try:
                                out = []
                                for it in group:
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
        routing_block: Dict[str, Any] = {}
        try:
            set_progress(app_username, 38, "Section 2.1: BGP General Settings")
            logger.info("  Starting Section 2.1: BGP General Settings [PROGRESS: 38%]")
            bgp_general = get_bgp_general_settings(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.1: BGP General Settings ({len(bgp_general)} found)")
            
            set_progress(app_username, 41, "Section 2.2: BGP Policies")
            logger.info("  Starting Section 2.2: BGP Policies [PROGRESS: 41%]")
            bgp_policies = get_bgp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.2: BGP Policies ({len(bgp_policies)} found)")
            
            set_progress(app_username, 44, "Section 2.3: BFD Policies")
            logger.info("  Starting Section 2.3: BFD Policies [PROGRESS: 44%]")
            bfd_policies = get_bfd_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.3: BFD Policies ({len(bfd_policies)} found)")
            
            set_progress(app_username, 47, "Section 2.4: OSPFv2 Policies")
            logger.info("  Starting Section 2.4: OSPFv2 Policies [PROGRESS: 47%]")
            ospfv2_policies = get_ospfv2_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.4: OSPFv2 Policies ({len(ospfv2_policies)} found)")
            
            set_progress(app_username, 50, "Section 2.5: OSPFv2 Interfaces")
            logger.info("  Starting Section 2.5: OSPFv2 Interfaces [PROGRESS: 50%]")
            ospfv2_interfaces = get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.5: OSPFv2 Interfaces ({len(ospfv2_interfaces)} found)")
            
            set_progress(app_username, 53, "Section 2.6: OSPFv3 Policies")
            logger.info("  Starting Section 2.6: OSPFv3 Policies [PROGRESS: 53%]")
            ospfv3_policies = get_ospfv3_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.6: OSPFv3 Policies ({len(ospfv3_policies)} found)")
            
            set_progress(app_username, 55, "Section 2.7: OSPFv3 Interfaces")
            logger.info("  Starting Section 2.7: OSPFv3 Interfaces [PROGRESS: 55%]")
            ospfv3_interfaces = get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.7: OSPFv3 Interfaces ({len(ospfv3_interfaces)} found)")
            
            set_progress(app_username, 57, "Section 2.8: EIGRP Policies")
            logger.info("  Starting Section 2.8: EIGRP Policies [PROGRESS: 57%]")
            eigrp_policies = get_eigrp_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.8: EIGRP Policies ({len(eigrp_policies)} found)")
            
            set_progress(app_username, 59, "Section 2.9: PBR Policies")
            logger.info("  Starting Section 2.9: PBR Policies [PROGRESS: 59%]")
            pbr_policies = get_pbr_policies(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.9: PBR Policies ({len(pbr_policies)} found)")
            
            set_progress(app_username, 62, "Section 2.10: IPv4 Static Routes")
            logger.info("  Starting Section 2.10: IPv4 Static Routes [PROGRESS: 62%]")
            ipv4_static = get_ipv4_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.10: IPv4 Static Routes ({len(ipv4_static)} found)")
            
            set_progress(app_username, 65, "Section 2.11: IPv6 Static Routes")
            logger.info("  Starting Section 2.11: IPv6 Static Routes [PROGRESS: 65%]")
            ipv6_static = get_ipv6_static_routes(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.11: IPv6 Static Routes ({len(ipv6_static)} found)")
            
            set_progress(app_username, 67, "Section 2.12: ECMP Zones")
            logger.info("  Starting Section 2.12: ECMP Zones [PROGRESS: 67%]")
            ecmp_zones = get_ecmp_zones(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.12: ECMP Zones ({len(ecmp_zones)} found)")
            
            set_progress(app_username, 69, "Section 2.13: VRFs")
            logger.info("  Starting Section 2.13: VRFs [PROGRESS: 69%]")
            vrfs = get_vrfs(fmc_ip, headers, domain_uuid, dev_id, dev_name) or []
            logger.info(f"  Finished Section 2.13: VRFs ({len(vrfs)} found)")
            
            routing_block = {
                "bgp_general_settings": bgp_general,
                "bgp_policies": bgp_policies,
                "bfd_policies": bfd_policies,
                "ospfv2_policies": ospfv2_policies,
                "ospfv2_interfaces": ospfv2_interfaces,
                "ospfv3_policies": ospfv3_policies,
                "ospfv3_interfaces": ospfv3_interfaces,
                "eigrp_policies": eigrp_policies,
                "pbr_policies": pbr_policies,
                "ipv4_static_routes": ipv4_static,
                "ipv6_static_routes": ipv6_static,
                "ecmp_zones": ecmp_zones,
                "vrfs": vrfs,
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
                        actual_type = (it or {}).get("type") or t
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
                        actual_type = (it or {}).get("type") or t
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
                            actual_type = (it or {}).get("type") or t
                            dep_ids_by_type.setdefault(actual_type, set()).add(iid)

                # Update aggregated dependency table with fetched objects (ensure UUIDs are recorded)
                fetched = (items_by_id or []) + (items_by_name or [])
                for it in fetched:
                    actual_type = (it or {}).get("type") or t
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
    except Exception as e:
        logger.error(f"Export error: {e}")
        return {"success": False, "message": str(e)}

@app.post("/api/fmc-config/config/get")
async def fmc_config_get(payload: Dict[str, Any], http_request: Request):
    try:
        # Ensure logs from utils.fmc_api surface while exporting
        username = get_current_username(http_request)
        reset_progress(username)
        _attach_user_log_handlers(username)
        # Add app username to payload for progress tracking
        payload["app_username"] = username
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
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: _delete_objects_sync(payload))
        return result
    except Exception as e:
        logger.error(f"FMC objects delete error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})

def _delete_objects_sync(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Delete FMC objects specified in YAML config."""
    try:
        fmc_ip = (payload.get("fmc_ip") or "").strip()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
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
        }
        errors: List[str] = []

        # Helper to delete objects by type from YAML
        def _delete_obj_list(items: List[Dict[str, Any]], object_type: str, key: str):
            if not items:
                return
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
            _delete_obj_list(obj.get("route_maps"), "RouteMap", "objects_route_maps")

        # Level 3: Access Lists
        acls = obj.get("access_lists") or {}
        if payload.get("delete_obj_access_lists_extended"):
            _delete_obj_list(acls.get("extended"), "ExtendedAccessList", "objects_access_lists_extended")
        if payload.get("delete_obj_access_lists_standard"):
            _delete_obj_list(acls.get("standard"), "StandardAccessList", "objects_access_lists_standard")

        # Level 2: Network Groups, SLA Monitors
        net = obj.get("network") or {}
        if payload.get("delete_obj_net_group"):
            _delete_obj_list(net.get("groups"), "NetworkGroup", "objects_network_groups")
        if payload.get("delete_obj_sla_monitors"):
            _delete_obj_list(obj.get("sla_monitors"), "SLAMonitor", "objects_sla_monitors")

        # Level 1: Base objects
        if payload.get("delete_obj_net_host"):
            _delete_obj_list(net.get("hosts"), "Host", "objects_network_hosts")
        if payload.get("delete_obj_net_range"):
            _delete_obj_list(net.get("ranges"), "Range", "objects_network_ranges")
        if payload.get("delete_obj_net_network"):
            _delete_obj_list(net.get("networks"), "Network", "objects_network_networks")
        if payload.get("delete_obj_net_fqdn"):
            _delete_obj_list(net.get("fqdns"), "FQDN", "objects_network_fqdns")
        
        if payload.get("delete_obj_port_objects"):
            prt = obj.get("port") or {}
            _delete_obj_list(prt.get("objects"), "ProtocolPortObject", "objects_port_objects")
        
        if payload.get("delete_obj_bfd_templates"):
            _delete_obj_list(obj.get("bfd_templates"), "BFDTemplate", "objects_bfd_templates")
        if payload.get("delete_obj_as_path_lists"):
            _delete_obj_list(obj.get("as_path_lists"), "ASPathList", "objects_as_path_lists")
        if payload.get("delete_obj_key_chains"):
            _delete_obj_list(obj.get("key_chains"), "KeyChain", "objects_key_chains")
        
        comm = obj.get("community_lists") or {}
        if payload.get("delete_obj_community_lists_community"):
            _delete_obj_list(comm.get("community"), "CommunityList", "objects_community_lists_community")
        if payload.get("delete_obj_community_lists_extended"):
            _delete_obj_list(comm.get("extended"), "ExtendedCommunityList", "objects_community_lists_extended")
        
        pref = obj.get("prefix_lists") or {}
        if payload.get("delete_obj_prefix_lists_ipv4"):
            _delete_obj_list(pref.get("ipv4"), "IPv4PrefixList", "objects_prefix_lists_ipv4")
        if payload.get("delete_obj_prefix_lists_ipv6"):
            _delete_obj_list(pref.get("ipv6"), "IPv6PrefixList", "objects_prefix_lists_ipv6")
        
        pools = obj.get("address_pools") or {}
        if payload.get("delete_obj_address_pools_ipv4"):
            _delete_obj_list(pools.get("ipv4"), "IPv4AddressPool", "objects_address_pools_ipv4")
        if payload.get("delete_obj_address_pools_ipv6"):
            _delete_obj_list(pools.get("ipv6"), "IPv6AddressPool", "objects_address_pools_ipv6")
        if payload.get("delete_obj_address_pools_mac"):
            _delete_obj_list(pools.get("mac"), "MacAddressPool", "objects_address_pools_mac")

        if errors:
            logger.info("Object delete completed with some errors. See terminal.")
        else:
            logger.info("Object delete completed successfully")
        return {"success": True, "deleted": deleted_summary, "errors": errors}
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

def set_progress(username: str, percent: int, label: str = ""):
    """Update progress for the current operation."""
    try:
        ctx = get_user_ctx(username)
        ctx["progress"]["percent"] = max(0, min(100, percent))
        ctx["progress"]["label"] = label
        ctx["progress"]["active"] = True
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

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}