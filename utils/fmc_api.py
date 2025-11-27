import requests
import logging
import time
import yaml
import warnings
import random
from collections import deque
from typing import List, Dict, Any
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

# Suppress warnings
warnings.simplefilter("ignore", InsecureRequestWarning)

logger = logging.getLogger(__name__)

# --- Global auth and rate limit state ---
_auth_state = {
    "fmc_ip": None,
    "username": None,
    "password": None,
    "domain_uuid": None,
    "headers": None,
    "token_time": 0.0,
}

class SimpleRateLimiter:
    """Token-bucket-like limiter for requests per time window."""
    def __init__(self, max_calls: int, period_seconds: int):
        self.max_calls = max_calls
        self.period = period_seconds
        self.events = deque()

    def acquire(self):
        now = time.time()
        # Remove events older than period
        while self.events and (now - self.events[0]) > self.period:
            self.events.popleft()
        if len(self.events) >= self.max_calls:
            sleep_for = self.period - (now - self.events[0]) + 0.01
            if sleep_for > 0:
                logger.debug(f"Rate limit reached: sleeping for {sleep_for:.2f}s to respect API limits")
                time.sleep(sleep_for)
        # Record this event
        self.events.append(time.time())

# Keep below 120 GET/min with headroom
_GET_RATE_LIMITER = SimpleRateLimiter(max_calls=110, period_seconds=60)

# ---- Pretty logging helpers ----
def _log_pretty_table(title: str, headers: list, rows: list) -> None:
    """Log a simple ASCII table with a title. Rows are lists of strings."""
    try:
        headers = [str(h or "") for h in headers]
        rows = [[str(c) if c is not None else "" for c in r] for r in (rows or [])]
        widths = [len(h) for h in headers]
        for r in rows:
            for i, c in enumerate(r):
                if i < len(widths):
                    widths[i] = max(widths[i], len(c))
                else:
                    widths.append(len(c))
        def line(sep_left: str, sep_mid: str, sep_right: str, fill: str) -> str:
            parts = [fill * (w + 2) for w in widths]
            return sep_left + sep_mid.join(parts) + sep_right
        def row(vals: list) -> str:
            cells = []
            for i, w in enumerate(widths):
                v = vals[i] if i < len(vals) else ""
                cells.append(" " + v.ljust(w) + " ")
            return "|" + "|".join(cells) + "|"
        title_line = f"{title} (count={len(rows)})"
        logger.info(title_line)
        logger.info(line("+", "+", "+", "-"))
        logger.info(row(headers))
        logger.info(line("+", "+", "+", "="))
        for r in rows:
            logger.info(row(r))
        logger.info(line("+", "+", "+", "-"))
        # Force-flush all handlers to stream logs live to UI
        try:
            for h in logger.handlers:
                if hasattr(h, "flush"):
                    h.flush()
            # Also flush parent handlers if propagate is True
            if logger.propagate:
                plogger = logger.parent
                while plogger is not None:
                    for h in getattr(plogger, "handlers", []):
                        if hasattr(h, "flush"):
                            h.flush()
                    plogger = plogger.parent
        except Exception:
            pass
    except Exception:
        # Never break flows due to logging
        pass

def _set_auth_state(fmc_ip: str, username: str, password: str, domain_uuid: str, headers: dict):
    _auth_state.update({
        "fmc_ip": fmc_ip,
        "username": username,
        "password": password,
        "domain_uuid": domain_uuid,
        "headers": headers,
        "token_time": time.time(),
    })

def _ensure_token_valid():
    """Refresh the FMC token proactively (~25 min) or if missing."""
    # If we don't have auth state yet, nothing to do
    if not _auth_state.get("fmc_ip") or not _auth_state.get("username") or not _auth_state.get("password"):
        return
    token_age = time.time() - float(_auth_state.get("token_time") or 0)
    # FMC tokens typically expire at 30 minutes; refresh at 25 minutes
    if token_age >= 25 * 60 or not _auth_state.get("headers"):
        try:
            logger.info("Refreshing FMC auth token (proactive refresh)...")
            # Perform direct auth call (avoid wrapper to not recurse)
            AUTH_URL = f"{_auth_state['fmc_ip']}/api/fmc_platform/v1/auth/generatetoken"
            base_headers = {"Content-Type": "application/json"}
            resp = requests.post(
                AUTH_URL,
                headers=base_headers,
                auth=HTTPBasicAuth(_auth_state["username"], _auth_state["password"]),
                verify=False,
            )
            resp.raise_for_status()
            token = resp.headers.get("X-auth-access-token")
            if not token:
                raise Exception("Token refresh failed: No token received")
            domain_uuid = resp.headers.get("DOMAIN_UUID") or _auth_state.get("domain_uuid")
            headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
            _set_auth_state(_auth_state["fmc_ip"], _auth_state["username"], _auth_state["password"], domain_uuid, headers)
            logger.info("FMC token refreshed.")
        except Exception as ex:
            logger.error(f"Failed to refresh FMC auth token: {ex}")

def _fmc_request(method: str, url: str, *, json: dict = None, params: dict = None) -> requests.Response:
    """Centralized request handler with GET rate limiting, retries/backoff, and auto token refresh."""
    if method.upper() == "GET":
        _GET_RATE_LIMITER.acquire()

    _ensure_token_valid()
    max_retries = 1

    # Use stored headers if available so that refreshed tokens are used automatically
    headers = _auth_state.get("headers") or {"Content-Type": "application/json"}

    backoff_base = 1.0
    last_response = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.request(method=method.upper(), url=url, headers=headers, json=json, params=params, verify=False)
        except requests.exceptions.RequestException as e:
            # Network error: backoff and retry
            if attempt >= max_retries:
                raise
            sleep_for = min(backoff_base * (2 ** attempt), 60.0) + random.uniform(0, 0.25)
            logger.warning(f"Network error on {method} {url}: {e}. Retrying in {sleep_for:.2f}s (attempt {attempt+1}/{max_retries})")
            time.sleep(sleep_for)
            continue

        status = resp.status_code
        # Success
        if 200 <= status < 300:
            return resp

        # Unauthorized: try a one-time re-auth and retry
        if status in (401, 419):
            if attempt < max_retries:
                try:
                    logger.info("Received 401/419. Re-authenticating and retrying...")
                    _ensure_token_valid()  # proactive check
                    # Force re-auth using stored credentials
                    if _auth_state.get("fmc_ip") and _auth_state.get("username") and _auth_state.get("password"):
                        AUTH_URL = f"{_auth_state['fmc_ip']}/api/fmc_platform/v1/auth/generatetoken"
                        base_headers = {"Content-Type": "application/json"}
                        r = requests.post(
                            AUTH_URL,
                            headers=base_headers,
                            auth=HTTPBasicAuth(_auth_state["username"], _auth_state["password"]),
                            verify=False,
                        )
                        r.raise_for_status()
                        token = r.headers.get("X-auth-access-token")
                        if token:
                            domain_uuid = r.headers.get("DOMAIN_UUID") or _auth_state.get("domain_uuid")
                            new_headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
                            _set_auth_state(_auth_state["fmc_ip"], _auth_state["username"], _auth_state["password"], domain_uuid, new_headers)
                            headers = new_headers
                            continue
                except Exception as reauth_ex:
                    logger.error(f"Re-authentication failed: {reauth_ex}")
            # If re-auth failed or exhausted, return response for caller to handle
            return resp

        # Rate limited or server busy: honor Retry-After or exponential backoff
        if status in (429, 500, 502, 503, 504, 408):
            last_response = resp
            if attempt >= max_retries:
                break
            retry_after = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
            if retry_after:
                try:
                    sleep_for = float(retry_after)
                except ValueError:
                    sleep_for = min(backoff_base * (2 ** attempt), 60.0)
            else:
                sleep_for = min(backoff_base * (2 ** attempt), 60.0)
            sleep_for += random.uniform(0, 0.25)
            logger.warning(
                f"HTTP {status} on {method} {url}. Retrying in {sleep_for:.2f}s (attempt {attempt+1}/{max_retries})"
            )
            time.sleep(sleep_for)
            continue

        # Other statuses: return to let caller handle raise_for_status and error extraction
        return resp

    # Exhausted retries
    return last_response if last_response is not None else resp

def fmc_get(url: str) -> requests.Response:
    return _fmc_request("GET", url)

def fmc_post(url: str, payload: dict) -> requests.Response:
    return _fmc_request("POST", url, json=payload)

def fmc_put(url: str, payload: dict) -> requests.Response:
    return _fmc_request("PUT", url, json=payload)

def fmc_delete(url: str, payload: dict = None, params: dict = None) -> requests.Response:
    return _fmc_request("DELETE", url, json=payload, params=params)

def extract_error_description(response):
    try:
        error_data = response.json()
        return error_data.get("error", {}).get("messages", [{}])[0].get("description", "No description available")
    except Exception:
        return "No description available"

def authenticate(fmc_ip, username, password):
    
    AUTH_URL = f"{fmc_ip}/api/fmc_platform/v1/auth/generatetoken"
    headers = {"Content-Type": "application/json"}

    try:
        logger.info("Authenticating to FMC...")
        response = requests.post(AUTH_URL, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
        response.raise_for_status()

        token = response.headers.get("X-auth-access-token")
        if not token:
            raise Exception("Authentication failed: No token received")

        domain_uuid = response.headers.get("DOMAIN_UUID")
        if not domain_uuid:
            raise Exception("Authentication failed: No domain UUID received")

        headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
        # Store state for automatic refresh and retries
        _set_auth_state(fmc_ip, username, password, domain_uuid, headers)
        logger.info("Authentication successful.")
        return domain_uuid, headers

    except requests.exceptions.RequestException as e:
        description = extract_error_description(e.response) if e.response else str(e)
        logger.error(f"Authentication failed: {e}. Description: {description}")
        raise Exception("Authentication failed.")

def get_ftd_uuid(fmc_ip, headers, domain_uuid, ftd_name):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords?limit=1000"
    logger.info(f"Fetching FTD UUID for device: {ftd_name}")
    response = fmc_get(url)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch FTD UUID. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    devices = response.json().get('items', [])
    for device in devices:
        if device['name'] == ftd_name:
            logger.info(f"Found FTD UUID for {ftd_name}: {device['id']}")
            return device['id']
    logger.error(f"FMC device {ftd_name} not found.")
    raise Exception(f"FMC device {ftd_name} not found.")

def get_ftd_name_by_id(fmc_ip, headers, domain_uuid, ftd_uuid):
    """Return device name for a given FTD UUID."""
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}"
    logger.info(f"Fetching FTD name for UUID: {ftd_uuid}")
    response = fmc_get(url)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch FTD record. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    try:
        return (response.json() or {}).get("name")
    except Exception:
        return None

def check_if_device_is_standalone(fmc_ip, headers, domain_uuid, ftd_uuid):
    """
    Check if the FTD device is standalone (not part of HA pair or cluster).
    Returns True if standalone, False if part of HA/cluster.
    """
    try:
        # Check if device is part of an HA pair
        ha_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devicehapairs/ftddevicehapairs?limit=1000"
        ha_response = fmc_get(ha_url)
        if ha_response.status_code == 200:
            ha_pairs = ha_response.json().get("items", [])
            for ha_pair in ha_pairs:
                primary = ha_pair.get("primary", {})
                secondary = ha_pair.get("secondary", {})
                if (primary.get("id") == ftd_uuid or secondary.get("id") == ftd_uuid):
                    logger.info(f"Device {ftd_uuid} is part of HA pair, keeping neighborHaMode")
                    return False
        
        # Check if device is part of a cluster
        cluster_url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/deviceclusters/ftddevicecluster?limit=1000"
        cluster_response = fmc_get(cluster_url)
        if cluster_response.status_code == 200:
            clusters = cluster_response.json().get("items", [])
            for cluster in clusters:
                members = cluster.get("clusterMembers", [])
                for member in members:
                    if member.get("device", {}).get("id") == ftd_uuid:
                        logger.info(f"Device {ftd_uuid} is part of cluster, keeping neighborHaMode")
                        return False
        
        logger.info(f"Device {ftd_uuid} is standalone, removing neighborHaMode")
        return True
        
    except Exception as e:
        logger.warning(f"Could not determine device HA/cluster status: {e}. Assuming standalone.")
        return True

def get_interface_uuid_map(fmc_ip, headers, domain_uuid, ftd_uuid):
    interface_types = ["physicalinterfaces", "subinterfaces", "etherchannelinterfaces"]
    interface_map = {}

    for int_type in interface_types:
        url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/{int_type}?expanded=true&limit=1000"
        logger.info(f"Fetching {int_type}...")
        response = fmc_get(url)

        if response.status_code != 200:
            description = extract_error_description(response)
            logger.error(f"Failed to fetch {int_type}. Description: {description}")
            response.raise_for_status()

        items = response.json().get('items', [])
        logger.info(f"Found {len(items)} {int_type}(s).")

        for iface in items:
            ifname = iface.get('ifname')
            if ifname:
                interface_map[ifname] = iface['id']
                logger.info(f"Found interface: {ifname}, UUID: {iface['id']}")

    return interface_map

def get_vrf_uuid_by_name(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_name):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters?limit=1000"
    response = fmc_get(url)

    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch VRF UUID. Description: {description}")
        response.raise_for_status()

    vrfs = response.json().get('items', [])
    for vrf in vrfs:
        if vrf.get('name') == vrf_name:
            return vrf.get('id')

    logger.error(f"VRF {vrf_name} not found.")
    return None

def create_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_name, vrf_description, interfaces, interface_map):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters"
    payload = {
        "type": "VirtualRouter",
        "name": vrf_name,
        "description": vrf_description,
        "interfaces": [
            {"id": interface_map[iface['name']], "type": iface['type'], "name": iface['name']}
            for iface in interfaces
        ]
    }

    logger.info(f"Creating VRF {vrf_name}...")
    response = fmc_post(url, payload)

    if response.status_code != 201:
        description = extract_error_description(response)
        logger.error(f"Failed to create VRF {vrf_name}. Description: {description}")
        response.raise_for_status()

    logger.info(f"Created VRF {vrf_name} with status code {response.status_code}.")

def delete_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_uuid):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters/{vrf_uuid}"
    logger.info(f"Deleting VRF with UUID {vrf_uuid}...")
    response = fmc_delete(url)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to delete VRF {vrf_uuid}. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    logger.info(f"Deleted VRF with UUID {vrf_uuid} with status code {response.status_code}.")

def get_bgp_and_af_uuids(fmc_ip, headers, domain_uuid, ftd_uuid):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp?expanded=true&limit=1000"
    logger.info(f"Fetching BGP and address family UUIDs for FTD: {ftd_uuid}")
    response = fmc_get(url)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch BGP info. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    items = response.json().get("items", [])
    if not items:
        logger.error("No BGP configuration found on device.")
        raise Exception("No BGP configuration found on device.")
    bgp = items[0]
    bgp_uuid = bgp.get("id")
    af_ipv4_uuid = bgp.get("addressFamilyIPv4", {}).get("id")
    af_ipv6_uuid = bgp.get("addressFamilyIPv6", {}).get("id")
    logger.info(f"Fetched BGP UUID: {bgp_uuid}, IPv4 AF UUID: {af_ipv4_uuid}, IPv6 AF UUID: {af_ipv6_uuid}")
    return bgp_uuid, af_ipv4_uuid, af_ipv6_uuid, bgp  # Return the full BGP config as well

def remove_key_recursive(obj, key_to_remove):
    if isinstance(obj, dict):
        return {k: remove_key_recursive(v, key_to_remove)
                for k, v in obj.items() if k != key_to_remove}
    elif isinstance(obj, list):
        return [remove_key_recursive(item, key_to_remove) for item in obj]
    else:
        return obj

def update_bgp_peers(
    fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid, af_ipv4_uuid, af_ipv6_uuid,
    ipv4_peers=None, ipv6_peers=None, current_bgp_config=None
):
    # Start with the current config as the base payload
    payload = dict(current_bgp_config) if current_bgp_config else {"id": bgp_uuid}

    # Helper to merge neighbors by address (avoiding duplicates)
    def merge_neighbors(existing, new, addr_key):
        existing_map = {n[addr_key]: n for n in existing}
        for n in new:
            existing_map[n[addr_key]] = {
                **n,
                "neighborGeneral": {"shutdown": False, "enableAddress": True},
            }
        return list(existing_map.values())

    # IPv4
    if ipv4_peers is not None:
        af_ipv4 = payload.get("addressFamilyIPv4", {})
        af_ipv4["id"] = af_ipv4_uuid
        existing_v4 = af_ipv4.get("neighbors", [])
        merged_v4 = merge_neighbors(existing_v4, ipv4_peers, "ipv4Address")
        af_ipv4["neighbors"] = merged_v4
        payload["addressFamilyIPv4"] = af_ipv4

    # IPv6
    if ipv6_peers is not None:
        af_ipv6 = payload.get("addressFamilyIPv6", {})
        af_ipv6["id"] = af_ipv6_uuid
        existing_v6 = af_ipv6.get("neighbors", [])
        merged_v6 = merge_neighbors(existing_v6, ipv6_peers, "ipv6Address")
        af_ipv6["neighbors"] = merged_v6
        payload["addressFamilyIPv6"] = af_ipv6

    # Remove fields not accepted by PUT (if any, e.g., 'links')
    payload.pop("links", None)

    # Remove all 'maximumPaths' before sending
    payload = remove_key_recursive(payload, "maximumPaths")

    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp/{bgp_uuid}"
    logger.info(f"Sending PUT to {url} with merged BGP config")
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to update BGP peers. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully updated BGP peers. Status: {response.status_code}. Response: {response.text}")

def delete_bgp_peers(
    fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid, af_ipv4_uuid, af_ipv6_uuid,
    current_bgp_config, ipv4_peers=None, ipv6_peers=None
):
    payload = dict(current_bgp_config) if current_bgp_config else {"id": bgp_uuid}

    # Build sets of addresses to remove
    ipv4_to_remove = set(peer["ipv4Address"] for peer in (ipv4_peers or []))
    ipv6_to_remove = set(peer["ipv6Address"] for peer in (ipv6_peers or []))

    # Remove matching IPv4 neighbors
    if "addressFamilyIPv4" in payload and "neighbors" in payload["addressFamilyIPv4"]:
        payload["addressFamilyIPv4"]["neighbors"] = [
            n for n in payload["addressFamilyIPv4"]["neighbors"]
            if n.get("ipv4Address") not in ipv4_to_remove
        ]
        payload["addressFamilyIPv4"]["id"] = af_ipv4_uuid

    # Remove matching IPv6 neighbors
    if "addressFamilyIPv6" in payload and "neighbors" in payload["addressFamilyIPv6"]:
        payload["addressFamilyIPv6"]["neighbors"] = [
            n for n in payload["addressFamilyIPv6"]["neighbors"]
            if n.get("ipv6Address") not in ipv6_to_remove
        ]
        payload["addressFamilyIPv6"]["id"] = af_ipv6_uuid

    payload.pop("links", None)
    payload = remove_key_recursive(payload, "maximumPaths")

    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp/{bgp_uuid}"
    logger.info(f"Sending PUT to {url} to remove specified BGP neighbors but keep other config")
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to remove specified BGP peers. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully removed specified BGP peers. Status: {response.status_code}. Response: {response.text}")


def get_domains(fmc_ip: str, headers: dict):
    """Fetch list of FMC domains using platform info endpoint.

    API: GET /api/fmc_platform/v1/info/domain
    Returns list of items with at least id and name.
    """
    url = f"{fmc_ip}/api/fmc_platform/v1/info/domain"
    logger.info("Fetching FMC domains via /api/fmc_platform/v1/info/domain")
    resp = fmc_get(url)
    if resp.status_code != 200:
        description = extract_error_description(resp)
        logger.error(f"Failed to fetch domains. Status: {resp.status_code}. Description: {description}")
        resp.raise_for_status()
    items = resp.json().get("items", [])
    # Normalize: ensure each item has 'id' set to its UUID for UI convenience
    for d in items:
        if isinstance(d, dict) and not d.get("id") and d.get("uuid"):
            d["id"] = d["uuid"]
    logger.info(f"Found {len(items)} domain(s)")
    return items

def get_security_zones(fmc_ip: str, headers: dict, domain_uuid: str):
    """Fetch SecurityZone objects for the given domain (limit=1000, expanded=true)."""
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/securityzones?expanded=true&limit=1000"
    logger.info(f"Fetching SecurityZones for domain {domain_uuid}")
    resp = fmc_get(url)
    if resp.status_code != 200:
        description = extract_error_description(resp)
        logger.error(f"Failed to fetch SecurityZones. Status: {resp.status_code}. Description: {description}")
        resp.raise_for_status()
    items = resp.json().get("items", [])
    try:
        rows = [[(z.get("name") or ""), (z.get("interfaceMode") or ""), (z.get("id") or "") ] for z in (items or [])]
        _log_pretty_table(f"SecurityZones in domain {domain_uuid}", ["Name", "Mode", "UUID"], rows)
    except Exception:
        pass
    return items

def post_security_zone(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict):
    """Create a SecurityZone in the given domain.
    Minimal required fields: name, type=SecurityZone. interfaceMode is recommended by API.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/securityzones"
    body = dict(payload or {})
    body.setdefault("type", "SecurityZone")
    if not body.get("name"):
        raise ValueError("SecurityZone payload requires 'name'")
    logger.info(f"Creating SecurityZone {body.get('name')}")
    resp = fmc_post(url, body)
    if resp.status_code not in (200, 201):
        description = extract_error_description(resp)
        logger.error(f"Failed to create SecurityZone. Status: {resp.status_code}. Description: {description}")
        resp.raise_for_status()
    return resp.json()

def get_loopback_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching loopback interfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/loopbackinterfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch loopback interfaces. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("ifname") or it.get("ifName") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"LoopbackInterfaces for {ftd_name or ftd_uuid}", ["Name", "Ifname", "UUID"], rows)
    except Exception:
        pass
    post_payloads = []
    for item in items:
        payload = dict(item)
        payload.pop("links", None)
        payload.pop("metadata", None)
        post_payloads.append(payload)
    return post_payloads



def create_loopback_interface(fmc_ip, headers, domain_uuid, ftd_uuid, loopback_payload):
    """
    Create a loopback interface on the destination FTD.
    """
    # Remove managementOnly field if present
    loopback_payload.pop("managementOnly", None)
    
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/loopbackinterfaces"
    logger.info(f"Creating loopback interface {loopback_payload.get('ifname')}")
    response = fmc_post(url, loopback_payload)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to create loopback interface. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully created loopback interface {loopback_payload.get('ifname')}. Status: {response.status_code}")
    return response.json()

def get_all_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid):
    """
    Fetch all interfaces from the source FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/ftdallinterfaces?offset=0&expanded=true&limit=1000"
    logger.info(f"Fetching all interfaces for FTD: {ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def get_physical_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching PhysicalInterfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/physicalinterfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("ifname") or it.get("ifName") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"PhysicalInterfaces for {ftd_name or ftd_uuid}", ["Name", "Ifname", "UUID"], rows)
    except Exception:
        pass
    return items

def put_physical_interface(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/physicalinterfaces/{obj_id}"
    # Sanitize payload per requirements
    try:
        payload = dict(payload or {})
        payload.pop("macLearn", None)
        mode = payload.get("mode")
        if isinstance(mode, str) and mode.upper() == "INLINE":
            payload.pop("securityZone", None)
            payload["mode"] = "NONE"
        elif not mode:
            payload["mode"] = "NONE"
    except Exception:
        pass
    logger.info(f"Updating PhysicalInterface {payload.get('name')}")
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update PhysicalInterface: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully updated PhysicalInterface {payload.get('name')}. Status: {response.status_code}")
    return response.json()

def get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching EtherChannelInterfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/etherchannelinterfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"EtherChannelInterfaces for {ftd_name or ftd_uuid}", ["Name", "UUID"], rows)
    except Exception:
        pass
    return items

def post_etherchannel_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/etherchannelinterfaces"
    # Sanitize payload per requirements
    try:
        payload = dict(payload or {})
        payload.pop("macLearn", None)
        mode = payload.get("mode")
        if isinstance(mode, str) and mode.upper() == "INLINE":
            payload.pop("securityZone", None)
            payload["mode"] = "NONE"
        elif not mode:
            payload["mode"] = "NONE"
    except Exception:
        pass
    logger.info(f"Creating EtherChannelInterface {payload.get('name')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create EtherChannelInterface: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully created EtherChannelInterface {payload.get('name')}. Status: {response.status_code}")
    return response.json()

def get_subinterfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching SubInterfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/subinterfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        def _parent(it):
            p = (it.get("parentInterface") or {})
            return p.get("name") or p.get("ifname") or p.get("ifName") or ""
        rows = [[(it.get("name") or ""), (it.get("ifname") or it.get("ifName") or ""), str(it.get("subIntfId") or ""), _parent(it), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"SubInterfaces for {ftd_name or ftd_uuid}", ["Name", "Ifname", "SubId", "Parent", "UUID"], rows)
    except Exception:
        pass
    return items

def post_subinterface(fmc_ip, headers, domain_uuid, ftd_uuid, payload, bulk=False):
    """
    Create subinterface(s) on FTD device.
    
    Args:
        payload: Single subinterface dict or list of subinterface dicts for bulk operation
        bulk: Boolean indicating whether to use bulk operation (default: False)
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/subinterfaces"
    if bulk:
        url += "?bulk=true"
        if not isinstance(payload, list):
            payload = [payload]
        # Sanitize each item and enforce mode rules
        sanitized_list = []
        for item in payload:
            try:
                p = dict(item or {})
                p.pop("id", None)
                p.pop("links", None)
                p.pop("metadata", None)
                p.pop("macLearn", None)
                mode = p.get("mode")
                if isinstance(mode, str) and mode.upper() == "INLINE":
                    p.pop("securityZone", None)
                    p["mode"] = "NONE"
                elif not mode:
                    p["mode"] = "NONE"
                sanitized_list.append(p)
            except Exception:
                sanitized_list.append(item)
        payload = sanitized_list
        logger.info(f"Creating {len(payload)} SubInterfaces in bulk")
    else:
        # Sanitize single payload and enforce mode rules
        payload = dict(payload or {})
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        payload.pop("macLearn", None)
        mode = payload.get("mode")
        if isinstance(mode, str) and mode.upper() == "INLINE":
            payload.pop("securityZone", None)
            payload["mode"] = "NONE"
        elif not mode:
            payload["mode"] = "NONE"
        subintf_name = f"{payload.get('name')}.{payload.get('subIntfId')}"
        logger.info(f"Creating SubInterface {subintf_name}")

    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        desc = extract_error_description(response)
        logger.error(f"Failed to create SubInterface(s). Status: {response.status_code}. Description: {desc}")
        raise Exception(desc)
    if bulk:
        try:
            count = len(payload) if isinstance(payload, list) else 1
        except Exception:
            count = 1
        logger.info(f"Successfully created {count} SubInterface(s). Status: {response.status_code}")
    else:
        subintf_name = f"{(payload or {}).get('name')}.{(payload or {}).get('subIntfId')}"
        logger.info(f"Successfully created SubInterface {subintf_name}. Status: {response.status_code}")
    return response.json()

def get_vti_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching VTIInterfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/virtualtunnelinterfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("ifname") or it.get("ifName") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"VTIInterfaces for {ftd_name or ftd_uuid}", ["Name", "Ifname", "UUID"], rows)
    except Exception:
        pass
    return items

def post_vti_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload, bulk=False):
    """
    Create VTI interface(s) on FTD device.
    
    Args:
        payload: Single VTI interface dict or list of VTI interface dicts for bulk operation
        bulk: Boolean indicating whether to use bulk operation (default: False)
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/virtualtunnelinterfaces"
    if bulk:
        url += "?bulk=true"
        if not isinstance(payload, list):
            payload = [payload]
        # Sanitize each item: remove fields FMC rejects
        sanitized = []
        for item in payload:
            item = dict(item or {})
            item.pop("id", None)
            item.pop("managementOnly", None)
            item.pop("links", None)
            item.pop("metadata", None)
            sanitized.append(item)
        payload = sanitized
        logger.info(f"Creating {len(payload)} VTI Interfaces in bulk")
    else:
        # Sanitize single payload
        payload = dict(payload or {})
        payload.pop("id", None)
        payload.pop("managementOnly", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        logger.info(f"Creating VTIInterface {payload.get('name')}")
    
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        desc = extract_error_description(response)
        logger.error(f"Failed to create VTIInterface(s). Status: {response.status_code}. Description: {desc}")
        raise Exception(desc)
    if bulk:
        try:
            count = len(payload) if isinstance(payload, list) else 1
        except Exception:
            count = 1
        logger.info(f"Successfully created {count} VTI Interface(s). Status: {response.status_code}")
    else:
        logger.info(f"Successfully created VTIInterface {(payload or {}).get('name')}. Status: {response.status_code}")
    return response.json()

def get_bfd_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bfdpolicies?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching BFD policies for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching BFD policies for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        def _intf(it):
            j = (it.get("interface") or {})
            return (j.get("name") or ""), (j.get("id") or "")
        rows = []
        for it in (items or []):
            nm, iid = _intf(it)
            rows.append([nm, iid, (it.get("id") or "")])
        _log_pretty_table(
            f"BFD Policies for {'VRF ' + (vrf_name or str(vrf_id)) if vrf_id else (ftd_name or ftd_uuid)}",
            ["Interface", "InterfaceUUID", "BFDUUID"],
            rows,
        )
    except Exception:
        pass
    return items

def post_bfd_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bfdpolicies")
    if vrf_id:
        logger.info(f"Creating BFD policy for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating BFD policy for FTD")
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "bfd", ui_auth_values=ui_auth_values)
    try:
        intf = (payload or {}).get("interface") or {}
        logger.info(
            f"BFD payload interface: type={intf.get('type')} name={intf.get('name')} ifname={intf.get('ifname')} id={intf.get('id')}"
        )
    except Exception:
        pass
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create BFDPolicy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv2_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfv2routes?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching OSPFv2 policies for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching OSPFv2 policies for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        # Policies generally include processId under 'id' or processConfiguration. Show processId/RouterId when present.
        def _pid(it):
            return str(it.get("processId") or it.get("id") or "")
        def _rid(it):
            return str(((it.get("processConfiguration") or {}).get("routerId")) or "")
        rows = [[_pid(it), _rid(it), (it.get("id") or "")] for it in (items or [])]
        _log_pretty_table(
            f"OSPFv2 Policies for {'VRF ' + (vrf_name or str(vrf_id)) if vrf_id else (ftd_name or ftd_uuid)}",
            ["ProcessId", "RouterId", "UUID"],
            rows,
        )
    except Exception:
        pass
    return items

def post_ospfv2_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "ospfv2", ui_auth_values=ui_auth_values)
    
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfv2routes")
    if vrf_id:
        logger.info(f"Creating OSPFv2 policy for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating OSPFv2 policy for FTD")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv2 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfinterface?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching OSPFv2 interfaces for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching OSPFv2 interfaces for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        def _dev(it):
            d = (it.get("deviceInterface") or {})
            return (d.get("name") or ""), (d.get("id") or "")
        rows = []
        for it in (items or []):
            nm, did = _dev(it)
            rows.append([nm, did, (it.get("id") or "")])
        _log_pretty_table(
            f"OSPFv2 Interfaces for {'VRF ' + (vrf_name or str(vrf_id)) if vrf_id else (ftd_name or ftd_uuid)}",
            ["deviceInterface", "deviceIntfUUID", "OSPFv2IntfUUID"],
            rows,
        )
    except Exception:
        pass
    return items

def post_ospfv2_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "ospfv2interface", ui_auth_values=ui_auth_values)
    
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfinterface")
    if vrf_id:
        logger.info(f"Creating OSPFv2 interface for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating OSPFv2 interface for FTD")
    # Debug: log deviceInterface details to verify remap
    try:
        dintf = (payload or {}).get("deviceInterface") or {}
        logger.info(
            f"OSPFv2 payload deviceInterface: type={dintf.get('type')} name={dintf.get('name')} ifname={dintf.get('ifname')} id={dintf.get('id')}"
        )
    except Exception:
        pass
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv2 interface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv3_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching OSPFv3 policies for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3routes?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ospfv3_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, ui_auth_values=None):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3routes"
    logger.info(f"Creating OSPFv3 policy with processId {payload.get('processId')}")
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "ospfv3", ui_auth_values=ui_auth_values)
    try:
        pc = (payload or {}).get("processConfiguration") or {}
        timers = pc.get("timers") or {}
        timers["lsaThrottleTimer"] = {
            "initialDelay": 5000,
            "minimumDelay": 10000,
            "maximumDelay": 10000
        }
        timers["spfThrottleTimer"] = {
            "initialDelay": 5000,
            "minimumHoldTime": 10000,
            "maximumWaitTime": 10000
        }
        pc["timers"] = timers
        payload["processConfiguration"] = pc
        logger.info(f"OSPFv3 timers overridden: lsaThrottleTimer={timers.get('lsaThrottleTimer')}, spfThrottleTimer={timers.get('spfThrottleTimer')}")
    except Exception:
        pass
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv3 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching OSPFv3 interfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3interfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        def _dev(it):
            d = (it.get("deviceInterface") or {})
            return (d.get("name") or ""), (d.get("id") or "")
        rows = []
        for it in (items or []):
            nm, did = _dev(it)
            rows.append([nm, did, (it.get("id") or "")])
        _log_pretty_table(
            f"OSPFv3 Interfaces for {ftd_name or ftd_uuid}",
            ["deviceInterface", "deviceIntfUUID", "OSPFv3IntfUUID"],
            rows,
        )
    except Exception:
        pass
    return items

def post_ospfv3_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload, ui_auth_values=None):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3interfaces"
    logger.info(f"Creating OSPFv3 interface for deviceInterface {payload.get('deviceInterface', {}).get('name')}")
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "ospfv3interface", ui_auth_values=ui_auth_values)
    # Debug: log auth algorithm and key lengths to diagnose FMC validation errors
    try:
        _auth = payload.get("authentication", {}) or {}
        _alg = _auth.get("authentication")
        _ak = _auth.get("authKey")
        _enc = (_auth.get("encryption", {}) or {}).get("encryptionKey")
        ak_len = len(_ak) if isinstance(_ak, str) else None
        enc_len = len(_enc) if isinstance(_enc, str) else None
        logger.info(
            f"OSPFv3 intf auth debug: alg={_alg}, authKey_len={ak_len}, encKey_len={enc_len}, intf={payload.get('deviceInterface', {}).get('name')}"
        )
    except Exception:
        pass
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv3 interface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_eigrp_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all EIGRP policies for the given FTD.
    """
    logger.info(f"Fetching EIGRP policies for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/eigrproutes?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def post_eigrp_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, ui_auth_values=None):
    """
    Creates an EIGRP policy on the destination FTD.
    """
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "eigrp", ui_auth_values=ui_auth_values)
    
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/eigrproutes"
    logger.info(f"Creating EIGRP policy with asNumber {payload.get('asNumber')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create EIGRP policy: {response.text}")
        response.raise_for_status()
    return response.json()

# ======= Helper functions for redistribution handling =======

def has_redistribute_protocols(payload):
    """Check if a routing protocol payload has redistributeProtocols configured."""
    if not isinstance(payload, dict):
        return False
    
    # Check direct redistributeProtocols (OSPF, EIGRP)
    if payload.get("redistributeProtocols"):
        return True
    
    # Check within address families (BGP)
    for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
        af = payload.get(af_key)
        if isinstance(af, dict) and af.get("redistributeProtocols"):
            return True
    
    return False

def strip_redistribute_protocols(payload):
    """
    Create a copy of payload with redistributeProtocols removed.
    Returns tuple: (clean_payload, redistribution_data)
    """
    import copy
    clean = copy.deepcopy(payload)
    redist_data = {}
    
    # Strip direct redistributeProtocols (OSPF, EIGRP)
    if "redistributeProtocols" in clean:
        redist_data["redistributeProtocols"] = clean.pop("redistributeProtocols")
    
    # Strip from address families (BGP)
    for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
        if af_key in clean and isinstance(clean[af_key], dict):
            if "redistributeProtocols" in clean[af_key]:
                if af_key not in redist_data:
                    redist_data[af_key] = {}
                redist_data[af_key]["redistributeProtocols"] = clean[af_key].pop("redistributeProtocols")
    
    return clean, redist_data

def restore_redistribute_protocols(payload, redist_data):
    """Restore redistributeProtocols to a payload."""
    import copy
    updated = copy.deepcopy(payload)
    
    # Restore direct redistributeProtocols
    if "redistributeProtocols" in redist_data:
        updated["redistributeProtocols"] = redist_data["redistributeProtocols"]
    
    # Restore to address families
    for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
        if af_key in redist_data and isinstance(redist_data[af_key], dict):
            if af_key not in updated:
                updated[af_key] = {}
            if "redistributeProtocols" in redist_data[af_key]:
                updated[af_key]["redistributeProtocols"] = redist_data[af_key]["redistributeProtocols"]
    
    return updated

# ======= PUT functions for updating routing protocols =======

def put_bgp_policy(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    """Update an existing BGP policy."""
    # Replace authentication values before PUT
    payload = replace_masked_auth_values(payload, "bgp", ui_auth_values=ui_auth_values)
    
    # Remove read-only fields that FMC doesn't accept in PUT
    payload.pop("links", None)
    payload.pop("metadata", None)
    
    # Check if device is standalone (not in HA pair or cluster)
    is_standalone = check_if_device_is_standalone(fmc_ip, headers, domain_uuid, ftd_uuid)
    
    if is_standalone:
        # Remove neighborHaMode from all neighbors if destination FTD is standalone
        def remove_neighbor_ha_mode(obj):
            if isinstance(obj, dict):
                if "neighborHaMode" in obj:
                    obj.pop("neighborHaMode", None)
                for value in obj.values():
                    remove_neighbor_ha_mode(value)
            elif isinstance(obj, list):
                for item in obj:
                    remove_neighbor_ha_mode(item)
        remove_neighbor_ha_mode(payload)
    
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, f"bgp/{obj_id}")
    # Remove deprecated maximumPaths before PUT
    if "addressFamilyIPv4" in payload and isinstance(payload["addressFamilyIPv4"], dict):
        payload["addressFamilyIPv4"].pop("maximumPaths", None)
    if "addressFamilyIPv6" in payload and isinstance(payload["addressFamilyIPv6"], dict):
        payload["addressFamilyIPv6"].pop("maximumPaths", None)
    
    if vrf_id:
        logger.info(f"Updating BGP policy {obj_id} for VRF {vrf_name or vrf_id} with redistribution")
    else:
        logger.info(f"Updating BGP policy {obj_id} with redistribution")
    
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update BGP policy: {response.text}")
        response.raise_for_status()
    return response.json()

def put_ospfv2_policy(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    """Update an existing OSPFv2 policy."""
    payload = replace_masked_auth_values(payload, "ospfv2", ui_auth_values=ui_auth_values)
    
    # Remove read-only fields that FMC doesn't accept in PUT
    payload.pop("links", None)
    payload.pop("metadata", None)
    
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, f"ospfv2routes/{obj_id}")
    
    if vrf_id:
        logger.info(f"Updating OSPFv2 policy {obj_id} for VRF {vrf_name or vrf_id} with redistribution")
    else:
        logger.info(f"Updating OSPFv2 policy {obj_id} with redistribution")
    
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update OSPFv2 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def put_ospfv3_policy(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload, ui_auth_values=None):
    """Update an existing OSPFv3 policy."""
    payload = replace_masked_auth_values(payload, "ospfv3", ui_auth_values=ui_auth_values)
    
    # Remove read-only fields that FMC doesn't accept in PUT
    payload.pop("links", None)
    payload.pop("metadata", None)
    
    # Apply the same timer overrides as in post_ospfv3_policy
    try:
        pc = (payload or {}).get("processConfiguration") or {}
        timers = pc.get("timers") or {}
        timers["lsaThrottleTimer"] = {
            "initialDelay": 5000,
            "minimumDelay": 10000,
            "maximumDelay": 10000
        }
        timers["spfThrottleTimer"] = {
            "initialDelay": 5000,
            "minimumHoldTime": 10000,
            "maximumWaitTime": 10000
        }
        pc["timers"] = timers
        payload["processConfiguration"] = pc
        logger.info(f"OSPFv3 timers overridden for PUT: lsaThrottleTimer={timers.get('lsaThrottleTimer')}, spfThrottleTimer={timers.get('spfThrottleTimer')}")
    except Exception:
        pass
    
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3routes/{obj_id}"
    logger.info(f"Updating OSPFv3 policy {obj_id} with redistribution")
    
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update OSPFv3 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def put_eigrp_policy(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload, ui_auth_values=None):
    """Update an existing EIGRP policy."""
    payload = replace_masked_auth_values(payload, "eigrp", ui_auth_values=ui_auth_values)
    
    # Remove read-only fields that FMC doesn't accept in PUT
    payload.pop("links", None)
    payload.pop("metadata", None)
    
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/eigrproutes/{obj_id}"
    logger.info(f"Updating EIGRP policy {obj_id} with redistribution")
    
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update EIGRP policy: {response.text}")
        response.raise_for_status()
    return response.json()

def put_bfd_policy(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    """Update an existing BFD policy."""
    payload = replace_masked_auth_values(payload, "bfd", ui_auth_values=ui_auth_values)
    
    # Remove read-only fields that FMC doesn't accept in PUT
    payload.pop("links", None)
    payload.pop("metadata", None)
    
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, f"bfdpolicies/{obj_id}")
    
    if vrf_id:
        logger.info(f"Updating BFD policy {obj_id} for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Updating BFD policy {obj_id}")
    
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update BFD policy: {response.text}")
        response.raise_for_status()
    return response.json()

def update_interface_ids(
    obj,
    dest_phys_map,
    dest_etherchannel_map,
    dest_subint_map,
    dest_vti_map,
    dest_loopback_map=None,
    dest_bridge_map=None,
):
    """
    Recursively update interface 'id' fields in the given object using the destination interface maps.
    Supports: PhysicalInterface, EtherChannelInterface, SubInterface, VTIInterface, LoopbackInterface, BridgeGroupInterface.
    """
    valid_types = {
        "PhysicalInterface",
        "EtherChannelInterface",
        "SubInterface",
        "VTIInterface",
        "LoopbackInterface",
        "BridgeGroupInterface",
    }
    # local normalizer for broader matching
    def _norm(s: str) -> str:
        try:
            k = str(s).strip()
            return k.lower().replace("-", "").replace("_", "").replace(" ", "")
        except Exception:
            return str(s)

    if isinstance(obj, dict):
        # Only update if this dict is a supported interface reference
        if "type" in obj and "name" in obj and obj["type"] in valid_types:
            intf_type = obj["type"]
            name = obj["name"]
            ifname = obj.get("ifname")
            old_id = obj.get("id")
            if intf_type == "PhysicalInterface":
                new_id = dest_phys_map.get(name) or (dest_phys_map.get(ifname) if ifname else None)
            elif intf_type == "EtherChannelInterface":
                new_id = dest_etherchannel_map.get(name) or (dest_etherchannel_map.get(ifname) if ifname else None)
            elif intf_type == "SubInterface":
                # Build a reliable parent.subId key. If name already includes .subId, strip it to get parent.
                sub_id_val = obj.get("subIntfId")
                parent_name = None
                if isinstance(name, str) and "." in name:
                    try:
                        parent_name, maybe_sub = name.rsplit(".", 1)
                        # if trailing token is numeric and equals subIntfId, treat left as parent
                        if not (maybe_sub.isdigit() and (sub_id_val is None or int(maybe_sub) == int(sub_id_val))):
                            parent_name = None  # do not trust split
                    except Exception:
                        parent_name = None
                if not parent_name:
                    parent_name = name
                subintf_key = f"{parent_name}.{sub_id_val}" if (sub_id_val is not None) else name
                # Prefer ifname (usually unique/name-if), then parent.subId, then name
                new_id = (
                    (dest_subint_map.get(ifname) if ifname else None)
                    or dest_subint_map.get(subintf_key)
                    or dest_subint_map.get(name)
                )
                # Fallback: parse name pattern like "Parent.123" when subIntfId not present
                if not new_id and isinstance(name, str) and "." in name:
                    try:
                        parent, subid_part = name.rsplit(".", 1)
                        if subid_part.isdigit():
                            parsed_key = f"{parent}.{int(subid_part)}"
                            new_id = dest_subint_map.get(parsed_key) or dest_subint_map.get(name)
                    except Exception:
                        pass
            elif intf_type == "VTIInterface":
                new_id = dest_vti_map.get(name) or (dest_vti_map.get(ifname) if ifname else None)
            elif intf_type == "LoopbackInterface" and dest_loopback_map is not None:
                new_id = dest_loopback_map.get(name) or (dest_loopback_map.get(ifname) if ifname else None)
            elif intf_type == "BridgeGroupInterface" and dest_bridge_map is not None:
                new_id = dest_bridge_map.get(name)
            else:
                new_id = None
            # Try lowercase and normalized keys if still not found
            if not new_id:
                candidates = []
                if intf_type == "SubInterface":
                    candidates = [subintf_key, name, ifname]
                else:
                    candidates = [name, ifname]
                candidates = [c for c in candidates if isinstance(c, str) and c]
                alt_keys = []
                for c in candidates:
                    alt_keys.extend([c.lower(), _norm(c)])
                maps = {
                    "PhysicalInterface": dest_phys_map,
                    "EtherChannelInterface": dest_etherchannel_map,
                    "SubInterface": dest_subint_map,
                    "VTIInterface": dest_vti_map,
                    "LoopbackInterface": dest_loopback_map or {},
                    "BridgeGroupInterface": dest_bridge_map or {},
                }
                m = maps.get(intf_type, {}) or {}
                for k in alt_keys:
                    if k in m:
                        new_id = m.get(k)
                        break

            if new_id:
                obj["id"] = new_id
                try:
                    logger.info(
                        f"Interface remap: type={intf_type} name={name} ifname={ifname} old_id={old_id} -> new_id={new_id}"
                    )
                except Exception:
                    pass
            else:
                # Provide helpful diagnostics on miss
                tried = []
                if intf_type == "SubInterface":
                    tried.append(subintf_key)
                    tried.append(name)
                    if ifname:
                        tried.append(ifname)
                else:
                    tried.extend([name, ifname] if ifname else [name])
                try:
                    logger.warning(
                        f"Interface not found on destination FTD: type={intf_type} name={name} ifname={ifname} tried_keys={list(filter(None, tried))}"
                    )
                except Exception:
                    logger.warning(f"Interface {name} of type {intf_type} not found on destination FTD.")
        # Recurse into all dict values
        for v in obj.values():
            update_interface_ids(
                v,
                dest_phys_map,
                dest_etherchannel_map,
                dest_subint_map,
                dest_vti_map,
                dest_loopback_map,
                dest_bridge_map,
            )
    elif isinstance(obj, list):
        for item in obj:
            update_interface_ids(
                item,
                dest_phys_map,
                dest_etherchannel_map,
                dest_subint_map,
                dest_vti_map,
                dest_loopback_map,
                dest_bridge_map,
            )

def get_pbr_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all Policy-Based Routing (PBR) policies for the given FTD.
    """
    logger.info(f"Fetching PBR policies for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/policybasedroutes?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def post_pbr_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, bulk=False):
    """
    Create Policy-Based Routing (PBR) policy/policies on FTD device.
    
    Args:
        payload: Single PBR policy dict or list of PBR policy dicts for bulk operation
        bulk: Boolean indicating whether to use bulk operation (default: False)
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/policybasedroutes"
    if bulk:
        url += "?bulk=true"
        if not isinstance(payload, list):
            payload = [payload]
        logger.info(f"Creating {len(payload)} PBR policies in bulk")
    else:
        logger.info(f"Creating PBR policy")
    
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create PBR policy/policies: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ipv4_static_routes(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv4staticroutes?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching IPv4 static routes for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching IPv4 static routes for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ipv4_static_route(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None, bulk=False):
    """
    Create IPv4 static route(s) on FTD device.
    
    Args:
        payload: Single route dict or list of route dicts for bulk operation
        bulk: Boolean indicating whether to use bulk operation (default: False)
    """
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv4staticroutes")
    if bulk:
        url += "?bulk=true"
        if not isinstance(payload, list):
            payload = [payload]
        if vrf_id:
            logger.info(f"Creating {len(payload)} IPv4 static routes in bulk for VRF {vrf_name or vrf_id}")
        else:
            logger.info(f"Creating {len(payload)} IPv4 static routes in bulk for FTD")
    else:
        if vrf_id:
            logger.info(f"Creating IPv4 static route for VRF {vrf_name or vrf_id}")
        else:
            logger.info(f"Creating IPv4 static route for FTD")
    
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create IPv4 static route(s): {response.text}")
        response.raise_for_status()
    return response.json()

def get_ipv6_static_routes(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv6staticroutes?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching IPv6 static routes for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching IPv6 static routes for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

# -------------------- Device/HA/Cluster Delete Helpers --------------------
def delete_devices_bulk(fmc_ip: str, headers: dict, domain_uuid: str, device_ids: list):
    """Bulk unregister devices from FMC using devicerecords bulk delete.

    API: DELETE /api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords?bulk=true&filter=ids:id1,id2
    """
    if not device_ids:
        return {"success": True, "message": "No device IDs provided", "deleted": 0}
    ids_csv = ",".join(device_ids)
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords"
    params = {"bulk": "true", "filter": f"ids:{ids_csv}"}
    logger.info(f"Bulk deleting {len(device_ids)} device(s): {ids_csv}")
    resp = fmc_delete(url, params=params)
    if resp.status_code not in [200, 202, 204]:
        description = extract_error_description(resp)
        logger.error(f"Bulk delete failed ({resp.status_code}): {description}")
        resp.raise_for_status()
    try:
        body = resp.json()
    except Exception:
        body = {"status_code": resp.status_code}
    logger.info(f"Bulk delete response: {body}")
    return body

def delete_ha_pair(fmc_ip: str, headers: dict, domain_uuid: str, object_id: str):
    """Delete a specific FTD HA pair by ID.

    API: DELETE /api/fmc_config/v1/domain/{domainUUID}/devicehapairs/ftddevicehapairs/{objectId}
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devicehapairs/ftddevicehapairs/{object_id}"
    logger.info(f"Deleting FTD HA pair {object_id}")
    resp = fmc_delete(url)
    if resp.status_code not in [200, 202, 204]:
        description = extract_error_description(resp)
        logger.error(f"Delete HA pair failed ({resp.status_code}): {description}")
        resp.raise_for_status()
    return {"status_code": resp.status_code}

def delete_cluster(fmc_ip: str, headers: dict, domain_uuid: str, object_id: str):
    """Delete a specific FTD Cluster by ID.

    API: DELETE /api/fmc_config/v1/domain/{domainUUID}/deviceclusters/ftddevicecluster/{objectId}
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/deviceclusters/ftddevicecluster/{object_id}"
    logger.info(f"Deleting FTD Cluster {object_id}")
    resp = fmc_delete(url)
    if resp.status_code not in [200, 202, 204]:
        description = extract_error_description(resp)
        logger.error(f"Delete Cluster failed ({resp.status_code}): {description}")
        resp.raise_for_status()
    return {"status_code": resp.status_code}

# -------------------- Interface Delete Helpers --------------------
def _bulk_or_iterative_delete(base_url: str, headers: dict, ids: list, type_name: str = None):
    """Attempt bulk delete with ?bulk=true and JSON body; if that fails, fallback to per-ID DELETE.

    Returns dict with counts and any errors encountered.
    """
    result = {"requested": len(ids), "deleted": 0, "errors": []}
    if not ids:
        return result
    # Try bulk first
    try:
        body = [{"id": i, **({"type": type_name} if type_name else {})} for i in ids]
        resp = fmc_delete(f"{base_url}?bulk=true", payload=body)
        if resp.status_code in (200, 202, 204):
            result["deleted"] = len(ids)
            return result
        else:
            # Log and fall back
            try:
                desc = extract_error_description(resp)
            except Exception:
                desc = resp.text
            logger.warning(f"Bulk delete not supported or failed at {base_url}: {desc}. Falling back to per-ID delete")
    except Exception as e:
        logger.warning(f"Bulk delete attempt raised exception at {base_url}: {e}. Falling back to per-ID delete")
    # Per ID
    for i in ids:
        try:
            r = fmc_delete(f"{base_url}/{i}")
            if r.status_code in (200, 202, 204):
                result["deleted"] += 1
            else:
                desc = extract_error_description(r)
                result["errors"].append({"id": i, "status": r.status_code, "error": desc})
        except Exception as ex:
            result["errors"].append({"id": i, "error": str(ex)})
    return result

def delete_loopback_interfaces(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/loopbackinterfaces"
    logger.info(f"Deleting {len(ids)} LoopbackInterface(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="LoopbackInterface")

def delete_physical_interfaces(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/physicalinterfaces"
    logger.info(f"Deleting {len(ids)} PhysicalInterface(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="PhysicalInterface")

def delete_etherchannel_interfaces(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/etherchannelinterfaces"
    logger.info(f"Deleting {len(ids)} EtherChannelInterface(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="EtherChannelInterface")

def delete_subinterfaces(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/subinterfaces"
    logger.info(f"Deleting {len(ids)} SubInterface(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="SubInterface")

def delete_inline_sets(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/inlinesets"
    logger.info(f"Deleting {len(ids)} InlineSet(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="InlineSet")

def delete_bridge_group_interfaces(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/bridgegroupinterfaces"
    logger.info(f"Deleting {len(ids)} BridgeGroupInterface(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="BridgeGroupInterface")

def delete_security_zones(fmc_ip: str, headers: dict, domain_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/securityzones"
    logger.info(f"Deleting {len(ids)} SecurityZone(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="SecurityZone")

def delete_vti_interfaces(fmc_ip: str, headers: dict, domain_uuid: str, ftd_uuid: str, ids: list):
    base = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/virtualtunnelinterfaces"
    logger.info(f"Deleting {len(ids)} VTIInterface(s)")
    return _bulk_or_iterative_delete(base, headers, ids, type_name="VTIInterface")

def post_ipv6_static_route(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None, bulk=False):
    """
    Create IPv6 static route(s) on FTD device.
    
    Args:
        payload: Single route dict or list of route dicts for bulk operation
        bulk: Boolean indicating whether to use bulk operation (default: False)
    """
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv6staticroutes")
    if bulk:
        url += "?bulk=true"
        if not isinstance(payload, list):
            payload = [payload]
        if vrf_id:
            logger.info(f"Creating {len(payload)} IPv6 static routes in bulk for VRF {vrf_name or vrf_id}")
        else:
            logger.info(f"Creating {len(payload)} IPv6 static routes in bulk for FTD")
    else:
        if vrf_id:
            logger.info(f"Creating IPv6 static route for VRF {vrf_name or vrf_id}")
        else:
            logger.info(f"Creating IPv6 static route for FTD")
    
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create IPv6 static route(s): {response.text}")
        response.raise_for_status()
    return response.json()

def get_bgp_general_settings(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all BGP general settings for the given FTD.
    """
    logger.info(f"Fetching BGP general settings for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgpgeneralsettings?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def post_bgp_general_settings(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates BGP general settings on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgpgeneralsettings"
    logger.info(f"Creating BGP general settings with asNumber {payload.get('asNumber')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create BGP general settings: {response.text}")
        response.raise_for_status()
    return response.json()

def get_bgp_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bgp?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching BGP policies for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching BGP policies for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        def _asn(it):
            return str(it.get("asNumber") or (it.get("generalSettings") or {}).get("asNumber") or "")
        rows = [[_asn(it), (it.get("id") or "")] for it in (items or [])]
        _log_pretty_table(
            f"BGP Policies for {'VRF ' + (vrf_name or str(vrf_id)) if vrf_id else (ftd_name or ftd_uuid)}",
            ["AS Number", "UUID"],
            rows,
        )
    except Exception:
        pass
    return items

def post_bgp_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None, ui_auth_values=None):
    # Replace authentication values before POST
    payload = replace_masked_auth_values(payload, "bgp", ui_auth_values=ui_auth_values)
    
    # Check if device is standalone (not in HA pair or cluster)
    is_standalone = check_if_device_is_standalone(fmc_ip, headers, domain_uuid, ftd_uuid)
    
    if is_standalone:
        # Remove neighborHaMode from all neighbors if destination FTD is standalone
        # This field is only supported on HA pairs, not standalone devices
        def remove_neighbor_ha_mode(obj):
            if isinstance(obj, dict):
                # Remove neighborHaMode from neighbor configurations
                if "neighborHaMode" in obj:
                    obj.pop("neighborHaMode", None)
                # Recurse into all dict values
                for value in obj.values():
                    remove_neighbor_ha_mode(value)
            elif isinstance(obj, list):
                for item in obj:
                    remove_neighbor_ha_mode(item)
        
        # Remove neighborHaMode from the entire payload
        remove_neighbor_ha_mode(payload)
    
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bgp")
    # Remove deprecated maximumPaths and address family IDs before POST
    if "addressFamilyIPv4" in payload and isinstance(payload["addressFamilyIPv4"], dict):
        payload["addressFamilyIPv4"].pop("maximumPaths", None)
        # Remove address family ID - let FMC assign new IDs
        payload["addressFamilyIPv4"].pop("id", None)
    if "addressFamilyIPv6" in payload and isinstance(payload["addressFamilyIPv6"], dict):
        payload["addressFamilyIPv6"].pop("maximumPaths", None)
        # Remove address family ID - let FMC assign new IDs
        payload["addressFamilyIPv6"].pop("id", None)
    if vrf_id:
        logger.info(f"Creating BGP policy for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating BGP policy for FTD")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create BGP policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ecmp_zones(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ecmpzones?expanded=true&limit=1000")
    if vrf_id:
        logger.info(f"Fetching ECMP zones for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching ECMP zones for FTD: {ftd_name or ftd_uuid}")
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(
            f"ECMP Zones for {'VRF ' + (vrf_name or str(vrf_id)) if vrf_id else (ftd_name or ftd_uuid)}",
            ["Name", "UUID"],
            rows,
        )
    except Exception:
        pass
    return items

def post_ecmp_zone(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ecmpzones")
    if vrf_id:
        logger.info(f"Creating ECMP zone for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating ECMP zone for FTD")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create ECMP zone: {response.text}")
        response.raise_for_status()
    return response.json()

def get_vrfs(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all VRFs (Virtual Routers) for the given FTD.
    """
    logger.info(f"Fetching VRFs for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("id") or "")] for it in (items or [])]
        _log_pretty_table(f"VRFs for {ftd_name or ftd_uuid}", ["Name", "UUID"], rows)
    except Exception:
        pass
    return items

def post_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates a VRF (Virtual Router) on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters"
    logger.info(f"Creating VRF {payload.get('name')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VRF: {response.text}")
        response.raise_for_status()
    return response.json()

def build_dest_interface_maps(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd):
    """
    Build and return all destination interface maps as a dictionary.
    """
    dest_loopbacks = get_loopback_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_loopback_map = {iface['name']: iface['id'] for iface in dest_loopbacks}

    dest_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_phys_map = {iface['name']: iface['id'] for iface in dest_phys if iface.get('type') == 'PhysicalInterface'}

    dest_etherchannels = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_etherchannel_map = {iface['name']: iface['id'] for iface in dest_etherchannels if iface.get('type') == 'EtherChannelInterface'}

    dest_subints = get_subinterfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_subint_map = {f"{iface['name']}.{iface['subIntfId']}": iface['id'] for iface in dest_subints}

    dest_vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_vti_map = {iface['name']: iface['id'] for iface in dest_vtis if 'name' in iface and 'id' in iface}

    # Bridge Group Interfaces (if supported on target)
    try:
        dest_bgis = get_bridge_group_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    except Exception:
        dest_bgis = []
    dest_bridge_map = {iface.get('name'): iface.get('id') for iface in (dest_bgis or []) if iface.get('name') and iface.get('id')}

    return {
        "dest_loopback_map": dest_loopback_map,
        "dest_phys_map": dest_phys_map,
        "dest_etherchannel_map": dest_etherchannel_map,
        "dest_subint_map": dest_subint_map,
        "dest_vti_map": dest_vti_map,
        "dest_bridge_map": dest_bridge_map,
    }

def get_bridge_group_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetch Bridge Group Interfaces for the given FTD.
    """
    logger.info(f"Fetching Bridge Group Interfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/bridgegroupinterfaces?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"Bridge Group Interfaces for {ftd_name or ftd_uuid}", ["Name", "UUID"], rows)
    except Exception:
        pass
    return items

def post_bridge_group_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Create a Bridge Group Interface on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/bridgegroupinterfaces"
    logger.info(f"Creating Bridge Group Interface {payload.get('name')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create Bridge Group Interface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_inline_sets(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all Inline Sets for the given FTD.
    """
    logger.info(f"Fetching Inline Sets for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/inlinesets?expanded=true&limit=1000"
    response = fmc_get(url)
    response.raise_for_status()
    items = response.json().get("items", [])
    try:
        rows = [[(it.get("name") or ""), (it.get("id") or "") ] for it in (items or [])]
        _log_pretty_table(f"Inline Sets for {ftd_name or ftd_uuid}", ["Name", "UUID"], rows)
    except Exception:
        pass
    return items

def post_inline_set(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates an Inline Set on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/inlinesets"
    logger.info(f"Creating Inline Set {payload.get('name')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create Inline Set: {response.text}")
        response.raise_for_status()
    return response.json()

def get_vpn_topologies(fmc_ip, headers, domain_uuid):
    """
    Fetch all VPN topologies from FMC.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns?expanded=true&limit=1000"
    logger.info("Fetching VPN topologies from FMC")
    response = fmc_get(url)
    response.raise_for_status()
    return response.json().get("items", [])

def get_vpn_endpoints(fmc_ip, headers, domain_uuid, vpn_id, vpn_name=None):
    """
    Fetch all endpoints for a given VPN topology (with pagination support).
    """
    all_items = []
    offset = 0
    limit = 1000
    logger.info(f"Fetching endpoints for VPN topology {vpn_name or vpn_id}")
    
    while True:
        url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints?expanded=true&offset={offset}&limit={limit}"
        response = fmc_get(url)
        response.raise_for_status()
        data = response.json()
        items = data.get("items", [])
        all_items.extend(items)
        
        # Check if there are more pages
        paging = data.get("paging", {})
        total = paging.get("count", 0)
        if len(all_items) >= total or not items:
            break
        offset += limit
    
    logger.info(f"Fetched {len(all_items)} total endpoint(s) for VPN topology {vpn_name or vpn_id}")
    return all_items

def post_vpn_topology(fmc_ip, headers, domain_uuid, payload):
    """
    Create a VPN topology on the destination FMC.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns"
    logger.info(f"Creating VPN topology {payload.get('name')}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VPN topology: {response.text}")
        response.raise_for_status()
    return response.json()

def post_vpn_endpoint(fmc_ip, headers, domain_uuid, vpn_id, payload):
    """
    Create a VPN endpoint under a given VPN topology.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints"
    logger.info(f"Creating VPN endpoint {payload.get('name')} for VPN {vpn_id}")
    response = fmc_post(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VPN endpoint: {response.text}")
        response.raise_for_status()
    return response.json()

def post_vpn_endpoints_bulk(fmc_ip, headers, domain_uuid, vpn_id, payloads):
    """
    Create VPN endpoints in bulk for a given VPN topology using '?bulk=true'.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints?bulk=true"
    if not isinstance(payloads, list):
        payloads = [payloads]
    logger.info(f"Creating {len(payloads)} VPN endpoint(s) in bulk for VPN {vpn_id}")
    response = fmc_post(url, payloads)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed bulk create VPN endpoints: {response.text}")
        response.raise_for_status()
    return response.json()

def put_vpn_endpoint(fmc_ip, headers, domain_uuid, vpn_id, endpoint_id, payload, vpn_name=None):
    """
    Update a VPN endpoint under a given VPN topology.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints/{endpoint_id}"
    response = fmc_put(url, payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update VPN endpoint: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ikev2_policies(fmc_ip, headers, domain_uuid):
    """
    Get all IKEv2 policies with pagination.
    Returns a dict mapping policy name to policy object with id.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2policies"
    policies = {}
    offset = 0
    limit = 1000
    
    while True:
        paginated_url = f"{url}?offset={offset}&limit={limit}&expanded=true"
        response = fmc_get(paginated_url)
        if not response or response.status_code != 200:
            logger.warning(f"Failed to fetch IKEv2 policies: {response.status_code if response else 'No response'}")
            break
        
        data = response.json()
        items = data.get('items', [])
        for item in items:
            name = item.get('name')
            if name:
                policies[name] = item
        
        # Check if there are more pages
        paging = data.get('paging', {})
        total = paging.get('count', 0)
        if offset + limit >= total:
            break
        offset += limit
    
    logger.info(f"Fetched {len(policies)} IKEv2 policies")
    return policies

def get_ikev2_ipsec_proposals(fmc_ip, headers, domain_uuid):
    """
    Get all IKEv2 IPSec proposals with pagination.
    Returns a dict mapping proposal name to proposal object with id.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2ipsecproposals"
    proposals = {}
    offset = 0
    limit = 1000
    
    while True:
        paginated_url = f"{url}?offset={offset}&limit={limit}&expanded=true"
        response = fmc_get(paginated_url)
        if not response or response.status_code != 200:
            logger.warning(f"Failed to fetch IKEv2 IPSec proposals: {response.status_code if response else 'No response'}")
            break
        
        data = response.json()
        items = data.get('items', [])
        for item in items:
            name = item.get('name')
            if name:
                proposals[name] = item
        
        # Check if there are more pages
        paging = data.get('paging', {})
        total = paging.get('count', 0)
        if offset + limit >= total:
            break
        offset += limit
    
    logger.info(f"Fetched {len(proposals)} IKEv2 IPSec proposals")
    return proposals

def post_ikev2_policy(fmc_ip, headers, domain_uuid, payload):
    """
    Create an IKEv2 policy.
    Returns the created policy object with id.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2policies"
    # Remove id, links, metadata from payload
    clean_payload = dict(payload)
    for key in ('id', 'links', 'metadata'):
        clean_payload.pop(key, None)
    
    logger.info(f"Creating IKEv2 policy: {clean_payload.get('name')}")
    response = fmc_post(url, clean_payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create IKEv2 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def post_ikev2_ipsec_proposal(fmc_ip, headers, domain_uuid, payload):
    """
    Create an IKEv2 IPSec proposal.
    Returns the created proposal object with id.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/ikev2ipsecproposals"
    # Remove id, links, metadata from payload
    clean_payload = dict(payload)
    for key in ('id', 'links', 'metadata'):
        clean_payload.pop(key, None)
    
    logger.info(f"Creating IKEv2 IPSec proposal: {clean_payload.get('name')}")
    response = fmc_post(url, clean_payload)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create IKEv2 IPSec proposal: {response.text}")
        response.raise_for_status()
    return response.json()

def replace_vpn_endpoint(fmc_ip, headers, domain_uuid, source_ftd, dest_ftd_name, vpn_configs):
    """
    For each VPN topology, update any endpoint whose name matches the source FTD,
    replacing its name, device info, and interface UUIDs with the destination FTD's.
    For all interface types, use the destination FTD's ifname for 'name' and UUID for 'id'.
    """
    # Get destination FTD UUID for device replacement
    dest_ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, dest_ftd_name)
    # Build full maps: {ifname: (id, ifname)}
    dest_phys_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_physical_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_ether_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_subint_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_subinterfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_vti_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_vti_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_loop_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_loopback_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}

    logger.info(f"Looking for VPN endpoints matching source FTD: '{source_ftd}'")
    logger.info(f"Will replace with destination FTD: '{dest_ftd_name}' (UUID: {dest_ftd_uuid})")
    
    # Get source FTD UUID for device matching
    try:
        get_ftd_uuid(fmc_ip, headers, domain_uuid, source_ftd)
    except Exception as e:
        logger.warning(f"Could not get UUID for source FTD {source_ftd}: {str(e)}")

    for vpn in vpn_configs:
        vpn_id = vpn.get("id")
        vpn_name = vpn.get("name")
        endpoints = vpn.get("endpoints", [])
        logger.info(f"Checking endpoints for VPN topology {vpn_name}")
        for ep in endpoints:
            ep_payload = dict(ep)
            endpoint_id = ep_payload.get("id")
            
            # Extract device information for matching
            device_name = None
            device_id = None
            if "device" in ep_payload and isinstance(ep_payload["device"], dict):
                device_name = ep_payload["device"].get("name", "Unknown")
                device_id = ep_payload["device"].get("id", "Unknown")
                logger.info(f"  Device name: {device_name}, Device ID: {device_id}")
            
            ep_payload.pop("links", None)
            ep_payload.pop("metadata", None)
            if ep.get("name") == source_ftd:
                logger.info(f"Updating endpoint {source_ftd} to {dest_ftd_name} for VPN topology {vpn_name}")
                ep_payload["name"] = dest_ftd_name
                if "device" in ep_payload and isinstance(ep_payload["device"], dict):
                    ep_payload["device"]["name"] = dest_ftd_name
                    ep_payload["device"]["id"] = dest_ftd_uuid
                # Update interface reference for all supported types
                if "interface" in ep_payload and isinstance(ep_payload["interface"], dict):
                    intf = ep_payload["interface"]
                    intf_type = intf.get("type")
                    intf_ifname = intf.get("name")
                    if intf_type == "PhysicalInterface" and intf_ifname in dest_phys_full_map:
                        dest_id, dest_ifname = dest_phys_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "EtherChannelInterface" and intf_ifname in dest_ether_full_map:
                        dest_id, dest_ifname = dest_ether_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "SubInterface" and intf_ifname in dest_subint_full_map:
                        dest_id, dest_ifname = dest_subint_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "VTI" and intf_ifname in dest_vti_full_map:
                        dest_id, dest_ifname = dest_vti_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "LoopbackInterface" and intf_ifname in dest_loop_full_map:
                        dest_id, dest_ifname = dest_loop_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    else:
                        logger.warning(f"{intf_type} interface {intf_ifname} not found on destination FTD for VPN endpoint {dest_ftd_name}")
                    put_vpn_endpoint(
                        fmc_ip, headers, domain_uuid, vpn_id, endpoint_id, ep_payload, vpn_name=vpn_name
                    )

def _vrf_url(base, domain_uuid, ftd_uuid, vrf_id, resource):
    if vrf_id:
        return f"{base}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters/{vrf_id}/{resource}"
    else:
        return f"{base}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/{resource}"

def replace_masked_auth_values(payload, protocol, fmc_data_path="inputs/fmc_data.yaml", ui_auth_values=None):
    """
    Replace authentication values in routing protocol payloads with values from fmc_data.yaml
    or from UI-provided values if available.
    
    Args:
        payload: The routing protocol payload to modify
        protocol: The routing protocol name (eigrp, ospfv2, ospfv2interface, ospfv3, ospfv3interface, bgp)
        fmc_data_path: Path to the fmc_data.yaml file
        ui_auth_values: Optional dict containing auth values from UI (overrides file values)
    
    Returns:
        Modified payload with authentication values from config or UI
    """
    # Use UI-provided auth values if available, otherwise try to load from file
    if ui_auth_values and len(ui_auth_values) > 0:
        # Use UI-provided auth values
        auth_config = {}
        if protocol == "eigrp" and "eigrp_password" in ui_auth_values:
            auth_config["password"] = ui_auth_values["eigrp_password"]
        elif protocol in ["ospfv2", "ospfv2interface"]:
            if "ospf_md5_key" in ui_auth_values:
                auth_config["md5Key"] = ui_auth_values["ospf_md5_key"]
            if "ospf_auth_key" in ui_auth_values:
                auth_config["authKey"] = ui_auth_values["ospf_auth_key"]
        elif protocol == "ospfv3interface":
            # Optional UI overrides for OSPFv3 interface auth/encryption keys
            if "ospfv3_auth_key" in ui_auth_values:
                auth_config["authKey"] = ui_auth_values["ospfv3_auth_key"]
            if "ospfv3_encryption_key" in ui_auth_values:
                auth_config["encryptionKey"] = ui_auth_values["ospfv3_encryption_key"]
        elif protocol == "bgp" and "bgp_secret" in ui_auth_values:
            auth_config["neighborSecret"] = ui_auth_values["bgp_secret"]
        elif protocol in ("bfd", "bfd_template") and "bfd_auth_key" in ui_auth_values:
            auth_config["authKey"] = ui_auth_values["bfd_auth_key"]
    else:
        # Try to load from file, but don't fail if file doesn't exist
        try:
            import os
            # Resolve path robustly: try as-given, project root, and utils dir
            candidate_paths = []
            if os.path.isabs(fmc_data_path):
                candidate_paths = [fmc_data_path]
            else:
                proj_root = os.path.dirname(os.path.dirname(__file__))
                utils_dir = os.path.dirname(__file__)
                candidate_paths = [
                    fmc_data_path,
                    os.path.join(proj_root, fmc_data_path),
                    os.path.join(utils_dir, fmc_data_path),
                ]
            resolved_path = next((p for p in candidate_paths if os.path.exists(p)), None)
            if resolved_path:
                with open(resolved_path, "r") as f:
                    fmc_data = yaml.safe_load(f)
                auth_config = fmc_data["fmc_data"]["auth"].get("ospfv2" if protocol == "ospfv2interface" else protocol, {})
            else:
                # File doesn't exist, use default values
                auth_config = {}
        except Exception as e:
            # If there's any error reading the file, use default values
            auth_config = {}
    
    if protocol == "eigrp":
        # Replace password in all eigrpInterfaces
        for eigrp_iface in payload.get("eigrpInterfaces", []):
            auth = eigrp_iface.get("eigrpProtocolConfiguration", {}).get("authentication", {})
            if "password" in auth and "password" in auth_config:
                _v = str(auth_config.get("password") or "").strip()
                if _v:
                    auth["password"] = _v
                
    elif protocol == "ospfv2":
        # Handle OSPFv2 policy authentication (virtualLinks)
        for area in payload.get("areas", []):
            for virtual_link in area.get("virtualLinks", []):
                auth = virtual_link.get("authentication", {})
                # Handle MD5 authentication
                if "md5AuthList" in auth:
                    for md5_auth in auth["md5AuthList"]:
                        if "md5Key" in md5_auth and "md5Key" in auth_config:
                            _v = str(auth_config.get("md5Key") or "").strip()
                            if _v:
                                md5_auth["md5Key"] = _v
                # Handle password authentication
                if "passwdAuth" in auth and "authKey" in auth["passwdAuth"] and "authKey" in auth_config:
                    _v = str(auth_config.get("authKey") or "").strip()
                    if _v:
                        auth["passwdAuth"]["authKey"] = _v
                    
    elif protocol == "ospfv2interface":
        # Handle OSPFv2 interface authentication
        ospf_auth = payload.get("ospfProtocolConfiguration", {}).get("ospfAuthentication", {})
        if ospf_auth:
            # Handle password authentication
            if "passwdAuth" in ospf_auth and "authKey" in ospf_auth["passwdAuth"] and "authKey" in auth_config:
                _v = str(auth_config.get("authKey") or "").strip()
                if _v:
                    ospf_auth["passwdAuth"]["authKey"] = _v
        
            # Handle MD5 authentication list
            if "md5AuthList" in ospf_auth:
                for md5_auth in ospf_auth["md5AuthList"]:
                    if "md5Key" in md5_auth and "md5Key" in auth_config:
                        _v = str(auth_config.get("md5Key") or "").strip()
                        if _v:
                            md5_auth["md5Key"] = _v
        
            # Handle area authentication
            if "areaAuth" in ospf_auth:
                area_auth = ospf_auth["areaAuth"]
                # Password authentication in area auth
                if "passwdAuth" in area_auth and "authKey" in area_auth["passwdAuth"] and "authKey" in auth_config:
                    _v = str(auth_config.get("authKey") or "").strip()
                    if _v:
                        area_auth["passwdAuth"]["authKey"] = _v
                # MD5 authentication in area auth
                if "md5AuthList" in area_auth:
                    for md5_auth in area_auth["md5AuthList"]:
                        if "md5Key" in md5_auth and "md5Key" in auth_config:
                            _v = str(auth_config.get("md5Key") or "").strip()
                            if _v:
                                md5_auth["md5Key"] = _v
          

    elif protocol == "ospfv3interface":
        # Only override keys for INTERFACE-level auth and only if those fields already exist.
        # Do not create auth/encryption blocks or insert new keys.
        auth_block = payload.get("authentication")
        if isinstance(auth_block, dict):
            auth_type = (auth_block.get("type") or "").upper()
            if auth_type == "INTERFACE":
                # authKey: override only if present in payload and provided by UI/config (non-empty)
                if ("authKey" in auth_block) and ("authKey" in auth_config):
                    _v = str(auth_config.get("authKey") or "").strip()
                    if _v:
                        auth_block["authKey"] = _v
                # encryption.encryptionKey: override only if present in payload and provided by UI/config (non-empty)
                enc = auth_block.get("encryption")
                if isinstance(enc, dict) and ("encryptionKey" in enc) and ("encryptionKey" in auth_config):
                    _v = str(auth_config.get("encryptionKey") or "").strip()
                    if _v:
                        enc["encryptionKey"] = _v
            # Preserve AREA/unknown types as-is without injecting any keys
            payload["authentication"] = auth_block

    elif protocol == "bgp":
        # Handle BGP neighbor authentication in both IPv4 and IPv6 address families
        for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
            af = payload.get(af_key, {})
            for neighbor in af.get("neighbors", []):
                neighbor_advanced = neighbor.get("neighborAdvanced", {})
                if "neighborSecret" in neighbor_advanced and "neighborSecret" in auth_config:
                    # Replace the neighborSecret value only if non-empty override provided
                    _v = str(auth_config.get("neighborSecret") or "").strip()
                    if _v:
                        neighbor_advanced["neighborSecret"] = _v
    elif protocol == "bfd":
        # BFD policy auth override: authentication.authKey
        try:
            auth = payload.get("authentication")
            if isinstance(auth, dict) and "authKey" in auth and "authKey" in auth_config:
                _v = str(auth_config.get("authKey") or "").strip()
                if _v:
                    auth["authKey"] = _v
        except Exception:
            pass
    elif protocol == "bfd_template":
        # BFD template object auth override: authentication.authKey
        try:
            auth = payload.get("authentication")
            if isinstance(auth, dict) and "authKey" in auth and "authKey" in auth_config:
                _v = str(auth_config.get("authKey") or "").strip()
                if _v:
                    auth["authKey"] = _v
        except Exception:
            pass
    return payload


def get_devicerecords(fmc_ip, headers, domain_uuid, bulk=True):
    """
    Get device records from FMC
    
    Args:
        fmc_ip (str): FMC IP address
        headers (dict): Authentication headers
        domain_uuid (str): Domain UUID
        bulk (bool): Whether to retrieve all devices at once
        
    Returns:
        list: List of device records
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords"
    if bulk:
        url += "?limit=1000"
    try:
        response = fmc_get(url)
        response.raise_for_status()
        return response.json().get('items', [])
    except Exception as e:
        logger.error(f"Failed to get device records: {str(e)}")
        return []

# -----------------------
# Object POST helpers
# -----------------------

def _sanitize_object_payload(payload: dict, type_default: str = None) -> dict:
    body = dict(payload or {})
    # Remove readonly/meta fields
    for k in ("id", "links", "metadata"):
        body.pop(k, None)
    if type_default and not body.get("type"):
        body["type"] = type_default
    return body

def _post_object(fmc_ip: str, domain_uuid: str, path_tail: str, payload: dict, type_default: str = None) -> dict:
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/{path_tail}"
    body = _sanitize_object_payload(payload, type_default)
    logger.info(f"POST {path_tail} -> {body.get('name')}")
    resp = fmc_post(url, body)
    if resp.status_code not in (200, 201):
        desc = extract_error_description(resp)
        logger.error(f"Failed to POST {path_tail}: {desc}")
        resp.raise_for_status()
    return resp.json()

def _post_object_bulk(fmc_ip: str, domain_uuid: str, path_tail: str, payloads: list, type_default: str = None) -> dict:
    """Bulk POST for object types that support it. Returns response with items list."""
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/{path_tail}?bulk=true"
    bodies = [_sanitize_object_payload(p, type_default) for p in payloads]
    names = [b.get('name', '<unnamed>') for b in bodies]
    logger.info(f"POST bulk {path_tail} ({len(bodies)} items) -> {', '.join(names[:5])}{'...' if len(names) > 5 else ''}")
    resp = fmc_post(url, bodies)
    if resp.status_code not in (200, 201):
        desc = extract_error_description(resp)
        logger.error(f"Failed to POST bulk {path_tail}: {desc}")
        resp.raise_for_status()
    return resp.json()

# Network objects
def post_host_object(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "hosts", payload, "Host")

def post_range_object(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "ranges", payload, "Range")

def post_network_object(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "networks", payload, "Network")

def post_fqdn_object(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "fqdns", payload, "FQDN")

def post_network_group(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "networkgroups", payload, "NetworkGroup")

# Bulk versions for objects that support bulk operations
def post_host_object_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "hosts", payloads, "Host")

def post_range_object_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "ranges", payloads, "Range")

def post_network_object_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "networks", payloads, "Network")

def post_fqdn_object_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "fqdns", payloads, "FQDN")

def post_network_group_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "networkgroups", payloads, "NetworkGroup")

def post_port_object_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "protocolportobjects", payloads, "ProtocolPortObject")

def post_key_chain_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "keychains", payloads, "KeyChainObject")

def post_sla_monitor_bulk(fmc_ip: str, headers: dict, domain_uuid: str, payloads: list) -> dict:
    return _post_object_bulk(fmc_ip, domain_uuid, "slamonitors", payloads, "SLAMonitor")

# Port objects (generic ProtocolPortObject)
def post_port_object(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    # Accept payloads for TCP/UDP/ICMP; default to ProtocolPortObject if type not provided
    type_default = payload.get("type") or "ProtocolPortObject"
    return _post_object(fmc_ip, domain_uuid, "protocolportobjects", payload, type_default)

# Templates and lists
def post_bfd_template(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict, ui_auth_values=None) -> dict:
    # Apply UI-provided overrides for authentication
    try:
        payload = replace_masked_auth_values(payload, "bfd_template", ui_auth_values=ui_auth_values)
    except Exception:
        pass
    return _post_object(fmc_ip, domain_uuid, "bfdtemplates", payload, "BFDTemplate")

def post_as_path_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "aspathlists", payload, "ASPathList")

def post_key_chain(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "keychains", payload, "KeyChain")

def post_sla_monitor(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "slamonitors", payload, "SLAMonitor")

def post_community_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "communitylists", payload, "CommunityList")

def post_extended_community_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "extendedcommunitylists", payload, "ExtendedCommunityList")

def post_ipv4_prefix_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "ipv4prefixlists", payload, "IPv4PrefixList")

def post_ipv6_prefix_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "ipv6prefixlists", payload, "IPv6PrefixList")

def post_extended_access_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "extendedaccesslists", payload, "ExtendedAccessList")

def post_standard_access_list(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "standardaccesslists", payload, "StandardAccessList")

def post_route_map(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "routemaps", payload, "RouteMap")

def post_ipv4_address_pool(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "ipv4addresspools", payload, "IPv4AddressPool")

def post_ipv6_address_pool(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "ipv6addresspools", payload, "IPv6AddressPool")

def post_mac_address_pool(fmc_ip: str, headers: dict, domain_uuid: str, payload: dict) -> dict:
    return _post_object(fmc_ip, domain_uuid, "macaddresspools", payload, "MacAddressPool")

# -----------------------
# Object DELETE helpers
# -----------------------

def _delete_object(fmc_ip: str, domain_uuid: str, path_tail: str, object_id: str) -> bool:
    """Generic helper to DELETE an object by ID."""
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/{path_tail}/{object_id}"
    try:
        resp = fmc_delete(url)
        if resp.status_code in (200, 204):
            return True
        desc = extract_error_description(resp)
        logger.error(f"Failed to DELETE {path_tail}/{object_id}: {desc}")
        return False
    except Exception as e:
        logger.error(f"Failed to DELETE {path_tail}/{object_id}: {e}")
        return False

def delete_objects_by_type(fmc_ip: str, headers: dict, domain_uuid: str, object_type: str, object_ids: List[str]) -> Dict[str, Any]:
    """Delete multiple objects of a given type. Returns {deleted: count, errors: [str]}."""
    path_tail = object_type_to_path(object_type)
    deleted = 0
    errors = []
    for obj_id in object_ids:
        success = _delete_object(fmc_ip, domain_uuid, path_tail, obj_id)
        if success:
            deleted += 1
        else:
            errors.append(f"Failed to delete {object_type} with ID {obj_id}")
    return {"deleted": deleted, "errors": errors}

# -----------------------
# Object GET helpers (lists)
# -----------------------

def _get_object_list(fmc_ip: str, domain_uuid: str, path_tail: str, expanded: bool = False) -> list:
    """Generic helper to GET a list of objects under /object/<path_tail>."""
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/{path_tail}?limit=1000"
    if expanded:
        url += "&expanded=true"
    try:
        resp = fmc_get(url)
        resp.raise_for_status()
        return resp.json().get("items", []) or []
    except Exception as e:
        logger.warning(f"Failed to GET {path_tail}: {e}")
        return []

# Mapping of FMC object type -> object collection path
_OBJECT_TYPE_TO_PATH = {
    # Network
    "Host": "hosts",
    "Range": "ranges",
    "Network": "networks",
    "FQDN": "fqdns",
    "NetworkGroup": "networkgroups",
    "SecurityZone": "securityzones",
    # Port
    "ProtocolPortObject": "protocolportobjects",
    # Templates & Lists
    "BFDTemplate": "bfdtemplates",
    "ASPathList": "aspathlists",
    "KeyChain": "keychains",
    "SLAMonitor": "slamonitors",
    "CommunityList": "communitylists",
    "ExtendedCommunityList": "extendedcommunitylists",
    "IPv4PrefixList": "ipv4prefixlists",
    "IPv6PrefixList": "ipv6prefixlists",
    "ExtendedAccessList": "extendedaccesslists",
    "StandardAccessList": "standardaccesslists",
    "RouteMap": "routemaps",
    # Address pools
    "IPv4AddressPool": "ipv4addresspools",
    "IPv6AddressPool": "ipv6addresspools",
    "MacAddressPool": "macaddresspools",
}

def object_type_to_path(type_name: str) -> str:
    """Return the object collection path for a given FMC object type name."""
    return _OBJECT_TYPE_TO_PATH.get(type_name, "")

def _get_object_by_id(fmc_ip: str, domain_uuid: str, path_tail: str, obj_id: str) -> dict:
    """Fetch a single object by its id from /object/<path_tail>/<id>. Returns {} if not found."""
    if not obj_id:
        return {}
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/{path_tail}/{obj_id}"
    try:
        resp = fmc_get(url)
        # Some endpoints may return 200 with dict, others 404 if missing
        if resp.status_code == 200:
            try:
                data = resp.json() or {}
                # Some endpoints may wrap in items
                if isinstance(data, dict) and data.get("id"):
                    return data
            except Exception:
                return {}
        return {}
    except Exception as e:
        logger.warning(f"GET by id failed for {path_tail}/{obj_id}: {e}")
        return {}

def get_objects_by_type_and_ids(fmc_ip: str, headers: dict, domain_uuid: str, type_name: str, ids: "set[str]") -> list:
    """Fetch objects for a given FMC type using their IDs. Avoids listing all objects.
    Returns list of found objects.
    """
    path = object_type_to_path(type_name)
    if not path:
        return []
    out = []
    for oid in sorted(list(ids or [])):
        it = _get_object_by_id(fmc_ip, domain_uuid, path, oid)
        if it:
            out.append(it)
    return out

# Network objects
def get_hosts(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "hosts")

def get_ranges(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "ranges")

def get_networks(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "networks")

def get_fqdns(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "fqdns")

def get_network_groups(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "networkgroups")

# Port objects
def get_port_objects(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "protocolportobjects")

# Templates and lists
def get_bfd_templates(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "bfdtemplates")

def get_as_path_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "aspathlists")

def get_key_chains(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "keychains")

def get_sla_monitors(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "slamonitors")

def get_community_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "communitylists")

def get_extended_community_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "extendedcommunitylists")

def get_ipv4_prefix_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "ipv4prefixlists")

def get_ipv6_prefix_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "ipv6prefixlists")

def get_extended_access_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "extendedaccesslists")

def get_standard_access_lists(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "standardaccesslists")

def get_route_maps(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "routemaps")

def get_ipv4_address_pools(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "ipv4addresspools")

def get_ipv6_address_pools(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "ipv6addresspools")

def get_mac_address_pools(fmc_ip: str, headers: dict, domain_uuid: str) -> list:
    return _get_object_list(fmc_ip, domain_uuid, "macaddresspools")

def build_dest_object_maps(fmc_ip: str, headers: dict, domain_uuid: str) -> dict:
    def _norm(s: str) -> str:
        try:
            k = str(s).strip()
            return k.lower().replace("-", "").replace("_", "").replace(" ", "")
        except Exception:
            return str(s)

    types_and_getters = [
        ("Host", get_hosts),
        ("Range", get_ranges),
        ("Network", get_networks),
        ("FQDN", get_fqdns),
        ("NetworkGroup", get_network_groups),
        ("ProtocolPortObject", get_port_objects),
        ("BFDTemplate", get_bfd_templates),
        ("ASPathList", get_as_path_lists),
        ("KeyChain", get_key_chains),
        ("SLAMonitor", get_sla_monitors),
        ("CommunityList", get_community_lists),
        ("ExtendedCommunityList", get_extended_community_lists),
        ("IPv4PrefixList", get_ipv4_prefix_lists),
        ("IPv6PrefixList", get_ipv6_prefix_lists),
        ("ExtendedAccessList", get_extended_access_lists),
        ("StandardAccessList", get_standard_access_lists),
        ("RouteMap", get_route_maps),
        ("IPv4AddressPool", get_ipv4_address_pools),
        ("IPv6AddressPool", get_ipv6_address_pools),
        ("MacAddressPool", get_mac_address_pools),
    ]

    out = {}
    for tname, getter in types_and_getters:
        try:
            items = getter(fmc_ip, headers, domain_uuid) or []
        except Exception:
            items = []
        m = {}
        for it in items:
            n = it.get("name")
            i = it.get("id")
            if n and i:
                m[n] = i
                m[n.lower()] = i
                m[_norm(n)] = i
        out[tname] = m
    # Accept alternate type spellings sometimes returned by payloads
    if "IPv4PrefixList" in out:
        out["IPV4PrefixList"] = out["IPv4PrefixList"]
    if "IPv6PrefixList" in out:
        out["IPV6PrefixList"] = out["IPv6PrefixList"]
    if "MacAddressPool" in out:
        out["MACAddressPool"] = out["MacAddressPool"]
    return out

def _canon_type(t: str) -> str:
    try:
        k = str(t or "").strip()
    except Exception:
        k = str(t)
    if not k:
        return ""
    aliases = {
        # Network
        "host": "Host",
        "range": "Range",
        "network": "Network",
        "fqdn": "FQDN",
        "networkgroup": "NetworkGroup",
        # Port objects (various representations)
        "protocolportobject": "ProtocolPortObject",
        "tcpportobject": "ProtocolPortObject",
        "udpportobject": "ProtocolPortObject",
        "icmpv4object": "ProtocolPortObject",
        "icmpv6object": "ProtocolPortObject",
        # Templates & Lists
        "bfdtemplate": "BFDTemplate",
        "aspathlist": "ASPathList",
        "keychain": "KeyChain",
        "slamonitor": "SLAMonitor",
        "communitylist": "CommunityList",
        "extendedcommunitylist": "ExtendedCommunityList",
        "ipv4prefixlist": "IPv4PrefixList",
        "ipV4prefixlist": "IPv4PrefixList",
        "IPV4PrefixList": "IPv4PrefixList",
        "ipv6prefixlist": "IPv6PrefixList",
        "IPV6PrefixList": "IPv6PrefixList",
        "extendedaccesslist": "ExtendedAccessList",
        "standardaccesslist": "StandardAccessList",
        "routemap": "RouteMap",
        # Address pools
        "ipv4addresspool": "IPv4AddressPool",
        "ipv6addresspool": "IPv6AddressPool",
        "macaddresspool": "MacAddressPool",
        "MACAddressPool": "MacAddressPool",
    }
    lk = k.lower()
    return aliases.get(lk, k)


def update_object_ids(obj, dest_obj_maps: dict):
    def _norm_name(s: str) -> str:
        try:
            k = str(s).strip()
            return k.lower().replace("-", "").replace("_", "").replace(" ", "")
        except Exception:
            return str(s)

    if isinstance(obj, dict):
        t = obj.get("type") or obj.get("objectType")
        n = obj.get("name")
        
        # Skip interfaces and security zones - they have dedicated resolvers
        if t in ("PhysicalInterface", "EtherchannelInterface", "SubInterface", "VTIInterface", 
                 "LoopbackInterface", "InlineSet", "BridgeGroupInterface", "SecurityZone"):
            # Still recurse into nested objects within these types
            for v in obj.values():
                update_object_ids(v, dest_obj_maps)
            return
        
        if n:
            canon = _canon_type(t) if t else ""
            tried_types = []
            new_id = None
            if canon:
                tried_types.append(canon)
                mp = (dest_obj_maps or {}).get(canon) or {}
                new_id = mp.get(n) or mp.get(str(n).lower()) or mp.get(_norm_name(n))
            if not new_id:
                for ctype, mp in (dest_obj_maps or {}).items():
                    tried_types.append(ctype)
                    cand = mp.get(n) or mp.get(str(n).lower()) or mp.get(_norm_name(n))
                    if cand:
                        new_id = cand
                        if not canon:
                            canon = ctype
                        break
            if new_id:
                old_id = obj.get("id")
                obj["id"] = new_id
                # Preserve original 'type' casing if present. Only set when missing.
                try:
                    if canon and not t:
                        obj["type"] = canon
                except Exception:
                    pass
                try:
                    logger.info(f"Object remap: type={canon or t} name={n} old_id={old_id} -> new_id={new_id}")
                except Exception:
                    pass
            else:
                try:
                    logger.warning(f"Object remap miss on destination: type={t} name={n} tried_types={list(set(tried_types))[:6]}")
                except Exception:
                    pass
        for v in obj.values():
            update_object_ids(v, dest_obj_maps)
    elif isinstance(obj, list):
        for item in obj:
            update_object_ids(item, dest_obj_maps)


def normalize_reference_objects(obj: dict) -> None:
    """Normalize nested object reference lists to id-only dicts where appropriate.

    This targets structures used by ACLs and RouteMaps where FMC expects lists of
    object references containing only an 'id'. We conservatively collapse elements
    under the following keys when they are lists of dicts:
      - 'objects' (e.g., networks.objects, sourceNetworks.objects, destinationNetworks.objects,
                   sourcePorts.objects, destinationPorts.objects)
      - 'ipv4PrefixListAddresses', 'ipv6PrefixListAddresses'
      - 'ipv4AccessListAddresses', 'ipv6AccessListAddresses'
    """
    KEYS = {
        "objects",
    }

    def _walk(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if k in KEYS and isinstance(v, list):
                    new_list = []
                    for it in v:
                        if isinstance(it, dict) and it.get("id"):
                            new_list.append({"id": it.get("id")})
                        else:
                            new_list.append(it)
                    node[k] = new_list
                else:
                    _walk(v)
        elif isinstance(node, list):
            for it in node:
                _walk(it)

    _walk(obj)