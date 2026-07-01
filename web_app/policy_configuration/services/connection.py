"""Source/target FMC connection management for policy replication.

The *target* FMC is whatever the user is connected to in the main FMC
Connection section (``ctx['fmc_auth']``). The *source* FMC is connected to
separately here and stored in ``ctx['policy_source_auth']`` so the two never
overlap. We authenticate without touching ``utils.fmc_api``'s module-global
auth state to avoid clobbering the target connection used elsewhere.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth

from ..models.schema import FmcMetadata, normalize_name
from .client import PolicyFmcClient, FmcApiError

logger = logging.getLogger(__name__)


def _normalize_base_url(fmc_ip: str) -> str:
    ip = (fmc_ip or "").strip()
    if not ip:
        return ""
    if not re.match(r"^https?://", ip):
        ip = f"https://{ip}"
    return ip.rstrip("/")


def authenticate_isolated(
    fmc_ip: str, username: str, password: str, timeout: float = 60.0,
) -> Tuple[str, Dict[str, str]]:
    """Authenticate to an FMC and return (domain_uuid, headers).

    Does NOT mutate any global auth state. Raises FmcApiError on failure.
    """
    base = _normalize_base_url(fmc_ip)
    if not base:
        raise FmcApiError("FMC host is required")
    auth_url = f"{base}/api/fmc_platform/v1/auth/generatetoken"
    try:
        resp = requests.post(
            auth_url, headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(username, password), verify=False, timeout=timeout,
        )
    except requests.exceptions.Timeout as e:
        raise FmcApiError(f"Connection to {base} timed out") from e
    except requests.exceptions.RequestException as e:
        raise FmcApiError(f"Could not reach {base}: {e}") from e

    if resp.status_code == 401:
        raise FmcApiError("Invalid credentials for source FMC", 401)
    if resp.status_code >= 400:
        raise FmcApiError(f"Source FMC auth failed (HTTP {resp.status_code})", resp.status_code)

    token = resp.headers.get("X-auth-access-token")
    if not token:
        raise FmcApiError("Source FMC authentication returned no token")
    domain_uuid = resp.headers.get("DOMAIN_UUID") or ""
    headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
    return domain_uuid, headers


def read_server_metadata(client: PolicyFmcClient) -> FmcMetadata:
    """Read version/build/model/status for an FMC connection."""
    meta = FmcMetadata(host=client.fmc_ip, domain_uuid=client.domain_uuid, status="connected")
    try:
        data = client.get_json("/api/fmc_platform/v1/info/serverversion")
        items = data.get("items") or []
        if items:
            sv = items[0]
            meta.version = str(sv.get("serverVersion") or sv.get("server_version") or "")
            meta.build = str(sv.get("vdbVersion") or sv.get("geoVersion") or sv.get("build") or "")
            # Some FMC builds embed the build number inside serverVersion string.
            m = re.search(r"\(build\s*(\d+)\)", meta.version, re.IGNORECASE)
            if m and not meta.build:
                meta.build = m.group(1)
            meta.model = str(sv.get("model") or sv.get("platformModel") or "FMC")
    except FmcApiError as e:
        logger.warning(f"Could not read server metadata: {e}")
        meta.status = "error"
    # Domain name (best effort).
    try:
        dinfo = client.get_json("/api/fmc_platform/v1/info/domain")
        for d in (dinfo.get("items") or []):
            if str(d.get("uuid") or d.get("id")) == client.domain_uuid:
                meta.domain_name = str(d.get("name") or "")
                break
    except FmcApiError:
        pass
    return meta


def build_target_client(ctx: Dict[str, Any], debug: bool = False) -> Optional[PolicyFmcClient]:
    """Construct a PolicyFmcClient for the currently connected target FMC."""
    auth = ctx.get("fmc_auth") or {}
    headers = auth.get("headers")
    domain_uuid = auth.get("domain_uuid")
    conn = ctx.get("fmc_connection") or {}
    fmc_ip = conn.get("fmc_ip") or auth.get("fmc_ip")
    if not headers or not domain_uuid:
        return None
    if not fmc_ip:
        # Fall back to whatever host last connected may have stored.
        fmc_ip = auth.get("fmc_ip") or ""
    creds = None
    if conn.get("username") and conn.get("password"):
        creds = (conn["username"], conn["password"])
    return PolicyFmcClient(
        _normalize_base_url(fmc_ip), headers, domain_uuid,
        credentials=creds, debug=debug,
    )


def build_source_client(ctx: Dict[str, Any], debug: bool = False) -> Optional[PolicyFmcClient]:
    """Construct a PolicyFmcClient for the previously connected source FMC."""
    src = ctx.get("policy_source_auth") or {}
    headers = src.get("headers")
    domain_uuid = src.get("domain_uuid")
    fmc_ip = src.get("fmc_ip")
    if not headers or not domain_uuid or not fmc_ip:
        return None
    creds = None
    if src.get("username") and src.get("password"):
        creds = (src["username"], src["password"])
    return PolicyFmcClient(fmc_ip, headers, domain_uuid, credentials=creds, debug=debug)


def is_same_fmc(source: PolicyFmcClient, target: PolicyFmcClient) -> bool:
    """True if source and target point at the same FMC host + domain."""
    try:
        sh = urlparse(source.fmc_ip).netloc.lower() or source.fmc_ip.lower()
        th = urlparse(target.fmc_ip).netloc.lower() or target.fmc_ip.lower()
    except Exception:
        sh, th = source.fmc_ip.lower(), target.fmc_ip.lower()
    return sh == th and normalize_name(source.domain_uuid) == normalize_name(target.domain_uuid)


def connect_source(
    ctx: Dict[str, Any], fmc_ip: str, username: str, password: str,
    domain_uuid: Optional[str] = None, debug: bool = False,
) -> Dict[str, Any]:
    """Authenticate to the source FMC and return source+target metadata.

    Stores source auth in ``ctx['policy_source_auth']`` (in-memory only).
    Raises FmcApiError for connection/auth/timeout problems and a ValueError
    when the source equals the target FMC.
    """
    base = _normalize_base_url(fmc_ip)
    default_domain, headers = authenticate_isolated(base, username, password)
    sel_domain = domain_uuid or default_domain
    if isinstance(sel_domain, str) and sel_domain.lower() == "undefined":
        sel_domain = default_domain

    src_headers = dict(headers)
    src_headers["DOMAIN_UUID"] = sel_domain
    source_client = PolicyFmcClient(
        base, src_headers, sel_domain, credentials=(username, password), debug=debug,
    )

    target_client = build_target_client(ctx, debug=debug)
    if target_client is None:
        # Persist source so the user can still fetch/upload; target needed for push.
        ctx["policy_source_auth"] = {
            "fmc_ip": base, "headers": src_headers, "domain_uuid": sel_domain,
            "username": username, "password": password,
        }
        source_meta = read_server_metadata(source_client)
        return {
            "success": True,
            "source": source_meta.to_dict(),
            "target": FmcMetadata(status="disconnected").to_dict(),
            "warning": "No target FMC connected. Connect a target FMC to push policies.",
        }

    if is_same_fmc(source_client, target_client):
        raise ValueError(
            "Source and target FMC are the same host/domain. "
            "Connect to a different source FMC to replicate policies."
        )

    # Persist source connection (in-memory ctx only; never logged/persisted to disk).
    ctx["policy_source_auth"] = {
        "fmc_ip": base, "headers": src_headers, "domain_uuid": sel_domain,
        "username": username, "password": password,
    }

    source_meta = read_server_metadata(source_client)
    target_meta = read_server_metadata(target_client)
    return {
        "success": True,
        "source": source_meta.to_dict(),
        "target": target_meta.to_dict(),
    }
