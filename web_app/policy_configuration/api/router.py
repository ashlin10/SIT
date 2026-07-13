"""FastAPI router for the FMC policy replication feature.

All endpoints are mounted under ``/api/policy-config``. The router delegates to
the services/dependency/validation/yaml modules in this package and integrates
with the host app's per-user context, logging and progress helpers (imported
lazily to avoid a circular import at module-load time).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from ..models.schema import PolicyConfig
from ..services.client import FmcApiError, PolicyFmcClient
from ..services import connection as conn
from ..services import acp_fetch
from ..services import push as push_svc
from ..services.push import _clear_resolution_cache
from ..validation.policy_validator import (
    sanitize_policy_config, validate_policy_doc,
)
from ..yaml.serializer import build_yaml, parse_yaml, StructureError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/policy-config", tags=["policy-config"])


# ── Host-app helper access (lazy import to dodge circular import) ──

def _host():
    """Return the host ``app`` module (loaded once the server is running)."""
    import app as _app  # top-level module when run as ``uvicorn app:app``
    return _app


def _username(request: Request) -> str:
    return _host().get_current_username(request)


def _ctx(username: str) -> Dict[str, Any]:
    ctx = _host().get_user_ctx(username)
    ctx.setdefault("policy_source_auth", None)
    ctx.setdefault("policy_config", None)
    return ctx


def _attach_logs(username: str) -> None:
    try:
        _host()._attach_user_log_handlers(username)
    except Exception:
        pass


def _log_fn() -> Callable[[str], None]:
    return lambda m: logger.info(m)


def _get_config(ctx: Dict[str, Any]) -> PolicyConfig:
    cfg = ctx.get("policy_config")
    if not isinstance(cfg, PolicyConfig):
        cfg = PolicyConfig()
        ctx["policy_config"] = cfg
    return cfg


def _get_acp_configs(ctx: Dict[str, Any]) -> Dict[str, PolicyConfig]:
    """Return the per-ACP config store, keyed by ACP name."""
    store = ctx.get("policy_acp_configs")
    if not isinstance(store, dict):
        store = {}
        ctx["policy_acp_configs"] = store
    return store


# ── Source connection + metadata ──

@router.post("/source/connect")
async def source_connect(payload: Dict[str, Any], http_request: Request):
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        _attach_logs(username)
        debug = bool(payload.get("debug"))
        result = conn.connect_source(
            ctx,
            fmc_ip=(payload.get("fmc_ip") or "").strip(),
            username=(payload.get("username") or "").strip(),
            password=payload.get("password") or "",
            domain_uuid=payload.get("domain_uuid"),
            debug=debug,
        )
        _clear_resolution_cache(ctx)
        try:
            _host().record_activity(username, "policy_source_connect",
                                    {"source": result.get("source", {}).get("host")})
        except Exception:
            pass
        return result
    except ValueError as e:  # same-FMC guard
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except FmcApiError as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"Policy source connect failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Target metadata ──

@router.post("/target/metadata")
async def target_metadata(payload: Dict[str, Any], http_request: Request):
    """Return the connected target FMC's version/build/model metadata."""
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        target = conn.build_target_client(ctx, debug=bool(payload.get("debug")))
        if target is None:
            return {"success": True, "target": conn.FmcMetadata(status="disconnected").to_dict()}
        loop = asyncio.get_running_loop()
        meta = await loop.run_in_executor(None, lambda: conn.read_server_metadata(target))
        return {"success": True, "target": meta.to_dict()}
    except Exception as e:
        logger.error(f"target metadata failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── ACP listing ──

@router.post("/acp/list")
async def acp_list(payload: Dict[str, Any], http_request: Request):
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        _attach_logs(username)
        client = conn.build_source_client(ctx, debug=bool(payload.get("debug")))
        if client is None:
            return JSONResponse(status_code=400, content={
                "success": False, "message": "Source FMC not connected. Connect first."})
        loop = asyncio.get_running_loop()
        rows = await loop.run_in_executor(None, lambda: acp_fetch.list_acps(client))
        return {"success": True, "acps": rows, "count": len(rows)}
    except FmcApiError as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"ACP list failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Fetch a single ACP (full detail) ──

@router.post("/acp/fetch")
async def acp_fetch_one(payload: Dict[str, Any], http_request: Request):
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        _attach_logs(username)
        acp_id = (payload.get("acp_id") or "").strip()
        if not acp_id:
            return JSONResponse(status_code=400, content={"success": False, "message": "acp_id is required"})
        client = conn.build_source_client(ctx, debug=bool(payload.get("debug")))
        if client is None:
            return JSONResponse(status_code=400, content={
                "success": False, "message": "Source FMC not connected. Connect first."})

        loop = asyncio.get_running_loop()
        # Faithful full fetch: ACP base + rules, every referenced dependent
        # policy (full payload, grouped by type), and all referenced objects
        # (fetched recursively through nested groups).
        acp, policies, objects = await loop.run_in_executor(
            None, lambda: acp_fetch.fetch_acp_full(client, acp_id, _log_fn()),
        )

        # Replace (not append): each fetch starts a fresh config so only the
        # latest fetched policy is loaded.  Multiple policies are combined
        # only at download time when the user selects which ones to include.
        cfg = PolicyConfig()
        ctx["policy_config"] = cfg
        _clear_resolution_cache(ctx)
        cfg.upsert_acp(acp)
        for subsection, items in policies.items():
            cfg.upsert_policies(subsection, items)
        cfg.upsert_objects(objects)
        # Inject source FMC metadata for provenance tracking.
        # Uses the same fields as Device Configuration's Get Config:
        # hostname, serverVersion (includes build), model, platform.
        src_auth = ctx.get("policy_source_auth") or {}
        cfg.meta["source_fmc"] = {
            "name": src_auth.get("hostname", "") or src_auth.get("fmc_ip", ""),
            "version": src_auth.get("version", ""),
            "model": src_auth.get("model", ""),
            "platform": src_auth.get("platform", ""),
        }
        # Store per-ACP config so download can combine selected ACPs.
        _get_acp_configs(ctx)[acp.name] = cfg
        yaml_text = build_yaml(cfg)
        ctx["policy_config_yaml"] = yaml_text
        return {
            "success": True,
            "acp": acp.to_summary(),
            "dependency_count": len(objects),
            "policy_count": sum(len(v) for v in policies.values()),
            "yaml": yaml_text,
            "filename": _yaml_filename(),
        }
    except FmcApiError as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"ACP fetch failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Upload policy YAML ──

@router.post("/upload")
async def upload_policy_yaml(http_request: Request, file: UploadFile = File(...)):
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        raw = (await file.read()).decode("utf-8", errors="replace")
        cfg = parse_yaml(raw)
        ctx["policy_config"] = cfg
        ctx["policy_config_yaml"] = raw
        _clear_resolution_cache(ctx)
        # Populate per-ACP store so download can combine selected ACPs.
        acp_store = _get_acp_configs(ctx)
        for acp in cfg.acps:
            per_acp = PolicyConfig()
            per_acp.upsert_acp(acp)
            per_acp.objects = list(cfg.objects)
            for sub, items in cfg.policies.items():
                per_acp.policies[sub] = list(items)
            if cfg.meta.get("source_fmc"):
                per_acp.meta["source_fmc"] = cfg.meta["source_fmc"]
            acp_store[acp.name] = per_acp
        return {
            "success": True,
            "filename": file.filename,
            "acps": [a.to_summary() for a in cfg.acps],
            "object_count": len(cfg.objects),
        }
    except StructureError as e:
        return JSONResponse(status_code=400, content={
            "success": False, "message": str(e), "errors": e.errors})
    except Exception as e:
        logger.error(f"Policy YAML upload failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Server-hosted policy YAMLs ──

_DEFAULT_SERVER_YAML_URL = "https://u32-scratch.cisco.com/scratch/aleroyds/vyper/policy/"


@router.post("/server-yamls/list")
async def list_server_yamls(payload: Dict[str, Any], http_request: Request):
    """List .yaml files available on the remote HTTPS server.

    For each file, downloads the first ~2 KB to read the ``metadata.source_fmc``
    block and extract version/build. Filenames are URL-decoded for display.
    """
    import re
    import yaml as _yaml
    import requests as _requests
    from urllib.parse import unquote
    base_url = (payload.get("url") or _DEFAULT_SERVER_YAML_URL).rstrip("/") + "/"
    try:
        resp = _requests.get(base_url, verify=False, timeout=15)
        resp.raise_for_status()
        html = resp.text
        # Parse href links ending in .yaml/.yml from the directory listing.
        links = re.findall(r'href="([^"]+\.ya?ml)"', html, re.IGNORECASE)
        files = []
        for raw_href in sorted(set(links)):
            display_name = unquote(raw_href).replace(".yaml", "").replace(".yml", "")
            file_url = base_url + raw_href
            version = ""
            # Read metadata from the YAML header (first ~2 KB is enough for the
            # metadata block).  We parse only the lines belonging to the
            # ``metadata:`` block instead of calling ``yaml.safe_load`` on the
            # (possibly truncated) content – large files broke safe_load.
            try:
                head = _requests.get(file_url, verify=False, timeout=10,
                                     headers={"Range": "bytes=0-2047"})
                head_text = head.text
                try:
                    # Extract just the metadata block (stops at first
                    # non-indented key after ``metadata:``).
                    meta_lines: list[str] = []
                    in_meta = False
                    for line in head_text.splitlines():
                        if line.rstrip() == "metadata:":
                            in_meta = True
                            meta_lines.append(line)
                            continue
                        if in_meta:
                            if line.startswith((" ", "\t")):
                                meta_lines.append(line)
                            else:
                                break
                    if meta_lines:
                        doc = _yaml.safe_load("\n".join(meta_lines))
                        if isinstance(doc, dict):
                            src = (doc.get("metadata") or {}).get("source_fmc") or {}
                            version = str(src.get("version") or "")
                except Exception:
                    pass
            except Exception:
                pass
            files.append({
                "name": display_name, "version": version,
                "url": file_url,
            })
        return {"success": True, "files": files, "base_url": base_url}
    except Exception as e:
        return JSONResponse(status_code=400, content={
            "success": False, "message": f"Failed to list server YAMLs: {e}"})


@router.post("/server-yamls/load")
async def load_server_yamls(payload: Dict[str, Any], http_request: Request):
    """Download and load one or more YAML files from the remote server."""
    import requests as _requests
    urls: List[str] = payload.get("urls") or []
    if not urls:
        return JSONResponse(status_code=400, content={
            "success": False, "message": "No YAML URLs provided"})
    username = _username(http_request)
    ctx = _ctx(username)
    errors = []
    loaded_names = []
    raw_texts: List[str] = []
    # Replace (not append): start fresh so only selected server policies are loaded.
    cfg = PolicyConfig()
    ctx["policy_config"] = cfg
    _clear_resolution_cache(ctx)
    acp_store = _get_acp_configs(ctx)
    for url in urls:
        try:
            resp = _requests.get(url, verify=False, timeout=30)
            resp.raise_for_status()
            raw = resp.text
            raw_texts.append(raw)
            one_cfg = parse_yaml(raw)
            # Merge into the session config.
            for acp in one_cfg.acps:
                cfg.upsert_acp(acp)
                # Store per-ACP config for selective download.
                per_acp = PolicyConfig()
                per_acp.upsert_acp(acp)
                per_acp.objects = list(one_cfg.objects)
                for sub, items in one_cfg.policies.items():
                    per_acp.policies[sub] = list(items)
                if one_cfg.meta.get("source_fmc"):
                    per_acp.meta["source_fmc"] = one_cfg.meta["source_fmc"]
                acp_store[acp.name] = per_acp
            for key, items in one_cfg.policies.items():
                cfg.upsert_policies(key, items)
            cfg.upsert_objects(one_cfg.objects)
            # Preserve source metadata from the loaded YAML.
            if one_cfg.meta.get("source_fmc"):
                cfg.meta["source_fmc"] = one_cfg.meta["source_fmc"]
            loaded_names.append(url.rsplit("/", 1)[-1])
        except Exception as e:
            errors.append(f"{url}: {e}")
    ctx["policy_config"] = cfg
    # When a single file was loaded, reuse its raw text directly to avoid an
    # expensive build_yaml re-serialisation on large files.
    if len(raw_texts) == 1 and len(loaded_names) == 1:
        yaml_text = raw_texts[0]
    else:
        yaml_text = build_yaml(cfg)
    ctx["policy_config_yaml"] = yaml_text
    return {
        "success": len(loaded_names) > 0,
        "loaded": loaded_names,
        "errors": errors,
        "yaml": yaml_text,
        "acps": [a.to_summary() for a in cfg.acps],
        "object_count": len(cfg.objects),
    }


# ── Current YAML / download ──

@router.post("/yaml")
async def current_yaml(payload: Dict[str, Any], http_request: Request):
    username = _username(http_request)
    ctx = _ctx(username)
    cfg = _get_config(ctx)
    return {"success": True, "yaml": build_yaml(cfg), "acps": [a.to_summary() for a in cfg.acps]}


@router.post("/download")
async def download_yaml(payload: Dict[str, Any], http_request: Request):
    """Download policy YAML.

    If ``selected_acps`` is provided, combine only those ACPs (and their
    dependent policies/objects) from the per-ACP config store into a single
    YAML.  Otherwise fall back to the current session config.
    """
    username = _username(http_request)
    ctx = _ctx(username)
    selected: List[str] = payload.get("selected_acps") or []
    acp_store = _get_acp_configs(ctx)
    if selected and acp_store:
        combined = PolicyConfig()
        for name in selected:
            src_cfg = acp_store.get(name)
            if not src_cfg:
                continue
            for a in src_cfg.acps:
                combined.upsert_acp(a)
            for subsection, items in src_cfg.policies.items():
                combined.upsert_policies(subsection, items)
            combined.upsert_objects(src_cfg.objects)
            if not combined.meta.get("source_fmc") and src_cfg.meta.get("source_fmc"):
                combined.meta["source_fmc"] = src_cfg.meta["source_fmc"]
        text = build_yaml(combined)
    else:
        cfg = _get_config(ctx)
        text = build_yaml(cfg)
    fname = _yaml_filename()
    return Response(content=text, media_type="application/x-yaml",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ── Target policies for assigned-policy mapping dropdowns ──

@router.post("/target-policies")
async def target_policies(payload: Dict[str, Any], http_request: Request):
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        target = conn.build_target_client(ctx, debug=bool(payload.get("debug")))
        if target is None:
            return JSONResponse(status_code=400, content={
                "success": False, "message": "No target FMC connected."})
        categories: List[str] = payload.get("categories") or list(push_svc.ASSIGNED_POLICY_ENDPOINTS.keys())
        loop = asyncio.get_running_loop()

        cfg = _get_config(ctx)

        def _collect():
            policies = {c: push_svc.list_target_policies(target, c) for c in categories}
            cert_realm = push_svc.list_target_cert_realm(target)
            source_refs = push_svc.extract_source_cert_realm_refs(cfg)
            return policies, cert_realm, source_refs

        policies, cert_realm, source_refs = await loop.run_in_executor(None, _collect)
        return {"success": True, "policies": policies, "cert_realm": cert_realm,
                "source_refs": source_refs}
    except FmcApiError as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"target-policies failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Preview (dry run) ──

@router.post("/preview")
async def preview(payload: Dict[str, Any], http_request: Request):
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        _attach_logs(username)
        target, err = _target_only(ctx, payload)
        if err:
            return JSONResponse(status_code=400, content={"success": False, "message": err})
        cfg = _get_config(ctx)
        loop = asyncio.get_running_loop()
        # Offline: preview resolves entirely from the fetched YAML (source=None).
        result = await loop.run_in_executor(None, lambda: push_svc.preview(
            cfg, payload.get("acp_names") or [], None, target,
            mappings=payload.get("mappings") or {},
            validate=bool(payload.get("validate", True)),
            source_version=payload.get("source_version", ""),
            target_version=payload.get("target_version", ""),
            schema_source=payload.get("schema_source", "oas"),
            log=_log_fn(),
            ctx=ctx,
        ))
        return result
    except FmcApiError as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"Policy preview failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Sanitize (strip OAS-unsupported fields) ──

@router.post("/sanitize")
async def sanitize(payload: Dict[str, Any], http_request: Request):
    """Strip the selected OAS-unsupported fields from the loaded policy config.

    ``removals`` is a list of ``"<SchemaName>:<field>"`` group keys (from
    validation warnings). Mutates the in-session config, rebuilds the YAML, and
    re-runs validation so the Push Preview panel can refresh.
    """
    try:
        username = _username(http_request)
        ctx = _ctx(username)
        _attach_logs(username)
        cfg = _get_config(ctx)
        removals = set(payload.get("removals") or [])
        if not removals:
            return {"success": False, "message": "No fields selected to sanitize."}
        source_version = payload.get("source_version", "")
        target_version = payload.get("target_version", "")
        schema_source = payload.get("schema_source", "oas")
        log = _log_fn()
        log("─── **Sanitize** ──────────────────────────────────────")
        loop = asyncio.get_running_loop()

        def _apply() -> int:
            # Strip against whichever version resolves a schema (target preferred).
            n = sanitize_policy_config(cfg, removals, target_version, schema_source, log)
            if source_version and source_version != target_version:
                n += sanitize_policy_config(cfg, removals, source_version, schema_source, log)
            return n

        removed = await loop.run_in_executor(None, _apply)
        log(f"  [sanitize] removed {removed} unsupported field occurrence(s)")

        # Rebuild the session YAML so downloads/pushes use the sanitized config.
        yaml_text = build_yaml(cfg)
        ctx["policy_config_yaml"] = yaml_text

        # Re-validate the selected ACPs so the preview panel refreshes.
        acps = push_svc._selected_acps(cfg, payload.get("acp_names") or [])
        validations: List[Dict[str, Any]] = []
        if acps:
            sub = PolicyConfig(acps=acps, objects=cfg.objects, meta=cfg.meta,
                               policies=dict(cfg.policies))
            doc = sub.to_yaml_doc()
            # Fall back to YAML metadata version when the frontend didn't supply one.
            sv = source_version or push_svc._meta_version(cfg)
            tv = target_version or push_svc._meta_version(cfg)
            if sv:
                validations.append(validate_policy_doc(doc, sv, "source", schema_source).to_dict())
            if tv:
                validations.append(validate_policy_doc(doc, tv, "target", schema_source).to_dict())

        return {
            "success": True,
            "removed": removed,
            "yaml": yaml_text,
            "filename": _yaml_filename(),
            "validations": validations,
        }
    except Exception as e:
        logger.error(f"Policy sanitize failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── Push ──

@router.post("/push")
async def push(payload: Dict[str, Any], http_request: Request):
    username = _username(http_request)
    try:
        ctx = _ctx(username)
        _attach_logs(username)
        _host().reset_progress(username)
        _host()._start_user_operation(username, "policy-push")
        target, err = _target_only(ctx, payload)
        if err:
            _host()._finish_user_operation(username, False, err)
            return JSONResponse(status_code=400, content={"success": False, "message": err})

        cfg = _get_config(ctx)
        loop = asyncio.get_running_loop()

        def _progress(pct: int, label: str) -> None:
            try:
                _host().set_progress(username, pct, label)
            except Exception:
                pass

        # Offline: the push uses the fetched YAML as its only source of
        # configuration and never contacts the source FMC (source=None).
        result = await loop.run_in_executor(None, lambda: push_svc.push(
            cfg, payload.get("acp_names") or [], None, target,
            mappings=payload.get("mappings") or {},
            validate=bool(payload.get("validate", True)),
            bulk=bool(payload.get("bulk", True)),
            per_rule_fallback=bool(payload.get("per_rule_fallback", False)),
            source_version=payload.get("source_version", ""),
            target_version=payload.get("target_version", ""),
            schema_source=payload.get("schema_source", "oas"),
            confirm_overrides=bool(payload.get("confirm_overrides", False)),
            cert_realm_extras=payload.get("cert_realm_extras") or {},
            strip_zones=bool(payload.get("strip_zones", False)),
            realm_password=payload.get("realm_password", "Bglsit@123"),
            log=_log_fn(),
            progress=_progress,
            ctx=ctx,
        ))
        _host()._finish_user_operation(username, bool(result.get("success")),
                                       result.get("message", "Policy push complete"))
        return result
    except FmcApiError as e:
        try:
            _host()._finish_user_operation(username, False, str(e))
        except Exception:
            pass
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"Policy push failed: {e}")
        try:
            _host()._finish_user_operation(username, False, str(e))
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


# ── helpers ──

def _both_clients(ctx: Dict[str, Any], payload: Dict[str, Any]):
    debug = bool(payload.get("debug"))
    source = conn.build_source_client(ctx, debug=debug)
    if source is None:
        return None, None, "Source FMC not connected. Connect first."
    target = conn.build_target_client(ctx, debug=debug)
    if target is None:
        return None, None, "No target FMC connected."
    if conn.is_same_fmc(source, target):
        return None, None, "Source and target FMC are the same; cannot replicate onto itself."
    return source, target, ""


def _target_only(ctx: Dict[str, Any], payload: Dict[str, Any]):
    """Return (target_client, error). Preview/push are offline and need only
    the connected target FMC — the source FMC is never contacted."""
    target = conn.build_target_client(ctx, debug=bool(payload.get("debug")))
    if target is None:
        return None, "No target FMC connected."
    return target, ""


def _yaml_filename() -> str:
    return f"policy-config-{int(time.time())}.yaml"
