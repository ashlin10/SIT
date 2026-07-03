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

        cfg = _get_config(ctx)
        _clear_resolution_cache(ctx)
        cfg.upsert_acp(acp)
        for subsection, items in policies.items():
            cfg.upsert_policies(subsection, items)
        cfg.upsert_objects(objects)
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


# ── Current YAML / download ──

@router.post("/yaml")
async def current_yaml(payload: Dict[str, Any], http_request: Request):
    username = _username(http_request)
    ctx = _ctx(username)
    cfg = _get_config(ctx)
    return {"success": True, "yaml": build_yaml(cfg), "acps": [a.to_summary() for a in cfg.acps]}


@router.post("/download")
async def download_yaml(payload: Dict[str, Any], http_request: Request):
    username = _username(http_request)
    ctx = _ctx(username)
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

        def _collect():
            return {c: push_svc.list_target_policies(target, c) for c in categories}

        result = await loop.run_in_executor(None, _collect)
        return {"success": True, "policies": result}
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
        source, target, err = _both_clients(ctx, payload)
        if err:
            return JSONResponse(status_code=400, content={"success": False, "message": err})
        cfg = _get_config(ctx)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: push_svc.preview(
            cfg, payload.get("acp_names") or [], source, target,
            mappings=payload.get("mappings") or {},
            validate=bool(payload.get("validate", True)),
            source_version=payload.get("source_version", ""),
            target_version=payload.get("target_version", ""),
            log=_log_fn(),
            ctx=ctx,
        ))
        return result
    except FmcApiError as e:
        return JSONResponse(status_code=400, content={"success": False, "message": str(e)})
    except Exception as e:
        logger.error(f"Policy preview failed: {e}")
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
        source, target, err = _both_clients(ctx, payload)
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

        result = await loop.run_in_executor(None, lambda: push_svc.push(
            cfg, payload.get("acp_names") or [], source, target,
            mappings=payload.get("mappings") or {},
            validate=bool(payload.get("validate", True)),
            bulk=bool(payload.get("bulk", True)),
            per_rule_fallback=bool(payload.get("per_rule_fallback", False)),
            source_version=payload.get("source_version", ""),
            target_version=payload.get("target_version", ""),
            confirm_overrides=bool(payload.get("confirm_overrides", False)),
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


def _yaml_filename() -> str:
    return f"policy-config-{int(time.time())}.yaml"
