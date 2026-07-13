"""Shared fixtures + a fake FMC client for policy-config tests.

Run from the repo root:
    python3 -m pytest web_app/policy_configuration/tests -q

No live FMC is required; ``FakeFmcClient`` mimics the parts of
``PolicyFmcClient`` the services depend on (paginated GET, object lookup by
name, POST/PUT, ``cfg_path``) using an in-memory data set.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

import pytest

# Make the web_app package importable regardless of CWD (mirrors the
# pre_push_validation test convention).
_HERE = os.path.dirname(os.path.abspath(__file__))
_WEB_APP = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
if _WEB_APP not in sys.path:
    sys.path.insert(0, _WEB_APP)

from policy_configuration.models.schema import normalize_name  # noqa: E402


class FakeFmcClient:
    """In-memory stand-in for PolicyFmcClient.

    ``data`` maps an object-endpoint suffix (e.g. ``"object/hosts"``) to a list
    of object dicts. ``fail_bulk`` makes bulk POSTs raise to exercise per-item
    fallback. ``created`` records POST bodies for assertions.
    """

    def __init__(
        self, fmc_ip: str = "https://src.example.com", domain_uuid: str = "dom-1",
        data: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        version: str = "7.6.0", build: str = "999", model: str = "FMCv",
    ):
        self.fmc_ip = fmc_ip
        self.domain_uuid = domain_uuid
        self.headers = {"X-auth-access-token": "tok"}
        self._data: Dict[str, List[Dict[str, Any]]] = data or {}
        self.version = version
        self.build = build
        self.model = model
        self.fail_bulk = False
        self.created: List[Dict[str, Any]] = []
        self.bulk_created: List[Dict[str, Any]] = []
        self.put_calls: List[Dict[str, Any]] = []
        self._next_id = 1000
        self._obj_cache: Dict[str, Dict[str, Any]] = {}

    # ── path helpers ──
    def cfg_path(self, suffix: str) -> str:
        return f"/api/fmc_config/v1/domain/{self.domain_uuid}/{suffix.lstrip('/')}"

    def _suffix(self, path: str) -> str:
        marker = f"/domain/{self.domain_uuid}/"
        return path.split(marker, 1)[1] if marker in path else path.lstrip("/")

    # ── reads ──
    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if path == "/api/fmc_platform/v1/info/serverversion":
            return {"items": [{"serverVersion": self.version, "build": self.build, "model": self.model}]}
        if path == "/api/fmc_platform/v1/info/domain":
            return {"items": [{"uuid": self.domain_uuid, "name": "Global"}]}
        suffix = self._suffix(path)
        # GET by id: suffix like "object/hosts/<id>"
        parts = suffix.rsplit("/", 1)
        if len(parts) == 2 and parts[0] in self._data:
            for obj in self._data[parts[0]]:
                if str(obj.get("id")) == parts[1]:
                    return obj
        # Could be an ACP base: policy/accesspolicies/<id>
        for key, items in self._data.items():
            for obj in items:
                if str(obj.get("id")) == suffix.rsplit("/", 1)[-1] and suffix.startswith(key.rsplit("/", 1)[0]):
                    return obj
        # ACP base direct match.
        if suffix.count("/") >= 2 and suffix.startswith("policy/accesspolicies/"):
            aid = suffix.split("/")[2]
            for obj in self._data.get("policy/accesspolicies", []):
                if str(obj.get("id")) == aid:
                    return obj
        return {}

    def get_paginated(self, path: str, *, expanded: bool = True, page_size: int = 1000,
                      params: Optional[Dict[str, Any]] = None, max_pages: int = 10000) -> List[Dict[str, Any]]:
        suffix = self._suffix(path)
        items = list(self._data.get(suffix, []))
        # Support a nameOrValue filter.
        if params and "filter" in params:
            flt = params["filter"]
            if flt.startswith("nameOrValue:"):
                q = flt.split(":", 1)[1].lower()
                items = [o for o in items if q in str(o.get("name", "")).lower()]
        return items

    def get_objects_by_names(self, object_suffix: str, names: List[str], obj_type: str,
                             *, supports_filter: bool = True, expanded: bool = True,
                             prefer_full_fetch: bool = False,
                             progress_cb=None) -> Dict[str, Dict[str, Any]]:
        want = {normalize_name(n) for n in names if n}
        out: Dict[str, Dict[str, Any]] = {}
        for o in self._data.get(object_suffix, []):
            nn = normalize_name(o.get("name"))
            if nn in want:
                out[nn] = o
        return out

    def request_stats(self) -> Dict[str, int]:
        return {"total": 0, "GET": 0, "retries": 0, "cache_hits": 0}

    def reset_request_stats(self) -> None:
        pass

    def cache_put(self, obj_type: str, obj: Dict[str, Any]) -> None:
        nm = obj.get("name")
        if nm:
            self._obj_cache[f"{obj_type}::{normalize_name(nm)}"] = obj

    def cache_get(self, obj_type: str, name: str) -> Optional[Dict[str, Any]]:
        return self._obj_cache.get(f"{obj_type}::{normalize_name(name)}")

    # ── writes ──
    def post(self, path: str, body: Any, *, bulk: bool = False) -> Any:
        suffix = self._suffix(path)
        if bulk:
            if self.fail_bulk:
                from policy_configuration.services.client import FmcApiError
                raise FmcApiError("bulk unsupported")
            items = []
            for b in body:
                items.append(self._store(suffix, b))
            # Record an aggregate bulk entry so tests can verify bulk was used.
            self.bulk_created.append({"suffix": suffix, "body": body, "id": "bulk", "bulk": True})
            return {"items": items}
        return self._store(suffix, body)

    def _store(self, suffix: str, body: Dict[str, Any]) -> Dict[str, Any]:
        obj = dict(body) if isinstance(body, dict) else {"_raw": body}
        obj["id"] = f"tgt-{self._next_id}"
        self._next_id += 1
        self.created.append({"suffix": suffix, "body": body, "id": obj["id"]})
        self._data.setdefault(suffix, []).append(obj)
        return obj

    def put(self, path: str, body: Any) -> Any:
        self.put_calls.append({"path": path, "body": body})
        return dict(body)

    def delete(self, path: str) -> Any:
        return {}


@pytest.fixture
def host_obj():
    def _mk(name, value, oid):
        return {"type": "Host", "name": name, "value": value, "id": oid}
    return _mk


@pytest.fixture
def acp_base():
    """A representative ACP base + rules referencing objects + dependent policies."""
    return {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "Corp-ACP", "type": "AccessPolicy",
             "links": {"self": "https://x/acp-1"}, "metadata": {"domain": "Global"},
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction",
                               "intrusionPolicy": {"id": "ips-1", "name": "Balanced",
                                                   "type": "IntrusionPolicy"}},
             "prefilterPolicySetting": {"id": "pf-1", "name": "Default Prefilter",
                                        "type": "PrefilterPolicy"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "rule-1", "name": "Allow-Web", "type": "AccessRule", "action": "ALLOW",
             "links": {"self": "https://x/rule-1"}, "metadata": {"ruleIndex": 1},
             "sourceNetworks": {"objects": [{"type": "Host", "name": "web1", "id": "h-1"}]},
             "destinationNetworks": {"objects": [{"type": "Host", "name": "web2", "id": "h-2"}]},
             "filePolicy": {"id": "fp-1", "name": "Block-Malware", "type": "FilePolicy"}},
            {"id": "rule-2", "name": "Block-FTP", "type": "AccessRule", "action": "BLOCK",
             "sourcePorts": {"objects": [{"type": "ProtocolPortObject", "name": "FTP", "id": "p-1"}]}},
        ],
        "policy/prefilterpolicies": [
            {"id": "pf-1", "name": "Default Prefilter", "type": "PrefilterPolicy",
             "links": {"self": "x"}, "metadata": {"domain": "Global"},
             "defaultAction": {"action": "ANALYZE_TUNNELS", "type": "PrefilterPolicyDefaultAction"}},
        ],
        "policy/filepolicies": [
            {"id": "fp-1", "name": "Block-Malware", "type": "FilePolicy",
             "description": "blocks malware"},
        ],
        "policy/intrusionpolicies": [
            {"id": "ips-1", "name": "Balanced", "type": "IntrusionPolicy",
             "inspectionMode": "DETECTION"},
        ],
        "object/hosts": [
            {"id": "h-1", "name": "web1", "value": "10.0.0.1", "type": "Host",
             "links": {"self": "x"}, "metadata": {"timestamp": 1}},
            {"id": "h-2", "name": "web2", "value": "10.0.0.2", "type": "Host"},
        ],
        "object/protocolportobjects": [
            {"id": "p-1", "name": "FTP", "protocol": "TCP", "port": "21", "type": "ProtocolPortObject"},
        ],
    }
