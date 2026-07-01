"""Create/reuse the dependent policies an ACP + its rules reference.

Scope (per product decision):
  * **File policies** and **Intrusion policies** are *created* on the target
    when a same-named policy does not already exist. Intrusion policies are
    created from their base policy (matched by name on the target); file
    policies are created container-first, then their file rules are cloned.
  * **Prefilter / Decryption / Identity** policies are *reuse-by-name only*
    (assigned when a same-named policy exists on the target, otherwise skipped)
    — they are version-sensitive and often permission-gated, so blind creation
    reliably fails (HTTP 422/403).

Every created/reused policy records a source->target id remap on the resolver so
the access-rule reference remapping rewrites rule bodies to the target id
instead of pruning the reference.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models.schema import AcpModel, PolicyConfig, PushSummary, normalize_name
from ..dependency_resolution.resolver import DependencyResolver
from .client import PolicyFmcClient, FmcApiError

logger = logging.getLogger(__name__)

# Rule/default-action policy types we create on the target, with source config
# subsection + target endpoint.
_CREATABLE = {
    "IntrusionPolicy": ("intrusion_policies", "policy/intrusionpolicies"),
    "FilePolicy": ("file_policies", "policy/filepolicies"),
}

# Server-managed keys never sent on a create.
_STRIP = ("id", "links", "metadata")


def ensure_rule_policies(
    acps: List[AcpModel], config: PolicyConfig, source: PolicyFmcClient,
    target: PolicyFmcClient, resolver: DependencyResolver, summary: PushSummary,
    log: Callable[[str], None],
) -> None:
    """Reuse-by-name or create every File/Intrusion policy referenced by *acps*.

    Registers source->target id remaps on *resolver* for each resolved policy.
    """
    refs = _collect_rule_policy_refs(acps)
    if not refs:
        return
    defs = _policy_def_index(config)
    log(f"[dep-policies] Resolving {len(refs)} File/Intrusion policy reference(s)")
    for ref_type, sid, name in refs:
        if sid and sid in resolver.remap_table:
            continue
        # 1) Reuse an identically-named policy already on the target.
        tid = resolver.resolve_target_id(ref_type, name, sid)
        if tid:
            resolver.register_remap(sid, tid)
            log(f"  [dep-policies] reuse {ref_type} '{name}' "
                f"(source={sid or '—'} -> target={tid})")
            continue
        # 2) Create it from the source definition.
        body_def = defs.get((ref_type, sid)) or defs.get((ref_type, normalize_name(name))) \
            or _fetch_source_def(source, ref_type, sid)
        if not body_def:
            log(f"  [dep-policies] {ref_type} '{name}': no source definition; leaving unresolved")
            continue
        new_id = _create_policy(ref_type, body_def, name, source, target, sid, resolver, log)
        if new_id:
            resolver.register_remap(sid, new_id)
            summary.objects_created.append(f"{ref_type} '{name}'")
            log(f"  [dep-policies] created {ref_type} '{name}' on target (id={new_id})")
        else:
            summary.skipped_settings.append(
                f"{ref_type} '{name}' could not be created on target; rule references pruned")


def _create_policy(
    ref_type: str, body_def: Dict[str, Any], name: str, source: PolicyFmcClient,
    target: PolicyFmcClient, source_id: str, resolver: DependencyResolver,
    log: Callable[[str], None],
) -> str:
    if ref_type == "IntrusionPolicy":
        return _create_intrusion_policy(target, body_def, log)
    if ref_type == "FilePolicy":
        return _create_file_policy(source, target, body_def, source_id, resolver, log)
    return ""


def _create_intrusion_policy(
    target: PolicyFmcClient, body_def: Dict[str, Any], log: Callable[[str], None],
) -> str:
    """Create an intrusion policy from its base policy (matched by name)."""
    name = str(body_def.get("name") or "")
    body: Dict[str, Any] = {"type": "IntrusionPolicy", "name": name}
    for k in ("inspectionMode", "inlineDrop"):
        if k in body_def:
            body[k] = body_def[k]
    base = body_def.get("basePolicy") if isinstance(body_def.get("basePolicy"), dict) else {}
    base_name = str(base.get("name") or "")
    if base_name:
        base_id = _find_policy_id_by_name(target, "policy/intrusionpolicies", base_name)
        if base_id:
            body["basePolicy"] = {"id": base_id, "type": "IntrusionPolicy"}
        else:
            log(f"  [dep-policies] IntrusionPolicy '{name}': base policy "
                f"'{base_name}' not found on target; skipping create")
            return ""
    try:
        created = target.post(target.cfg_path("policy/intrusionpolicies"), body)
        return str(created.get("id") or "") if isinstance(created, dict) else ""
    except FmcApiError as e:
        log(f"  [dep-policies] failed to create IntrusionPolicy '{name}': {e}")
        return ""


def _create_file_policy(
    source: PolicyFmcClient, target: PolicyFmcClient, body_def: Dict[str, Any],
    source_id: str, resolver: DependencyResolver, log: Callable[[str], None],
) -> str:
    """Create a file policy container, then clone its file rules from source."""
    name = str(body_def.get("name") or "")
    body = {k: v for k, v in body_def.items() if k not in _STRIP}
    body.setdefault("type", "FilePolicy")
    # File rules are created separately (they are not part of the container body).
    body.pop("fileRules", None)
    try:
        created = target.post(target.cfg_path("policy/filepolicies"), body)
    except FmcApiError as e:
        log(f"  [dep-policies] failed to create FilePolicy '{name}': {e}")
        return ""
    new_id = str(created.get("id") or "") if isinstance(created, dict) else ""
    if not new_id:
        return ""
    if source_id:
        _clone_file_rules(source, target, source_id, new_id, name, resolver, log)
    return new_id


def _clone_file_rules(
    source: PolicyFmcClient, target: PolicyFmcClient, source_pid: str,
    target_pid: str, name: str, resolver: DependencyResolver,
    log: Callable[[str], None],
) -> None:
    """Copy the source file policy's file rules onto the newly created target one."""
    try:
        rules = source.get_paginated(
            source.cfg_path(f"policy/filepolicies/{source_pid}/filerules"), expanded=True)
    except FmcApiError as e:
        log(f"  [dep-policies] FilePolicy '{name}': could not read file rules: {e}")
        return
    path = target.cfg_path(f"policy/filepolicies/{target_pid}/filerules")
    ok = 0
    for r in rules:
        body = {k: v for k, v in r.items() if k not in _STRIP}
        # Predefined FileType/FileCategory ids are globally consistent; only
        # remap ids we actually know a target equivalent for.
        resolver.remap_references(body)
        try:
            target.post(path, body)
            ok += 1
        except FmcApiError as e:
            log(f"  [dep-policies] FilePolicy '{name}': file rule "
                f"'{r.get('name', '?')}' failed: {e}")
    if rules:
        log(f"  [dep-policies] FilePolicy '{name}': cloned {ok}/{len(rules)} file rule(s)")


# ── reuse-by-name for assigned prefilter/decryption/identity ──

def match_assigned_policy_by_name(
    target: PolicyFmcClient, endpoints: List[str], name: str,
) -> str:
    """Return the id of a same-named policy on the target, or "" if absent."""
    for suffix in endpoints:
        pid = _find_policy_id_by_name(target, suffix, name)
        if pid:
            return pid
    return ""


# ── helpers ──

def _collect_rule_policy_refs(acps: List[AcpModel]) -> List[Tuple[str, str, str]]:
    """Deduped (type, source_id, name) for File/Intrusion refs in rules + default action."""
    found: Dict[Tuple[str, str], Tuple[str, str, str]] = {}

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            t = node.get("type")
            if isinstance(t, str) and t in _CREATABLE and (node.get("id") or node.get("name")):
                sid = str(node.get("id", ""))
                nm = str(node.get("name", ""))
                found.setdefault((t, sid or normalize_name(nm)), (t, sid, nm))
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for it in node:
                _walk(it)

    for acp in acps:
        _walk(acp.default_action)
        for rule in acp.access_rules or []:
            _walk(rule)
    return list(found.values())


def _policy_def_index(config: PolicyConfig) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Index config dependent-policy definitions by (type, id) and (type, name)."""
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    sub_to_type = {sub: t for t, (sub, _ep) in _CREATABLE.items()}
    for sub, items in (config.policies or {}).items():
        ptype = sub_to_type.get(sub)
        if not ptype:
            continue
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if it.get("id"):
                index[(ptype, str(it["id"]))] = it
            if it.get("name"):
                index[(ptype, normalize_name(it["name"]))] = it
    return index


def _fetch_source_def(
    source: PolicyFmcClient, ref_type: str, source_id: str,
) -> Optional[Dict[str, Any]]:
    """Fetch a policy definition from the source FMC by id (fallback path)."""
    entry = _CREATABLE.get(ref_type)
    if not entry or not source_id:
        return None
    suffix = entry[1]
    try:
        body = source.get_json(source.cfg_path(f"{suffix}/{source_id}"))
        if isinstance(body, dict) and body.get("id"):
            return body
    except FmcApiError:
        pass
    return None


def _find_policy_id_by_name(
    target: PolicyFmcClient, suffix: str, name: str,
) -> str:
    """Return the id of a target policy named *name* under *suffix* (or "")."""
    nn = normalize_name(name)
    try:
        items = target.get_paginated(target.cfg_path(suffix), expanded=False)
    except FmcApiError:
        return ""
    for it in items:
        if normalize_name(it.get("name")) == nn:
            return str(it.get("id") or "")
    return ""
