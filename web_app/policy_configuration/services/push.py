"""Push orchestration: preview + execute ACP replication to the target FMC.

Flow (mirrors Device Configuration Push Config):
  1. (optional) validate source + target-resolved YAML against FMC OAS schema.
  2. discover + resolve dependencies, build a plan.
  3. block on conflicts / cycles / unresolved references.
  4. create missing objects in dependency order; remap references to target ids.
  5. resolve assigned-policy create/override mappings.
  6. create or update each ACP, then push its access rules (bulk w/ fallback).
  7. return a complete success/warning/partial-failure summary.
"""
from __future__ import annotations

import copy
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models.schema import (
    AcpModel, PolicyConfig, PushSummary, normalize_name,
)
from ..dependency_resolution.resolver import DependencyResolver, GLOBAL_ID_TYPES
from ..validation.policy_validator import validate_policy_doc
from .acp_fetch import harvest_dependencies
from .client import PolicyFmcClient, FmcApiError
from . import dependent_policies

logger = logging.getLogger(__name__)


# ── Resolution caching ──

@dataclass
class _CachedResolution:
    """Cached resolver + plan from a prior preview, reusable in push."""
    key: str
    resolver: DependencyResolver
    plan: Any  # ResolutionPlan


def _resolution_cache_key(
    acp_names: List[str],
    source: PolicyFmcClient,
    target: PolicyFmcClient,
    mappings: Dict[str, Dict[str, str]],
) -> str:
    """Deterministic hash of the inputs that affect resolution.

    If any of these change between preview and push the cached resolution is
    invalid and must be recomputed.
    """
    parts = [
        "|".join(sorted(acp_names)),
        source.fmc_ip, source.domain_uuid,
        target.fmc_ip, target.domain_uuid,
        str(sorted(mappings.items())),
    ]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _get_cached_resolution(
    ctx: Optional[Dict[str, Any]], key: str,
) -> Optional[_CachedResolution]:
    if ctx is None:
        return None
    cached = ctx.get("_resolution_cache")
    if isinstance(cached, _CachedResolution) and cached.key == key:
        return cached
    return None


def _set_cached_resolution(
    ctx: Optional[Dict[str, Any]], cached: _CachedResolution,
) -> None:
    if ctx is not None:
        ctx["_resolution_cache"] = cached


def _clear_resolution_cache(ctx: Optional[Dict[str, Any]]) -> None:
    if ctx is not None:
        ctx.pop("_resolution_cache", None)


# Category -> candidate list endpoints on the target FMC (for mapping dropdowns).
ASSIGNED_POLICY_ENDPOINTS: Dict[str, List[str]] = {
    "prefilterPolicy": ["policy/prefilterpolicies"],
    "decryptionPolicy": ["policy/decryptionpolicies", "policy/sslpolicies"],
    "identityPolicy": ["policy/identitypolicies"],
}

# Category -> ACP base field used to assign the policy reference.
_CATEGORY_TO_ACP_FIELD: Dict[str, str] = {
    "prefilterPolicy": "prefilterPolicySetting",
    "decryptionPolicy": "decryptionPolicySetting",
    "identityPolicy": "identityPolicySetting",
}

# ACP-base keys that hold assigned-policy references by source id. They are
# applied deliberately via the assigned-policy mapping (create/override), so the
# raw source values must NOT be copied verbatim into the target body (their
# source ids do not exist on the target and cause HTTP 500/422).
_ACP_ASSIGNED_KEYS = {
    "prefilterPolicySetting", "decryptionPolicySetting", "sslPolicy",
    "identityPolicySetting", "securityIntelligence",
    "securityIntelligencePolicySetting", "securityIntelligencePolicy",
}

# Rule-referenced policy/variable types that are NOT part of the object
# dependency graph and must be resolved on the target by name at push time.
_RULE_POLICY_TYPES = {"IntrusionPolicy", "FilePolicy", "VariableSet"}

# Types whose ids are globally consistent across FMCs — imported from resolver.
# When such a reference cannot be name-matched on the target the source id is
# still valid, so it is kept rather than pruned.
_GLOBAL_ID_TYPES = GLOBAL_ID_TYPES

# Max access rules per bulk POST (FMC accepts up to 1000; we split larger sets).
_RULE_BULK_BATCH = 1000

# Rule-body keys that are read-only/server-managed and must not be POSTed.
_RULE_STRIP_KEYS = ("id", "links", "metadata", "commentHistoryList", "ruleIndex")


def list_target_policies(target: PolicyFmcClient, category: str) -> List[Dict[str, Any]]:
    """Return existing target policies of *category* for the mapping dropdown."""
    out: List[Dict[str, Any]] = []
    for suffix in ASSIGNED_POLICY_ENDPOINTS.get(category, []):
        try:
            items = target.get_paginated(target.cfg_path(suffix), expanded=True)
            for it in items:
                out.append({"id": it.get("id"), "name": it.get("name"), "type": it.get("type")})
            if out:
                break
        except FmcApiError as e:
            logger.debug(f"list_target_policies({category}) via {suffix} failed: {e}")
    return out


def _selected_acps(config: PolicyConfig, names: List[str]) -> List[AcpModel]:
    wanted = {normalize_name(n) for n in names}
    return [a for a in config.acps if normalize_name(a.name) in wanted]


def _seed_refs(acps: List[AcpModel]):
    seen = {}
    for acp in acps:
        for ref in harvest_dependencies(acp):
            seen.setdefault(ref.key, ref)
    return list(seen.values())


def preview(
    config: PolicyConfig,
    acp_names: List[str],
    source: PolicyFmcClient,
    target: PolicyFmcClient,
    *,
    mappings: Optional[Dict[str, Dict[str, str]]] = None,
    validate: bool = True,
    source_version: str = "",
    target_version: str = "",
    log: Optional[Callable[[str], None]] = None,
    ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Dry-run: resolve dependencies + validate, but make no target changes."""
    log = log or (lambda m: logger.info(m))
    acps = _selected_acps(config, acp_names)
    if not acps:
        return {"success": False, "message": "No matching ACPs selected"}

    cache_key = _resolution_cache_key(acp_names, source, target, mappings or {})
    cached = _get_cached_resolution(ctx, cache_key)
    if cached:
        log("[resolve] Reusing cached resolution from previous run")
        resolver, plan = cached.resolver, cached.plan
    else:
        resolver = DependencyResolver(source, target, log=log)
        resolver.discover(_seed_refs(acps))
        plan = resolver.build_plan()
        _set_cached_resolution(ctx, _CachedResolution(key=cache_key, resolver=resolver, plan=plan))

    validations: List[Dict[str, Any]] = []
    if validate:
        sub = PolicyConfig(acps=acps, objects=config.objects, meta=config.meta)
        doc = sub.to_yaml_doc()
        validations.append(validate_policy_doc(doc, source_version, "source").to_dict())
        validations.append(validate_policy_doc(doc, target_version, "target").to_dict())

    overrides = _override_summary(acps, mappings or {})
    return {
        "success": True,
        "selected_acps": [a.name for a in acps],
        "plan": plan.to_dict(),
        "validations": validations,
        "assigned_policy_mappings": overrides,
    }


def _override_summary(acps: List[AcpModel], mappings: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for acp in acps:
        acp_map = mappings.get(acp.name, {})
        for cat, ap in acp.assigned_policies.items():
            choice = acp_map.get(cat, "__create__")
            out.append({
                "acp": acp.name,
                "category": cat,
                "source_name": ap.name,
                "behavior": "override" if choice and choice != "__create__" else "create",
                "target_policy_id": "" if choice == "__create__" else choice,
                "supported": ap.supported,
            })
    return out


def push(
    config: PolicyConfig,
    acp_names: List[str],
    source: PolicyFmcClient,
    target: PolicyFmcClient,
    *,
    mappings: Optional[Dict[str, Dict[str, str]]] = None,
    validate: bool = True,
    bulk: bool = True,
    per_rule_fallback: bool = False,
    source_version: str = "",
    target_version: str = "",
    confirm_overrides: bool = False,
    log: Optional[Callable[[str], None]] = None,
    progress: Optional[Callable[[int, str], None]] = None,
    ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute the replication. Returns a result dict with a PushSummary.

    Rule-push strategy:
      * ``bulk=True`` (default) attempts a single bulk POST of the access rules.
      * ``per_rule_fallback`` (default ``False``) controls whether a *failed*
        bulk push is retried rule-by-rule. When disabled, a bulk failure stops
        rule submission for that batch and is reported as-is; when enabled, the
        push transitions to per-rule submission and records each rule's outcome.
    """
    log = log or (lambda m: logger.info(m))
    progress = progress or (lambda p, m: None)
    mappings = mappings or {}
    summary = PushSummary()
    summary.per_rule_fallback_enabled = per_rule_fallback

    acps = _selected_acps(config, acp_names)
    if not acps:
        return {"success": False, "message": "No matching ACPs selected"}

    log(f"[push] Rule-push strategy: {'bulk' if bulk else 'per-rule'}; "
        f"per-rule fallback if bulk fails: {'ENABLED' if per_rule_fallback else 'DISABLED'}")

    # ── 1. Validation ──
    progress(5, "Validating policy configuration")
    if validate:
        sub = PolicyConfig(acps=acps, objects=config.objects, meta=config.meta)
        doc = sub.to_yaml_doc()
        src_res = validate_policy_doc(doc, source_version, "source")
        tgt_res = validate_policy_doc(doc, target_version, "target")
        summary.validation_errors = src_res.errors + tgt_res.errors
        summary.validation_warnings = src_res.warnings + tgt_res.warnings
        for w in summary.validation_warnings:
            log(f"  [validate] WARNING: {w.get('scope', '')}: {w.get('message', '')}")
        if src_res.has_blocking or tgt_res.has_blocking:
            log("Push blocked: schema validation reported blocking errors")
            return {"success": False, "message": "Validation failed",
                    "summary_tables": _summary_tables(summary), "summary": summary.to_dict()}

    # ── 2. Dependency resolution (reuse cached from preview when available) ──
    progress(20, "Resolving dependencies")
    cache_key = _resolution_cache_key(acp_names, source, target, mappings)
    cached = _get_cached_resolution(ctx, cache_key)
    if cached:
        log("[resolve] Reusing cached resolution from preview")
        resolver, plan = cached.resolver, cached.plan
    else:
        log("[resolve] No cached resolution available; running fresh resolution")
        resolver = DependencyResolver(source, target, log=log)
        resolver.discover(_seed_refs(acps))
        plan = resolver.build_plan()

    if plan.cycles:
        log(f"Push blocked: circular dependencies: {plan.cycles}")
        return {"success": False, "message": "Circular dependency detected",
                "summary_tables": _summary_tables(summary), "summary": summary.to_dict(),
                "plan": plan.to_dict()}
    if plan.conflicts:
        log(f"Push blocked: {len(plan.conflicts)} incompatible name collision(s)")
        return {"success": False, "message": "Incompatible object name collisions",
                "summary_tables": _summary_tables(summary), "summary": summary.to_dict(),
                "plan": plan.to_dict()}

    # Structured reused-object logging (name, type, source/target id, match
    # method, and the access rules that reference it) for auditability.
    ref_index = _build_reference_index(acps)
    summary.objects_reused = [r.name for r in plan.to_reuse]
    if plan.to_reuse:
        log(f"[resolve] {len(plan.to_reuse)} object(s) matched and reused on target FMC:")
        for r in plan.to_reuse:
            refs = ref_index.get(r.source_id) or ref_index.get(r.key) or []
            used_by = f"; used by rule(s): {', '.join(sorted(set(refs)))}" if refs else ""
            log(f"  [reuse] {r.type} '{r.name}' "
                f"(source={r.source_id or '—'} -> target={r.target_id or '—'}, "
                f"match={r.match_method or 'name'}){used_by}")
    if plan.unresolved:
        summary.objects_unresolved = [f"{u.get('type')} '{u.get('name')}'" for u in plan.unresolved]
        log(f"[resolve] {len(plan.unresolved)} reference(s) could not be resolved on target FMC:")
        for u in plan.unresolved:
            refs = ref_index.get(u.get("source_id")) or []
            used_by = f"; referenced by: {', '.join(sorted(set(refs)))}" if refs else ""
            log(f"  [unresolved] {u.get('type')} '{u.get('name')}': {u.get('reason')}{used_by}")

    # ── 3. Create missing objects in dependency order ──
    progress(40, "Creating dependent objects")
    created, partial = resolver.apply(plan, bulk=bulk)
    summary.objects_created = created
    summary.partial_changes.extend(f"object: {n}" for n in partial)

    # ── 3b. Reuse-by-name or create File/Intrusion policies referenced by rules ──
    progress(48, "Resolving dependent File/Intrusion policies")
    dependent_policies.ensure_rule_policies(acps, config, source, target, resolver, summary, log)

    # ── 4. Per-ACP create/update ──
    total = max(len(acps), 1)
    for idx, acp in enumerate(acps):
        pct = 50 + int(40 * (idx / total))
        progress(pct, f"Pushing ACP '{acp.name}'")
        try:
            _push_one_acp(acp, source, target, resolver, mappings.get(acp.name, {}),
                          confirm_overrides, summary, bulk, per_rule_fallback, log)
            summary.successful_acps.append(acp.name)
        except FmcApiError as e:
            log(f"  ACP '{acp.name}' failed: {e}")
            summary.failed_acps.append({"name": acp.name, "error": str(e)})
        except Exception as e:  # pragma: no cover - defensive
            log(f"  ACP '{acp.name}' error: {e}")
            summary.failed_acps.append({"name": acp.name, "error": str(e)})

    progress(100, "Push complete")
    _clear_resolution_cache(ctx)
    _log_final_summary(summary, plan, log)
    ok = not summary.failed_acps and not summary.rules_failed
    return {
        "success": ok,
        "message": _push_result_message(ok, summary),
        "summary": summary.to_dict(),
        "summary_tables": _summary_tables(summary),
        "plan": plan.to_dict(),
    }


def _push_result_message(ok: bool, summary: PushSummary) -> str:
    """Build a message that distinguishes the four rule-push outcomes."""
    if not summary.bulk_failed:
        # Bulk succeeded (or there was nothing to bulk-push).
        return "Policy push complete" if ok else "Policy push completed with failures"
    if not summary.per_rule_fallback_enabled:
        # Bulk failed and fallback was disabled -> rules were not retried.
        return ("Bulk rule push failed and per-rule fallback was disabled; "
                "no rules were submitted individually")
    if ok:
        return "Bulk rule push failed; per-rule fallback succeeded for all rules"
    return "Bulk rule push failed; per-rule fallback completed with some failures"


def _build_reference_index(acps: List[AcpModel]) -> Dict[str, List[str]]:
    """Map each referenced object id -> [rule names that reference it].

    Enables logging *which* access rules reuse (or fail to resolve) an object.
    """
    index: Dict[str, List[str]] = {}

    def _walk(node: Any, rule_name: str) -> None:
        if isinstance(node, dict):
            oid = node.get("id")
            if isinstance(oid, str) and node.get("type"):
                index.setdefault(oid, [])
                if rule_name not in index[oid]:
                    index[oid].append(rule_name)
            for v in node.values():
                _walk(v, rule_name)
        elif isinstance(node, list):
            for it in node:
                _walk(it, rule_name)

    for acp in acps:
        for rule in acp.access_rules or []:
            name = str(rule.get("name", "?"))
            _walk(rule, name)
    return index


def _log_final_summary(summary: PushSummary, plan, log: Callable[[str], None]) -> None:
    """Emit a concise end-of-push summary block."""
    total_rules = len(summary.rules_pushed) + len(summary.rules_failed) + len(summary.rules_skipped)
    log("──────── Policy push summary ────────")
    log(f"  ACPs:              {len(summary.successful_acps)} ok, {len(summary.failed_acps)} failed")
    log(f"  Access rules:      {total_rules} total")
    log(f"    pushed:          {len(summary.rules_pushed)}")
    log(f"    failed:          {len(summary.rules_failed)}")
    log(f"    skipped:         {len(summary.rules_skipped)}")
    log(f"  Objects reused:    {len(summary.objects_reused)}")
    log(f"  Objects created:   {len(summary.objects_created)}")
    log(f"  Objects unresolved:{len(summary.objects_unresolved)}")
    if summary.dropped_references:
        log(f"  Dropped refs:      {len(summary.dropped_references)} "
            "(stale source references pruned from rules)")
    log("─────────────────────────────────────")


def _push_one_acp(
    acp: AcpModel, source: PolicyFmcClient, target: PolicyFmcClient,
    resolver: DependencyResolver, acp_map: Dict[str, str], confirm_overrides: bool,
    summary: PushSummary, bulk: bool, per_rule_fallback: bool,
    log: Callable[[str], None],
) -> None:
    # Resolve assigned-policy mappings first so we can embed refs in the ACP body.
    assigned_fields: Dict[str, Any] = {}
    for cat, ap in acp.assigned_policies.items():
        if not ap.supported:
            summary.skipped_settings.append(f"{acp.name}: assigned {cat} unsupported on target")
            continue
        field = _CATEGORY_TO_ACP_FIELD.get(cat)
        if not field:
            # Category not embeddable on the ACP base (e.g. SI/AI Defense); skip safely.
            summary.skipped_settings.append(f"{acp.name}: assigned {cat} not applied")
            continue
        choice = acp_map.get(cat, "__create__")
        if choice and choice != "__create__":
            if not confirm_overrides:
                summary.skipped_settings.append(
                    f"{acp.name}: override of {cat} requires confirmation; skipped")
                continue
            assigned_fields[field] = {"id": choice, "type": ap.type or _cat_type(cat)}
            summary.policies_overridden.append(f"{acp.name}:{cat}")
        else:
            # Prefilter/Decryption/Identity are reuse-by-name only: assign a
            # same-named policy already present on the target; never blind-copy
            # the source body (version/permission-sensitive -> HTTP 422/403).
            endpoints = ASSIGNED_POLICY_ENDPOINTS.get(cat, [])
            new_id = dependent_policies.match_assigned_policy_by_name(target, endpoints, ap.name)
            if new_id:
                assigned_fields[field] = {"id": new_id, "type": ap.type or _cat_type(cat)}
                summary.policies_overridden.append(f"{acp.name}:{cat} (reused '{ap.name}')")
                log(f"  Assigned existing {cat} '{ap.name}' on target (id={new_id})")
            else:
                summary.skipped_settings.append(
                    f"{acp.name}: {cat} '{ap.name}' not found on target; not assigned "
                    "(create it on the target or map it in the preview)")

    # Build the ACP container body.
    body: Dict[str, Any] = {"type": "AccessPolicy", "name": acp.name}
    if acp.default_action:
        da = copy.deepcopy(acp.default_action)
        da.pop("id", None)
        # Remap/prune stale policy references (intrusion/variable set) so the
        # default action does not carry source ids the target FMC rejects.
        _resolve_and_prune_refs(da, resolver, acp.name, summary, log)
        body["defaultAction"] = da
    body.update(assigned_fields)
    for k, v in (acp.raw_base or {}).items():
        if k in ("id", "name", "type", "links", "metadata", "rules",
                 "accessrules", "defaultAction"):
            continue
        # Skip assigned-policy references (handled via assigned_fields) so stale
        # source ids never reach the target body.
        if k in _ACP_ASSIGNED_KEYS:
            continue
        body.setdefault(k, v)

    # Create or update.
    existing = _find_target_acp(target, acp.name)
    acp_path = target.cfg_path("policy/accesspolicies")
    if existing:
        acp_id = existing.get("id")
        body["id"] = acp_id
        log(f"  Updating existing ACP '{acp.name}' (id={acp_id})")
        target.put(f"{acp_path}/{acp_id}", body)
        summary.policies_overridden.append(f"ACP:{acp.name}")
    else:
        log(f"  Creating ACP '{acp.name}'")
        created = target.post(acp_path, body)
        acp_id = created.get("id") if isinstance(created, dict) else None
        if not acp_id:
            raise FmcApiError(f"ACP '{acp.name}' creation returned no id")

    # Push access rules.
    _push_rules(acp, acp_id, target, resolver, bulk, per_rule_fallback, summary, log)


def _prepare_rule_body(
    rule: Dict[str, Any], resolver: DependencyResolver, acp_name: str,
    summary: PushSummary, log: Callable[[str], None],
) -> Dict[str, Any]:
    """Return a target-ready rule body: stripped, remapped and reference-pruned.

    All source object ids are remapped to target ids; rule-referenced policies
    (intrusion/file/variable set) are resolved by name on the target; and any
    reference that cannot be resolved to a valid target id is pruned so the
    payload FMC receives never carries a stale source id (the root cause of the
    HTTP 500 on rule creation).
    """
    rb = copy.deepcopy(rule)
    for k in _RULE_STRIP_KEYS:
        rb.pop(k, None)
    _resolve_and_prune_refs(rb, resolver, acp_name, summary, log,
                            rule_name=str(rule.get("name", "?")))
    _reconcile_rule_flags(rb)
    return rb


def _reconcile_rule_flags(rb: Dict[str, Any]) -> None:
    """Fix rule flags left inconsistent after reference pruning.

    FMC rejects (HTTP 400) a rule with ``logFiles: true`` when no ``filePolicy``
    is attached. Pruning an unresolved file policy therefore requires clearing
    ``logFiles`` so the rule still pushes (file logging is meaningless without a
    file policy anyway).
    """
    if rb.get("logFiles") and not rb.get("filePolicy"):
        rb["logFiles"] = False


def _resolve_and_prune_refs(
    node: Any, resolver: DependencyResolver, acp_name: str,
    summary: PushSummary, log: Callable[[str], None], rule_name: str = "",
) -> bool:
    """Recursively remap/resolve or prune object references in *node* in place.

    Returns ``False`` when *node* is itself an unresolvable reference (so the
    caller drops it from its container). Dropped references are recorded on the
    summary and logged.
    """
    if isinstance(node, list):
        node[:] = [
            it for it in node
            if _resolve_and_prune_refs(it, resolver, acp_name, summary, log, rule_name) is not False
        ]
        return True

    if isinstance(node, dict):
        t = node.get("id")
        obj_type = node.get("type")
        if isinstance(obj_type, str) and isinstance(t, str) and t:
            status = _classify_ref(node, obj_type, t, resolver)
            if status == "drop":
                dropped = {"scope": rule_name or acp_name, "type": obj_type,
                           "name": node.get("name", ""), "source_id": t}
                summary.dropped_references.append(dropped)
                log(f"    [ref] pruned unresolved {obj_type} "
                    f"'{node.get('name', t)}' from '{rule_name or acp_name}' "
                    "(no valid target equivalent)")
                return False
        # Recurse; drop child keys whose value is an unresolvable reference.
        for k in list(node.keys()):
            v = node[k]
            if _resolve_and_prune_refs(v, resolver, acp_name, summary, log, rule_name) is False:
                node.pop(k, None)
        return True

    return True


def _classify_ref(
    node: Dict[str, Any], obj_type: str, sid: str, resolver: DependencyResolver,
) -> str:
    """Resolve/remap a single reference node; return "keep" or "drop"."""
    remap = resolver.remap_table
    if sid in remap:
        node["id"] = remap[sid]
        return "keep"
    # Policies/variable sets are not in the object graph: resolve now by name.
    if obj_type in _RULE_POLICY_TYPES:
        tid = resolver.resolve_target_id(obj_type, str(node.get("name", "")), sid)
        if tid:
            node["id"] = tid
            return "keep"
        return "drop"
    # Object types already classified by the plan.
    if sid in resolver.unresolved_source_ids:
        return "keep" if obj_type in _GLOBAL_ID_TYPES else "drop"
    return "keep"


def _push_rules(
    acp: AcpModel, acp_id: str, target: PolicyFmcClient,
    resolver: DependencyResolver, bulk: bool, per_rule_fallback: bool,
    summary: PushSummary, log: Callable[[str], None],
) -> None:
    rules = acp.access_rules or []
    if not rules:
        return

    # Prepare (strip + remap + prune) each rule body, keeping index + source id.
    prepared: List[Tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    for idx, r in enumerate(rules, 1):
        body = _prepare_rule_body(r, resolver, acp.name, summary, log)
        prepared.append((idx, r, body))

    path = target.cfg_path(f"policy/accesspolicies/{acp_id}/accessrules")
    log(f"  Pushing {len(prepared)} access rule(s) for ACP '{acp.name}' -> {path}")

    if bulk and len(prepared) > 1:
        # Split into FMC-supported batches. Whether a failed batch is retried
        # rule-by-rule is governed by *per_rule_fallback*.
        for start in range(0, len(prepared), _RULE_BULK_BATCH):
            chunk = prepared[start:start + _RULE_BULK_BATCH]
            _push_rule_batch(chunk, acp, acp_id, path, target, per_rule_fallback,
                             summary, log)
    else:
        for idx, src, body in prepared:
            _push_rule_single(idx, src, body, acp, path, target, summary, log)


def _push_rule_batch(
    chunk: List[Tuple[int, Dict[str, Any], Dict[str, Any]]],
    acp: AcpModel, acp_id: str, path: str, target: PolicyFmcClient,
    per_rule_fallback: bool, summary: PushSummary, log: Callable[[str], None],
) -> None:
    """Bulk-push a batch of rules.

    On a bulk failure, retry rule-by-rule only when *per_rule_fallback* is set;
    otherwise stop and record the whole batch as failed (with the bulk error).
    """
    bodies = [b for (_, _, b) in chunk]
    lo, hi = chunk[0][0], chunk[-1][0]
    log(f"    [bulk] POST {len(bodies)} rule(s) (index {lo}-{hi}) to {acp.name}")
    try:
        resp = target.post(path, bodies, bulk=True)
        items = resp.get("items") if isinstance(resp, dict) else resp
        items = items if isinstance(items, list) else []
        for i, (idx, src, body) in enumerate(chunk):
            new_id = ""
            if i < len(items) and isinstance(items[i], dict):
                new_id = str(items[i].get("id", ""))
            _record_rule_pushed(idx, src, new_id, acp, "bulk", summary, log)
        log(f"    [bulk] OK — {len(bodies)} rule(s) created (index {lo}-{hi})")
    except FmcApiError as e:
        summary.bulk_failed = True
        if per_rule_fallback:
            log(f"    [bulk] FAILED (index {lo}-{hi}) HTTP {e.status or '?'}: {e}; "
                "per-rule fallback ENABLED — transitioning to per-rule submission")
            summary.fallback_used = True
            for idx, src, body in chunk:
                _push_rule_single(idx, src, body, acp, path, target, summary, log)
        else:
            log(f"    [bulk] FAILED (index {lo}-{hi}) HTTP {e.status or '?'}: {e}; "
                "per-rule fallback DISABLED — not retrying individually")
            for idx, src, body in chunk:
                name = str(src.get("name", "?"))
                summary.rules_failed.append({
                    "name": name, "index": idx, "acp": acp.name,
                    "source_id": str(src.get("id", "")), "status": e.status,
                    "error": f"bulk push failed and per-rule fallback disabled: {e}",
                })


def _push_rule_single(
    idx: int, src: Dict[str, Any], body: Dict[str, Any], acp: AcpModel,
    path: str, target: PolicyFmcClient, summary: PushSummary,
    log: Callable[[str], None],
) -> None:
    """Push a single rule, logging full context on success or failure."""
    name = str(src.get("name", "?"))
    try:
        resp = target.post(path, body)
        new_id = str(resp.get("id", "")) if isinstance(resp, dict) else ""
        _record_rule_pushed(idx, src, new_id, acp, "per-rule", summary, log)
    except FmcApiError as e:
        summary.rules_failed.append({
            "name": name, "index": idx, "acp": acp.name,
            "source_id": str(src.get("id", "")), "status": e.status,
            "error": str(e),
        })
        log(f"    [rule {idx}] FAILED '{name}' on ACP '{acp.name}' "
            f"(endpoint={path}) HTTP {e.status or '?'}: {e}")


def _record_rule_pushed(
    idx: int, src: Dict[str, Any], new_id: str, acp: AcpModel, method: str,
    summary: PushSummary, log: Callable[[str], None],
) -> None:
    name = str(src.get("name", "?"))
    entry = {
        "name": name, "index": idx, "acp": acp.name,
        "source_id": str(src.get("id", "")), "target_id": new_id, "method": method,
    }
    summary.rules_pushed.append(entry)
    log(f"    [rule {idx}] pushed '{name}' via {method} "
        f"(source={src.get('id', '—')} -> target={new_id or '—'}, position={idx})")


def _find_target_acp(target: PolicyFmcClient, name: str) -> Optional[Dict[str, Any]]:
    try:
        items = target.get_paginated(target.cfg_path("policy/accesspolicies"), expanded=True)
    except FmcApiError:
        return None
    nn = normalize_name(name)
    for it in items:
        if normalize_name(it.get("name")) == nn:
            return it
    return None


def _cat_type(cat: str) -> str:
    return {
        "prefilterPolicy": "PrefilterPolicy",
        "decryptionPolicy": "DecryptionPolicy",
        "identityPolicy": "IdentityPolicy",
    }.get(cat, "")


def _summary_tables(summary: PushSummary) -> Dict[str, List[List[str]]]:
    """Shape the summary into applied/failed/skipped tables (UI convention)."""
    applied: List[List[str]] = []
    for n in summary.successful_acps:
        applied.append(["ACP", n, "pushed"])
    for r in summary.rules_pushed:
        applied.append(["Access Rule", f"{r.get('acp', '')}: {r.get('name', '?')}",
                        f"pushed ({r.get('method', '')})"])
    for n in summary.objects_created:
        applied.append(["Object", n, "created"])
    for n in summary.objects_reused:
        applied.append(["Object", n, "reused"])
    for n in summary.policies_overridden:
        applied.append(["Policy", n, "overridden"])

    failed: List[List[str]] = [["ACP", f.get("name", "?"), f.get("error", "")] for f in summary.failed_acps]
    for r in summary.rules_failed:
        failed.append(["Access Rule", f"{r.get('acp', '')}: {r.get('name', '?')}",
                       f"HTTP {r.get('status') or '?'}: {r.get('error', '')}"])

    skipped: List[List[str]] = [["Setting", s, "skipped"] for s in summary.skipped_settings]
    for r in summary.rules_skipped:
        skipped.append(["Access Rule", r.get("name", "?"), r.get("reason", "skipped")])
    for d in summary.dropped_references:
        skipped.append(["Pruned Ref", f"{d.get('type', '')} {d.get('name', '')}",
                        f"in {d.get('scope', '')}"])
    for u in summary.objects_unresolved:
        skipped.append(["Unresolved", u, "no target equivalent"])
    for p in summary.partial_changes:
        skipped.append(["Partial", p, "may need cleanup"])
    return {"applied": applied, "failed": failed, "skipped": skipped}
