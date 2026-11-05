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
from ..dependency_resolution.resolver import DependencyResolver
from ..validation.policy_validator import validate_policy_doc, strip_unsupported_fields
from .acp_fetch import harvest_dependencies, harvest_object_refs
from .client import PolicyFmcClient, FmcApiError
from . import dependent_policies
from .dependent_policies import sanitize_fmc_name

logger = logging.getLogger(__name__)


def _meta_version(config: PolicyConfig) -> str:
    """Extract the source FMC version from config metadata, or ''."""
    src = (config.meta.get("source_fmc") or {})
    return str(src.get("version") or "")


# ── Resolution caching ──

@dataclass
class _CachedResolution:
    """Cached resolver + plan from a prior preview, reusable in push."""
    key: str
    resolver: DependencyResolver
    plan: Any  # ResolutionPlan


def _resolution_cache_key(
    acp_names: List[str],
    source: Optional[PolicyFmcClient],
    target: PolicyFmcClient,
    mappings: Dict[str, Dict[str, str]],
) -> str:
    """Deterministic hash of the inputs that affect resolution.

    If any of these change between preview and push the cached resolution is
    invalid and must be recomputed. *source* is optional (offline push).
    """
    parts = [
        "|".join(sorted(acp_names)),
        source.fmc_ip if source else "", source.domain_uuid if source else "",
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
    "securityIntelligencePolicy": ["policy/securityintelligencepolicies"],
}

# Category -> ACP base field used to assign the policy reference.
# NOTE: securityIntelligencePolicy is intentionally omitted — FMC exposes SI only
# as a read-only GET sub-resource of the access policy (no standalone create and
# no assignable reference field), so it is skipped rather than POSTed (which
# returned HTTP 404 "Invalid URL").
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

# Rule reference remapping/pruning is centralized in
# ``DependencyResolver.resolve_and_prune_refs`` (shared by access-rule and
# dependent-policy rule pushes so both behave identically).

# Max access rules per bulk POST (FMC accepts up to 1000; we split larger sets).
_RULE_BULK_BATCH = 1000

# Rule metadata category values that mean "no user-defined category" — the rule
# belongs to the default section and must be posted without a ?category= param.
_DEFAULT_RULE_CATEGORIES = frozenset({"", "--undefined--", "default", "standard_category"})

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


# ── Target cert / realm listing for UI dropdowns ──

_CERT_REALM_ENDPOINTS: Dict[str, str] = {
    "internalCAs": "object/internalcas",
    "internalCerts": "object/internalcertificates",
    "realms": "object/realms",
}


def list_target_cert_realm(
    target: PolicyFmcClient,
) -> Dict[str, List[Dict[str, Any]]]:
    """Return Internal CAs, Internal Certificates, and Realms from the target FMC."""
    result: Dict[str, List[Dict[str, Any]]] = {}
    for key, suffix in _CERT_REALM_ENDPOINTS.items():
        items: List[Dict[str, Any]] = []
        try:
            raw = target.get_paginated(target.cfg_path(suffix), expanded=False)
            for it in raw:
                items.append({"id": it.get("id"), "name": it.get("name"), "type": it.get("type")})
            logger.info(f"list_target_cert_realm({key}) via {suffix}: "
                        f"{len(items)} object(s) on target")
        except FmcApiError as e:
            # Elevated to WARNING: an empty CA/cert list silently disables cert
            # remapping in the UI, which later manifests as an opaque FMC
            # "must provide exactly 1 certificate" rejection at push time.
            logger.warning(f"list_target_cert_realm({key}) via {suffix} FAILED: {e}")
        result[key] = items
    return result


def _ensure_realms(
    config: PolicyConfig, target: PolicyFmcClient,
    resolver: DependencyResolver, summary: PushSummary,
    realm_password: str,
    log: Callable[[str], None],
) -> None:
    """Pre-push: ensure every referenced realm exists on the target FMC.

    For each realm stored in ``config.policies["realms"]``:
      1. Check if a same-named realm exists on the target.
      2. If yes, register the source->target id remap.
      3. If not, create it from the expanded definition (with *realm_password*).
      4. On failure, mark the source id as unresolved so downstream references
         are pruned rather than pushed with stale source ids.
    """
    realm_defs = config.policies.get("realms") or []
    if not realm_defs:
        return
    log(f"[realms] Ensuring {len(realm_defs)} realm(s) on target FMC")

    # Fetch existing target realms (name -> id).
    target_realms: Dict[str, str] = {}
    try:
        raw = target.get_paginated(target.cfg_path("object/realms"), expanded=False)
        for r in raw:
            name = normalize_name(r.get("name", ""))
            if name:
                target_realms[name] = str(r.get("id", ""))
    except FmcApiError as e:
        log(f"  [realms] WARNING: could not list target realms: {e}")

    for realm_def in realm_defs:
        if not isinstance(realm_def, dict):
            continue
        source_id = str(realm_def.get("id", ""))
        name = str(realm_def.get("name", ""))
        nn = normalize_name(name)
        if not source_id or not name:
            continue

        # 1) Already exists on target?
        existing_id = target_realms.get(nn, "")
        if existing_id:
            resolver.register_remap(source_id, existing_id)
            log(f"  [realms] realm '{name}' found on target (id={existing_id})")
            continue

        # 2) Create from expanded definition.
        body = copy.deepcopy(realm_def)
        # Strip server-managed and source-specific keys.
        for _k in ("id", "links", "metadata", "version", "realmId"):
            body.pop(_k, None)
        # Strip AD-specific groups/users — they require directory
        # discovery which hasn't happened on the target yet.
        for _k in ("includedGroups", "excludedGroups",
                   "includedUsers", "excludedUsers"):
            body.pop(_k, None)
        # Strip empty proxy dict (causes validation error).
        if body.get("proxy") in (None, {}):
            body.pop("proxy", None)
        # Strip source-FMC-specific ids from directoryConfigurations entries;
        # they are meaningless on the target and older FMC versions reject them.
        dir_cfgs = body.get("directoryConfigurations")
        if isinstance(dir_cfgs, list):
            for dc in dir_cfgs:
                if isinstance(dc, dict):
                    dc.pop("id", None)
        # FMC masks dirPassword on GET; inject the user-provided password.
        if realm_password:
            body["dirPassword"] = realm_password
        elif body.get("dirPassword") in ("*********", "****"):
            log(f"  [realms] WARNING: realm '{name}' has a masked dirPassword "
                f"and no realm password was provided; FMC may reject the create")
        try:
            created = target.post(target.cfg_path("object/realms"), body)
            new_id = str(created.get("id", "")) if isinstance(created, dict) else ""
            if new_id:
                resolver.register_remap(source_id, new_id)
                summary.realms_created.append(f"Realm '{name}'")
                log(f"  [realms] created realm '{name}' on target (id={new_id})")
            else:
                resolver._unresolved_ids.add(source_id)
                summary.realms_failed.append(f"Realm '{name}': no id in response")
                log(f"  [realms] WARNING: realm '{name}' creation returned no id")
        except FmcApiError as e:
            resolver._unresolved_ids.add(source_id)
            summary.realms_failed.append(f"Realm '{name}': {e}")
            log(f"  [realms] WARNING: failed to create realm '{name}': {e}")


def extract_source_cert_realm_refs(
    config: PolicyConfig,
) -> Dict[str, List[Dict[str, str]]]:
    """Scan the PolicyConfig for unique cert source references.

    Returns ``{"sourceCerts": [...], "sourceRealms": [...]}`` where each entry
    is ``{name, type, source_id}``.  Realm references are no longer collected
    for UI mapping — they are handled automatically via _ensure_realms.
    """
    seen_certs: Dict[str, Dict[str, str]] = {}

    # Scan decryption policy rules for InternalCA / InternalCertificate refs.
    for dp in config.policies.get("decryption_policies") or []:
        for rule in dp.get("decryptionpolicyrules") or []:
            for cert_key in ("decryptionCerts", "internalCerts"):
                objs = (rule.get(cert_key) or {}).get("objects") or []
                for obj in objs:
                    name = obj.get("name", "")
                    if name and name not in seen_certs:
                        seen_certs[name] = {
                            "name": name,
                            "type": obj.get("type", "InternalCA"),
                            "source_id": obj.get("id", ""),
                        }

    # Scan identity policy container-level authCert (PKI_InternalCert).
    for ip in config.policies.get("identity_policies") or []:
        auth_cert = ip.get("authCert")
        if isinstance(auth_cert, dict):
            cert_name = auth_cert.get("name", "")
            if cert_name and cert_name not in seen_certs:
                seen_certs[cert_name] = {
                    "name": cert_name,
                    "type": auth_cert.get("type", "PKI_InternalCert"),
                    "source_id": auth_cert.get("id", ""),
                }

    return {
        "sourceCerts": list(seen_certs.values()),
        "sourceRealms": [],
    }


def _selected_acps(config: PolicyConfig, names: List[str]) -> List[AcpModel]:
    wanted = {normalize_name(n) for n in names}
    return [a for a in config.acps if normalize_name(a.name) in wanted]


def _seed_refs(acps: List[AcpModel], config: Optional[PolicyConfig] = None):
    seen = {}
    for acp in acps:
        for ref in harvest_dependencies(acp):
            seen.setdefault(ref.key, ref)
    # Also harvest object references from embedded dependent-policy rules
    # (decryption / prefilter / identity).  These rules reference objects
    # (NetworkGroup, Host, SecurityZone, …) that must be discovered and
    # resolved just like access-rule references; without this, objects only
    # used in dependent-policy rules would keep their source ids and cause
    # FMC 400 "Unable to load container" errors on the target.
    if config is not None:
        from .dependent_policies import _ASSIGNED_CREATABLE
        for _ptype, (subsection, _ep, embed_key, _rsub) in _ASSIGNED_CREATABLE.items():
            for pol_def in (config.policies or {}).get(subsection) or []:
                if not isinstance(pol_def, dict):
                    continue
                rules = pol_def.get(embed_key)
                if isinstance(rules, list):
                    for ref in harvest_object_refs(*rules):
                        seen.setdefault(ref.key, ref)
    return list(seen.values())


def preview(
    config: PolicyConfig,
    acp_names: List[str],
    source: Optional[PolicyFmcClient],
    target: PolicyFmcClient,
    *,
    mappings: Optional[Dict[str, Dict[str, str]]] = None,
    validate: bool = True,
    source_version: str = "",
    target_version: str = "",
    schema_source: str = "oas",
    log: Optional[Callable[[str], None]] = None,
    ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Dry-run: resolve dependencies + validate, but make no target changes.

    Resolution is offline: object bodies come from the fetched ``config``;
    *source* is optional and only used as a legacy fallback.
    """
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
        resolver.discover(_seed_refs(acps, config), config_objects=config.objects)
        plan = resolver.build_plan()
        _set_cached_resolution(ctx, _CachedResolution(key=cache_key, resolver=resolver, plan=plan))

    validations: List[Dict[str, Any]] = []
    if validate:
        sub = PolicyConfig(acps=acps, objects=config.objects, meta=config.meta,
                           policies=dict(config.policies))
        doc = sub.to_yaml_doc()
        # Fall back to the YAML metadata version when caller didn't supply one.
        sv = source_version or _meta_version(config)
        tv = target_version or _meta_version(config)
        if sv:
            src_res = validate_policy_doc(doc, sv, "source", schema_source)
            validations.append(src_res.to_dict())
        if tv:
            tgt_res = validate_policy_doc(doc, tv, "target", schema_source)
            validations.append(tgt_res.to_dict())
        all_warnings: List[Dict[str, Any]] = []
        for v in validations:
            all_warnings.extend(v.get("warnings") or [])
        if all_warnings:
            log("─── **Schema Validation** ──────────────────────────────")
            _log_validation_grouped(all_warnings, log)
            log("")

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


def _log_validation_grouped(
    warnings: List[Dict[str, Any]], log: Callable[[str], None],
    label: str = "validate",
) -> None:
    """Log validation warnings grouped by ``group_key`` (``<Schema>:<field>``).

    Sanitisable field mismatches that appear on many rules are collapsed into
    a single log line with a count, matching the Push Preview UI format.
    Non-groupable warnings are logged individually.

    When source *and* target validation both produce the same ``group_key``,
    the count shown is the **max** across the two sides (not the sum) because
    the same field on the same objects is flagged by each run independently.
    """
    if not warnings:
        return
    from collections import Counter
    # Count per (group_key, side) so source+target don't double-count.
    per_side: Dict[tuple, int] = Counter()
    grouped_msg: Dict[str, str] = {}
    other: List[Dict[str, Any]] = []
    seen_other: set = set()
    for w in warnings:
        gk = w.get("group_key")
        if gk and w.get("sanitizable"):
            side = w.get("side", "")
            per_side[(gk, side)] += 1
            if gk not in grouped_msg:
                grouped_msg[gk] = str(w.get("message", ""))
        else:
            # Deduplicate identical non-groupable warnings across sides.
            dedup = (w.get("scope", ""), w.get("message", ""))
            if dedup not in seen_other:
                seen_other.add(dedup)
                other.append(w)
    # Collapse per-side counts: take the max across sides for each group_key.
    grouped: Dict[str, int] = {}
    for (gk, _side), cnt in per_side.items():
        grouped[gk] = max(grouped.get(gk, 0), cnt)
    for gk, cnt in sorted(grouped.items()):
        msg = grouped_msg.get(gk, gk)
        suffix = f" (x{cnt})" if cnt > 1 else ""
        log(f"  [{label}] WARNING: {msg}{suffix}")
    for w in other:
        log(f"  [{label}] WARNING: {w.get('scope', '')}: {w.get('message', '')}")


_SUBSECTION_WIDTH = 52


def _subsection_start(log: Callable[[str], None], title: str, indent: int = 0) -> None:
    """Log a subsection start marker (e.g. ``┌── **Decryption Policy** ──``)."""
    pad = "  " * indent
    prefix = f"{pad}┌── **{title}** "
    # Subtract 4 for the ** markers that won't render visually.
    fill = max(3, _SUBSECTION_WIDTH - len(prefix) + 4)
    log(f"{prefix}{'─' * fill}")


def _subsection_end(log: Callable[[str], None], title: str = "", indent: int = 0) -> None:
    """Log a subsection end marker (e.g. ``└── end Decryption Policy ──``)."""
    pad = "  " * indent
    label = f"end {title} " if title else ""
    prefix = f"{pad}└── {label}"
    fill = max(3, _SUBSECTION_WIDTH - len(prefix))
    log(f"{prefix}{'─' * fill}")
    log("")


def push(
    config: PolicyConfig,
    acp_names: List[str],
    source: Optional[PolicyFmcClient],
    target: PolicyFmcClient,
    *,
    mappings: Optional[Dict[str, Dict[str, str]]] = None,
    validate: bool = True,
    bulk: bool = True,
    per_rule_fallback: bool = False,
    source_version: str = "",
    target_version: str = "",
    schema_source: str = "oas",
    confirm_overrides: bool = False,
    cert_realm_extras: Optional[Dict[str, Dict[str, str]]] = None,
    strip_zones: bool = False,
    realm_password: str = "Bglsit@123",
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
    log("─── **Validation** ───────────────────────────────────")
    progress(5, "Validating policy configuration")
    if validate:
        sub = PolicyConfig(acps=acps, objects=config.objects, meta=config.meta,
                           policies=dict(config.policies))
        doc = sub.to_yaml_doc()
        # Fall back to the YAML metadata version when caller didn't supply one.
        sv = source_version or _meta_version(config)
        tv = target_version or _meta_version(config)
        src_res = validate_policy_doc(doc, sv, "source", schema_source) if sv else None
        tgt_res = validate_policy_doc(doc, tv, "target", schema_source) if tv else None
        summary.validation_errors = (src_res.errors if src_res else []) + (tgt_res.errors if tgt_res else [])
        summary.validation_warnings = (src_res.warnings if src_res else []) + (tgt_res.warnings if tgt_res else [])
        _log_validation_grouped(summary.validation_warnings, log)
        if (src_res and src_res.has_blocking) or (tgt_res and tgt_res.has_blocking):
            log("Push blocked: schema validation reported blocking errors")
            return {"success": False, "message": "Validation failed",
                    "summary_tables": _summary_tables(summary), "summary": summary.to_dict()}

    # ── 2. Dependency resolution (reuse cached from preview when available) ──
    log("")
    log("─── **Dependency Resolution** ─────────────────────────")
    progress(20, "Resolving dependencies")
    cache_key = _resolution_cache_key(acp_names, source, target, mappings)
    cached = _get_cached_resolution(ctx, cache_key)
    if cached:
        log("[resolve] Reusing cached resolution from preview")
        resolver, plan = cached.resolver, cached.plan
    else:
        log("[resolve] No cached resolution available; running fresh resolution")
        resolver = DependencyResolver(source, target, log=log)
        resolver.discover(_seed_refs(acps, config), config_objects=config.objects)
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

    summary.objects_reused = [r.name for r in plan.to_reuse]
    if plan.to_reuse:
        log(f"[resolve] {len(plan.to_reuse)} object(s) matched and reused on target FMC:")
        for r in plan.to_reuse:
            log(f"  [reuse] {r.type} '{r.name}' "
                f"(source={r.source_id or '—'} -> target={r.target_id or '—'}, "
                f"match={r.match_method or 'name'})")
    if plan.unresolved:
        summary.objects_unresolved = [f"{u.get('type')} '{u.get('name')}'" for u in plan.unresolved]
        log(f"[resolve] {len(plan.unresolved)} reference(s) could not be resolved on target FMC:")
        for u in plan.unresolved:
            log(f"  [unresolved] {u.get('type')} '{u.get('name')}': {u.get('reason')}")

    # ── 3. Create missing objects in dependency order ──
    log("")
    log("─── **Push Policies** ──────────────────────────────────")
    progress(40, "Creating dependent objects")
    created, partial = resolver.apply(plan, bulk=bulk, per_item_fallback=per_rule_fallback)
    summary.objects_created = created
    summary.partial_changes.extend(f"object: {n}" for n in partial)

    # ── 3b. Ensure realms exist on target (check/create before dependent policies) ──
    progress(44, "Ensuring realms on target")
    _subsection_start(log, "Realm Resolution")
    try:
        _ensure_realms(config, target, resolver, summary, realm_password, log)
    except Exception as e:  # pragma: no cover
        log(f"[realms] WARNING: realm resolution error: {e}; continuing")
    _subsection_end(log, "Realm Resolution")

    if summary.realms_failed:
        log(f"[push] WARNING: {len(summary.realms_failed)} realm(s) failed to create; "
            f"dependent policies/rules referencing them may fail")

    # ── 3c. Reuse-by-name or create File/Intrusion policies referenced by rules ──
    progress(48, "Resolving dependent File/Intrusion policies")
    _subsection_start(log, "Intrusion & File Policies")
    try:
        dependent_policies.ensure_rule_policies(acps, config, source, target, resolver, summary, log)
    except Exception as e:  # pragma: no cover - defensive; per-policy errors handled inside
        log(f"[dep-policies] WARNING: dependent policy resolution error: {e}; continuing")
    _subsection_end(log, "Intrusion & File Policies")

    # ── 4. Per-ACP create/update ──
    total = max(len(acps), 1)
    cert_realm_extras = cert_realm_extras or {}
    # Build a reverse lookup {id → name} for target certs/CAs/realms so that
    # log messages can display human-readable target names, not just UUIDs.
    target_cert_names = _build_target_name_map(target)
    if strip_zones:
        log("[push] Zone stripping ENABLED — sourceZones/destinationZones will be removed from all rules")
    for idx, acp in enumerate(acps):
        pct = 50 + int(40 * (idx / total))
        progress(pct, f"Pushing ACP '{acp.name}'")
        _subsection_start(log, f"Access Control Policy: {acp.name}")
        try:
            _push_one_acp(acp, config, source, target, resolver, mappings.get(acp.name, {}),
                          confirm_overrides, summary, bulk, per_rule_fallback, log,
                          cert_realm=cert_realm_extras.get(acp.name, {}),
                          strip_zones=strip_zones,
                          target_cert_names=target_cert_names)
            summary.successful_acps.append(acp.name)
        except FmcApiError as e:
            log(f"  ACP '{acp.name}' failed: {e}")
            summary.failed_acps.append({"name": acp.name, "error": str(e)})
        except Exception as e:  # pragma: no cover - defensive
            log(f"  ACP '{acp.name}' error: {e}")
            summary.failed_acps.append({"name": acp.name, "error": str(e)})
        _subsection_end(log, f"Access Control Policy: {acp.name}")

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
    """Emit a concise end-of-push summary block with Objects and Policies sections."""
    log("")
    log("──────── Push Summary ────────")

    # ── Objects section ──
    log("┌── Objects ─────────────────────────────")
    log(f"│  Created:    {len(summary.objects_created)}")
    log(f"│  Reused:     {len(summary.objects_reused)}")
    log(f"│  Unresolved: {len(summary.objects_unresolved)}")
    env: Dict[str, Tuple[int, str]] = {}
    for u in getattr(plan, "unresolved", None) or []:
        if u.get("environmental"):
            n, _ = env.get(u.get("type", "?"), (0, ""))
            env[u.get("type", "?")] = (n + 1, str(u.get("reason", "")))
    for t, (n, reason) in env.items():
        log(f"│    environmental: {t}×{n} — {reason}")
    if summary.dropped_references:
        log(f"│  Pruned refs:{len(summary.dropped_references)}")
    log("└────────────────────────────────────────")
    log("")

    # ── Policies section ──
    log("┌── Policies ────────────────────────────")
    # ACP totals with access rule breakdown.
    total_rules = len(summary.rules_pushed) + len(summary.rules_failed) + len(summary.rules_skipped)
    log(f"│  ACP: {len(summary.successful_acps)} pushed, "
        f"{len(summary.failed_acps)} failed | "
        f"rules: {len(summary.rules_pushed)} pushed, "
        f"{len(summary.rules_failed)} failed, "
        f"{len(summary.rules_skipped)} skipped "
        f"({total_rules} total)")
    # Per-type breakdown of dependent policies.
    _log_dep_type_breakdown(summary, log)
    log("└────────────────────────────────────────")
    log("")


def _log_dep_type_breakdown(summary: PushSummary, log: Callable[[str], None]) -> None:
    """Log a per-policy-type breakdown of dependent policies and their rules."""
    _zero = lambda: {"pushed": 0, "failed": 0, "skipped": 0,
                     "rules_pushed": 0, "rules_failed": 0, "rules_skipped": 0}
    types: Dict[str, Dict[str, int]] = {}
    for dp in summary.dep_policies_pushed:
        pt = dp.get("policy_type", "Unknown")
        types.setdefault(pt, _zero())
        types[pt]["pushed"] += 1
    for dp in summary.dep_policies_failed:
        pt = dp.get("policy_type", "Unknown")
        types.setdefault(pt, _zero())
        types[pt]["failed"] += 1
    for dp in summary.dep_policies_skipped:
        pt = dp.get("policy_type", "Unknown")
        types.setdefault(pt, _zero())
        types[pt]["skipped"] += 1
    for r in summary.dep_policy_rules_pushed:
        pt = r.get("policy_type", "Unknown")
        types.setdefault(pt, _zero())
        types[pt]["rules_pushed"] += 1
    for r in summary.dep_policy_rules_failed:
        pt = r.get("policy_type", "Unknown")
        types.setdefault(pt, _zero())
        types[pt]["rules_failed"] += 1
    for r in summary.dep_policy_rules_skipped:
        pt = r.get("policy_type", "Unknown")
        types.setdefault(pt, _zero())
        types[pt]["rules_skipped"] += 1
    for pt, c in sorted(types.items()):
        label = pt.replace("Policy", "")
        pol_parts = []
        if c["pushed"]:
            pol_parts.append(f"{c['pushed']} pushed")
        if c["failed"]:
            pol_parts.append(f"{c['failed']} failed")
        if c["skipped"]:
            pol_parts.append(f"{c['skipped']} skipped")
        rule_parts = []
        if c["rules_pushed"]:
            rule_parts.append(f"{c['rules_pushed']} pushed")
        if c["rules_failed"]:
            rule_parts.append(f"{c['rules_failed']} failed")
        if c["rules_skipped"]:
            rule_parts.append(f"{c['rules_skipped']} skipped")
        line = f"│  {label}: {', '.join(pol_parts)}"
        if rule_parts:
            line += f" | rules: {', '.join(rule_parts)}"
        log(line)


def _build_target_name_map(target: PolicyFmcClient) -> Dict[str, str]:
    """Build a {id → name} lookup from target FMC certs, CAs, and realms.

    Used purely for log messages — maps opaque UUIDs to human-readable names.
    Failures are silently ignored (the map will just be incomplete).
    """
    name_map: Dict[str, str] = {}
    for suffix in ("object/internalcas", "object/internalcertificates", "object/realms"):
        try:
            for it in target.get_paginated(target.cfg_path(suffix), expanded=False):
                obj_id = it.get("id")
                obj_name = it.get("name")
                if obj_id and obj_name:
                    name_map[obj_id] = obj_name
        except Exception:
            pass  # non-fatal — log messages will just show id instead of name
    return name_map


def _log_replacement_selections(
    acp: AcpModel, acp_map: Dict[str, str],
    cert_realm: Dict[str, Any], log: Callable[[str], None],
    target_cert_names: Optional[Dict[str, str]] = None,
    target_policies: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> None:
    """Log the user-selected replacements for this ACP (diagnostics).

    Emitted at push time so the terminal UI shows exactly which target objects
    each source reference is being remapped to — assigned policies (create vs
    reuse), Internal CA / Internal Certificate mappings, and realm mappings —
    or clearly states that no selection was received (the common cause of
    DECRYPT_RESIGN "must provide exactly 1 certificate" failures).
    """
    names = target_cert_names or {}
    _subsection_start(log, "Replacement Selections", indent=1)

    # Assigned-policy overrides (from the "Assigned Policies" section).
    any_assigned = False
    for cat, ap in acp.assigned_policies.items():
        if not ap.name:
            continue
        if not ap.supported:
            log(f"    [replace] {cat}: '{ap.name}' → unsupported on target (skipped)")
            any_assigned = True
            continue
        choice = acp_map.get(cat, "__create__")
        if choice and choice != "__create__":
            tgt_name = names.get(choice, "")
            tgt_label = f"'{tgt_name}' (id={choice})" if tgt_name else f"id={choice}"
            log(f"    [replace] {cat}: '{ap.name}' → REUSE existing target policy {tgt_label}")
        else:
            log(f"    [replace] {cat}: '{ap.name}' → CREATE new on target")
        any_assigned = True
    if not any_assigned:
        log("    [replace] no assigned policies on this ACP")

    # Certificate mappings (Internal CA / Internal Certificate).
    cert_mappings = cert_realm.get("certMappings") or {}
    if cert_mappings:
        for src_name, tgt_id in cert_mappings.items():
            if tgt_id:
                tgt_name = names.get(tgt_id, "")
                tgt_label = f"'{tgt_name}' (id={tgt_id})" if tgt_name else f"id={tgt_id}"
                log(f"    [replace] certificate '{src_name}' → target {tgt_label}")
            else:
                log(f"    [replace] certificate '{src_name}' → NO target selected "
                    "(rule will be rejected if it requires this cert)")
    else:
        log("    [replace] certificate mappings: NONE received — DECRYPT_* rules "
            "that reference an Internal CA/Cert will be rejected by FMC")
    legacy_ca = cert_realm.get("internalCaId", "")
    legacy_cert = cert_realm.get("internalCertId", "")
    if legacy_ca:
        ca_name = names.get(legacy_ca, "")
        ca_label = f"'{ca_name}' (id={legacy_ca})" if ca_name else f"id={legacy_ca}"
        log(f"    [replace] legacy Internal CA {ca_label}")
    if legacy_cert:
        cert_name = names.get(legacy_cert, "")
        cert_label = f"'{cert_name}' (id={legacy_cert})" if cert_name else f"id={legacy_cert}"
        log(f"    [replace] legacy Internal Certificate {cert_label}")

    # Realm mappings (identity policies).
    realm_mappings = cert_realm.get("realmMappings") or {}
    if realm_mappings:
        for src_name, tgt_id in realm_mappings.items():
            tgt_name = names.get(tgt_id, "") if tgt_id else ""
            tgt_label = f"'{tgt_name}' (id={tgt_id})" if tgt_name else (f"id={tgt_id}" if tgt_id else "(none)")
            log(f"    [replace] realm '{src_name}' → target {tgt_label}")

    _subsection_end(log, "Replacement Selections", indent=1)


def _push_one_acp(
    acp: AcpModel, config: PolicyConfig, source: PolicyFmcClient,
    target: PolicyFmcClient,
    resolver: DependencyResolver, acp_map: Dict[str, str], confirm_overrides: bool,
    summary: PushSummary, bulk: bool, per_rule_fallback: bool,
    log: Callable[[str], None],
    cert_realm: Optional[Dict[str, str]] = None,
    strip_zones: bool = False,
    target_cert_names: Optional[Dict[str, str]] = None,
) -> None:
    # Surface the user's replacement selections up front for traceability.
    _log_replacement_selections(acp, acp_map, cert_realm or {}, log,
                                target_cert_names=target_cert_names)

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
        _dep_label = f"{(_cat_type(cat) or cat)}: {ap.name}"
        _subsection_start(log, _dep_label, indent=1)
        choice = acp_map.get(cat, "__create__")
        if choice and choice != "__create__":
            if not confirm_overrides:
                summary.skipped_settings.append(
                    f"{acp.name}: override of {cat} requires confirmation; skipped")
                _subsection_end(log, _dep_label, indent=1)
                continue
            assigned_fields[field] = {"id": choice, "type": ap.type or _cat_type(cat)}
            summary.policies_overridden.append(f"{acp.name}:{cat}")
        else:
            # 1) Reuse a same-named policy already on the target.
            endpoints = ASSIGNED_POLICY_ENDPOINTS.get(cat, [])
            new_id = dependent_policies.match_assigned_policy_by_name(target, endpoints, ap.name)
            if new_id:
                assigned_fields[field] = {"id": new_id, "type": ap.type or _cat_type(cat)}
                summary.policies_overridden.append(f"{acp.name}:{cat} (reused '{ap.name}')")
                summary.dep_policies_pushed.append({"policy_type": _cat_type(cat), "name": ap.name, "action": "reused"})
                log(f"  Assigned existing {cat} '{ap.name}' on target (id={new_id})")
            else:
                # 2) Try creating from the embedded definition in the fetched YAML.
                ptype = _cat_type(cat)
                try:
                    created_id = dependent_policies.create_assigned_policy(
                        ptype, ap.name, ap.source_id or "",
                        config, target, resolver, log,
                        cert_realm=cert_realm or {},
                        summary=summary,
                        strip_zones=strip_zones,
                        target_cert_names=target_cert_names or {})
                except Exception as e:
                    log(f"  [dep-policies] WARNING: {ptype} '{ap.name}' create failed: {e}")
                    created_id = ""
                if created_id:
                    assigned_fields[field] = {"id": created_id, "type": ptype}
                    summary.objects_created.append(f"{ptype} '{ap.name}'")
                    summary.dep_policies_pushed.append({"policy_type": ptype, "name": ap.name, "action": "created"})
                    log(f"  Created {cat} '{ap.name}' on target (id={created_id})")
                else:
                    summary.skipped_settings.append(
                        f"{acp.name}: {cat} '{ap.name}' not found on target and could "
                        "not be created; not assigned")
                    summary.dep_policies_skipped.append({"policy_type": ptype, "name": ap.name})
        _subsection_end(log, _dep_label, indent=1)

    # Build the ACP container body.
    safe_acp_name = sanitize_fmc_name(acp.name)
    if safe_acp_name != acp.name:
        log(f"  [push] Sanitized ACP name '{acp.name}' → '{safe_acp_name}'")
    body: Dict[str, Any] = {"type": "AccessPolicy", "name": safe_acp_name}
    if acp.default_action:
        da = copy.deepcopy(acp.default_action)
        da.pop("id", None)
        # Remap/prune stale policy references (intrusion/variable set) so the
        # default action does not carry source ids the target FMC rejects.
        resolver.resolve_and_prune_refs(da)
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
        # FMC PUT requires the target's own defaultAction id.
        try:
            target_da = (target.get_json(f"{acp_path}/{acp_id}") or {}).get("defaultAction") or {}
        except FmcApiError:
            target_da = {}
        if target_da.get("id"):
            body.setdefault("defaultAction", {})["id"] = target_da["id"]
            body["defaultAction"].setdefault("type", target_da.get("type", "AccessPolicyDefaultAction"))
        log(f"  Updating existing ACP '{acp.name}' (id={acp_id})")
        target.put(f"{acp_path}/{acp_id}", body)
        summary.policies_overridden.append(f"ACP:{acp.name}")
    else:
        log(f"  Creating ACP '{acp.name}'")
        created = target.post(acp_path, body)
        acp_id = created.get("id") if isinstance(created, dict) else None
        if not acp_id:
            raise FmcApiError(f"ACP '{acp.name}' creation returned no id")

    # ── Explicitly assign dependent policies to the ACP via PUT ─────────
    # FMC requires `defaultAction` (with its server-assigned id) in every
    # PUT payload.  GET the ACP to retrieve it, then merge in assigned fields.
    if assigned_fields:
        log(f"  Assigning dependent policies to ACP '{acp.name}':")
        for _af_key, _af_ref in assigned_fields.items():
            log(f"    {_af_key} -> {_af_ref.get('type', '')} "
                f"(id={_af_ref.get('id', '')})")
        try:
            current_acp = target.get_json(f"{acp_path}/{acp_id}")
        except FmcApiError:
            current_acp = {}
        assign_body: Dict[str, Any] = {
            "type": "AccessPolicy", "name": acp.name, "id": acp_id}
        # Include defaultAction from the GET response (required by FMC PUT).
        if isinstance(current_acp, dict) and "defaultAction" in current_acp:
            assign_body["defaultAction"] = current_acp["defaultAction"]
        assign_body.update(assigned_fields)
        try:
            target.put(f"{acp_path}/{acp_id}", assign_body)
            log(f"  Assigned {len(assigned_fields)} dependent "
                f"policy(ies) to ACP '{acp.name}'")
        except FmcApiError as e:
            log(f"  WARNING: failed to assign dependent policies "
                f"to ACP '{acp.name}': {e}")

    # Push access rules.
    _subsection_start(log, "Access Rules", indent=1)
    _push_rules(acp, acp_id, target, resolver, bulk, per_rule_fallback, summary, log,
                strip_zones=strip_zones)
    _subsection_end(log, "Access Rules", indent=1)


def _prepare_rule_body(
    rule: Dict[str, Any], resolver: DependencyResolver, acp_name: str,
    summary: PushSummary, log: Callable[[str], None], *,
    strip_zones: bool = False,
    target_fmc_version: str = "",
) -> Tuple[Dict[str, Any], List[str]]:
    """Return a target-ready rule body and list of OAS-stripped field names.

    All source object ids are remapped to target ids; rule-referenced policies
    (intrusion/file/variable set) are resolved by name on the target; and any
    reference that cannot be resolved to a valid target id is pruned so the
    payload FMC receives never carries a stale source id (the root cause of the
    HTTP 500 on rule creation).
    """
    rb = copy.deepcopy(rule)
    for k in _RULE_STRIP_KEYS:
        rb.pop(k, None)
    rule_name = str(rule.get("name", "?"))

    def _on_drop(node: Dict[str, Any]) -> None:
        obj_type = str(node.get("type", ""))
        sid = str(node.get("id", ""))
        summary.dropped_references.append(
            {"scope": rule_name, "type": obj_type,
             "name": node.get("name", ""), "source_id": sid})
        log(f"    [ref] pruned unresolved {obj_type} "
            f"'{node.get('name', sid)}' from '{rule_name}' "
            "(no valid target equivalent)")

    resolver.resolve_and_prune_refs(rb, _on_drop)
    _reconcile_rule_flags(rb)
    # Strip zones if requested.
    if strip_zones:
        for zk in ("sourceZones", "destinationZones"):
            if zk in rb:
                rb.pop(zk, None)
    # Strip Users/UserGroups, keep only Realm references (remapped).
    _strip_users_keep_realms(rb, resolver, acp_name, log)
    # Push-time OAS sanitise: strip fields unsupported on target FMC.
    stripped: List[str] = []
    if target_fmc_version:
        stripped = strip_unsupported_fields(rb, "AccessRule", target_fmc_version)
    return rb, stripped


def _reconcile_rule_flags(rb: Dict[str, Any]) -> None:
    """Fix rule flags left inconsistent after reference pruning.

    FMC rejects (HTTP 400) a rule with ``logFiles: true`` when no ``filePolicy``
    is attached. Pruning an unresolved file policy therefore requires clearing
    ``logFiles`` so the rule still pushes (file logging is meaningless without a
    file policy anyway).
    """
    if rb.get("logFiles") and not rb.get("filePolicy"):
        rb["logFiles"] = False


def _strip_users_keep_realms(
    rb: Dict[str, Any], resolver: DependencyResolver,
    acp_name: str, log: Callable[[str], None],
) -> None:
    """Strip Users/UserGroups from ``users.objects``, keeping only Realm refs.

    Realm source IDs are remapped to target IDs via the resolver.  Users and
    user groups are unconditionally removed — only Realm references are pushed.
    """
    users_block = rb.get("users")
    if not isinstance(users_block, dict):
        return
    objects = users_block.get("objects")
    if not isinstance(objects, list):
        return
    remap = resolver.remap_table
    target_ids = set(remap.values())
    kept: list = []
    rule_name = rb.get("name", "?")
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type", "")
        if otype != "Realm":
            # Drop all non-Realm objects (RealmUser, RealmUserGroup, etc.)
            log(f"    [strip-users] dropped {otype} '{obj.get('name', '?')}' "
                f"from rule '{rule_name}' on ACP '{acp_name}'")
            continue
        # Remap the Realm source ID to target ID.
        oid = obj.get("id", "")
        if oid in remap:
            obj["id"] = remap[oid]
            kept.append(obj)
        elif oid in target_ids or len(oid) < 30:
            kept.append(obj)
        else:
            log(f"    [strip-users] dropped unresolvable Realm "
                f"'{obj.get('name', oid)}' from rule '{rule_name}' "
                f"on ACP '{acp_name}'")
    if kept:
        users_block["objects"] = kept
    else:
        rb.pop("users", None)


def _push_rules(
    acp: AcpModel, acp_id: str, target: PolicyFmcClient,
    resolver: DependencyResolver, bulk: bool, per_rule_fallback: bool,
    summary: PushSummary, log: Callable[[str], None], *,
    strip_zones: bool = False,
) -> None:
    rules = acp.access_rules or []
    if not rules:
        return
    # Sort rules by metadata.ruleIndex so they are pushed in the correct order.
    rules = sorted(
        rules,
        key=lambda r: (r.get("metadata") or {}).get("ruleIndex", 999999),
    )

    # Prepare (strip + remap + prune) each rule body, keeping index + source id.
    prepared: List[Tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    oas_strip_counts: Dict[str, int] = {}
    for idx, r in enumerate(rules, 1):
        body, stripped = _prepare_rule_body(r, resolver, acp.name, summary, log,
                                            strip_zones=strip_zones,
                                            target_fmc_version=target.fmc_version or "")
        for _f in stripped:
            oas_strip_counts[_f] = oas_strip_counts.get(_f, 0) + 1
        prepared.append((idx, r, body))
    if oas_strip_counts:
        parts = [f"'{f}' (x{c})" if c > 1 else f"'{f}'"
                 for f, c in sorted(oas_strip_counts.items())]
        log(f"  [access-rules] stripped unsupported fields: {', '.join(parts)}")

    path = target.cfg_path(f"policy/accesspolicies/{acp_id}/accessrules")
    log(f"  Pushing {len(prepared)} access rule(s) for ACP '{acp.name}' -> {path}")

    # Group consecutive rules by (section, category) — preserving ruleIndex order
    # — so each group can be created in the same section/category it had on the
    # source. Categories are pre-created on the ACP so ?category= placement works.
    groups = _group_rules_by_placement(prepared)
    _ensure_acp_categories(target, acp_id, groups, log)

    for (section, category), items in groups:
        gpath = _rule_path_with_placement(path, section, category)
        # A categorized/sectioned POST that FMC rejects should still create the
        # rule — fall back to the plain endpoint so placement never blocks it.
        fb = path if gpath != path else None
        if bulk and len(items) > 1:
            for start in range(0, len(items), _RULE_BULK_BATCH):
                chunk = items[start:start + _RULE_BULK_BATCH]
                _push_rule_batch(chunk, acp, acp_id, gpath, target,
                                 per_rule_fallback, summary, log, fallback_path=fb)
        else:
            for idx, src, body in items:
                _push_rule_single(idx, src, body, acp, gpath, target, summary, log,
                                  fallback_path=fb)


def _rule_placement(src: Dict[str, Any]) -> Tuple[str, str]:
    """Return the (section, category) an access rule should be created in.

    ``category`` is blank for rules in no user-defined category; ``section`` is
    blank for the implicit Default section (no query parameter needed).
    """
    meta = src.get("metadata") if isinstance(src.get("metadata"), dict) else {}
    section = str(meta.get("section") or "")
    cat = meta.get("category")
    if isinstance(cat, dict):
        category = str(cat.get("name") or "")
    elif isinstance(cat, str):
        category = cat
    else:
        category = ""
    if category.strip().lower() in _DEFAULT_RULE_CATEGORIES:
        category = ""
    if section.strip().lower() in ("", "default"):
        section = ""
    return section, category


def _group_rules_by_placement(
    prepared: List[Tuple[int, Dict[str, Any], Dict[str, Any]]],
) -> List[Tuple[Tuple[str, str], List[Tuple[int, Dict[str, Any], Dict[str, Any]]]]]:
    """Group prepared rules into ordered runs sharing the same (section, category)."""
    groups: List[Tuple[Tuple[str, str], List[Tuple[int, Dict[str, Any], Dict[str, Any]]]]] = []
    for idx, src, body in prepared:
        key = _rule_placement(src)
        if groups and groups[-1][0] == key:
            groups[-1][1].append((idx, src, body))
        else:
            groups.append((key, [(idx, src, body)]))
    return groups


def _rule_path_with_placement(path: str, section: str, category: str) -> str:
    """Append ?section=/?category= query parameters to an access-rule path."""
    from urllib.parse import quote
    params = []
    # A category implies its section; only send section on its own when there is
    # no category (FMC rejects section+category combinations that disagree).
    if category:
        params.append(f"category={quote(category)}")
    elif section:
        params.append(f"section={quote(section)}")
    return f"{path}?{'&'.join(params)}" if params else path


def _ensure_acp_categories(
    target: PolicyFmcClient, acp_id: str,
    groups: List[Tuple[Tuple[str, str], List[Any]]],
    log: Callable[[str], None],
) -> None:
    """Create the ACP's user-defined categories (in source order) if missing.

    FMC places an access rule in a category via ``?category=<name>`` only when
    that category already exists on the policy, so create them first. Failures
    are non-fatal: rules fall back to the plain endpoint.
    """
    wanted: List[str] = []
    for (section, category), _ in groups:
        if category and category not in wanted:
            wanted.append(category)
    if not wanted:
        return
    cat_path = target.cfg_path(f"policy/accesspolicies/{acp_id}/categories")
    try:
        existing = {normalize_name(c.get("name"))
                    for c in target.get_paginated(cat_path, expanded=False)}
    except FmcApiError:
        existing = set()
    for cat in wanted:
        if normalize_name(cat) in existing:
            continue
        try:
            target.post(cat_path, {"type": "Category", "name": cat})
            log(f"    [category] created '{cat}' on ACP")
        except FmcApiError as e:
            log(f"    [category] WARNING: could not create '{cat}': {e}; "
                "rules will fall back to the default section")


def _push_rule_batch(
    chunk: List[Tuple[int, Dict[str, Any], Dict[str, Any]]],
    acp: AcpModel, acp_id: str, path: str, target: PolicyFmcClient,
    per_rule_fallback: bool, summary: PushSummary, log: Callable[[str], None],
    fallback_path: Optional[str] = None,
) -> None:
    """Bulk-push a batch of rules.

    On a bulk failure, retry rule-by-rule when *per_rule_fallback* is set;
    otherwise bisect the batch recursively so only the offending rule(s) fail.

    *path* may carry ?section=/?category= placement parameters. If the whole
    categorized bulk is rejected and *fallback_path* (the plain endpoint) is
    given, the batch is retried there so rule creation is never blocked by a
    placement problem (the rules simply land in the default section).
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
        # First, if this was a placement (section/category) POST, retry the whole
        # batch on the plain endpoint before giving up — placement must never
        # prevent a rule from being created.
        if fallback_path and fallback_path != path:
            log(f"    [bulk] FAILED (index {lo}-{hi}) with placement HTTP "
                f"{e.status or '?'}: {e}; retrying batch without section/category")
            _push_rule_batch(chunk, acp, acp_id, fallback_path, target,
                             per_rule_fallback, summary, log, fallback_path=None)
            return
        summary.bulk_failed = True
        if per_rule_fallback:
            log(f"    [bulk] FAILED (index {lo}-{hi}) HTTP {e.status or '?'}: {e}; "
                "per-rule fallback ENABLED — transitioning to per-rule submission")
            summary.fallback_used = True
            already_exists = 0
            for idx, src, body in chunk:
                name = str(src.get("name", "?"))
                try:
                    resp = target.post(path, body)
                    new_id = str(resp.get("id", "")) if isinstance(resp, dict) else ""
                    _record_rule_pushed(idx, src, new_id, acp, "per-rule", summary, log)
                except FmcApiError as e2:
                    err_msg = str(e2).lower()
                    if "already exists" in err_msg or "name already" in err_msg:
                        # Rule was created by the initial bulk POST whose
                        # response triggered an HTTP 500/retry.
                        already_exists += 1
                        _record_rule_pushed(idx, src, "", acp, "per-rule (already existed)", summary, log)
                    else:
                        summary.rules_failed.append({
                            "name": name, "index": idx, "acp": acp.name,
                            "source_id": str(src.get("id", "")), "status": e2.status,
                            "error": str(e2),
                        })
                        log(f"    [rule {idx}] FAILED '{name}' on ACP '{acp.name}' "
                            f"(endpoint={path}) HTTP {e2.status or '?'}: {e2}")
            if already_exists:
                log(f"    [bulk] {already_exists}/{len(chunk)} rule(s) already existed "
                    f"(created by prior bulk attempt); counted as success")
        elif len(chunk) > 1:
            # Bisect: retry each half (left then right, preserving rule order)
            # so a single bad rule cannot sink the whole batch.
            mid = len(chunk) // 2
            log(f"    [bulk] FAILED (index {lo}-{hi}) HTTP {e.status or '?'}: {e}; "
                f"splitting → index {lo}-{chunk[mid - 1][0]}, {chunk[mid][0]}-{hi}")
            for half in (chunk[:mid], chunk[mid:]):
                _push_rule_batch(half, acp, acp_id, path, target,
                                 per_rule_fallback, summary, log, fallback_path=None)
        else:
            idx, src, _body = chunk[0]
            name = str(src.get("name", "?"))
            summary.rules_failed.append({
                "name": name, "index": idx, "acp": acp.name,
                "source_id": str(src.get("id", "")), "status": e.status,
                "error": str(e),
            })
            log(f"    [rule {idx}] FAILED '{name}' on ACP '{acp.name}' "
                f"(endpoint={path}) HTTP {e.status or '?'}: {e}")


def _push_rule_single(
    idx: int, src: Dict[str, Any], body: Dict[str, Any], acp: AcpModel,
    path: str, target: PolicyFmcClient, summary: PushSummary,
    log: Callable[[str], None], fallback_path: Optional[str] = None,
) -> None:
    """Push a single rule, logging full context on success or failure.

    If *path* carries section/category placement and FMC rejects it, the rule is
    retried on *fallback_path* (the plain endpoint) so placement never blocks it.
    """
    name = str(src.get("name", "?"))
    try:
        resp = target.post(path, body)
        new_id = str(resp.get("id", "")) if isinstance(resp, dict) else ""
        _record_rule_pushed(idx, src, new_id, acp, "per-rule", summary, log)
    except FmcApiError as e:
        if fallback_path and fallback_path != path:
            log(f"    [rule {idx}] '{name}' placement rejected HTTP "
                f"{e.status or '?'}: {e}; retrying without section/category")
            _push_rule_single(idx, src, body, acp, fallback_path, target,
                              summary, log, fallback_path=None)
            return
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
        "securityIntelligencePolicy": "SecurityIntelligencePolicy",
    }.get(cat, "")


_DEP_POLICY_TYPES = {"PrefilterPolicy", "DecryptionPolicy", "IdentityPolicy",
                     "IntrusionPolicy", "FilePolicy", "SecurityIntelligencePolicy"}


def _summary_tables(summary: PushSummary) -> Dict[str, List[List[str]]]:
    """Shape the summary into applied/failed/skipped tables (UI convention)."""
    applied: List[List[str]] = []
    for n in summary.successful_acps:
        applied.append(["ACP", n, "pushed"])
    for r in summary.rules_pushed:
        applied.append(["Access Rule", f"{r.get('acp', '')}: {r.get('name', '?')}",
                        f"pushed ({r.get('method', '')})"])
    for n in summary.objects_created:
        # Differentiate dependent policies from plain objects.
        is_dep = any(n.startswith(pt) for pt in _DEP_POLICY_TYPES)
        applied.append(["Dependent Policy" if is_dep else "Object", n, "created"])
    for n in summary.objects_reused:
        applied.append(["Object", n, "reused"])
    for n in summary.policies_overridden:
        applied.append(["Policy", n, "overridden"])
    # Dependent policy outcomes (container-level).
    for dp in summary.dep_policies_pushed:
        action = dp.get("action", "pushed")
        applied.append(["Dependent Policy", f"{dp.get('policy_type', '')} '{dp.get('name', '?')}'", action])
    # Dependent policy rule outcomes.
    for r in summary.dep_policy_rules_pushed:
        ptype = r.get("policy_type", "")
        label = ptype.replace("Policy", " Rule")
        applied.append([label, f"{r.get('policy', '')}: {r.get('name', '?')}", "pushed"])

    failed: List[List[str]] = [["ACP", f.get("name", "?"), f.get("error", "")] for f in summary.failed_acps]
    for r in summary.rules_failed:
        failed.append(["Access Rule", f"{r.get('acp', '')}: {r.get('name', '?')}",
                       f"HTTP {r.get('status') or '?'}: {r.get('error', '')}"])
    for dp in summary.dep_policies_failed:
        failed.append(["Dependent Policy", f"{dp.get('policy_type', '')} '{dp.get('name', '?')}'",
                        dp.get("error", "")])
    for r in summary.dep_policy_rules_failed:
        ptype = r.get("policy_type", "")
        label = ptype.replace("Policy", " Rule")
        failed.append([label, f"{r.get('policy', '')}: {r.get('name', '?')}",
                       r.get("error", "")])

    skipped: List[List[str]] = [["Setting", s, "skipped"] for s in summary.skipped_settings]
    for r in summary.rules_skipped:
        skipped.append(["Access Rule", r.get("name", "?"), r.get("reason", "skipped")])
    for dp in summary.dep_policies_skipped:
        skipped.append(["Dependent Policy", f"{dp.get('policy_type', '')} '{dp.get('name', '?')}'",
                        "not found / could not be created"])
    for r in summary.dep_policy_rules_skipped:
        ptype = r.get("policy_type", "")
        label = ptype.replace("Policy", " Rule")
        skipped.append([label, f"{r.get('policy', '')}: {r.get('name', '?')}",
                        r.get("reason", "skipped")])
    for d in summary.dropped_references:
        skipped.append(["Pruned Ref", f"{d.get('type', '')} {d.get('name', '')}",
                        f"in {d.get('scope', '')}"])
    for u in summary.objects_unresolved:
        skipped.append(["Unresolved", u, "no target equivalent"])
    for p in summary.partial_changes:
        skipped.append(["Partial", p, "may need cleanup"])
    return {"applied": applied, "failed": failed, "skipped": skipped}
