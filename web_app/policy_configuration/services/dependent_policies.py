"""Create/reuse the dependent policies an ACP + its rules reference.

Scope:
  * **File policies** and **Intrusion policies** are *created* on the target
    when a same-named policy does not already exist. Intrusion policies are
    created from their base policy (matched by name on the target); file
    policies are created container-first, then their file rules are cloned.
  * **Prefilter / Decryption / Identity** policies are created on the target
    from their embedded definitions (rules populated at fetch time) when a
    same-named policy does not already exist. The container is created first,
    then the embedded rules are cloned one by one.

Every created/reused policy records a source->target id remap on the resolver so
the access-rule reference remapping rewrites rule bodies to the target id
instead of pruning the reference.
"""
from __future__ import annotations

import copy
import ipaddress as _ipaddress
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models.schema import AcpModel, PolicyConfig, PushSummary, normalize_name
from ..dependency_resolution.resolver import DependencyResolver
from ..validation.policy_validator import (
    _IDENTITY_MIN_VERSION_WEIGHT, _fmc_version_weight, strip_unsupported_fields,
)
from .client import PolicyFmcClient, FmcApiError

logger = logging.getLogger(__name__)

# ── FMC policy name sanitization ──
# FMC allows: alphanumerics, hyphen (-), underscore (_), colon (:),
# whitespace and period (.).  All other characters are replaced with
# underscores to prevent FMC 400 "invalid characters" errors.
_FMC_NAME_INVALID = re.compile(r"[^a-zA-Z0-9 \t\-_:.]")


def sanitize_fmc_name(name: str) -> str:
    """Replace characters that FMC considers invalid in policy names."""
    return _FMC_NAME_INVALID.sub("_", name)


# ── IPv6 host literal detection ──
# The source FMC sometimes misinterprets IPv6 host literals (e.g. 180:2::100)
# as Country objects.  These must be converted back to Host literals before
# pushing to the target FMC.


def _is_ipv6_id(value: str) -> bool:
    """Return True if *value* looks like an IPv6 address rather than a real id."""
    if not value or ":" not in value:
        return False
    try:
        _ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _fix_ipv6_country_objects(rule_body: Dict[str, Any],
                              policy_name: str,
                              log: Callable[[str], None]) -> None:
    """Convert misinterpreted Country objects whose id is an IPv6 address
    into Host literals in ``sourceNetworks`` / ``destinationNetworks``."""
    for net_key in ("sourceNetworks", "destinationNetworks"):
        net = rule_body.get(net_key)
        if not isinstance(net, dict):
            continue
        objects = net.get("objects")
        if not isinstance(objects, list):
            continue
        keep: List[Dict[str, Any]] = []
        promoted: List[Dict[str, Any]] = []
        for obj in objects:
            if (isinstance(obj, dict)
                    and obj.get("type") == "Country"
                    and _is_ipv6_id(str(obj.get("id", "")))):
                promoted.append({"type": "Host", "value": str(obj["id"])})
                log(f"  [dep-policies] {policy_name}: converted "
                    f"Country '{obj.get('name', '')}' (id={obj['id']}) to "
                    f"IPv6 Host literal in rule '{rule_body.get('name', '?')}'")
            else:
                keep.append(obj)
        if promoted:
            net["objects"] = keep if keep else None
            if not keep:
                del net["objects"]
            literals = net.setdefault("literals", [])
            literals.extend(promoted)


# Rule/default-action policy types we create on the target, with source config
# subsection + target endpoint.
_CREATABLE = {
    "IntrusionPolicy": ("intrusion_policies", "policy/intrusionpolicies"),
    "FilePolicy": ("file_policies", "policy/filepolicies"),
}

# Server-managed keys never sent on a create.
_STRIP = ("id", "links", "metadata")

# PKI / certificate keys that reference source-FMC-specific objects (Internal CA,
# Internal Cert, etc.) and cannot be remapped to the target FMC.
_PKI_KEYS = frozenset({
    "internalCerts", "decryptionCerts", "externalCertificates",
    "authCert", "trustedCAs",
})

# Assigned-policy types that can be created from an embedded definition.
# Maps FMC type -> (config subsection, API container suffix, rule embed key,
#                    rule API sub-resource).
_ASSIGNED_CREATABLE: Dict[str, Tuple[str, str, str, str]] = {
    "PrefilterPolicy": ("prefilter_policies", "policy/prefilterpolicies",
                        "prefilterrules", "prefilterrules"),
    "DecryptionPolicy": ("decryption_policies", "policy/decryptionpolicies",
                         "decryptionpolicyrules", "decryptionpolicyrules"),
    "IdentityPolicy": ("identity_policies", "policy/identitypolicies",
                       "identityrules", "identityrules"),
    # NOTE: SecurityIntelligencePolicy is intentionally absent. It is ACP-scoped
    # and exposed only as a GET sub-resource under the access policy
    # (.../accesspolicies/{id}/securityintelligencepolicies) — there is no
    # standalone POST endpoint. Attempting to create one returned HTTP 404
    # ("Invalid URL"); it is now skipped gracefully by the push layer.
}

# Maps policy type -> OAS schema hint for the embedded rule type. Used by
# push-time OAS sanitisation to strip unsupported rule fields.
_RULE_SCHEMA_HINT: Dict[str, str] = {
    "PrefilterPolicy": "PrefilterRule",
    "DecryptionPolicy": "DecryptionPolicyRule",
    "IdentityPolicy": "IdentityRule",
}


def ensure_rule_policies(
    acps: List[AcpModel], config: PolicyConfig,
    source: Optional[PolicyFmcClient],
    target: PolicyFmcClient, resolver: DependencyResolver, summary: PushSummary,
    log: Callable[[str], None],
) -> None:
    """Reuse-by-name or create every File/Intrusion policy referenced by *acps*.

    Operates offline from the fetched *config* (definitions + embedded file
    rules); *source* is optional and only used as a legacy fallback when the
    config lacks a definition. A single policy that cannot be created is skipped
    with a warning — it never aborts the rest of the push. Registers
    source->target id remaps on *resolver* for each resolved policy.
    """
    refs = _collect_rule_policy_refs(acps)
    if not refs:
        return
    defs = _policy_def_index(config)
    log(f"[dep-policies] Resolving {len(refs)} File/Intrusion policy reference(s)")
    for ref_type, sid, name in refs:
        if sid and sid in resolver.remap_table:
            continue
        try:
            # 1) Reuse an identically-named policy already on the target.
            tid = resolver.resolve_target_id(ref_type, name, sid)
            if tid:
                resolver.register_remap(sid, tid)
                summary.dep_policies_pushed.append({"policy_type": ref_type, "name": name, "action": "reused"})
                log(f"  [dep-policies] reuse {ref_type} '{name}' "
                    f"(source={sid or '—'} -> target={tid})")
                continue
            # 2) Create it from the fetched (offline) definition.
            body_def = defs.get((ref_type, sid)) or defs.get((ref_type, normalize_name(name))) \
                or _fetch_source_def(source, ref_type, sid)
            if not body_def:
                summary.skipped_settings.append(
                    f"{ref_type} '{name}' has no definition in the fetched YAML; "
                    "skipped (rule references pruned)")
                log(f"  [dep-policies] {ref_type} '{name}': no definition in fetched YAML; leaving unresolved")
                continue
            new_id = _create_policy(ref_type, body_def, name, source, target, sid, resolver, log)
            if new_id:
                resolver.register_remap(sid, new_id)
                summary.objects_created.append(f"{ref_type} '{name}'")
                summary.dep_policies_pushed.append({"policy_type": ref_type, "name": name, "action": "created"})
                log(f"  [dep-policies] created {ref_type} '{name}' on target (id={new_id})")
            else:
                summary.skipped_settings.append(
                    f"{ref_type} '{name}' could not be created on target; skipped "
                    "(rule references pruned)")
                summary.dep_policies_skipped.append({"policy_type": ref_type, "name": name})
        except FmcApiError as e:
            # A single dependent policy failure must not abort the push.
            summary.skipped_settings.append(
                f"{ref_type} '{name}' failed to create on target: {e}; skipped")
            summary.dep_policies_failed.append({"policy_type": ref_type, "name": name, "error": str(e)})
            log(f"  [dep-policies] WARNING: {ref_type} '{name}' create failed: {e}; "
                "skipping and continuing")
        except Exception as e:  # pragma: no cover - defensive
            summary.skipped_settings.append(
                f"{ref_type} '{name}' error: {e}; skipped")
            summary.dep_policies_failed.append({"policy_type": ref_type, "name": name, "error": str(e)})
            log(f"  [dep-policies] WARNING: {ref_type} '{name}' error: {e}; "
                "skipping and continuing")


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
        # FMC 400 "Policy name … is in use" means the policy already exists.
        # Look it up by name and return its id instead of failing.
        if e.status == 400 and "name" in str(e).lower() and "in use" in str(e).lower():
            log(f"  [dep-policies] IntrusionPolicy '{name}' already exists on target; reusing")
            existing_id = _find_policy_id_by_name(target, "policy/intrusionpolicies", name)
            if existing_id:
                return existing_id
        log(f"  [dep-policies] failed to create IntrusionPolicy '{name}': {e}")
        return ""


def _create_file_policy(
    source: Optional[PolicyFmcClient], target: PolicyFmcClient,
    body_def: Dict[str, Any], source_id: str, resolver: DependencyResolver,
    log: Callable[[str], None],
) -> str:
    """Create a file policy container, then clone its file rules.

    File rules are taken from the offline definition's embedded ``fileRules``
    (populated at fetch time); when absent, they are read from *source* as a
    legacy fallback if a source client is available.
    """
    name = str(body_def.get("name") or "")
    body = {k: v for k, v in body_def.items() if k not in _STRIP}
    body.setdefault("type", "FilePolicy")
    # File rules are created separately (they are not part of the container body).
    embedded_rules = body.pop("fileRules", None)
    try:
        created = target.post(target.cfg_path("policy/filepolicies"), body)
    except FmcApiError as e:
        log(f"  [dep-policies] failed to create FilePolicy '{name}': {e}")
        return ""
    new_id = str(created.get("id") or "") if isinstance(created, dict) else ""
    if not new_id:
        return ""
    rules: List[Dict[str, Any]] = []
    if isinstance(embedded_rules, list) and embedded_rules:
        rules = [r for r in embedded_rules if isinstance(r, dict)]
    elif source is not None and source_id:
        rules = _read_source_file_rules(source, source_id, name, log)
    # Sort by metadata.ruleIndex to preserve correct rule order.
    rules = sorted(
        rules,
        key=lambda r: (r.get("metadata") or {}).get("ruleIndex", 999999),
    )
    _clone_file_rules(target, new_id, rules, name, resolver, log)
    return new_id


def _read_source_file_rules(
    source: PolicyFmcClient, source_pid: str, name: str,
    log: Callable[[str], None],
) -> List[Dict[str, Any]]:
    """Legacy fallback: read a file policy's file rules from the source FMC."""
    try:
        return source.get_paginated(
            source.cfg_path(f"policy/filepolicies/{source_pid}/filerules"), expanded=True)
    except FmcApiError as e:
        log(f"  [dep-policies] FilePolicy '{name}': could not read file rules: {e}")
        return []


def _clone_file_rules(
    target: PolicyFmcClient, target_pid: str, rules: List[Dict[str, Any]],
    name: str, resolver: DependencyResolver, log: Callable[[str], None],
) -> None:
    """Create *rules* under the newly created target file policy."""
    if not rules:
        return
    path = target.cfg_path(f"policy/filepolicies/{target_pid}/filerules")
    ok = 0
    fr_strip_counts: Dict[str, int] = {}
    for r in rules:
        body = {k: v for k, v in r.items() if k not in _STRIP}
        # Predefined FileType/FileCategory ids are globally consistent; only
        # remap ids we actually know a target equivalent for.
        resolver.remap_references(body)
        # Push-time OAS sanitise: strip unsupported file rule fields.
        for _f in strip_unsupported_fields(body, "FileRule", target.fmc_version or ""):
            fr_strip_counts[_f] = fr_strip_counts.get(_f, 0) + 1
        try:
            target.post(path, body)
            ok += 1
        except FmcApiError as e:
            log(f"  [dep-policies] FilePolicy '{name}': file rule "
                f"'{r.get('name', '?')}' failed: {e}")
    if fr_strip_counts:
        parts = [f"'{f}' (x{c})" if c > 1 else f"'{f}'"
                 for f, c in sorted(fr_strip_counts.items())]
        log(f"  [dep-policies] FilePolicy '{name}': stripped unsupported "
            f"rule fields: {', '.join(parts)}")
    log(f"  [dep-policies] FilePolicy '{name}': cloned {ok}/{len(rules)} file rule(s)")


# ── create / reuse assigned prefilter/decryption/identity ──

# Decryption rule actions that require specific certificate types.
_DECRYPT_CA_ACTIONS = frozenset({"DECRYPT_RESIGN"})
_DECRYPT_CERT_ACTIONS = frozenset({"DECRYPT_KNOWN_KEY", "DECRYPT_REPLACE_CERT"})


def create_assigned_policy(
    policy_type: str, name: str, source_id: str,
    config: PolicyConfig, target: PolicyFmcClient,
    resolver: DependencyResolver, log: Callable[[str], None],
    cert_realm: Optional[Dict[str, str]] = None,
    summary: Optional[PushSummary] = None,
    strip_zones: bool = False,
    target_cert_names: Optional[Dict[str, str]] = None,
) -> str:
    """Create a prefilter/decryption/identity/SI policy on the target from config.

    Returns the new target id, or "" on failure. The container is created first,
    then embedded rules are cloned one by one (if the policy type has rules).
    """
    entry = _ASSIGNED_CREATABLE.get(policy_type)
    if not entry:
        return ""
    subsection, container_ep, embed_key, rule_subpath = entry

    # The FMC REST API only exposes POST on policy/identitypolicies from 10.0.
    if policy_type == "IdentityPolicy":
        vw = _fmc_version_weight(target.fmc_version or "")
        if 0 < vw < _IDENTITY_MIN_VERSION_WEIGHT:
            log(f"  [dep-policies] IdentityPolicy '{name}': create not supported by "
                f"the FMC REST API before 10.0 (target v{target.fmc_version}); "
                "create it manually on the target or select an existing policy")
            return ""

    # Look up the definition from the config.
    body_def = _find_assigned_def(config, subsection, source_id, name)
    if not body_def:
        log(f"  [dep-policies] {policy_type} '{name}': no definition in fetched YAML")
        return ""

    # Build the container body (strip server-managed keys, embedded rules,
    # the 'rules' reference stub, and 'categories' reference stub).
    _skip = set(_STRIP) | {"rules", "categories"}
    if embed_key:
        _skip.add(embed_key)
    body: Dict[str, Any] = {k: v for k, v in body_def.items()
                            if k not in _skip}
    body.setdefault("type", policy_type)
    body.setdefault("name", name)
    # Sanitize the policy name to replace characters FMC rejects.
    raw_name = str(body.get("name", ""))
    safe_name = sanitize_fmc_name(raw_name)
    if safe_name != raw_name:
        log(f"  [dep-policies] {policy_type}: sanitized name "
            f"'{raw_name}' → '{safe_name}'")
        body["name"] = safe_name
    # Strip PKI cert references from the container body (source-specific).
    for pk in _PKI_KEYS:
        body.pop(pk, None)
    # Strip nested server-managed keys (e.g. defaultAction.id/links).
    _strip_nested_ids(body)

    # Push-time OAS sanitise: strip fields the target FMC version does not
    # recognise to avoid HTTP 422 "Unrecognized Field" errors.
    _oas_strip_counts: Dict[str, int] = {}
    for _f in strip_unsupported_fields(body, policy_type, target.fmc_version or ""):
        _oas_strip_counts[_f] = _oas_strip_counts.get(_f, 0) + 1

    # Re-inject authCert for identity policies using the cert mapping.
    if policy_type == "IdentityPolicy":
        _inject_auth_cert(body, body_def, cert_realm or {}, name, log)

    try:
        created = target.post(target.cfg_path(container_ep), body)
    except FmcApiError as e:
        log(f"  [dep-policies] failed to create {policy_type} '{name}': {e}")
        return ""
    new_id = str(created.get("id") or "") if isinstance(created, dict) else ""
    if not new_id:
        return ""

    # For identity policies, fetch the default built-in category so we can
    # place rules via the ?intoCategory= query parameter (FMC requirement).
    category_id = ""
    if policy_type == "IdentityPolicy":
        category_id = _fetch_default_identity_category(target, container_ep, new_id, log)

        # FMC may ignore authCert during the initial POST.  GET the policy
        # back, inject the authCert, and PUT to ensure it is set before rules.
        auth_cert_ref = body.get("authCert")
        if isinstance(auth_cert_ref, dict) and auth_cert_ref.get("id"):
            try:
                id_pol_path = target.cfg_path(f"{container_ep}/{new_id}")
                current = target.get_json(id_pol_path)
                if isinstance(current, dict):
                    current["authCert"] = auth_cert_ref
                    # Strip read-only stubs that FMC returns but rejects on PUT.
                    for _ro in ("rules", "categories", "metadata", "links"):
                        current.pop(_ro, None)
                    target.put(id_pol_path, current)
                    log(f"  [dep-policies] IdentityPolicy '{name}': "
                        f"set authCert via PUT (id={auth_cert_ref['id']})")
            except FmcApiError as e:
                log(f"  [dep-policies] IdentityPolicy '{name}': "
                    f"WARNING: failed to PUT authCert: {e}")

    # Resolve cert extras.
    # New-style: per-reference mappings (sourceName → targetId).
    # Legacy fallback: single flat internalCaId / internalCertId.
    cert_realm = cert_realm or {}
    cert_mappings: Dict[str, str] = cert_realm.get("certMappings") or {}
    legacy_ca_id = cert_realm.get("internalCaId", "")
    legacy_cert_id = cert_realm.get("internalCertId", "")

    # Clone embedded rules.
    embedded = body_def.get(embed_key)
    if isinstance(embedded, list) and embedded:
        # Sort rules by metadata.ruleIndex so they are pushed in the correct
        # order.  Rules without metadata fall back to their original position.
        embedded = sorted(
            embedded,
            key=lambda r: (r.get("metadata") or {}).get("ruleIndex", 999999),
        )
        base_rule_path = target.cfg_path(f"{container_ep}/{new_id}/{rule_subpath}")
        # Prepare all rule bodies first.  Each entry keeps the source category
        # name so the rule can be recreated in the same category on the target.
        prepared: List[Tuple[Dict[str, Any], Dict[str, Any], str]] = []
        for r in embedded:
            if not isinstance(r, dict):
                continue
            # Capture the source category *before* stripping metadata.
            cat_name = _rule_category_name(r)
            rule_body = copy.deepcopy(r)
            # Strip server-managed keys.
            for sk in _STRIP:
                rule_body.pop(sk, None)
            # Strip PKI cert refs (source-FMC-specific, not remappable).
            for pk in _PKI_KEYS:
                rule_body.pop(pk, None)
            # Resolve object references to target ids in a SINGLE pass, pruning
            # only the references with no valid target equivalent.  Never remap
            # first and prune afterwards: once ids are rewritten to target ids
            # they are no longer remap-table keys, so a naive prune would drop
            # every successfully-remapped reference (the root cause of empty
            # sourceNetworks / sourceZones on cloned Decryption rules).
            _rname = str(r.get("name", "?"))

            def _on_drop(node: Dict[str, Any], _rn: str = _rname) -> None:
                log(f"  [dep-policies] {policy_type} '{name}': pruned unresolved "
                    f"{node.get('type', '')} "
                    f"'{node.get('name', node.get('id', ''))}' from rule '{_rn}'")

            resolver.resolve_and_prune_refs(rule_body, _on_drop)

            # Strip zones from dependent policy rules if requested.
            if strip_zones:
                rule_body.pop("sourceZones", None)
                rule_body.pop("destinationZones", None)

            # Inject user-selected certs for decryption rules.  Always run for
            # DecryptionPolicy (even when no mapping was received) so rules that
            # require a cert but have none are flagged loudly instead of failing
            # silently at the FMC with an opaque "must provide exactly 1
            # certificate" error.
            if policy_type == "DecryptionPolicy":
                _inject_decryption_certs(rule_body, r, cert_mappings,
                                         legacy_ca_id, legacy_cert_id, name, log,
                                         target_cert_names=target_cert_names or {})

            # Inject realm for identity rules (using resolver remap table).
            if policy_type == "IdentityPolicy":
                _inject_realm(rule_body, r, resolver, name, log)

            # Fix IPv6 host literals misinterpreted as Country objects.
            if policy_type == "IdentityPolicy":
                _fix_ipv6_country_objects(rule_body, name, log)

            # Strip Users/UserGroups, keep only Realm refs (remapped).
            _strip_dep_users_keep_realms(rule_body, resolver, name, log)

            # Push-time OAS sanitise: strip rule fields unsupported on target.
            rule_hint = _RULE_SCHEMA_HINT.get(policy_type, "")
            if rule_hint:
                for _f in strip_unsupported_fields(
                        rule_body, rule_hint, target.fmc_version or ""):
                    _oas_strip_counts[_f] = _oas_strip_counts.get(_f, 0) + 1

            prepared.append((r, rule_body, cat_name))

        ok = _clone_dep_rules(target, base_rule_path, prepared, policy_type,
                              name, category_id, summary, log)

    # Log consolidated push-time OAS removals for this policy.
    if _oas_strip_counts:
        parts = [f"'{f}' (x{c})" if c > 1 else f"'{f}'"
                 for f, c in sorted(_oas_strip_counts.items())]
        log(f"  [dep-policies] {policy_type} '{name}': stripped unsupported "
            f"fields: {', '.join(parts)}")

    return new_id


# Dependent-policy rule endpoints whose POST accepts a named ``?category=`` query
# parameter (verified against the FMC OpenAPI schema).  Decryption rules support
# it; prefilter rules do not (they have no categories); identity rules are placed
# via the built-in default category id (``?intoCategory=``).
_NAMED_CATEGORY_TYPES = frozenset({"DecryptionPolicy"})

# Category names that mean "no user-defined category" — the rule belongs to the
# policy's default/built-in section and must be posted without a category param.
_DEFAULT_CATEGORY_NAMES = frozenset({
    "", "standard_category", "--undefined--", "default", "mandatory",
})


def _rule_category_name(rule: Dict[str, Any]) -> str:
    """Return the source category name of a dependent-policy *rule* (or "")."""
    meta = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    cat = meta.get("category")
    if isinstance(cat, dict):
        return str(cat.get("name") or "")
    if isinstance(cat, str):
        return cat
    return ""


def _preserve_category(cat: str) -> bool:
    """True when *cat* is a real user category worth recreating on the target."""
    return bool(cat) and cat.strip().lower() not in _DEFAULT_CATEGORY_NAMES


def _clone_dep_rules(
    target: PolicyFmcClient, base_rule_path: str,
    prepared: List[Tuple[Dict[str, Any], Dict[str, Any], str]],
    policy_type: str, name: str,
    category_id: str, summary: Optional[PushSummary],
    log: Callable[[str], None],
) -> int:
    """Create the prepared rules on the target, preserving order and category.

    Dispatch by policy type:

    * **Identity** — every rule is placed in the built-in default category via
      the ``?intoCategory=<id>`` query parameter (FMC requirement).
    * **Decryption** — rules are grouped by their source category (in rule order)
      and posted with the named ``?category=<name>`` parameter so the target
      policy keeps the same category layout.  If a category is rejected the rules
      are recreated without it so rule creation never regresses.
    * **Prefilter / others** — posted in order (bulk when supported) with no
      category (those rule types have none).
    """
    if not prepared:
        return 0
    # Identity: single built-in category placement.
    if category_id:
        path = f"{base_rule_path}?intoCategory={category_id}"
        return _post_dep_rules(target, path, [(o, b) for (o, b, _) in prepared],
                               policy_type, name, summary, log)

    # All rule types (Decryption / Prefilter / others): ordered bulk push
    # without any category parameter.  FMC rejects ?category= on bulk POST
    # for decryption rules, and the fallback round-trip is wasteful.  Rules
    # land in the policy's default section; categories can be reorganized on
    # the target afterwards if needed.
    plain = [(o, b) for (o, b, _) in prepared]
    if len(plain) > 1:
        return _bulk_push_dep_rules(target, base_rule_path, plain, policy_type,
                                    name, summary, log)
    return _post_dep_rules(target, base_rule_path, plain, policy_type, name,
                           summary, log)


def _post_dep_rules(
    target: PolicyFmcClient, path: str,
    items: List[Tuple[Dict[str, Any], Dict[str, Any]]],
    policy_type: str, name: str, summary: Optional[PushSummary],
    log: Callable[[str], None], category: str = "",
) -> int:
    """POST each rule sequentially to *path*; record outcomes. Returns count OK.

    A per-rule POST is used (no bulk) so category/ordering is exact and a single
    HTTP 500 can never silently duplicate an entire batch.  When *category* is
    set, a failure is reported softly (the caller retries without the category).
    """
    ok = 0
    total = len(items)
    for idx, (orig, rule_body) in enumerate(items, 1):
        rname = orig.get("name", "?")
        log(f"  [dep-policies] {policy_type} '{name}': "
            f"pushing rule {idx}/{total} '{rname}'")
        try:
            target.post(path, rule_body)
            ok += 1
            log(f"  [dep-policies] {policy_type} '{name}': "
                f"rule '{rname}' OK ({ok}/{total})")
            if summary is not None:
                summary.dep_policy_rules_pushed.append({
                    "policy_type": policy_type, "policy": name, "name": rname,
                })
        except FmcApiError as e:
            # Reactive zone fix: if the FMC rejects a decryption rule because
            # sourceZones ≠ destinationZones, strip both zones and retry once.
            if (policy_type == "DecryptionPolicy"
                    and _DECRYPT_ZONE_ERROR in str(e).lower()
                    and _strip_decryption_zones(rule_body, name, log)):
                try:
                    target.post(path, rule_body)
                    ok += 1
                    log(f"  [dep-policies] {policy_type} '{name}': "
                        f"rule '{rname}' OK after zone strip ({ok}/{total})")
                    if summary is not None:
                        summary.dep_policy_rules_pushed.append({
                            "policy_type": policy_type, "policy": name,
                            "name": rname,
                        })
                    continue
                except FmcApiError as e2:
                    e = e2  # fall through to normal failure handling
            if category:
                # Soft failure — caller will retry without the category.
                log(f"  [dep-policies] {policy_type} '{name}': rule '{rname}' "
                    f"rejected for category '{category}': {e}")
                return ok
            log(f"  [dep-policies] {policy_type} '{name}': rule '{rname}' failed: {e}")
            if summary is not None:
                summary.dep_policy_rules_failed.append({
                    "policy_type": policy_type, "policy": name,
                    "name": rname, "error": str(e),
                })
    return ok


def _bulk_push_dep_rules(
    target: PolicyFmcClient, path: str,
    prepared: List[Tuple[Dict[str, Any], Dict[str, Any]]],
    policy_type: str, policy_name: str,
    summary: Optional[PushSummary], log: Callable[[str], None],
    category: str = "",
) -> int:
    """Bulk-POST prepared dependent-policy rules with per-rule fallback on failure.

    When *category* is set and the bulk POST fails, return 0 immediately (soft
    failure) so the caller can retry the entire group without the category —
    mirroring the ``_post_dep_rules`` soft-failure contract.
    """
    bodies = [rb for (_, rb) in prepared]
    log(f"  [dep-policies] {policy_type} '{policy_name}': "
        f"bulk POST {len(bodies)} rule(s)")
    try:
        resp = target.post(path, bodies, bulk=True)
        items = resp.get("items") if isinstance(resp, dict) else resp
        items = items if isinstance(items, list) else []
        ok = 0
        for i, (orig, _) in enumerate(prepared):
            new_id = ""
            if i < len(items) and isinstance(items[i], dict):
                new_id = str(items[i].get("id", ""))
            if new_id:
                ok += 1
                if summary is not None:
                    summary.dep_policy_rules_pushed.append({
                        "policy_type": policy_type, "policy": policy_name,
                        "name": orig.get("name", "?"),
                    })
            else:
                if summary is not None:
                    summary.dep_policy_rules_failed.append({
                        "policy_type": policy_type, "policy": policy_name,
                        "name": orig.get("name", "?"),
                        "error": "bulk response missing id",
                    })
        log(f"  [dep-policies] {policy_type} '{policy_name}': "
            f"bulk OK — {ok}/{len(bodies)} rule(s)")
        return ok
    except FmcApiError as e:
        if category:
            # Soft failure — caller will retry without the category.
            log(f"  [dep-policies] {policy_type} '{policy_name}': "
                f"bulk rejected for category '{category}': {e}")
            return 0
        log(f"  [dep-policies] {policy_type} '{policy_name}': "
            f"bulk FAILED: {e}; falling back to per-rule POST")
        ok = 0
        already_exists = 0
        total = len(prepared)
        for idx, (orig, rule_body) in enumerate(prepared, 1):
            rname = orig.get("name", "?")
            log(f"  [dep-policies] {policy_type} '{policy_name}': "
                f"pushing rule {idx}/{total} '{rname}'")
            try:
                target.post(path, rule_body)
                ok += 1
                log(f"  [dep-policies] {policy_type} '{policy_name}': "
                    f"rule '{rname}' OK ({ok}/{total})")
                if summary is not None:
                    summary.dep_policy_rules_pushed.append({
                        "policy_type": policy_type, "policy": policy_name,
                        "name": rname,
                    })
            except FmcApiError as e2:
                err_msg = str(e2).lower()
                if "already exists" in err_msg or "name already" in err_msg:
                    # Rule was created by the initial bulk POST whose response
                    # triggered an HTTP 500/retry; treat as success.
                    ok += 1
                    already_exists += 1
                    log(f"  [dep-policies] {policy_type} '{policy_name}': "
                        f"rule '{rname}' already exists (prior bulk); counted as OK ({ok}/{total})")
                    if summary is not None:
                        summary.dep_policy_rules_pushed.append({
                            "policy_type": policy_type, "policy": policy_name,
                            "name": rname,
                        })
                elif (policy_type == "DecryptionPolicy"
                      and _DECRYPT_ZONE_ERROR in err_msg
                      and _strip_decryption_zones(rule_body, policy_name, log)):
                    # Reactive zone fix: strip mismatched zones and retry once.
                    try:
                        target.post(path, rule_body)
                        ok += 1
                        log(f"  [dep-policies] {policy_type} '{policy_name}': "
                            f"rule '{rname}' OK after zone strip ({ok}/{total})")
                        if summary is not None:
                            summary.dep_policy_rules_pushed.append({
                                "policy_type": policy_type, "policy": policy_name,
                                "name": rname,
                            })
                    except FmcApiError as e3:
                        log(f"  [dep-policies] {policy_type} '{policy_name}': "
                            f"rule '{rname}' failed after zone strip: {e3}")
                        if summary is not None:
                            summary.dep_policy_rules_failed.append({
                                "policy_type": policy_type, "policy": policy_name,
                                "name": rname, "error": str(e3),
                            })
                else:
                    log(f"  [dep-policies] {policy_type} '{policy_name}': "
                        f"rule '{rname}' failed: {e2}")
                    if summary is not None:
                        summary.dep_policy_rules_failed.append({
                            "policy_type": policy_type, "policy": policy_name,
                            "name": rname, "error": str(e2),
                        })
        if already_exists:
            log(f"  [dep-policies] {policy_type} '{policy_name}': "
                f"{already_exists}/{total} rule(s) already existed "
                f"(created by prior bulk attempt); counted as success")
        return ok


# Error substring returned by FMC when decryption rules have mismatched zones.
# Some FMC versions (7.x) require identical sourceZones / destinationZones;
# newer versions (≥10.x) do not.  We strip zones reactively only when this
# specific error is encountered.
_DECRYPT_ZONE_ERROR = "same zone object for both source and destination"


def _strip_decryption_zones(
    rule_body: Dict[str, Any], policy_name: str,
    log: Callable[[str], None],
) -> bool:
    """Remove sourceZones and destinationZones from a decryption *rule_body*.

    Called reactively when the FMC rejects a rule with the 'same zone object'
    error.  Returns True if any zone key was actually removed (i.e. a retry is
    worthwhile).
    """
    rname = rule_body.get("name", "?")
    src = rule_body.pop("sourceZones", None)
    dst = rule_body.pop("destinationZones", None)
    if src or dst:
        src_names = ", ".join(o.get("name", "?") for o in (src or {}).get("objects") or []) or "(none)"
        dst_names = ", ".join(o.get("name", "?") for o in (dst or {}).get("objects") or []) or "(none)"
        log(f"  [dep-policies] DecryptionPolicy '{policy_name}': stripped zones on rule "
            f"'{rname}' — src [{src_names}] / dst [{dst_names}] "
            f"(FMC requires same zone for both; retrying without zones)")
        return True
    return False


def _inject_decryption_certs(
    rule_body: Dict[str, Any], original_rule: Dict[str, Any],
    cert_mappings: Dict[str, str],
    legacy_ca_id: str, legacy_cert_id: str,
    policy_name: str, log: Callable[[str], None],
    target_cert_names: Optional[Dict[str, str]] = None,
) -> None:
    """Inject user-selected Internal CA or Internal Cert into a decryption rule.

    Uses per-reference *cert_mappings* (sourceName → targetId) when available,
    falling back to legacy flat *legacy_ca_id* / *legacy_cert_id*.
    """
    names = target_cert_names or {}
    action = rule_body.get("ruleAction", "")
    rname = rule_body.get("name", "?")
    if action in _DECRYPT_CA_ACTIONS:
        target_id, src_name = _resolve_cert_target(original_rule, "decryptionCerts", cert_mappings, legacy_ca_id)
        if target_id:
            rule_body["decryptionCerts"] = {
                "objects": [{"id": target_id, "type": "InternalCA"}]
            }
            tgt_name = names.get(target_id, "")
            tgt_label = f"'{tgt_name}' (id={target_id})" if tgt_name else f"id={target_id}"
            log(f"  [dep-policies] DecryptionPolicy '{policy_name}': "
                f"injected InternalCA '{src_name}' → {tgt_label} into {action} rule '{rname}'")
        else:
            src = _cert_source_names(original_rule, "decryptionCerts")
            log(f"  [dep-policies] DecryptionPolicy '{policy_name}': WARNING — "
                f"no target Internal CA mapping for {action} rule '{rname}' "
                f"(source cert(s): {src or 'none'}); FMC will reject this rule. "
                f"Map the Internal CA in the Assigned Policies section before push.")
    elif action in _DECRYPT_CERT_ACTIONS:
        target_id, src_name = _resolve_cert_target(original_rule, "internalCerts", cert_mappings, legacy_cert_id)
        if target_id:
            rule_body["internalCerts"] = {
                "objects": [{"id": target_id, "type": "InternalCertificate"}]
            }
            tgt_name = names.get(target_id, "")
            tgt_label = f"'{tgt_name}' (id={target_id})" if tgt_name else f"id={target_id}"
            log(f"  [dep-policies] DecryptionPolicy '{policy_name}': "
                f"injected InternalCertificate '{src_name}' → {tgt_label} into {action} rule '{rname}'")
        else:
            src = _cert_source_names(original_rule, "internalCerts")
            log(f"  [dep-policies] DecryptionPolicy '{policy_name}': WARNING — "
                f"no target Internal Certificate mapping for {action} rule '{rname}' "
                f"(source cert(s): {src or 'none'}); FMC will reject this rule. "
                f"Map the Internal Certificate in the Assigned Policies section before push.")


def _cert_source_names(original_rule: Dict[str, Any], cert_key: str) -> str:
    """Return a comma-joined list of source cert names under *cert_key* (or "")."""
    objs = (original_rule.get(cert_key) or {}).get("objects") or []
    names = [str(o.get("name", "")) for o in objs if o.get("name")]
    return ", ".join(names)


def _resolve_cert_target(
    original_rule: Dict[str, Any], cert_key: str,
    cert_mappings: Dict[str, str], legacy_id: str,
) -> Tuple[str, str]:
    """Look up the target cert id for a source cert reference in *original_rule*.

    Returns ``(target_id, source_name)``.
    """
    objs = (original_rule.get(cert_key) or {}).get("objects") or []
    for obj in objs:
        src_name = obj.get("name", "")
        if src_name and src_name in cert_mappings:
            return cert_mappings[src_name], src_name
    # Legacy fallback — no name available.
    first_name = objs[0].get("name", "?") if objs else "?"
    return legacy_id, first_name


def _inject_realm(
    rule_body: Dict[str, Any], original_rule: Dict[str, Any],
    resolver: "DependencyResolver",
    policy_name: str, log: Callable[[str], None],
) -> None:
    """Inject realm into an identity rule using the resolver's remap table.

    Source realm IDs are remapped to target IDs via the resolver (populated
    by ``_ensure_realms`` in push.py before dependent policies are created).
    """
    auth_type = rule_body.get("authenticationType", "")
    if auth_type in ("ACTIVE", "PASSIVE"):
        src_realm = original_rule.get("realm") if isinstance(original_rule.get("realm"), dict) else {}
        src_id = src_realm.get("id", "")
        remap = resolver.remap_table
        target_id = remap.get(src_id, "") if src_id else ""
        if target_id:
            rule_body["realm"] = {"id": target_id, "type": "IdentityRealm"}
            log(f"  [dep-policies] IdentityPolicy '{policy_name}': "
                f"injected realm into {auth_type} rule '{rule_body.get('name', '?')}'")
        else:
            # Strip stale source realm if no mapping available.
            rule_body.pop("realm", None)
            if src_id:
                log(f"  [dep-policies] IdentityPolicy '{policy_name}': "
                    f"stripped unresolvable realm from {auth_type} rule "
                    f"'{rule_body.get('name', '?')}'")


def _inject_auth_cert(
    body: Dict[str, Any], body_def: Dict[str, Any],
    cert_realm: Dict[str, Any],
    policy_name: str, log: Callable[[str], None],
) -> None:
    """Re-inject ``authCert`` on an identity-policy container using cert mappings.

    The ``authCert`` key references a source-FMC-specific ``PKI_InternalCert``
    (e.g. captive-portal cert) and is stripped by ``_PKI_KEYS``.  If the user
    provided a cert mapping for it, inject the target certificate id.
    """
    src_cert = body_def.get("authCert")
    if not isinstance(src_cert, dict):
        return
    src_name = src_cert.get("name", "")
    if not src_name:
        return
    cert_mappings: Dict[str, str] = cert_realm.get("certMappings") or {}
    target_id = cert_mappings.get(src_name, "")
    if target_id:
        # Preserve the source discriminator type (FMC uses "PKI_InternalCert"
        # for an identity policy's captive-portal authCert reference). Sending
        # the generic "InternalCertificate" type makes FMC silently ignore the
        # reference, so the server certificate never gets applied.
        cert_type = src_cert.get("type") or "PKI_InternalCert"
        body["authCert"] = {"id": target_id, "type": cert_type}
        log(f"  [dep-policies] IdentityPolicy '{policy_name}': "
            f"injected authCert '{src_name}' -> target id {target_id}")
    else:
        log(f"  [dep-policies] IdentityPolicy '{policy_name}': "
            f"authCert '{src_name}' has no cert mapping; omitted")


def _fetch_default_identity_category(
    target: PolicyFmcClient, container_ep: str, policy_id: str,
    log: Callable[[str], None],
) -> str:
    """Return the id of the first built-in identity-policy category, or ""."""
    try:
        cats = target.get_paginated(
            target.cfg_path(f"{container_ep}/{policy_id}/identitycategories"),
            expanded=False)
        if cats:
            return str(cats[0].get("id", ""))
    except Exception as e:
        log(f"  [dep-policies] could not fetch identity categories: {e}")
    return ""


def _find_assigned_def(
    config: PolicyConfig, subsection: str, source_id: str, name: str,
) -> Optional[Dict[str, Any]]:
    """Locate the policy definition by id or name in the config subsection."""
    items = (config.policies or {}).get(subsection) or []
    nn = normalize_name(name)
    for it in items:
        if not isinstance(it, dict):
            continue
        if source_id and str(it.get("id", "")) == source_id:
            return it
        if normalize_name(it.get("name")) == nn:
            return it
    return None


def _strip_nested_ids(body: Dict[str, Any]) -> None:
    """Remove server-managed 'id' and 'links' from nested dicts (e.g. defaultAction)."""
    for k, v in list(body.items()):
        if isinstance(v, dict):
            v.pop("id", None)
            v.pop("links", None)
            v.pop("metadata", None)
            # Recurse one level for nested dicts like defaultAction.
            _strip_nested_ids(v)


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
    source: Optional[PolicyFmcClient], ref_type: str, source_id: str,
) -> Optional[Dict[str, Any]]:
    """Fetch a policy definition from the source FMC by id (legacy fallback).

    Returns ``None`` when no source client is available (offline push).
    """
    if source is None:
        return None
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


def _strip_dep_users_keep_realms(
    rule_body: Dict[str, Any], resolver: "DependencyResolver",
    policy_name: str, log: Callable[[str], None],
) -> None:
    """Strip Users/UserGroups from ``users.objects``, keeping only Realm refs.

    Realm source IDs are remapped to target IDs via the resolver.  Users and
    user groups are unconditionally removed — only Realm references are pushed.
    """
    users_block = rule_body.get("users")
    if not isinstance(users_block, dict):
        return
    objects = users_block.get("objects")
    if not isinstance(objects, list):
        return
    remap = resolver.remap_table
    target_ids = set(remap.values())
    kept: list = []
    rule_name = rule_body.get("name", "?")
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type", "")
        if otype != "Realm":
            # Drop all non-Realm objects (RealmUser, RealmUserGroup, etc.)
            log(f"    [strip-users] dropped {otype} '{obj.get('name', '?')}' "
                f"from dep rule '{rule_name}' on '{policy_name}'")
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
                f"'{obj.get('name', oid)}' from dep rule '{rule_name}' "
                f"on '{policy_name}'")
    if kept:
        users_block["objects"] = kept
    else:
        rule_body.pop("users", None)
