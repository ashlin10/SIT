"""Validate policy YAML against the FMC OAS (OpenAPI) schema.

Reuses the existing ``pre_push_validation`` OAS infrastructure
(``oas_schema_loader`` + ``OasSchemaIndex``) so policy documents are checked
against the *actual* request/response models a given FMC version accepts.

Two validations are run by the push workflow:
  * the **source** policy YAML against the source FMC version, and
  * the **target-resolved** YAML (after id/reference remap) against the target
    FMC version,
so differences between source/target FMC versions are accounted for.

"FTL schema" in the original requirement maps to the project's FMC OAS schema
(established terminology in ``pre_push_validation``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..models.schema import normalize_name

logger = logging.getLogger(__name__)

# Map policy YAML 'type' discriminators to OAS component schema names. The
# OasSchemaIndex resolves most names directly; these cover the policy types.
_POLICY_TYPE_TO_SCHEMA: Dict[str, str] = {
    "AccessPolicy": "AccessPolicy",
    "AccessRule": "AccessRule",
    "PrefilterPolicy": "PrefilterPolicy",
    "AccessPolicyDefaultAction": "AccessPolicyDefaultAction",
    "AccessPolicyInheritanceSetting": "AccessPolicyInheritanceSetting",
    "ElephantFlowSettings": "ElephantFlowSettings",
    "ShadowTrafficSetting": "ShadowTrafficSetting",
    "EVESetting": "EVESetting",
    "LoggingSetting": "LoggingSetting",
    "AdvancedLoggingSetting": "AdvancedLoggingSetting",
    "SecurityIntelligencePolicy": "SecurityIntelligencePolicy",
    "IdentityPolicy": "IdentityPolicy",
    "DecryptionPolicy": "DecryptionPolicy",
    "AIDefenseSetting": "AIDefenseSetting",
}

# Dependent-policy subsection -> (container schema hint, embedded rule key, rule schema hint).
_DEPENDENT_POLICY_SCHEMAS: Dict[str, tuple] = {
    "prefilter_policies": ("PrefilterPolicy", "prefilterrules", "PrefilterRule"),
    "decryption_policies": ("DecryptionPolicy", "decryptionpolicyrules", "DecryptionPolicyRule"),
    "identity_policies": ("IdentityPolicy", "identityrules", "IdentityRule"),
    "file_policies": ("FilePolicy", "fileRules", "FileRule"),
    "intrusion_policies": ("IntrusionPolicy", None, None),
    # SecurityIntelligencePolicy is not pushed; skip validation to avoid noise.
    # "security_intelligence_policies": ("SecurityIntelligencePolicy", None, None),
}

# Fields always permissible regardless of the resolved schema's property list.
_META_FIELDS = {"id", "links", "metadata", "type", "version", "name"}
# Nested keys we never descend into (polymorphic / simplified config shapes that
# do not match the strict OAS model, to avoid false positives).
_SKIP_RECURSE = {"metadata", "links", "ipv4", "ipv6"}
# OAS schemas that are abstract base types / interfaces whose property lists are
# intentionally incomplete (they omit derived-type fields like ``port`` on
# ``PortLiteral`` or ``icmpType`` on ``ICMPv4PortLiteral``).  Validating items
# against these base schemas produces false-positive warnings, so we skip them.
# All ``I*Literal`` schemas are covered by _is_skip_schema() below.
_SKIP_ABSTRACT_SCHEMAS = {
    "IBasePortLiteral", "ICipherSuiteLiteral", "IDistinguishedNameLiteral",
    "INetworkAddressLiteral", "ISecurityGroupTagLiteral", "IUrlLiteral",
    "IValueLiteral", "IVlanTagLiteral",
}


def _is_skip_schema(name: str) -> bool:
    """Return True if *name* is an abstract schema that should be skipped.

    Matches all ``I<Name>Literal`` interface schemas in addition to the
    explicit ``_SKIP_ABSTRACT_SCHEMAS`` set.
    """
    if name in _SKIP_ABSTRACT_SCHEMAS:
        return True
    # Catch any future I*Literal interface schemas automatically.
    if name.startswith("I") and name.endswith("Literal") and len(name) > 8:
        return True
    return False


# Maximum nesting depth walked when validating/stripping against the schema.
_MAX_DEPTH = 6
# Version weight threshold: IdentityPolicy / IdentityRule schemas are
# incomplete in FMC versions below 10.0 — skip validation to avoid noise.
_IDENTITY_MIN_VERSION_WEIGHT = 100000  # 10.0.0 -> 10*10000 + 0*100 + 0


def _fmc_version_weight(fmc_version: str) -> int:
    """Parse an FMC version string into a sortable integer weight.

    Handles strings like ``'7.4.1'``, ``'10.0.1 (build 172)'``, etc.
    Returns ``-1`` if the version cannot be parsed.
    """
    import re as _re
    m = _re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", fmc_version or "")
    if not m:
        return -1
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return major * 10000 + minor * 100 + patch


@dataclass
class PolicyValidationResult:
    side: str  # "source" | "target"
    fmc_version: str = ""
    oas_version: str = ""
    schema_found: bool = False
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_blocking(self) -> bool:
        return bool(self.errors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "side": self.side,
            "fmc_version": self.fmc_version,
            "oas_version": self.oas_version,
            "schema_found": self.schema_found,
            "errors": self.errors,
            "warnings": self.warnings,
            "has_blocking": self.has_blocking,
        }


def _load_index(fmc_version: str, schema_source: str = "oas"):
    """Build an OasSchemaIndex for *fmc_version*; returns (index, label).

    *schema_source* selects ``'oas'`` (default) or ``'ftl'`` schemas.
    """
    try:
        from web_app.pre_push_validation.oas_schema_loader import (
            resolve_oas_version, load_oas_schemas,
        )
        from web_app.pre_push_validation.oas_schema_validator import OasSchemaIndex
    except Exception:  # pragma: no cover - import path fallback
        from pre_push_validation.oas_schema_loader import (  # type: ignore
            resolve_oas_version, load_oas_schemas,
        )
        from pre_push_validation.oas_schema_validator import OasSchemaIndex  # type: ignore

    if schema_source == "ftl":
        idx, lbl = _load_ftl_index(fmc_version)
        if idx is not None:
            return idx, lbl
        # Fall back to OAS if no FTL schema found.

    label = resolve_oas_version(fmc_version or "")
    if not label:
        return None, ""
    schemas = load_oas_schemas(label)
    if not schemas:
        return None, label
    return OasSchemaIndex(schemas, label), label


def _load_ftl_index(fmc_version: str):
    """Try to load an FTL schema for *fmc_version*; returns (index, label) or (None, '')."""
    import json as _json
    import os as _os
    try:
        from web_app.pre_push_validation.oas_schema_validator import OasSchemaIndex
        from web_app.pre_push_validation.oas_schema_loader import version_weight
    except Exception:
        from pre_push_validation.oas_schema_validator import OasSchemaIndex  # type: ignore
        from pre_push_validation.oas_schema_loader import version_weight  # type: ignore

    _here = _os.path.dirname(_os.path.abspath(__file__))
    _repo = _os.path.dirname(_os.path.dirname(_os.path.dirname(_here)))
    ftl_dir = _os.path.join(_repo, "schemas", "ftl_schemas")
    if not _os.path.isdir(ftl_dir):
        return None, ""
    # Discover available FTL schema files and pick closest <= requested version.
    import re as _re
    candidates = []
    for fn in _os.listdir(ftl_dir):
        m = _re.search(r"IMS_(\d+)_(\d+)(?:_(\d+))?", fn)
        if m and fn.endswith(".json"):
            parts = [m.group(1), m.group(2)]
            if m.group(3):
                parts.append(m.group(3))
            label = ".".join(parts)
            candidates.append((version_weight(label), label, fn))
    if not candidates:
        return None, ""
    candidates.sort()
    from web_app.pre_push_validation.oas_schema_loader import _clean_version
    target = _clean_version(fmc_version or "")
    tw = version_weight(target) if target else -1
    if tw < 0:
        return None, ""
    le = [c for c in candidates if c[0] <= tw]
    chosen = max(le, key=lambda c: c[0]) if le else min(candidates, key=lambda c: c[0])
    path = _os.path.join(ftl_dir, chosen[2])
    try:
        with open(path, "r") as f:
            raw = _json.load(f)
    except Exception:
        return None, ""
    # FTL schemas may be a flat dict of type -> properties.
    schemas = raw.get("components", {}).get("schemas") if isinstance(raw.get("components"), dict) else None
    if not schemas:
        schemas = raw.get("definitions") or raw
    if not isinstance(schemas, dict):
        return None, ""
    return OasSchemaIndex(schemas, f"FTL-{chosen[1]}"), f"FTL-{chosen[1]}"


def validate_policy_doc(
    doc: Dict[str, Any], fmc_version: str, side: str = "source",
    schema_source: str = "oas",
) -> PolicyValidationResult:
    """Validate a policy YAML document against the FMC OAS schema.

    Each issue is tagged with the affected ACP / rule / setting / assigned
    policy / object so the UI can point the user at the problem. Field-name
    mismatches are *warnings*; structural type problems are *errors* (blocking).

    *schema_source* selects ``'oas'`` (default) or ``'ftl'`` schemas.
    """
    result = PolicyValidationResult(side=side, fmc_version=fmc_version)
    index, label = _load_index(fmc_version, schema_source)
    result.oas_version = label
    if index is None:
        result.warnings.append({
            "scope": "schema",
            "message": f"No OAS schema available for FMC version '{fmc_version}'; "
                       "schema validation skipped.",
        })
        return result
    result.schema_found = True

    # Flat, Device-Configuration-style document: ACPs live at the top level
    # (a legacy ``policy.accesspolicies`` wrapper is still tolerated).
    acps = doc.get("access_policies")
    if acps is None:
        acps = (doc.get("policy") or {}).get("accesspolicies") or []
    if not isinstance(acps, list):
        result.errors.append({"scope": "access_policies", "message": "'access_policies' must be a list"})
        return result

    for acp in acps:
        if not isinstance(acp, dict):
            result.errors.append({"scope": "access_policies", "message": "ACP entry is not a mapping"})
            continue
        acp_name = acp.get("name", "?")
        # Validate the ACP container against AccessPolicy (the raw faithful
        # payload). Embedded access rules are validated separately.
        _validate_typed(index, acp, "AccessPolicy", f"ACP '{acp_name}'", result,
                        skip_keys={"accessrules"})
        # Rules.
        for i, rule in enumerate(acp.get("accessrules") or []):
            if isinstance(rule, dict):
                _validate_typed(index, rule, "AccessRule",
                                f"ACP '{acp_name}' rule[{i}] '{rule.get('name', i)}'", result)

    # ── Dependent policies ──
    vw = _fmc_version_weight(fmc_version)
    for section_key, (container_hint, rule_key, rule_hint) in _DEPENDENT_POLICY_SCHEMAS.items():
        policies = doc.get(section_key)
        if not isinstance(policies, list):
            continue
        # IdentityPolicy schemas are incomplete on FMC versions below 10.0;
        # skip validation entirely to avoid false-positive warnings.
        if section_key == "identity_policies" and 0 < vw < _IDENTITY_MIN_VERSION_WEIGHT:
            n = len([p for p in policies if isinstance(p, dict)])
            if n:
                result.warnings.append({
                    "scope": "identity_policies",
                    "message": f"IdentityPolicy validation skipped for FMC v{fmc_version} "
                               f"(schema incomplete below 10.0); {n} policy(ies) not checked.",
                })
            continue
        for p in policies:
            if not isinstance(p, dict):
                continue
            pname = p.get("name", "?")
            scope = f"{section_key} '{pname}'"
            skip = {rule_key} if rule_key else set()
            _validate_typed(index, p, container_hint, scope, result, skip_keys=skip)
            if rule_key and rule_hint:
                for ri, r in enumerate(p.get(rule_key) or []):
                    if isinstance(r, dict):
                        _validate_typed(
                            index, r, rule_hint,
                            f"{scope} rule[{ri}] '{r.get('name', ri)}'", result,
                        )

    # ── Objects ──
    objects_block = doc.get("objects")
    if isinstance(objects_block, dict):
        _validate_objects_block(index, objects_block, result)

    return result


def _validate_objects_block(
    index, objects_block: Dict[str, Any], result: PolicyValidationResult,
) -> None:
    """Validate objects within the nested ``objects`` block.

    Walks both flat (``objects.icmpv4: [...]``) and nested
    (``objects.network.hosts: [...]``) categories.
    """
    for top_key, val in objects_block.items():
        if isinstance(val, list):
            for i, obj in enumerate(val):
                if isinstance(obj, dict):
                    obj_type = obj.get("type", top_key)
                    scope = f"objects.{top_key}[{i}] '{obj.get('name', i)}'"
                    _validate_typed(index, obj, obj_type, scope, result)
        elif isinstance(val, dict):
            for sub_key, sub_list in val.items():
                if isinstance(sub_list, list):
                    for i, obj in enumerate(sub_list):
                        if isinstance(obj, dict):
                            obj_type = obj.get("type", sub_key)
                            scope = f"objects.{top_key}.{sub_key}[{i}] '{obj.get('name', i)}'"
                            _validate_typed(index, obj, obj_type, scope, result)


def sanitize_policy_config(
    config: Any, removal_keys: set, fmc_version: str,
    schema_source: str = "oas",
    log: Optional[Callable[[str], None]] = None,
) -> int:
    """Strip OAS-unsupported fields from a ``PolicyConfig`` in place.

    *removal_keys* is a set of ``"<SchemaName>:<field>"`` group keys (as emitted
    on validation warnings). Every ACP container, access rule, dependent-policy
    container/rule, and object is resolved to its OAS schema; any field whose
    ``"<schema>:<field>"`` is in *removal_keys* is removed. Returns the number of
    field occurrences removed.

    The mutation is applied to the live config (``acp.raw_base``,
    ``acp.access_rules``, ``config.policies``, ``config.objects``) so the change
    persists into the subsequent YAML serialization and push.
    """
    log = log or (lambda m: None)
    if not removal_keys:
        return 0
    index, _label = _load_index(fmc_version, schema_source)
    if index is None:
        return 0

    removed = 0
    # Collect removals grouped by "Schema:field" for consolidated logging.
    removal_counts: Dict[str, int] = {}

    def _strip(node: Dict[str, Any], schema_hint: str, scope: str,
               skip_keys: Optional[set] = None, depth: int = 0) -> None:
        nonlocal removed
        if not isinstance(node, dict):
            return
        skip_keys = skip_keys or set()
        schema_name = index.resolve_name(node.get("type") or schema_hint) or \
            index.resolve_name(schema_hint)
        if not schema_name:
            return
        props = index.props(schema_name) or {}
        for field_name in list(node.keys()):
            if field_name in skip_keys:
                continue
            gk = f"{schema_name}:{field_name}"
            if gk in removal_keys:
                node.pop(field_name, None)
                removed += 1
                removal_counts[gk] = removal_counts.get(gk, 0) + 1
                continue
            # Recurse into nested objects/arrays with a known child schema so
            # nested removal keys (e.g. IApplicationsContainer:applicationDefaultPort)
            # are applied too.
            if depth >= _MAX_DEPTH or field_name in _SKIP_RECURSE:
                continue
            child_schema = props.get(field_name)
            if not child_schema or _is_skip_schema(child_schema):
                continue
            value = node.get(field_name)
            if isinstance(value, dict):
                _strip(value, child_schema, scope, depth=depth + 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        _strip(item, child_schema, scope, depth=depth + 1)

    acps = getattr(config, "acps", []) or []
    for acp in acps:
        raw = getattr(acp, "raw_base", None)
        if isinstance(raw, dict):
            _strip(raw, "AccessPolicy", f"ACP '{getattr(acp, 'name', '?')}'",
                   skip_keys={"accessrules"})
        for i, rule in enumerate(getattr(acp, "access_rules", []) or []):
            _strip(rule, "AccessRule",
                   f"ACP '{getattr(acp, 'name', '?')}' rule[{i}]")
        # Re-derive in-memory ACP fields (settings/assigned) after mutation.
        try:
            acp.derive_from_raw()
        except Exception:  # pragma: no cover - defensive
            pass

    policies = getattr(config, "policies", {}) or {}
    for section_key, (container_hint, rule_key, rule_hint) in _DEPENDENT_POLICY_SCHEMAS.items():
        for p in policies.get(section_key) or []:
            if not isinstance(p, dict):
                continue
            skip = {rule_key} if rule_key else set()
            _strip(p, container_hint, f"{section_key} '{p.get('name', '?')}'", skip_keys=skip)
            if rule_key:
                for ri, r in enumerate(p.get(rule_key) or []):
                    _strip(r, rule_hint, f"{section_key} '{p.get('name', '?')}' rule[{ri}]")

    for obj in getattr(config, "objects", []) or []:
        if isinstance(obj, dict):
            _strip(obj, obj.get("type", ""), f"object '{obj.get('name', '?')}'")

    # Log consolidated removals: one line per Schema:field with count.
    for gk, cnt in sorted(removal_counts.items()):
        schema_name, field_name = gk.split(":", 1)
        suffix = f" (x{cnt})" if cnt > 1 else ""
        log(f"  [sanitize] removed '{field_name}' from {schema_name}{suffix}")

    return removed


def strip_unsupported_fields(
    body: Dict[str, Any], schema_hint: str, fmc_version: str,
    skip_keys: Optional[set] = None,
) -> List[str]:
    """Strip fields from *body* that the target FMC schema does not recognise.

    Returns a list of field names that were removed. This is intended for
    push-time sanitisation so that policies/rules created on an older target
    FMC never contain fields that would trigger HTTP 422 errors.

    Callers are responsible for logging; the returned list enables grouped /
    consolidated output instead of per-body spam.
    """
    if not fmc_version or not isinstance(body, dict):
        return []
    index, _label = _load_index(fmc_version)
    if index is None:
        return []
    removed: List[str] = []
    _strip_recursive(index, body, schema_hint, skip_keys or set(), removed, 0)
    return removed


def _strip_recursive(
    index, node: Dict[str, Any], schema_hint: str, skip_keys: set,
    removed: List[str], depth: int,
) -> None:
    """Recursively strip OAS-unsupported fields from *node* in place.

    Descends into nested objects/arrays that resolve to a known child schema
    (via ``$ref``) so nested unsupported fields — e.g. ``advancedOptions.
    quicDecryption`` or ``applications.applicationDefaultPort`` — are stripped
    too, preventing HTTP 422 "Unrecognized Field" errors on push.
    """
    if not isinstance(node, dict):
        return
    schema_name = index.resolve_name(node.get("type") or schema_hint) or \
        index.resolve_name(schema_hint)
    if not schema_name:
        return
    props = index.props(schema_name) or {}
    allowed = set(props.keys()) | _META_FIELDS
    for field_name in list(node.keys()):
        if field_name in skip_keys or str(field_name).startswith("_"):
            continue
        if field_name not in allowed:
            node.pop(field_name, None)
            removed.append(field_name)
            continue
        if depth >= _MAX_DEPTH or field_name in _SKIP_RECURSE:
            continue
        child_schema = props.get(field_name)
        if not child_schema or _is_skip_schema(child_schema):
            continue
        value = node.get(field_name)
        if isinstance(value, dict):
            _strip_recursive(index, value, child_schema, set(), removed, depth + 1)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _strip_recursive(index, item, child_schema, set(), removed, depth + 1)


def _validate_typed(
    index, obj: Dict[str, Any], schema_hint: str, scope: str,
    result: PolicyValidationResult, skip_keys: Optional[set] = None,
    depth: int = 0,
) -> None:
    """Flag fields not present in the resolved OAS schema as warnings.

    Recurses into nested objects/arrays that resolve to a known child schema
    (via ``$ref``) so unsupported *nested* fields — e.g. ``advancedOptions.
    quicDecryption`` on a DecryptionPolicy or ``applications.applicationDefaultPort``
    on an AccessRule — are caught too, not just top-level ones.
    """
    if not isinstance(obj, dict):
        return
    skip_keys = skip_keys or set()
    schema_name = index.resolve_name(obj.get("type") or schema_hint) or \
        index.resolve_name(schema_hint)
    if not schema_name:
        # Only warn about unresolved types at the top level; unresolved nested
        # refs are silently skipped to avoid false positives on polymorphic
        # sub-objects (e.g. Application references inside a rule).
        if depth == 0:
            result.warnings.append({
                "scope": scope,
                "message": f"Type '{schema_hint}' not found in OAS v{result.oas_version} "
                           "(feature may be unsupported on this FMC version).",
            })
        return
    props = index.props(schema_name) or {}
    allowed = set(props.keys()) | _META_FIELDS
    for field_name, value in obj.items():
        if field_name in skip_keys or str(field_name).startswith("_"):
            continue
        if field_name not in allowed:
            result.warnings.append({
                "scope": scope,
                "field": field_name,
                "schema": schema_name,
                # Stable, version-agnostic key used by the sanitizer + the UI to
                # group identical field mismatches and to strip them on Fix.
                "group_key": f"{schema_name}:{field_name}",
                "sanitizable": True,
                "side": result.side,
                "message": f"Field '{field_name}' is not present in {schema_name} "
                           f"(OAS v{result.oas_version}); unsupported/deprecated.",
            })
            continue
        # Recurse into nested objects/arrays that have a known child schema.
        if depth >= _MAX_DEPTH or field_name in _SKIP_RECURSE:
            continue
        child_schema = props.get(field_name)
        if not child_schema or _is_skip_schema(child_schema):
            continue
        child_scope = f"{scope} > {field_name}"
        if isinstance(value, dict):
            _validate_typed(index, value, child_schema, child_scope, result,
                            depth=depth + 1)
        elif isinstance(value, list):
            for j, item in enumerate(value):
                if isinstance(item, dict):
                    _validate_typed(index, item, child_schema,
                                    f"{child_scope}[{j}]", result, depth=depth + 1)
