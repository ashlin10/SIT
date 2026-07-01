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
from typing import Any, Dict, List, Optional

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


def _load_index(fmc_version: str):
    """Build an OasSchemaIndex for *fmc_version*; returns (index, oas_label)."""
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

    label = resolve_oas_version(fmc_version or "")
    if not label:
        return None, ""
    schemas = load_oas_schemas(label)
    if not schemas:
        return None, label
    return OasSchemaIndex(schemas, label), label


def validate_policy_doc(
    doc: Dict[str, Any], fmc_version: str, side: str = "source",
) -> PolicyValidationResult:
    """Validate a policy YAML document against the FMC OAS schema.

    Each issue is tagged with the affected ACP / rule / setting / assigned
    policy / object so the UI can point the user at the problem. Field-name
    mismatches are *warnings*; structural type problems are *errors* (blocking).
    """
    result = PolicyValidationResult(side=side, fmc_version=fmc_version)
    index, label = _load_index(fmc_version)
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

    return result


def _validate_typed(
    index, obj: Dict[str, Any], schema_hint: str, scope: str,
    result: PolicyValidationResult, skip_keys: Optional[set] = None,
) -> None:
    """Flag fields not present in the resolved OAS schema as warnings."""
    skip_keys = skip_keys or set()
    schema_name = index.resolve_name(obj.get("type") or schema_hint) or \
        index.resolve_name(schema_hint)
    if not schema_name:
        # Schema for this type not present in this FMC version -> warning only.
        result.warnings.append({
            "scope": scope,
            "message": f"Type '{schema_hint}' not found in OAS v{result.oas_version} "
                       "(feature may be unsupported on this FMC version).",
        })
        return
    props = index.props(schema_name) or {}
    allowed = set(props.keys()) | {"id", "links", "metadata", "type", "version", "name"}
    for field_name in obj.keys():
        if field_name in skip_keys or str(field_name).startswith("_"):
            continue
        if field_name not in allowed:
            result.warnings.append({
                "scope": scope,
                "field": field_name,
                "message": f"Field '{field_name}' is not present in {schema_name} "
                           f"(OAS v{result.oas_version}); unsupported/deprecated.",
            })
