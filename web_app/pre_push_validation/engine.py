"""Orchestrates the deterministic pre-push validation + sanitization.

These functions are pure with respect to the FMC: the caller is responsible for
fetching the target device interfaces and passing them in. The model/version
and FMC schema checks need no network access (they resolve from the bundled
schema files).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from functools import lru_cache

from .interface_validator import detect_interface_conflicts
from .model_resolver import resolve_all
from .model_validator import validate_model
from .models import (
    CAT_META,
    Issue,
    SEVERITY_INFO,
    TargetInfo,
    ValidationReport,
)
from .oas_schema_loader import load_oas_schemas, resolve_oas_version
from .oas_schema_validator import OasSchemaIndex, validate_oas_schema
from .sanitizer import sanitize as _sanitize
from .schema_loader import load_model_schema


@lru_cache(maxsize=8)
def _oas_index(oas_version: str) -> OasSchemaIndex | None:
    """Build (and cache) an OasSchemaIndex for a resolved OAS version label."""
    schemas = load_oas_schemas(oas_version) if oas_version else None
    if not schemas:
        return None
    return OasSchemaIndex(schemas, version=oas_version)


def _resolve_target(raw_model: str, raw_version: str, fmc_version: str):
    sku, label, branch = resolve_all(raw_model, raw_version, fmc_version)
    model_schema = load_model_schema(sku, label) if (sku and label) else None
    oas_version = resolve_oas_version(fmc_version or raw_version)
    oas_index = _oas_index(oas_version) if oas_version else None
    return sku, label, branch, model_schema, oas_version, oas_index


def validate_config(config: Dict[str, Any],
                    target_interfaces: List[Dict[str, Any]],
                    *,
                    device_id: str = "",
                    device_name: str = "",
                    raw_model: str = "",
                    raw_version: str = "",
                    fmc_version: str = "",
                    schema_source: str = "oas") -> ValidationReport:
    """Run all deterministic checks and return a ValidationReport."""
    config = config or {}
    sku, label, branch, model_schema, oas_version, oas_index = _resolve_target(
        raw_model, raw_version, fmc_version)

    fmc_schema_found = oas_index is not None
    fmc_schema_label = oas_version

    target = TargetInfo(
        device_id=device_id,
        device_name=device_name,
        raw_model=raw_model,
        raw_version=raw_version,
        fmc_version=fmc_version,
        resolved_sku=sku,
        resolved_model_label=label,
        resolved_ftl_branch=fmc_schema_label,
        model_schema_found=model_schema is not None,
        fmc_schema_found=fmc_schema_found,
    )
    report = ValidationReport(target=target)

    # 1. Interface conflicts (needs the fetched target interfaces).
    report.interface_conflicts = detect_interface_conflicts(config, target_interfaces or [])

    # 2. Target FTD model/version capability checks (always uses model_schemas).
    if model_schema:
        for issue in validate_model(config, model_schema):
            report.add(issue)
    else:
        report.add(Issue(
            id="meta:model-schema",
            category=CAT_META,
            severity=SEVERITY_INFO,
            message=(f"Could not resolve a model schema for model='{raw_model}' "
                     f"version='{raw_version}' (sku={sku}, label={label}); "
                     "model/version capability checks were skipped."),
            proposed_action="",
            auto_fixable=False,
        ))

    # 3. Target FMC version schema checks.
    if oas_index:
        for issue in validate_oas_schema(config, oas_index):
            report.add(issue)
    else:
        report.add(Issue(
            id="meta:fmc-schema",
            category=CAT_META,
            severity=SEVERITY_INFO,
            message=(f"Could not resolve an FMC OAS schema for version='{fmc_version}'; "
                     f"FMC schema field checks were skipped."),
            proposed_action="",
            auto_fixable=False,
        ))

    return report


def _collect_fixes(config: Dict[str, Any],
                   raw_model: str, raw_version: str, fmc_version: str,
                   accepted_ids: Optional[List[str]],
                   schema_source: str = "oas") -> List[Dict[str, Any]]:
    """Re-run the (network-free) validators to rebuild fix directives.

    If ``accepted_ids`` is provided, only fixes for those issue ids are returned;
    otherwise every auto-fixable fix is included.
    """
    _, _, _, model_schema, _oas_version, oas_index = _resolve_target(
        raw_model, raw_version, fmc_version)
    issues: List[Issue] = []
    if model_schema:
        issues += validate_model(config, model_schema)
    if oas_index:
        issues += validate_oas_schema(config, oas_index)

    accepted = set(accepted_ids) if accepted_ids is not None else None
    fixes: List[Dict[str, Any]] = []
    for issue in issues:
        if not issue.fix:
            continue
        if accepted is not None and issue.id not in accepted:
            continue
        fixes.append(issue.fix)
    return fixes


def sanitize_config(config: Dict[str, Any],
                    *,
                    raw_model: str = "",
                    raw_version: str = "",
                    fmc_version: str = "",
                    interface_mappings: Optional[Dict[str, str]] = None,
                    accepted_issue_ids: Optional[List[str]] = None,
                    speed_changes: Optional[Dict[str, Any]] = None,
                    interface_removals: Optional[List[str]] = None,
                    member_changes: Optional[Dict[str, Dict[str, str]]] = None,
                    etherchannel_id_changes: Optional[Dict[str, int]] = None,
                    schema_source: str = "oas") -> Dict[str, Any]:
    """Produce a sanitized config + change list + diff.

    Field-removal fixes are rebuilt deterministically from the schemas; interface
    renames come from ``interface_mappings``, ``speed_changes`` apply corrected
    hardware speeds, ``interface_removals`` drop interfaces entirely,
    ``member_changes`` migrate port-channel / BVI / inline-set membership,
    and ``etherchannel_id_changes`` re-number EtherChannel IDs.
    No FMC access required.
    """
    fixes = _collect_fixes(config or {}, raw_model, raw_version, fmc_version,
                           accepted_issue_ids, schema_source)
    return _sanitize(config or {}, fixes, interface_mappings or {},
                     speed_changes or {}, interface_removals or [],
                     member_changes or {}, etherchannel_id_changes or {})
