"""Validate interface + routing config against the target FTD model/version
capabilities described in the model_schemas files.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .config_types import INTERFACE_SECTIONS, SECTION_TO_MODEL_TYPE
from .models import (
    CAT_MODEL_FIELD,
    CAT_MODEL_TYPE,
    CAT_ROUTING,
    Issue,
    SEVERITY_BLOCKING,
    SEVERITY_WARNING,
)

# Meta fields that are always allowed and never flagged at the model layer.
_META_FIELDS = {"id", "links", "metadata", "type"}


def _item_name(item: Dict[str, Any]) -> str:
    return str(item.get("ifname") or item.get("name") or item.get("id") or "")


def validate_model(config: Dict[str, Any], model_schema: Dict[str, Any]) -> List[Issue]:
    """Return model/version capability issues for the given config."""
    issues: List[Issue] = []
    if not model_schema:
        return issues
    ifaces = model_schema.get("interfaces") or {}
    sku = model_schema.get("model", "")
    fmc_ver = model_schema.get("fmc_version", "")

    for section in INTERFACE_SECTIONS:
        items = config.get(section)
        if not isinstance(items, list) or not items:
            continue
        type_key = SECTION_TO_MODEL_TYPE.get(section)
        type_def = ifaces.get(type_key) if type_key else None
        if not type_def:
            continue  # type not described for this model -> handled by FMC layer

        if not type_def.get("supported", True):
            reason = type_def.get("reason") or f"{type_key} not supported on {sku}"
            issues.append(Issue(
                id=f"model:{section}:type",
                category=CAT_MODEL_TYPE,
                severity=SEVERITY_BLOCKING,
                message=f"{type_key} is not supported on target model {sku} (FMC {fmc_ver}): {reason}",
                section=section,
                type=type_key,
                proposed_action=f"Remove all {section} ({len(items)} item(s))",
                auto_fixable=True,
                fix={"op": "remove_section", "section": section},
            ))
            continue

        excluded = type_def.get("excluded_fields") or {}
        hw_def = type_def.get("hardware_fragment") or {}
        # Excluded fields apply to the whole type; report once per (section, field).
        _check_excluded_fields(issues, section, type_key, items, excluded)
        _check_hw_excluded_fields(issues, section, type_key, items, hw_def)
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            name = _item_name(item)
            _check_hardware_values(issues, section, type_key, idx, name, item, hw_def)
            if section == "etherchannel_interfaces":
                _check_etherchannel(issues, section, type_key, idx, name, item, type_def)

    _check_routing(issues, config, model_schema)
    return issues


def _check_excluded_fields(issues, section, type_key, items, excluded):
    for field, reason in (excluded or {}).items():
        if any(isinstance(it, dict) and field in it for it in items):
            issues.append(Issue(
                id=f"model:{section}:field:{field}",
                category=CAT_MODEL_FIELD,
                severity=SEVERITY_WARNING,
                message=f"Field '{field}' is not supported on this model/version: {reason}",
                section=section,
                type=type_key,
                item_name="(all items)",
                field=field,
                proposed_action=f"Remove field '{field}' from all {section}",
                auto_fixable=True,
                fix={"op": "remove_field_all", "section": section, "field_path": [field]},
            ))


def _check_hw_excluded_fields(issues, section, type_key, items, hw_def):
    if not hw_def:
        return
    hw_excluded = hw_def.get("excluded_fields") or {}
    for field, reason in hw_excluded.items():
        if any(isinstance(it, dict) and isinstance(it.get("hardware"), dict)
               and field in it["hardware"] for it in items):
            issues.append(Issue(
                id=f"model:{section}:field:hardware.{field}",
                category=CAT_MODEL_FIELD,
                severity=SEVERITY_WARNING,
                message=f"Hardware field '{field}' is not supported on this model/version: {reason}",
                section=section,
                type=type_key,
                item_name="(all items)",
                field=f"hardware.{field}",
                proposed_action=f"Remove field 'hardware.{field}' from all {section}",
                auto_fixable=True,
                fix={"op": "remove_field_all", "section": section, "field_path": ["hardware", field]},
            ))


def _check_hardware_values(issues, section, type_key, idx, name, item, hw_def):
    hw = item.get("hardware")
    if not isinstance(hw, dict) or not hw_def:
        return
    hw_excluded = hw_def.get("excluded_fields") or {}
    spd = hw.get("speed")

    if spd is not None and "speed" not in hw_excluded:
        # Per-interface speed check: use per_interface_speeds if available for the
        # specific hardware interface name, otherwise fall back to the combined set.
        hw_name = str(item.get("name") or "")
        per_iface = hw_def.get("per_interface_speeds") or {}
        mgmt_speeds = hw_def.get("management_speeds") or {}
        iface_speeds = per_iface.get(hw_name) or mgmt_speeds.get(hw_name)
        if iface_speeds:
            allowed_speeds = set(iface_speeds)
            if spd not in allowed_speeds:
                issues.append(Issue(
                    id=f"model:{section}:{idx}:hardware.speed",
                    category=CAT_MODEL_FIELD,
                    severity=SEVERITY_WARNING,
                    message=f"Speed '{spd}' is not supported on interface '{hw_name}' "
                            f"(allowed: {sorted(allowed_speeds)})",
                    section=section,
                    type=type_key,
                    item_name=name,
                    field="hardware.speed",
                    current_value=spd,
                    proposed_action="Remove field 'hardware.speed' (let device auto-negotiate)",
                    auto_fixable=True,
                    fix={"op": "remove_field_path", "pointer": [section, idx, "hardware", "speed"]},
                ))
        else:
            # Fallback: combined builtin + netmod set
            speeds = hw_def.get("supported_speeds") or {}
            allowed_speeds = set((speeds.get("builtin") or []) + (speeds.get("netmod") or []))
            if allowed_speeds and spd not in allowed_speeds:
                issues.append(Issue(
                    id=f"model:{section}:{idx}:hardware.speed",
                    category=CAT_MODEL_FIELD,
                    severity=SEVERITY_WARNING,
                    message=f"Interface speed '{spd}' is not supported on this model/version "
                            f"(allowed: {sorted(allowed_speeds)})",
                    section=section,
                    type=type_key,
                    item_name=name,
                    field="hardware.speed",
                    current_value=spd,
                    proposed_action="Remove field 'hardware.speed' (let device auto-negotiate)",
                    auto_fixable=True,
                    fix={"op": "remove_field_path", "pointer": [section, idx, "hardware", "speed"]},
                ))

    allowed_duplex = set(hw_def.get("supported_duplex") or [])
    dup = hw.get("duplex")
    if dup is not None and allowed_duplex and "duplex" not in hw_excluded and dup not in allowed_duplex:
        issues.append(Issue(
            id=f"model:{section}:{idx}:hardware.duplex",
            category=CAT_MODEL_FIELD,
            severity=SEVERITY_WARNING,
            message=f"Interface duplex '{dup}' is not supported on this model/version "
                    f"(allowed: {sorted(allowed_duplex)})",
            section=section,
            type=type_key,
            item_name=name,
            field="hardware.duplex",
            current_value=dup,
            proposed_action="Remove field 'hardware.duplex'",
            auto_fixable=True,
            fix={"op": "remove_field_path", "pointer": [section, idx, "hardware", "duplex"]},
        ))


def _check_etherchannel(issues, section, type_key, idx, name, item, type_def):
    constraints = type_def.get("etherchannel_constraints") or {}
    id_range = constraints.get("id_range") or {}
    ec_id = item.get("etherChannelId")
    try:
        ec_id_int = int(ec_id) if ec_id is not None else None
    except (TypeError, ValueError):
        ec_id_int = None
    if ec_id_int is not None and id_range:
        lo, hi = id_range.get("min"), id_range.get("max")
        if lo is not None and hi is not None and not (lo <= ec_id_int <= hi):
            issues.append(Issue(
                id=f"model:{section}:{idx}:etherChannelId",
                category=CAT_MODEL_FIELD,
                severity=SEVERITY_BLOCKING,
                message=f"EtherChannel id {ec_id_int} is out of range [{lo}-{hi}] for this model",
                section=section,
                type=type_key,
                item_name=name,
                field="etherChannelId",
                current_value=ec_id,
                proposed_action=f"Set etherChannelId within [{lo}-{hi}]",
                auto_fixable=False,
            ))


def _check_routing(issues, config, model_schema):
    routing = config.get("routing") or {}
    if not isinstance(routing, dict):
        return
    vrfs = routing.get("vrfs")
    if not vrfs:
        return
    vrf_def = ((model_schema.get("routing") or {}).get("vrf") or {})
    if vrf_def and not vrf_def.get("supported", True):
        reason = vrf_def.get("reason") or "VRF not supported on this model/version"
        issues.append(Issue(
            id="model:routing.vrfs:type",
            category=CAT_ROUTING,
            severity=SEVERITY_WARNING,
            message=f"VRF/virtual routers are not supported on the target model/version: {reason}",
            section="routing.vrfs",
            type="VirtualRouter",
            proposed_action=f"Remove routing.vrfs ({len(vrfs)} item(s))",
            auto_fixable=True,
            fix={"op": "remove_routing_key", "key": "vrfs"},
        ))
