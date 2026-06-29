"""Mappings between YAML config sections and schema type names, plus helpers
for locating interface-name references throughout a config document.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


# YAML interface section key -> model_schemas interface type key.
SECTION_TO_MODEL_TYPE: Dict[str, str] = {
    "loopback_interfaces": "LoopbackInterface",
    "physical_interfaces": "PhysicalInterface",
    "etherchannel_interfaces": "EtherChannelInterface",
    "subinterfaces": "SubInterface",
    "vti_interfaces": "VirtualTunnelInterface (VTI)",
    "inline_sets": "InlineSet (Inline Pair)",
    "bridge_group_interfaces": "BridgeGroupInterface (BVI)",
    "vlan_interfaces": "VlanInterface",
    "vni_interfaces": "VNIInterface (VXLAN/VTEP)",
    "redundant_interfaces": "RedundantInterface",
}

# YAML interface section key -> ftl_schema model (class) name.
# (Retained for reference / the legacy FTL validator; the active field-name
#  validator now uses SECTION_TO_OAS_SCHEMA below.)
SECTION_TO_FTL_TYPE: Dict[str, str] = {
    "loopback_interfaces": "LoopbackInterface",
    "physical_interfaces": "PhysicalInterface",
    "etherchannel_interfaces": "EtherChannelInterface",
    "subinterfaces": "SubInterface",
    "vti_interfaces": "VirtualTunnelInterface",
    "inline_sets": "InlineSet",
    "bridge_group_interfaces": "BridgeGroupInterface",
    "vlan_interfaces": "VlanInterface",
    "vni_interfaces": "VNIInterface",
    "redundant_interfaces": "RedundantInterface",
}

# YAML interface section key -> FMC OAS (OpenAPI) component schema name.
# These are the request/response model names exposed under
# ``components.schemas`` in the version-specific OAS documents.
SECTION_TO_OAS_SCHEMA: Dict[str, str] = {
    "loopback_interfaces": "FTDLoopbackInterface",
    "physical_interfaces": "FTDPhysicalInterface",
    "etherchannel_interfaces": "FTDEtherChannelInterface",
    "subinterfaces": "FTDSubInterface",
    "vti_interfaces": "FTDVTIInterface",
    "inline_sets": "InlineSet",
    "bridge_group_interfaces": "FTDBridgeGroupInterface",
    "vlan_interfaces": "FTDVlanInterface",
    "vni_interfaces": "FTDVNIInterface",
    "redundant_interfaces": "FTDRedundantInterface",
}

# All interface sections (order matters for stable reporting).
INTERFACE_SECTIONS: List[str] = list(SECTION_TO_MODEL_TYPE.keys())

# Keys whose string value denotes a *hardware* interface name (the kind that can
# differ between source and target devices).
HARDWARE_NAME_KEYS = {"name"}

# Reference sub-objects (dict) whose nested "name" denotes a hardware interface.
HARDWARE_REF_OBJECT_KEYS = {"tunnelSource", "borrowIPfrom", "deviceInterface", "parentInterface"}

# Reference list keys whose items (dicts) carry a hardware interface "name".
HARDWARE_REF_LIST_KEYS = {"selectedInterfaces", "hwPortAssociations"}

# Keys that directly hold a hardware interface name as a plain string.
HARDWARE_NAME_STRING_KEYS = {"interfaceName", "parentName"}

# Keys we never descend into when scanning/renaming interface references
# (avoids accidental collisions with zone / object names).
SKIP_KEYS = {"securityZone", "metadata", "links", "ipv4", "ipv6"}


def _split_parent(name: str) -> str:
    """For a subinterface name like 'Ethernet1/1.100' return the parent part."""
    if isinstance(name, str) and "." in name:
        return name.split(".", 1)[0]
    return name


def collect_referenced_interface_names(config: Dict[str, Any]) -> Dict[str, List[str]]:
    """Return a map of hardware-interface-name -> list of human-readable paths
    where that name is referenced across all interface + routing sections.
    """
    refs: Dict[str, List[str]] = {}

    def _add(name: str, path: str) -> None:
        if not name or not isinstance(name, str):
            return
        refs.setdefault(name, [])
        if path not in refs[name]:
            refs[name].append(path)

    # Interface sections
    for section in INTERFACE_SECTIONS:
        items = config.get(section) or []
        if not isinstance(items, list):
            continue
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            base = f"{section}[{idx}]"
            # Primary hardware name (physical/etherchannel/etc).
            if section in ("physical_interfaces", "etherchannel_interfaces",
                           "vlan_interfaces"):
                _add(item.get("name"), f"{base}.name")
            if section == "subinterfaces":
                _add(_split_parent(item.get("name") or ""), f"{base}.name(parent)")
                _add(item.get("parentName"), f"{base}.parentName")
            _scan_refs(item, base, _add)

    # Routing section
    routing = config.get("routing") or {}
    if isinstance(routing, dict):
        for rkey, rval in routing.items():
            if not isinstance(rval, list):
                continue
            for idx, item in enumerate(rval):
                if isinstance(item, dict):
                    _scan_refs(item, f"routing.{rkey}[{idx}]", _add)
    return refs


def _scan_refs(obj: Any, path: str, add) -> None:
    """Recursively scan for hardware interface references, skipping SKIP_KEYS."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS:
                continue
            child = f"{path}.{k}"
            if k in HARDWARE_NAME_STRING_KEYS and isinstance(v, str):
                add(v, child)
            elif k in HARDWARE_REF_OBJECT_KEYS and isinstance(v, dict):
                if isinstance(v.get("name"), str):
                    add(v.get("name"), f"{child}.name")
            elif k in HARDWARE_REF_LIST_KEYS and isinstance(v, list):
                for i, it in enumerate(v):
                    if isinstance(it, dict) and isinstance(it.get("name"), str):
                        add(it.get("name"), f"{child}[{i}].name")
            elif isinstance(v, (dict, list)):
                _scan_refs(v, child, add)
    elif isinstance(obj, list):
        for i, it in enumerate(obj):
            _scan_refs(it, f"{path}[{i}]", add)
