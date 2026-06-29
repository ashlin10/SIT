"""Validate config field *names* against the target FMC version's OAS schema.

The FMC OpenAPI Specification (OAS) exposes ``components.schemas[<Name>]`` where
each schema is a JSON-Schema object with a ``properties`` map. Nested objects are
referenced with ``$ref`` (directly, or via ``items.$ref`` for arrays). We walk the
config's typed objects, resolve each to its OAS component schema, and flag any
field that is not present in that schema's property set as unsupported/deprecated
for the target FMC version.

This replaces the older ftl_schema based field validation, which was inaccurate.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Optional

from .config_types import INTERFACE_SECTIONS, SECTION_TO_OAS_SCHEMA
from .models import CAT_FMC_FIELD, Issue, SEVERITY_WARNING
from .oas_schema_loader import version_weight

# Fields that are always permissible regardless of the schema property list.
_META_FIELDS = {"id", "links", "metadata", "type", "version", "name"}
# Properties we do not descend into (polymorphic / simplified config shapes that
# do not match the strict OAS model, to avoid false positives).
_SKIP_RECURSE = {"metadata", "links", "ipv4", "ipv6"}
_MAX_DEPTH = 5

# Candidate name templates used to resolve a config ``type`` discriminator to an
# OAS component schema name. First template that resolves to a non-empty schema
# wins. Interface sections bypass this via SECTION_TO_OAS_SCHEMA.
_CANDIDATE_TEMPLATES = (
    "{t}",
    "{t}Object",
    "{t}ObjectModel",
    "{t}Model",
    "FTD{t}",
    "I{t}",
    "IFP{t}",
    "FP{t}",
)

# Explicit API ``type`` value -> OAS component schema name for types that
# _CANDIDATE_TEMPLATES cannot resolve.  Keys are the exact ``type`` string
# returned by the FMC API.  Lookup tries an exact key first, then a
# case-insensitive fallback.
_TYPE_TO_OAS_SCHEMA: Dict[str, str] = {
    # ── Interfaces ──
    "LoopbackInterface":       "FTDLoopbackInterface",
    "PhysicalInterface":       "FTDPhysicalInterface",
    "EtherChannelInterface":   "FTDEtherChannelInterface",
    "SubInterface":            "FTDSubInterface",
    "VTIInterface":            "FTDVTIInterface",
    "InlineSet":               "InlineSet",
    "BridgeGroupInterface":    "FTDBridgeGroupInterface",
    # ── Routing ──
    # BGP General Settings
    "bgp_general_settings":    "BGPGeneralSettingModel",
    # BGP Policies
    "bgp":                     "BGPIPvAddressFamilyModel",
    # BFD Policies
    "BFDPolicy":               "BFDPolicyModel",
    # OSPFv2 Policies
    "OspfRoute":               "OspfPolicyModel",
    # OSPFv2 Interfaces
    "OspfInterface":           "OspfInterfacePolicyModel",
    # OSPFv3 Policies
    "ospfv3policy":            "Ospfv3PolicyModel",
    # OSPFv3 Interfaces
    "ospfv3interface":         "Ospfv3InterfacePolicyModel",
    # EIGRP Policies
    "EigrpRoute":              "EigrpPolicyModel",
    # PBR Policies
    "PolicyBasedRoutes":       "PBRPolicyModel",
    # IPv4 Static Routes
    "IPv4StaticRoute":         "IPv4StaticRouteModel",
    # IPv6 Static Routes
    "IPv6StaticRoute":         "IPv6StaticRouteModel",
    # ECMP Zones
    "ecmpzones":               "ECMPZoneModel",
    # VRFs
    "VirtualRouter":           "VirtualRouterModel",
    # ── Objects ──
    # Security Zones
    "SecurityZone":            "SecurityZoneObject",
    # Host
    "Host":                    "HostObject",
    # Range
    "Range":                   "RangeObject",
    # Network
    "Network":                 "NetworkObject",
    # FQDN
    "FQDN":                    "FQDNObject",
    # Group
    "NetworkGroup":            "NetworkGroup",
    # Port Objects
    "ProtocolPortObject":      "ProtocolPortObject",
    "PortObjectGroup":         "PortObjectGroup",
    # BFD Template
    "BFDTemplate":             "BFDTemplate",
    # AS Path
    "AsPathList":              "AsPathList",
    # Key Chain
    "KeyChain":                "KeyChainObject",
    # SLA Monitor
    "SLAMonitor":              "SLAMonitorObjectModel",
    # Community List (Community)
    "CommunityList":           "CommunityList",
    # Community List (Extended)
    "ExtendedCommunityList":   "ExtendedCommunityList",
    # IPv4 Prefix List
    "IPV4PrefixList":          "IPv4PrefixList",
    # IPv6 Prefix List
    "IPV6PrefixList":          "IPv6PrefixList",
    # Access List (Extended)
    "ExtendedAccessList":      "ExtendedAccessListModel",
    # Access List (Standard)
    "StandardAccessList":      "StandardACL",
    # Route Map
    "RouteMap":                "RouteMap",
    # IPv4 Pools
    "IPv4AddressPool":         "IPv4AddressPool",
    # IPv6 Pools
    "IPv6AddressPool":         "IPv6AddressPool",
    # MAC Address Pool
    "MacAddressPool":          "MacAddressPool",
}

# Explicit unsupported-field overrides for OAS inaccuracies.
# Each entry maps (schema_name, field_name) -> max_version_label.  The field is
# flagged as unsupported when the target OAS version is <= that label, even if
# the OAS document itself lists the property.
_FIELD_UNSUPPORTED_OVERRIDES: Dict[tuple, str] = {
    ("FTDVTIInterface", "enableSGTPropagate"):        "7.7",
    ("VirtualAccessInterface", "enableSGTPropagate"): "7.7",
}

# When inside a VRF routing block (routing.vrf_specific.<name>.*), some types
# resolve to VRF-specific OAS schemas that differ from the global variants.
_VRF_TYPE_OVERRIDES: Dict[str, str] = {
    "bgp":  "VrfBGPIPvAddressFamilyModel",
}


def _ref_name(ref: str) -> Optional[str]:
    """Extract the schema name from a $ref string.

    Supports both OpenAPI 3 ('#/components/schemas/X') and Swagger 2.0
    ('#/definitions/X') reference formats.
    """
    if isinstance(ref, str) and (
        ref.startswith("#/components/schemas/") or ref.startswith("#/definitions/")
    ):
        return ref.rsplit("/", 1)[-1]
    return None


class OasSchemaIndex:
    """Wraps an OAS ``components.schemas`` dict with prop lookup + name resolution."""

    def __init__(self, schemas: Dict[str, Any], version: str = ""):
        self.schemas = schemas or {}
        self.version = version
        self._version_weight = version_weight(version) if version else -1
        # case-insensitive name lookup for fuzzy resolution
        self._lc = {name.lower(): name for name in self.schemas}

    def is_field_unsupported(self, schema_name: str, field_name: str) -> bool:
        """Return True if an explicit override marks *field_name* unsupported."""
        max_ver = _FIELD_UNSUPPORTED_OVERRIDES.get((schema_name, field_name))
        if max_ver is None:
            return False
        return self._version_weight <= version_weight(max_ver)

    def _resolve_schema_obj(self, name: str) -> Optional[Dict[str, Any]]:
        s = self.schemas.get(name)
        return s if isinstance(s, dict) else None

    @lru_cache(maxsize=None)  # type: ignore[misc]
    def props(self, schema_name: str) -> Optional[Dict[str, Optional[str]]]:
        """Return {prop_name: child_schema_name_or_None} for a schema, or None.

        Handles ``allOf`` composition and resolves each property's ``$ref`` (or
        ``items.$ref``) to the child schema name for recursion.
        """
        schema = self._resolve_schema_obj(schema_name)
        if schema is None:
            return None
        out: Dict[str, Optional[str]] = {}

        def _merge(props_obj: Dict[str, Any]) -> None:
            for pname, pdef in (props_obj or {}).items():
                if not isinstance(pdef, dict):
                    out.setdefault(pname, None)
                    continue
                child = _ref_name(pdef.get("$ref") or "")
                if not child:
                    items = pdef.get("items")
                    if isinstance(items, dict):
                        child = _ref_name(items.get("$ref") or "")
                out[pname] = child

        if isinstance(schema.get("properties"), dict):
            _merge(schema["properties"])
        for part in (schema.get("allOf") or []):
            if isinstance(part, dict):
                ref = _ref_name(part.get("$ref") or "")
                if ref:
                    sub = self._resolve_schema_obj(ref) or {}
                    if isinstance(sub.get("properties"), dict):
                        _merge(sub["properties"])
                if isinstance(part.get("properties"), dict):
                    _merge(part["properties"])
        return out or None

    def resolve_name(self, type_name: Optional[str]) -> Optional[str]:
        """Resolve a config 'type' discriminator to an OAS component schema name."""
        if not type_name or not isinstance(type_name, str):
            return None
        # 1. Exact match.
        if type_name in self.schemas and self.props(type_name):
            return type_name
        # 2. Explicit mapping (covers abbreviations / naming mismatches).
        mapped = _TYPE_TO_OAS_SCHEMA.get(type_name) or _TYPE_TO_OAS_SCHEMA.get(type_name.lower())
        if mapped and self.props(mapped):
            return mapped
        # 3. Template-based fuzzy resolution.
        for tmpl in _CANDIDATE_TEMPLATES:
            cand = tmpl.format(t=type_name)
            actual = self.schemas.get(cand) and cand or self._lc.get(cand.lower())
            if actual and self.props(actual):
                return actual
        return None


class _OasValidator:
    def __init__(self, index: OasSchemaIndex):
        self.index = index
        self.issues: List[Issue] = []
        self._seq = 0

    def _resolve_with_overrides(
        self, type_val: Any, overrides: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """Resolve a type discriminator, checking *overrides* before the global map."""
        if not type_val or not isinstance(type_val, str):
            return None
        if overrides:
            mapped = overrides.get(type_val.lower())
            if mapped and self.index.props(mapped):
                return mapped
        return self.index.resolve_name(type_val)

    def validate_object(self, item: Dict[str, Any], schema_name: str, section: str,
                        pointer: List[Any], depth: int = 0) -> None:
        if depth > _MAX_DEPTH or not isinstance(item, dict):
            return
        props = self.index.props(schema_name)
        if not props:
            return
        allowed = set(props.keys())
        name = str(item.get("ifname") or item.get("name") or item.get("id") or "")
        for field, value in item.items():
            explicitly_unsupported = self.index.is_field_unsupported(schema_name, field)
            if explicitly_unsupported:
                self._seq += 1
                field_ptr = list(pointer) + [field]
                self.issues.append(Issue(
                    id=f"oas:{section}:{self._seq}",
                    category=CAT_FMC_FIELD,
                    severity=SEVERITY_WARNING,
                    message=f"Field '{field}' on {schema_name} is unsupported in "
                            f"FMC v{self.index.version} (known OAS inaccuracy).",
                    section=section,
                    type=schema_name,
                    item_name=name,
                    field=_ptr_to_str(field_ptr),
                    current_value=_summarize(value),
                    proposed_action=f"Remove field '{field}'",
                    auto_fixable=True,
                    fix={"op": "remove_field_path", "pointer": field_ptr},
                ))
                continue
            if field in _META_FIELDS or field in allowed:
                pass
            else:
                self._seq += 1
                field_ptr = list(pointer) + [field]
                self.issues.append(Issue(
                    id=f"oas:{section}:{self._seq}",
                    category=CAT_FMC_FIELD,
                    severity=SEVERITY_WARNING,
                    message=f"Field '{field}' on {schema_name} is not present in the target "
                            f"FMC OAS schema (v{self.index.version}); it is unsupported or "
                            f"deprecated in this version.",
                    section=section,
                    type=schema_name,
                    item_name=name,
                    field=_ptr_to_str(field_ptr),
                    current_value=_summarize(value),
                    proposed_action=f"Remove field '{field}'",
                    auto_fixable=True,
                    fix={"op": "remove_field_path", "pointer": field_ptr},
                ))
                continue
            # Recurse into child objects/arrays with a known schema ref.
            if field in _SKIP_RECURSE:
                continue
            child_schema = props.get(field)
            if not child_schema:
                continue
            child_ptr = list(pointer) + [field]
            if isinstance(value, dict):
                self.validate_object(value, child_schema, section, child_ptr, depth + 1)
            elif isinstance(value, list):
                for i, it in enumerate(value):
                    if isinstance(it, dict):
                        self.validate_object(it, child_schema, section, child_ptr + [i], depth + 1)

    def walk_typed(self, obj: Any, section: str, pointer: List[Any],
                    depth: int = 0, *,
                    type_overrides: Optional[Dict[str, str]] = None) -> None:
        if depth > _MAX_DEPTH:
            return
        if isinstance(obj, dict):
            schema_name = self._resolve_with_overrides(
                obj.get("type"), type_overrides,
            )
            if schema_name:
                self.validate_object(obj, schema_name, section, pointer, depth)
            else:
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        self.walk_typed(v, section, list(pointer) + [k],
                                        depth + 1, type_overrides=type_overrides)
        elif isinstance(obj, list):
            for i, it in enumerate(obj):
                self.walk_typed(it, section, list(pointer) + [i],
                                depth + 1, type_overrides=type_overrides)


def validate_oas_schema(config: Dict[str, Any], index: Optional[OasSchemaIndex]) -> List[Issue]:
    """Return field-name issues for the config against the target FMC OAS schema."""
    if not index:
        return []
    v = _OasValidator(index)

    # Interface sections use the known OAS schema even if the 'type' attr differs.
    for section in INTERFACE_SECTIONS:
        items = config.get(section)
        if not isinstance(items, list):
            continue
        schema_name = SECTION_TO_OAS_SCHEMA.get(section)
        if not schema_name:
            continue
        if not index.props(schema_name):
            # Fall back to fuzzy resolution (e.g. Swagger 2.0 7.0 uses
            # 'FPPhysicalInterface' rather than 'FTDPhysicalInterface').
            generic = schema_name[3:] if schema_name.startswith("FTD") else schema_name
            schema_name = index.resolve_name(generic) or ""
            if not schema_name:
                continue
        for idx, item in enumerate(items):
            if isinstance(item, dict):
                v.validate_object(item, schema_name, section, [section, idx])

    # Routing + objects: discover typed objects generically.
    routing = config.get("routing")
    if isinstance(routing, dict):
        # Walk non-VRF routing sections with default type mappings.
        for rkey, rval in routing.items():
            if rkey == "vrf_specific":
                continue
            if isinstance(rval, (dict, list)):
                v.walk_typed(rval, "routing", ["routing", rkey])
        # VRF-specific sections use VRF type overrides.
        vrf_block = routing.get("vrf_specific")
        if isinstance(vrf_block, dict):
            for vrf_name, vrf_data in vrf_block.items():
                if isinstance(vrf_data, (dict, list)):
                    v.walk_typed(
                        vrf_data, "routing",
                        ["routing", "vrf_specific", vrf_name],
                        type_overrides=_VRF_TYPE_OVERRIDES,
                    )
    for section in ("objects",):
        block = config.get(section)
        if isinstance(block, (dict, list)):
            v.walk_typed(block, section, [section])

    return v.issues


def _ptr_to_str(pointer: List[Any]) -> str:
    out = ""
    for p in pointer:
        if isinstance(p, int):
            out += f"[{p}]"
        else:
            out = f"{out}.{p}" if out else str(p)
    return out


def _summarize(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return f"<{type(value).__name__} len={len(value)}>"
    return value
