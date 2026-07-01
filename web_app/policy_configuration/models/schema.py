"""Data models for the FMC policy replication feature.

These are intentionally lightweight (dataclasses + plain dicts) so they can be
serialized to/from JSON for the API layer and to/from YAML for the
``policy.accesspolicies`` document without an extra mapping layer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Secret redaction ──

_SECRET_KEYS = {
    "password", "passwd", "secret", "token", "x-auth-access-token",
    "x-auth-refresh-token", "authorization", "auth", "apikey", "api_key",
    "preSharedKey", "pre_shared_key",
}


def redact(obj: Any) -> Any:
    """Return a deep copy of *obj* with secret-looking values masked.

    Used before logging any payload/headers so passwords, tokens and
    authorization headers never reach the terminal/log stream.
    """
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _SECRET_KEYS:
                out[k] = "***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def normalize_name(name: Optional[str]) -> str:
    """Normalize an object/policy name for safe identity matching.

    Lower-cases and collapses whitespace. We deliberately do NOT strip
    punctuation because FMC treats names as significant; this only guards
    against trivial case/whitespace differences.
    """
    if not name:
        return ""
    return re.sub(r"\s+", " ", str(name).strip()).lower()


# ── FMC metadata (source + target) ──

@dataclass
class FmcMetadata:
    host: str = ""
    domain_uuid: str = ""
    domain_name: str = ""
    version: str = ""
    build: str = ""
    model: str = ""
    status: str = "disconnected"  # connected | disconnected | error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "domain_uuid": self.domain_uuid,
            "domain_name": self.domain_name,
            "version": self.version,
            "build": self.build,
            "model": self.model,
            "status": self.status,
        }


# ── Dependency reference (object referenced by a rule/policy/setting) ──

@dataclass
class DependencyRef:
    """A reference to a dependent FMC object discovered while walking an ACP."""
    type: str
    name: str = ""
    source_id: str = ""
    # Populated during resolution against the target FMC:
    target_id: str = ""
    action: str = "pending"  # create | reuse | override | conflict | unresolved
    # How a reused/matched target object was identified (name | value | id).
    match_method: str = ""

    @property
    def key(self) -> str:
        return f"{self.type}::{normalize_name(self.name) or self.source_id}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "name": self.name,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "action": self.action,
            "match_method": self.match_method,
        }


# ── Assigned policy (Prefilter / Decryption / SI / Identity / AI Defense) ──

@dataclass
class AssignedPolicy:
    category: str          # prefilterPolicy | decryptionPolicy | ...
    type: str = ""         # FMC schema type (PrefilterPolicy, ...)
    name: str = ""
    source_id: str = ""
    supported: bool = True  # False when target FMC version lacks this category

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "type": self.type,
            "name": self.name,
            "source_id": self.source_id,
            "supported": self.supported,
        }


# ── Access Control Policy ──

# Base-payload keys that reference an assigned policy, by UI category. Used to
# derive in-memory assigned-policy state from a faithful raw ACP payload (both
# after a live fetch and after a YAML round-trip).
_ASSIGNED_BASE_KEYS: Dict[str, List[str]] = {
    "prefilterPolicy": ["prefilterPolicySetting", "prefilterPolicy"],
    "decryptionPolicy": ["decryptionPolicySetting", "sslPolicy", "decryptionPolicy"],
    "identityPolicy": ["identityPolicySetting", "identityPolicy"],
    "securityIntelligencePolicy": ["securityIntelligencePolicySetting",
                                   "securityIntelligencePolicy", "securityIntelligence"],
}

# Setting keys surfaced in the ACP base, mapped to the label used for the UI.
_SETTING_BASE_KEYS: Dict[str, str] = {
    "elephantFlowSettings": "ElephantFlowSettings",
    "shadowTrafficSetting": "ShadowTrafficSetting",
    "eveSetting": "EVESetting",
    "loggingSetting": "LoggingSetting",
    "advancedLoggingSetting": "AdvancedLoggingSetting",
    "loggingSettings": "LoggingSetting",
}


def _ref_view(ref: Any) -> Dict[str, str]:
    """Extract {name,type,id} from an assigned-policy reference (may be wrapped)."""
    if not isinstance(ref, dict):
        return {}
    pol = ref.get("policy") if isinstance(ref.get("policy"), dict) else ref
    name = pol.get("name") or ref.get("name") or ""
    ptype = pol.get("type") or ref.get("type") or ""
    sid = pol.get("id") or ref.get("id") or ""
    if not (name or sid):
        return {}
    return {"name": str(name), "type": str(ptype), "id": str(sid)}


@dataclass
class AcpModel:
    name: str
    source_id: str = ""
    # Faithful raw ACP base payload (FMC JSON minus 'links'/'metadata'/'rules').
    # This is what gets serialized to YAML verbatim (plus embedded accessrules);
    # no synthetic fields are added.
    raw_base: Dict[str, Any] = field(default_factory=dict)
    access_rules: List[Dict[str, Any]] = field(default_factory=list)
    # ── Derived, in-memory only (NOT serialized) — used by push + the UI. ──
    default_action: Dict[str, Any] = field(default_factory=dict)
    inheritance_settings: Dict[str, Any] = field(default_factory=dict)
    assigned_policies: Dict[str, AssignedPolicy] = field(default_factory=dict)
    settings: Dict[str, Any] = field(default_factory=dict)
    unsupported_settings: List[str] = field(default_factory=list)
    fetched: bool = False
    fetch_error: str = ""

    def rule_count(self) -> int:
        return len(self.access_rules)

    def derive_from_raw(self) -> None:
        """Populate the in-memory derived fields from ``raw_base``.

        Keeps push/UI logic working off the same faithful payload that is
        written to YAML, with no duplicated/synthetic state on disk.
        """
        raw = self.raw_base or {}
        if not self.name:
            self.name = str(raw.get("name", ""))
        if not self.source_id:
            self.source_id = str(raw.get("id", ""))
        self.default_action = dict(raw.get("defaultAction") or {})
        self.inheritance_settings = dict(raw.get("inheritanceSettings") or {})
        assigned: Dict[str, AssignedPolicy] = {}
        for cat, keys in _ASSIGNED_BASE_KEYS.items():
            for k in keys:
                view = _ref_view(raw.get(k))
                if view:
                    assigned[cat] = AssignedPolicy(
                        category=cat, type=view["type"], name=view["name"],
                        source_id=view["id"],
                    )
                    break
        self.assigned_policies = assigned
        settings: Dict[str, Any] = {}
        for k, label in _SETTING_BASE_KEYS.items():
            v = raw.get(k)
            if isinstance(v, dict) and v:
                settings[label] = v
        self.settings = settings

    def to_yaml_dict(self) -> Dict[str, Any]:
        """Faithful JSON->YAML view: the raw base payload + embedded rules."""
        doc: Dict[str, Any] = dict(self.raw_base)
        doc["accessrules"] = self.access_rules
        return doc

    @classmethod
    def from_yaml_dict(cls, d: Dict[str, Any]) -> "AcpModel":
        raw = {k: v for k, v in d.items() if k != "accessrules"}
        acp = cls(
            name=str(d.get("name", "")),
            source_id=str(d.get("id", "")),
            raw_base=raw,
            access_rules=list(d.get("accessrules") or []),
            fetched=True,
        )
        acp.derive_from_raw()
        return acp

    def to_summary(self) -> Dict[str, Any]:
        """Lightweight representation for UI rows / expanded detail."""
        return {
            "name": self.name,
            "source_id": self.source_id,
            "fetched": self.fetched,
            "fetch_error": self.fetch_error,
            "rule_count": self.rule_count(),
            "assigned_policies": {c: ap.to_dict() for c, ap in self.assigned_policies.items()},
            "settings_keys": sorted(self.settings.keys()),
            "settings": self.settings,
            "unsupported_settings": sorted(self.unsupported_settings),
            "default_action": self.default_action,
        }


# ── Full policy configuration (one or more ACPs + shared objects) ──

# Ordered list of dependent-policy YAML subsections (one per policy type).
POLICY_SUBSECTIONS: List[str] = [
    "prefilter_policies",
    "security_intelligence_policies",
    "identity_policies",
    "decryption_policies",
    "file_policies",
    "intrusion_policies",
]


@dataclass
class PolicyConfig:
    acps: List[AcpModel] = field(default_factory=list)
    # Dependent policies grouped by YAML subsection name (faithful payloads).
    policies: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    # Flat list of faithful dependent-object payloads (serialized into the
    # nested ``objects`` block; matches the Device Configuration convention).
    objects: List[Dict[str, Any]] = field(default_factory=list)
    # In-memory provenance only — NOT serialized to the source YAML.
    meta: Dict[str, Any] = field(default_factory=dict)

    def get_acp(self, name: str) -> Optional[AcpModel]:
        nn = normalize_name(name)
        for a in self.acps:
            if normalize_name(a.name) == nn:
                return a
        return None

    def upsert_acp(self, acp: AcpModel) -> None:
        nn = normalize_name(acp.name)
        for i, a in enumerate(self.acps):
            if normalize_name(a.name) == nn:
                self.acps[i] = acp
                return
        self.acps.append(acp)

    def upsert_objects(self, objs: List[Dict[str, Any]]) -> None:
        """Merge objects, deduplicating by id (fallback type+name)."""
        index = {self._obj_key(o): i for i, o in enumerate(self.objects)}
        for o in objs or []:
            if not isinstance(o, dict):
                continue
            k = self._obj_key(o)
            if k in index:
                self.objects[index[k]] = o
            else:
                index[k] = len(self.objects)
                self.objects.append(o)

    def upsert_policies(self, subsection: str, items: List[Dict[str, Any]]) -> None:
        """Merge dependent policies into *subsection*, deduplicating by id."""
        cur = self.policies.setdefault(subsection, [])
        seen = {str(p.get("id")) for p in cur if isinstance(p, dict) and p.get("id")}
        seen_names = {normalize_name(p.get("name")) for p in cur if isinstance(p, dict)}
        for it in items or []:
            if not isinstance(it, dict):
                continue
            oid = str(it.get("id") or "")
            nn = normalize_name(it.get("name"))
            if (oid and oid in seen) or (not oid and nn and nn in seen_names):
                continue
            cur.append(it)
            if oid:
                seen.add(oid)
            if nn:
                seen_names.add(nn)

    @staticmethod
    def _obj_key(o: Dict[str, Any]) -> str:
        oid = str(o.get("id") or "")
        if oid:
            return f"id::{oid}"
        return f"{o.get('type', '')}::{normalize_name(o.get('name'))}"

    def to_yaml_doc(self) -> Dict[str, Any]:
        """Build the flat, Device-Configuration-style source document.

        Faithful JSON->YAML: ACPs (with embedded ``accessrules``), the six
        dependent-policy subsections, and a nested ``objects`` block. No
        synthetic/migration fields are added.
        """
        doc: Dict[str, Any] = {}
        doc["access_policies"] = [a.to_yaml_dict() for a in self.acps]
        for key in POLICY_SUBSECTIONS:
            items = self.policies.get(key)
            if items:
                doc[key] = sorted(items, key=lambda p: normalize_name(p.get("name", "")))
        if self.objects:
            doc["objects"] = build_objects_block(self.objects)
        return doc


# ── Object categorization (Device-Configuration nested layout) ──

# FMC object type -> (top_key, sub_key|None) within the ``objects`` block.
# Network/Port/Interface categories mirror the Device Configuration workflow
# exactly; ACP-specific types use sibling snake_case keys.
_OBJECT_CATEGORY: Dict[str, tuple] = {
    "Host": ("network", "hosts"),
    "Range": ("network", "ranges"),
    "Network": ("network", "networks"),
    "FQDN": ("network", "fqdns"),
    "NetworkGroup": ("network", "groups"),
    "ProtocolPortObject": ("port", "objects"),
    "PortObjectGroup": ("port", "groups"),
    "AnyProtocolPortObject": ("port", "any"),
    "SecurityZone": ("interface", "security_zones"),
    "InterfaceGroup": ("interface", "interface_groups"),
    "ICMPV4Object": ("icmpv4", None),
    "ICMPV6Object": ("icmpv6", None),
    "Url": ("urls", None),
    "UrlGroup": ("url_groups", None),
    "URLCategory": ("url_categories", None),
    "Application": ("applications", None),
    "ApplicationFilter": ("application_filters", None),
    "VlanTag": ("vlan_tags", None),
    "VlanGroupTag": ("vlan_groups", None),
    "SecurityGroupTag": ("security_group_tags", None),
    "ISESecurityGroupTag": ("ise_security_group_tags", None),
    "EndPointDeviceType": ("endpoint_device_types", None),
    "ContinentObject": ("continents", None),
    "CountryObject": ("countries", None),
    "GeolocationObject": ("geolocations", None),
    "SecurityIntelligence": ("security_intelligence", None),
    "SIURLList": ("si_url_lists", None),
    "SIURLFeed": ("si_url_feeds", None),
    "DNSServerGroup": ("dns_server_groups", None),
    "SLAMonitor": ("sla_monitors", None),
    "TimeRange": ("time_ranges", None),
    "TimeZoneObject": ("time_zone_objects", None),
    "VariableSet": ("variable_sets", None),
    "SnmpAlert": ("snmp_alerts", None),
    "SyslogAlert": ("syslog_alerts", None),
}


def object_category(obj_type: str) -> tuple:
    """Return (top_key, sub_key|None) for *obj_type* (snake_case fallback)."""
    if obj_type in _OBJECT_CATEGORY:
        return _OBJECT_CATEGORY[obj_type]
    return (_snake(obj_type or "other"), None)


def _snake(name: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", str(name))
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower()


def build_objects_block(objects: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Group a flat object list into the nested DC-style ``objects`` block.

    Deduplicates by id within each category and sorts deterministically.
    """
    block: Dict[str, Any] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        top, sub = object_category(obj.get("type", ""))
        if sub is None:
            block.setdefault(top, []).append(obj)
        else:
            block.setdefault(top, {}).setdefault(sub, []).append(obj)

    def _dedup_sort(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        out: List[Dict[str, Any]] = []
        for it in sorted(items, key=lambda o: normalize_name(o.get("name", ""))):
            oid = str(it.get("id") or "")
            key = oid or f"{it.get('type','')}::{normalize_name(it.get('name'))}"
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    result: Dict[str, Any] = {}
    for top in sorted(block.keys()):
        val = block[top]
        if isinstance(val, list):
            result[top] = _dedup_sort(val)
        else:
            result[top] = {sub: _dedup_sort(lst) for sub, lst in sorted(val.items())}
    return result


def ungroup_objects(block: Any) -> List[Dict[str, Any]]:
    """Flatten a nested ``objects`` block back to a flat object list.

    Walks the structure generically so both nested (network.hosts) and flat
    (applications) categories are recovered.
    """
    flat: List[Dict[str, Any]] = []

    def _walk(node: Any) -> None:
        if isinstance(node, list):
            for it in node:
                if isinstance(it, dict) and it.get("type"):
                    flat.append(it)
                else:
                    _walk(it)
        elif isinstance(node, dict):
            for v in node.values():
                _walk(v)

    _walk(block)
    return flat


# ── Resolution plan (output of the dependency resolver) ──

@dataclass
class ResolutionPlan:
    to_create: List[DependencyRef] = field(default_factory=list)
    to_reuse: List[DependencyRef] = field(default_factory=list)
    to_override: List[DependencyRef] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    unresolved: List[Dict[str, Any]] = field(default_factory=list)
    cycles: List[List[str]] = field(default_factory=list)
    # Ordered dependency levels (each a list of DependencyRef keys).
    levels: List[List[str]] = field(default_factory=list)

    @property
    def has_blocking(self) -> bool:
        return bool(self.conflicts or self.unresolved or self.cycles)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "to_create": [r.to_dict() for r in self.to_create],
            "to_reuse": [r.to_dict() for r in self.to_reuse],
            "to_override": [r.to_dict() for r in self.to_override],
            "conflicts": self.conflicts,
            "unresolved": self.unresolved,
            "cycles": self.cycles,
            "levels": self.levels,
            "has_blocking": self.has_blocking,
        }


# ── Final push summary ──

@dataclass
class PushSummary:
    successful_acps: List[str] = field(default_factory=list)
    failed_acps: List[Dict[str, str]] = field(default_factory=list)
    objects_created: List[str] = field(default_factory=list)
    objects_reused: List[str] = field(default_factory=list)
    objects_unresolved: List[str] = field(default_factory=list)
    policies_overridden: List[str] = field(default_factory=list)
    skipped_settings: List[str] = field(default_factory=list)
    validation_errors: List[Dict[str, Any]] = field(default_factory=list)
    validation_warnings: List[Dict[str, Any]] = field(default_factory=list)
    partial_changes: List[str] = field(default_factory=list)
    # Access-rule outcomes (per rule).
    rules_pushed: List[Dict[str, Any]] = field(default_factory=list)
    rules_failed: List[Dict[str, Any]] = field(default_factory=list)
    rules_skipped: List[Dict[str, Any]] = field(default_factory=list)
    dropped_references: List[Dict[str, Any]] = field(default_factory=list)
    # Rule-push strategy outcome (bulk vs per-rule fallback).
    per_rule_fallback_enabled: bool = False
    bulk_failed: bool = False
    fallback_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "successful_acps": self.successful_acps,
            "failed_acps": self.failed_acps,
            "objects_created": self.objects_created,
            "objects_reused": self.objects_reused,
            "objects_unresolved": self.objects_unresolved,
            "policies_overridden": self.policies_overridden,
            "skipped_settings": self.skipped_settings,
            "validation_errors": self.validation_errors,
            "validation_warnings": self.validation_warnings,
            "partial_changes": self.partial_changes,
            "rules_pushed": self.rules_pushed,
            "rules_failed": self.rules_failed,
            "rules_skipped": self.rules_skipped,
            "dropped_references": self.dropped_references,
            "per_rule_fallback_enabled": self.per_rule_fallback_enabled,
            "bulk_failed": self.bulk_failed,
            "fallback_used": self.fallback_used,
        }
