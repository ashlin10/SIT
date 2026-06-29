"""Data models for the pre-push validation engine.

These are plain dataclasses that serialize to JSON-friendly dicts via ``to_dict``
so they can be returned directly from the FastAPI endpoints and consumed by the
frontend review panel.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Severity ordering used for sorting / summary counts.
SEVERITY_BLOCKING = "blocking"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

_SEVERITY_RANK = {SEVERITY_BLOCKING: 0, SEVERITY_WARNING: 1, SEVERITY_INFO: 2}


# Issue categories (drives grouping + icons in the UI).
CAT_INTERFACE = "interface"          # interface name conflict
CAT_MODEL_FIELD = "model_field"      # field/value unsupported on target FTD model/version
CAT_MODEL_TYPE = "model_type"        # whole interface type unsupported on target model
CAT_FMC_FIELD = "fmc_field"          # field unsupported/deprecated in target FMC schema
CAT_ROUTING = "routing"              # routing capability (e.g. VRF) unsupported
CAT_META = "meta"                    # informational (could not resolve model/version, etc.)


@dataclass
class Issue:
    """A single detected validation problem and its proposed remediation."""

    id: str
    category: str
    severity: str
    message: str
    section: str = ""                 # YAML section key, e.g. "physical_interfaces"
    type: str = ""                    # interface/object type involved
    item_name: str = ""               # name of the offending item
    field: str = ""                   # offending field path within the item
    current_value: Any = None
    proposed_action: str = ""         # human readable action, e.g. "Remove field 'LLDP'"
    auto_fixable: bool = True         # whether the sanitizer can resolve this automatically
    fix: Optional[Dict[str, Any]] = None  # machine-readable directive for the sanitizer

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "section": self.section,
            "type": self.type,
            "itemName": self.item_name,
            "field": self.field,
            "currentValue": self.current_value,
            "proposedAction": self.proposed_action,
            "autoFixable": self.auto_fixable,
        }


@dataclass
class InterfaceConflict:
    """A source-referenced hardware interface that does not exist on the target."""

    source_name: str
    referenced_in: List[str] = field(default_factory=list)   # human readable paths
    available_targets: List[str] = field(default_factory=list)
    suggested_target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sourceName": self.source_name,
            "referencedIn": self.referenced_in,
            "availableTargets": self.available_targets,
            "suggestedTarget": self.suggested_target,
        }


@dataclass
class TargetInfo:
    """Resolved target device metadata used for the validation."""

    device_id: str = ""
    device_name: str = ""
    raw_model: str = ""
    raw_version: str = ""
    fmc_version: str = ""
    resolved_sku: Optional[str] = None
    resolved_model_label: Optional[str] = None
    resolved_ftl_branch: Optional[str] = None
    model_schema_found: bool = False
    fmc_schema_found: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deviceId": self.device_id,
            "deviceName": self.device_name,
            "rawModel": self.raw_model,
            "rawVersion": self.raw_version,
            "fmcVersion": self.fmc_version,
            "resolvedSku": self.resolved_sku,
            "resolvedModelLabel": self.resolved_model_label,
            "resolvedFtlBranch": self.resolved_ftl_branch,
            "modelSchemaFound": self.model_schema_found,
            "fmcSchemaFound": self.fmc_schema_found,
        }


@dataclass
class ValidationReport:
    """Full report for a single target device."""

    target: TargetInfo
    issues: List[Issue] = field(default_factory=list)
    interface_conflicts: List[InterfaceConflict] = field(default_factory=list)

    def add(self, issue: Issue) -> None:
        self.issues.append(issue)

    @property
    def counts(self) -> Dict[str, int]:
        c = {SEVERITY_BLOCKING: 0, SEVERITY_WARNING: 0, SEVERITY_INFO: 0}
        for i in self.issues:
            c[i.severity] = c.get(i.severity, 0) + 1
        # interface conflicts are blocking until mapped
        c[SEVERITY_BLOCKING] += len(self.interface_conflicts)
        return c

    def sorted_issues(self) -> List[Issue]:
        return sorted(self.issues, key=lambda i: (_SEVERITY_RANK.get(i.severity, 9), i.section, i.item_name))

    @staticmethod
    def _strip_indices(path: str) -> str:
        """Remove array indices from a dotted path for grouping.

        e.g. 'routing.ospfv3_interfaces[0].properties.enableBFD'
          -> 'routing.ospfv3_interfaces.properties.enableBFD'
        """
        return re.sub(r"\[\d+\]", "", path)

    def _deduped_issues(self) -> List[Dict[str, Any]]:
        """Group identical issues by message + generic field path, adding count."""
        seen: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        for issue in self.sorted_issues():
            generic_field = self._strip_indices(issue.field)
            key = f"{issue.severity}|{issue.section}|{issue.type}|{generic_field}|{issue.message}"
            if key in seen:
                seen[key]["count"] += 1
                seen[key]["_ids"].append(issue.id)
                seen[key]["_fields"].append(issue.field)
            else:
                d = issue.to_dict()
                d["field"] = generic_field
                d["count"] = 1
                d["_ids"] = [issue.id]
                d["_fields"] = [issue.field]
                seen[key] = d
                order.append(key)
        result = []
        for key in order:
            entry = seen[key]
            entry["groupIds"] = entry.pop("_ids")
            entry["groupFields"] = entry.pop("_fields")
            result.append(entry)
        return result

    def to_dict(self) -> Dict[str, Any]:
        deduped = self._deduped_issues()
        # Counts reflect the deduped (grouped) issue count, not raw totals.
        c = {SEVERITY_BLOCKING: 0, SEVERITY_WARNING: 0, SEVERITY_INFO: 0}
        for d in deduped:
            sev = d.get("severity", SEVERITY_INFO)
            c[sev] = c.get(sev, 0) + 1
        c[SEVERITY_BLOCKING] += len(self.interface_conflicts)
        return {
            "target": self.target.to_dict(),
            "issues": deduped,
            "interfaceConflicts": [c.to_dict() for c in self.interface_conflicts],
            "counts": c,
            "hasBlocking": c.get(SEVERITY_BLOCKING, 0) > 0,
        }
