"""Deterministic YAML (de)serialization for the policy configuration model.

The source document is a *faithful JSON->YAML* conversion of the FMC payloads
and follows the flat, Device-Configuration-style layout::

    access_policies:
      - id: ...
        name: <ACP>
        defaultAction: { ... }
        prefilterPolicySetting: { ... }
        accessrules: [ ... ]              # raw rule payloads
    prefilter_policies: [ ... ]            # full dependent-policy payloads
    security_intelligence_policies: [ ... ]
    identity_policies: [ ... ]
    decryption_policies: [ ... ]
    file_policies: [ ... ]
    intrusion_policies: [ ... ]
    objects:                               # Device Configuration object layout
      network: { hosts: [...], ranges: [...], networks: [...], ... }
      port: { objects: [...] }
      applications: [ ... ]
      ...

The build is deterministic (stable ordering) so repeated fetches do not produce
noisy diffs. Parsing validates required structure and raises ``StructureError``
with an actionable message rather than an unhandled exception. A legacy
``policy:``-wrapped document is still accepted for backward compatibility.
"""
from __future__ import annotations

from typing import Any, Dict, List

import yaml

from ..models.schema import (
    AcpModel, PolicyConfig, POLICY_SUBSECTIONS, normalize_name, ungroup_objects,
)


class StructureError(ValueError):
    """Raised when an uploaded/parsed policy document is structurally invalid."""

    def __init__(self, message: str, errors: List[str] | None = None):
        super().__init__(message)
        self.errors = errors or [message]


# Prefer C-accelerated loader/dumper when available (5-10× faster on large files).
_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_Dumper = getattr(yaml, "CSafeDumper", yaml.SafeDumper)


def build_yaml(config: PolicyConfig) -> str:
    """Serialize a PolicyConfig to a deterministic YAML string."""
    doc = config.to_yaml_doc()
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True)


def parse_yaml(text: str) -> PolicyConfig:
    """Parse YAML text into a PolicyConfig, validating structure first."""
    try:
        doc = yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as e:
        raise StructureError(f"Invalid YAML: {e}")
    if not isinstance(doc, dict):
        raise StructureError("Top-level YAML must be a mapping")
    doc = _unwrap_legacy(doc)
    validate_structure(doc)
    return _from_doc(doc)


def _unwrap_legacy(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a legacy ``policy:``-wrapped document to the flat layout."""
    if "access_policies" in doc:
        return doc
    policy = doc.get("policy")
    if isinstance(policy, dict):
        flat: Dict[str, Any] = {}
        flat["access_policies"] = policy.get("accesspolicies") or policy.get("access_policies") or []
        dep = policy.get("dependentObjects")
        if isinstance(dep, dict):
            flat["objects"] = dep
        elif isinstance(policy.get("objects"), list):
            # legacy flat object list -> wrap so ungroup_objects can read it
            flat["objects"] = {"_legacy": policy["objects"]}
        for key in POLICY_SUBSECTIONS:
            if isinstance(policy.get(key), list):
                flat[key] = policy[key]
        return flat
    return doc


def _from_doc(doc: Dict[str, Any]) -> PolicyConfig:
    cfg = PolicyConfig()
    # Preserve source FMC metadata (provenance) when present.
    meta_block = doc.get("metadata")
    if isinstance(meta_block, dict) and meta_block.get("source_fmc"):
        cfg.meta["source_fmc"] = meta_block["source_fmc"]
    for a in doc.get("access_policies") or []:
        if isinstance(a, dict):
            cfg.acps.append(AcpModel.from_yaml_dict(a))
    for key in POLICY_SUBSECTIONS:
        items = doc.get(key)
        if isinstance(items, list):
            cfg.policies[key] = [p for p in items if isinstance(p, dict)]
    obj_block = doc.get("objects")
    if obj_block:
        cfg.objects = ungroup_objects(obj_block)
    return cfg


def validate_structure(doc: Dict[str, Any]) -> List[str]:
    """Validate required sections/types/duplicates.

    Returns a list of *warnings*. Raises ``StructureError`` (aggregating all
    blocking problems) when the document cannot be used.
    """
    errors: List[str] = []
    warnings: List[str] = []

    acps = doc.get("access_policies")
    if acps is None:
        raise StructureError("Missing required top-level 'access_policies' list",
                             ["Missing 'access_policies'"])
    if not isinstance(acps, list):
        raise StructureError("'access_policies' must be a list")

    seen_names: set = set()
    for i, acp in enumerate(acps):
        loc = f"access_policies[{i}]"
        if not isinstance(acp, dict):
            errors.append(f"{loc}: each ACP must be a mapping")
            continue
        name = acp.get("name")
        if not name or not str(name).strip():
            errors.append(f"{loc}: ACP is missing a 'name'")
            continue
        nn = normalize_name(name)
        if nn in seen_names:
            errors.append(f"{loc}: duplicate ACP name '{name}'")
        seen_names.add(nn)

        rules = acp.get("accessrules", [])
        if rules is not None and not isinstance(rules, list):
            errors.append(f"{loc}.accessrules: must be a list")

    # Dependent policy subsections must be lists when present.
    for key in POLICY_SUBSECTIONS:
        val = doc.get(key)
        if val is not None and not isinstance(val, list):
            errors.append(f"'{key}': must be a list")

    # Objects block must be a mapping (nested DC-style layout) when present.
    obj_block = doc.get("objects")
    if obj_block is not None:
        if not isinstance(obj_block, dict):
            errors.append("'objects': must be a mapping of categories")
        else:
            for obj in ungroup_objects(obj_block):
                if not obj.get("type"):
                    errors.append("objects: an entry is missing 'type'")
                elif not obj.get("name") and not obj.get("id"):
                    warnings.append("objects: an entry has neither 'name' nor 'id'")

    if errors:
        raise StructureError(
            f"Policy document has {len(errors)} structural problem(s)", errors
        )
    return warnings
