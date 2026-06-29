"""Resolve FMC-reported model/version strings into schema identifiers.

FMC reports device models as free-form strings such as:
    "Cisco Firepower 4145 Threat Defense"
    "Cisco Secure Firewall 3120 Threat Defense"
    "Cisco Firepower Threat Defense for VMware"
    "Cisco Firepower 1010 Threat Defense"
    "Cisco ISA3000 Threat Defense"

This module maps those into a model_schemas SKU, a model-schema version label,
and an ftl-schema branch. All resolvers degrade gracefully (return ``None``)
when no confident match is found.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

from .schema_loader import (
    MODEL_VERSION_LABELS,
    SKU_FAMILY,
    VERSIONS,
    version_weight,
)

_VIRTUAL_HINTS = ("vmware", "kvm", "azure", " aws", "amazon", "vsphere", "virtual",
                  "hyper-v", "hyperv", "openstack", "gcp", "oci", "nutanix", "ftdv", "vftd")

# Known numeric SKUs sorted longest-first so e.g. "1010" matches before "10".
_NUMERIC_SKUS = sorted(
    {sku for sku in SKU_FAMILY if sku[:1].isdigit()},
    key=lambda s: (-len(re.sub(r"\D", "", s)), s),
)


def resolve_sku(model_string: str) -> Optional[str]:
    """Map an FMC model string to a model_schemas SKU (or None if unknown)."""
    if not model_string:
        return None
    s = model_string.strip().lower()

    # Virtual / cloud variants
    if any(h in s for h in _VIRTUAL_HINTS):
        return "FTDv"

    # ISA 3000 industrial appliance
    if "isa" in s and "3000" in s:
        return "ISA3000"

    # Extract numeric runs from the string and match against known SKUs.
    digit_runs = re.findall(r"\d{3,4}", model_string)
    # Prefer 4-digit then 3-digit matches.
    for run in sorted(set(digit_runs), key=lambda r: (-len(r), r)):
        if run in SKU_FAMILY:
            return run
        # Some SKUs have suffixes (1010E, 1210CP); match the numeric base.
        for sku in _NUMERIC_SKUS:
            base = re.sub(r"\D", "", sku)
            if base == run:
                return run if run in SKU_FAMILY else sku
    return None


def resolve_model_label(sw_version: str) -> Optional[str]:
    """Map an FTD software version to the closest available model-schema label.

    Picks the highest available label that is <= the requested version. If the
    version is older than everything available, returns the lowest label.
    """
    target = _clean_version(sw_version)
    if not target:
        return None
    tw = version_weight(target)
    if tw < 0:
        return None
    # Exact match first.
    if target in MODEL_VERSION_LABELS:
        return target
    # Highest label <= target.
    candidates = [(version_weight(l), l) for l in MODEL_VERSION_LABELS]
    le = [c for c in candidates if c[0] <= tw]
    if le:
        return max(le, key=lambda c: c[0])[1]
    # Older than everything -> lowest available.
    return min(candidates, key=lambda c: c[0])[1]


# Point-release branches that should only match their exact version.
# For any other patch version within the same major.minor, prefer the
# general branch instead.  E.g. 7.4.8 should use IMS_7_4_MAIN, not
# IMS_7_4_1_MAIN.
_EXACT_ONLY_BRANCHES = {"IMS_7_4_1_MAIN"}


def resolve_ftl_branch(fmc_version: str) -> Optional[str]:
    """Map an FMC version to the closest ftl_schema branch (<= target)."""
    target = _clean_version(fmc_version)
    if not target:
        return None
    tw = version_weight(target)
    if tw < 0:
        return None
    # Build (weight, branch) from VERSIONS list.
    pairs = [(version_weight(label), branch) for branch, label in VERSIONS]
    # Exact label match.
    for branch, label in VERSIONS:
        if label == target:
            return branch
    # Filter out exact-only branches so they are not picked for other versions.
    le = [p for p in pairs if p[0] <= tw and p[1] not in _EXACT_ONLY_BRANCHES]
    if le:
        return max(le, key=lambda p: p[0])[1]
    return min(pairs, key=lambda p: p[0])[1]


def resolve_all(model_string: str, ftd_version: str, fmc_version: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Convenience wrapper returning (sku, model_label, ftl_branch)."""
    sku = resolve_sku(model_string)
    label = resolve_model_label(ftd_version)
    # FMC schema branch is gated by the FMC version, falling back to the FTD
    # version if the FMC version is unavailable.
    branch = resolve_ftl_branch(fmc_version or ftd_version)
    return sku, label, branch


def _clean_version(v: str) -> str:
    """Extract a dotted numeric version from strings like '7.4.1 (build 172)'."""
    if not v:
        return ""
    m = re.search(r"\d+(?:\.\d+){0,3}", str(v))
    return m.group(0) if m else ""
