"""Locates and caches the FMC OpenAPI Specification (OAS) schemas on disk.

The OAS schemas live in ``schemas/oas_schemas/`` as version-specific OpenAPI 3
documents (``fmc_oas3_<ver>.json`` / ``fmc_7_0.json``). They replace the older
``ftl_schemas`` for field-name validation because the OAS components describe
exactly the request/response models the FMC REST API accepts per version.

Only the ``components.schemas`` section is consumed by the validator. This module
resolves an FMC version string to the closest available OAS document (the highest
available version that is <= the requested one) and caches the parsed JSON.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple


# ── Locate the repo-level schemas directory ──
# This file: <repo>/web_app/pre_push_validation/oas_schema_loader.py
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
SCHEMAS_DIR = os.path.join(_REPO_ROOT, "schemas")
OAS_SCHEMAS_DIR = os.path.join(SCHEMAS_DIR, "oas_schemas")


# ── Available OAS documents, ordered oldest -> newest ──
# (version_label, filename). There are no 6.x / 7.5 / 7.4.1 OAS documents; the
# resolver picks the closest available version <= the requested FMC version.
OAS_VERSIONS: List[Tuple[str, str]] = [
    ("7.0", "fmc_7_0.json"),
    ("7.1", "fmc_oas3_7_1.json"),
    ("7.2", "fmc_oas3_7_2.json"),
    ("7.3", "fmc_oas3_7_3.json"),
    ("7.4", "fmc_oas3_7_4.json"),
    ("7.6", "fmc_oas3_7_6.json"),
    ("7.7", "fmc_oas3_7_7.json"),
    ("10.0", "fmc_oas3_10_0.json"),
    ("10.1", "fmc_oas3_10_1.json"),
    ("10.5", "fmc_oas3_10_5.json"),
]

OAS_VERSION_LABELS: List[str] = [label for label, _ in OAS_VERSIONS]


def version_weight(label: str) -> int:
    """Sortable numeric weight for a dotted version label ('7.4.1' -> 70401)."""
    try:
        parts = (label or "").split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return major * 10000 + minor * 100 + patch
    except Exception:
        return -1


def _clean_version(v: str) -> str:
    """Extract a dotted numeric version from strings like '7.4.1 (build 172)'."""
    if not v:
        return ""
    m = re.search(r"\d+(?:\.\d+){0,3}", str(v))
    return m.group(0) if m else ""


def resolve_oas_version(fmc_version: str) -> Optional[str]:
    """Map an FMC version string to the closest available OAS version label.

    Picks the highest available label that is <= the requested version. If the
    requested version is older than every available document, returns the lowest
    available label (so validation still runs against the closest known schema).
    """
    target = _clean_version(fmc_version)
    if not target:
        return None
    tw = version_weight(target)
    if tw < 0:
        return None
    if target in OAS_VERSION_LABELS:
        return target
    pairs = [(version_weight(label), label) for label in OAS_VERSION_LABELS]
    le = [p for p in pairs if p[0] <= tw]
    if le:
        return max(le, key=lambda p: p[0])[1]
    return min(pairs, key=lambda p: p[0])[1]


def oas_schema_path(label: str) -> Optional[str]:
    for ver, fname in OAS_VERSIONS:
        if ver == label:
            path = os.path.join(OAS_SCHEMAS_DIR, fname)
            return path if os.path.isfile(path) else None
    return None


@lru_cache(maxsize=8)
def _load_oas_document(label: str) -> Optional[Dict]:
    path = oas_schema_path(label)
    if not path:
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


@lru_cache(maxsize=8)
def load_oas_schemas(label: str) -> Optional[Dict]:
    """Return the schema component mapping for the given OAS version label.

    Handles both OpenAPI 3 documents (``components.schemas``) and the older
    Swagger 2.0 document used for FMC 7.0 (top-level ``definitions``).
    """
    doc = _load_oas_document(label)
    if not doc:
        return None
    comps = (doc.get("components") or {})
    schemas = comps.get("schemas")
    if isinstance(schemas, dict) and schemas:
        return schemas
    # Swagger 2.0 fallback.
    definitions = doc.get("definitions")
    return definitions if isinstance(definitions, dict) else None
