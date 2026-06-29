"""Locates and caches the model_schemas and ftl_schemas on disk.

The mapping tables (SKU -> family folder, ordered version list) mirror the
authoritative definitions in ``schemas/_generate_schemas.py``. They are kept
local here so the runtime validation path has no dependency on the (heavy)
generator module.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, List, Optional, Tuple


# ── Locate the repo-level schemas directory ──
# This file: <repo>/web_app/pre_push_validation/schema_loader.py
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
SCHEMAS_DIR = os.path.join(_REPO_ROOT, "schemas")
MODEL_SCHEMAS_DIR = os.path.join(SCHEMAS_DIR, "model_schemas")


# ── Ordered (branch, fmc_version_label) list — mirrors _generate_schemas.VERSIONS ──
VERSIONS: List[Tuple[str, str]] = [
    ("IMS_6_3_0", "6.3"),
    ("IMS_6_4_0", "6.4"),
    ("IMS_6_5_0", "6.5"),
    ("IMS_6_6_0", "6.6"),
    ("IMS_6_7_0", "6.7"),
    ("IMS_7_0_0", "7.0"),
    ("IMS_7_1_0", "7.1"),
    ("IMS_7_2_0", "7.2"),
    ("IMS_7_3_0", "7.3"),
    ("IMS_7_4_MAIN", "7.4"),
    ("IMS_7_4_1_MAIN", "7.4.1"),
    ("IMS_7_6_MAIN", "7.6"),
    ("IMS_7_7_MAIN", "7.7"),
    ("IMS_10_0_MAIN", "10.0"),
    ("IMS_10_1_MAIN", "10.1"),
    ("IMS_10_5_MAIN", "10.5"),
]

# SKU -> platform family (mirrors _generate_schemas.SKU_FAMILY)
SKU_FAMILY: Dict[str, str] = {
    "220": "Arsenal_200",
    "1010": "WM_1010", "1010E": "WM_1010", "1010E-no-PoE": "WM_1010",
    "1120": "KP_1100", "1140": "KP_1100", "1150": "KP_1100",
    "1210CE": "FW_1200", "1210CP": "FW_1200", "1220CX": "FW_1200",
    "1230": "FW_1200", "1240": "FW_1200", "1250": "FW_1200",
    "2110": "FP_2100", "2120": "FP_2100", "2130": "FP_2100", "2140": "FP_2100",
    "3105": "TPK_3100", "3110": "TPK_3100", "3120": "TPK_3100",
    "3130": "TPK_3100", "3140": "TPK_3100",
    "4110": "SSP_4100", "4112": "SSP_4100", "4115": "SSP_4100", "4120": "SSP_4100",
    "4125": "SSP_4100", "4140": "SSP_4100", "4145": "SSP_4100", "4150": "SSP_4100",
    "4215": "WA_4200", "4225": "WA_4200", "4245": "WA_4200",
    "6160": "WPK_6100", "6170": "WPK_6100",
    "9300": "SSP_9300",
    "ISA3000": "ISA_3000",
    "FTDv": "FTDv",
}

# Family -> folder name (mirrors _generate_schemas.FAMILY_FOLDER)
FAMILY_FOLDER: Dict[str, str] = {
    "Arsenal_200": "200_Arsenal",
    "WM_1010": "1010_Westminster",
    "KP_1100": "1100_Kingpin",
    "FW_1200": "1200_Victoria",
    "FP_2100": "2100_Series",
    "TPK_3100": "3100_Tufnell_Park",
    "SSP_4100": "4100_SSP",
    "WA_4200": "4200_Wembley_Arena",
    "WPK_6100": "6100_Woodside_Park",
    "SSP_9300": "9300_SSP",
    "ISA_3000": "ISA_3000",
    "FTDv": "FTDv_Virtual",
}

# Available model-schema version labels, ordered.
MODEL_VERSION_LABELS: List[str] = [label for _, label in VERSIONS]


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


def model_schema_path(sku: str, label: str) -> Optional[str]:
    family = SKU_FAMILY.get(sku)
    if not family:
        return None
    folder = FAMILY_FOLDER.get(family)
    if not folder:
        return None
    path = os.path.join(MODEL_SCHEMAS_DIR, folder, sku, f"{sku}_interfaces_{label}.json")
    return path if os.path.isfile(path) else None


@lru_cache(maxsize=64)
def load_model_schema(sku: str, label: str) -> Optional[dict]:
    path = model_schema_path(sku, label)
    if not path:
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None

