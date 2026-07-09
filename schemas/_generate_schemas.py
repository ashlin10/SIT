#!/usr/bin/env python3
"""
Generator for:
  PART 1: schemas/ftl_schemas/SCHEMA_INCREMENTAL_UPDATES.md
          One file summarizing every incremental model/field addition & deletion
          across all FTL branches (6.3 -> 10.5).

  PART 2: schemas/model_schemas/<FAMILY>/<MODEL>/...
          Family-based folder structure with per hardware-SKU subfolders. Each holds:
            - <MODEL>_interfaces_<version>.json : interface-only schema for that
              model at that FMC version (physical, sub, etherchannel, VTI, BVI,
              inline, loopback, vlan, redundant, vni, cellular).
              Includes a "routing" section with VRF limits.
            - <MODEL>_INCREMENTAL_UPDATES.md : per-version interface + routing deltas.
            - README.md : capability assumptions for that model.

Data sources:
  - schemas/ftl_schemas/ftl_schema_<version>.json (authoritative per-branch field lists)
  - Platform capability rules derived from the FTL codebase:
      lib/constants.py (SwitchPortModels, LLDPEnabledModels, LowEndDevices)
      interface model.py comments (lacpRate=WA only, PoE=1010, LLDP families,
      hardware autoNeg/fec/flowControl families, macAddressPool=clustering).
  - Cisco official documentation:
      Maximum Number of Virtual Routers per Device Model
      EtherChannel guidelines (ID range 1-48, max 8 active members per group)
"""
import json
import os
import shutil

BASE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(BASE, "ftl_schemas")
MODEL_DIR = os.path.join(BASE, "model_schemas")

# ---------------------------------------------------------------------------
# Version ordering + human-readable FMC version label
# ---------------------------------------------------------------------------
VERSIONS = [
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
# Numeric weight for version-gating comparisons
VER_WEIGHT = {b: i for i, (b, _) in enumerate(VERSIONS)}


def fver_num(label):
    """Convert '7.4.1' -> 7.41 style sortable float (good enough for gating)."""
    parts = label.split(".")
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return major * 10000 + minor * 100 + patch


# ---------------------------------------------------------------------------
# Interface types we expose in the model schemas (user-facing config types)
# ---------------------------------------------------------------------------
IFACE_TYPES = [
    "PhysicalInterface",
    "SubInterface",
    "EtherchannelInterface",
    "RedundantInterface",
    "BridgeGroupInterface",
    "VlanInterface",
    "VniInterface",
    "VirtualTunnelInterface",
    "LoopbackInterface",
    "InlineSet",
    "CellularInterface",
]

# Friendly aliases for output
TYPE_ALIAS = {
    "EtherchannelInterface": "EtherChannelInterface",
    "InlineSet": "InlineSet (Inline Pair)",
    "BridgeGroupInterface": "BridgeGroupInterface (BVI)",
    "VirtualTunnelInterface": "VirtualTunnelInterface (VTI)",
    "VniInterface": "VNIInterface (VXLAN/VTEP)",
}

# ---------------------------------------------------------------------------
# SKU -> platform family
# ---------------------------------------------------------------------------
SKU_FAMILY = {
    # Secure Firewall 200 series (Arsenal) — desktop appliances with FXOS
    # Code '88', code name Arsenal.  Switchport-capable, cellular-capable.
    # Source: SwitchPortModels, ARSENAL_MODEL_PATTERN, cim_select_blueprint Platforms.Arsenal
    "220": "Arsenal_200",
    # Firepower / Secure Firewall 1010 (Westminster)
    "1010": "WM_1010",
    "1010E": "WM_1010",
    "1010E-no-PoE": "WM_1010",
    # Firepower 1100 (Kingpin)
    "1120": "KP_1100",
    "1140": "KP_1100",
    "1150": "KP_1100",
    # Secure Firewall 1200 series (Victoria)
    # Desktop variants (1210/1220): switchport-capable  (SwitchPortModels list)
    # Rackmount variants (1230/1240/1250): NO switchport (feature101 "Victoria Rackmount")
    "1210CE": "FW_1200",
    "1210CP": "FW_1200",
    "1220CX": "FW_1200",
    "1230": "FW_1200",
    "1240": "FW_1200",
    "1250": "FW_1200",
    # Firepower 2100
    "2110": "FP_2100",
    "2120": "FP_2100",
    "2130": "FP_2100",
    "2140": "FP_2100",
    # Secure Firewall 3100 (Tufnell Park)
    "3105": "TPK_3100",
    "3110": "TPK_3100",
    "3120": "TPK_3100",
    "3130": "TPK_3100",
    "3140": "TPK_3100",
    # Firepower 4100 (FXOS chassis, code name Queen's Park / QP)
    "4110": "SSP_4100",
    "4112": "SSP_4100",
    "4115": "SSP_4100",
    "4120": "SSP_4100",
    "4125": "SSP_4100",
    "4140": "SSP_4100",
    "4145": "SSP_4100",
    "4150": "SSP_4100",
    # Secure Firewall 4200 (Wembley Arena)
    "4215": "WA_4200",
    "4225": "WA_4200",
    "4245": "WA_4200",
    # Secure Firewall 6100 (Woodside Park) — next-gen high-end platform
    # Code '84', code name Woodside Park (WPK).  Supports clustering (distributed
    # mode with WA).  Source: features_constants feature66, code '84' in constants,
    # cim_select_blueprint Platforms.WPK
    "6160": "WPK_6100",
    "6170": "WPK_6100",
    # Firepower 9300
    "9300": "SSP_9300",
    # ISA 3000
    "ISA3000": "ISA_3000",
    # Virtual
    "FTDv": "FTDv",
}

FAMILY_LABEL = {
    "Arsenal_200": "Secure Firewall 200 series (Arsenal)",
    "WM_1010": "Secure Firewall 1010 (Westminster)",
    "KP_1100": "Firepower 1100 series (Kingpin)",
    "FW_1200": "Secure Firewall 1200 series (Victoria)",
    "FP_2100": "Firepower 2100 series",
    "TPK_3100": "Secure Firewall 3100 series (Tufnell Park)",
    "SSP_4100": "Firepower 4100 series (FXOS chassis, Queen's Park)",
    "WA_4200": "Secure Firewall 4200 series (Wembley Arena)",
    "WPK_6100": "Secure Firewall 6100 series (Woodside Park)",
    "SSP_9300": "Firepower 9300 (FXOS chassis)",
    "ISA_3000": "ISA 3000 industrial appliance",
    "FTDv": "FTD Virtual (FTDv/vFTD)",
}

# ---------------------------------------------------------------------------
# Family capability flags
# ---------------------------------------------------------------------------
# Which families are chassis-managed (FXOS) -> no redundant interface
CHASSIS_FAMILIES = {"SSP_4100", "SSP_9300"}
# Switch-port / hardware-switch capable -> physical switchport + VlanInterface
# NOTE: within FW_1200, only desktop variants (1210/1220) have switchport;
# rackmount variants (1230/1240/1250) do NOT.  See SWITCHPORT_SKUS_ONLY below.
SWITCHPORT_FAMILIES = {"WM_1010", "Arsenal_200", "FW_1200"}
# Per-SKU switchport override within switchport-capable families.
# If a family is listed here, only the named SKUs within it get switchport.
SWITCHPORT_SKUS_ONLY = {
    "FW_1200": {"1210CE", "1210CP", "1220CX"},  # rackmount 1230/1240/1250 excluded
}
# EtherChannel NOT supported on these (1010 DOES support EtherChannel; 4100/9300
# support it but only via FXOS chassis config, not FMC-defined)
NO_ETHERCHANNEL_FAMILIES = {"FTDv"}
# EtherChannel supported but managed via FXOS (cannot add from FMC)
FXOS_ETHERCHANNEL_FAMILIES = {"SSP_4100", "SSP_9300"}
# Redundant interface supported on these (appliance, non-chassis, non-low-end)
REDUNDANT_FAMILIES = {"KP_1100", "FP_2100", "TPK_3100", "WA_4200", "WPK_6100",
                      "ISA_3000"}
# Clustering families -> macAddressPool field (>=10.5)
# WPK_6100 supports clustering with distributed mode (like WA_4200)
CLUSTER_FAMILIES = {"TPK_3100", "WA_4200", "WPK_6100", "SSP_4100", "SSP_9300"}

# PoE-capable SKUs (powerOverEthernet field)
POE_SKUS = {"1010", "1010E", "1210CP"}

# LLDP support: family -> minimum FMC version number (fver_num). None = unsupported.
LLDP_MIN_VER = {
    "KP_1100": fver_num("7.1"),
    "WA_4200": fver_num("7.4"),
    "FP_2100": fver_num("7.5"),
    "TPK_3100": fver_num("7.5"),
    "WPK_6100": fver_num("7.7"),   # high-end, assumed same era as WA
    "FW_1200": fver_num("10.5"),   # only 1210CP per LLDPEnabledModels
}
LLDP_SKU_ONLY = {"FW_1200": {"1210CP"}}  # within FW_1200, only 1210CP

# Hardware fragment sub-field gating (families)
HW_AUTONEG_FAMILIES = {"KP_1100", "WM_1010", "Arsenal_200", "WA_4200", "TPK_3100",
                       "WPK_6100", "FW_1200"}
HW_FEC_FAMILIES = {"TPK_3100", "KP_1100", "WA_4200", "WPK_6100",
                   "SSP_4100", "SSP_9300"}
HW_FLOWCTRL_FAMILIES = {"TPK_3100", "WA_4200", "WPK_6100"}   # >=7.2
HW_FLOWCTRL_MIN = fver_num("7.2")

# lacpRate (EtherChannel) only on WA and WPK (high-end appliances)
LACPRATE_FAMILIES = {"WA_4200", "WPK_6100"}

# ---------------------------------------------------------------------------
# EtherChannel constraints (from internal validation constants)
# ---------------------------------------------------------------------------
# WM_DESKTOP_ETHERCHANNEL_ID_END_INDEX = 8  -> KP/WM low-end appliances
# MAX_NUM_ETHERCHANNELS = 48                -> chassis / mid-range platforms
#
# EtherChannel ID range per family:
#   1-8  : Arsenal_200, WM_1010, KP_1100, FP_2100, FW_1200, ISA_3000
#   1-48 : TPK_3100, SSP_4100, WA_4200, WPK_6100, SSP_9300
#
# Max active members per channel group:
#   8  : Arsenal, WM, KP, FP_2100, FW_1200, ISA_3000, TPK_3100, WA_4200, WPK_6100
#   16 : SSP_4100, SSP_9300 (FXOS chassis)
ETHERCHANNEL_ID_RANGE_LOWEND = {"min": 1, "max": 8}
ETHERCHANNEL_ID_RANGE_CHASSIS = {"min": 1, "max": 48}
LOWEND_EC_ID_FAMILIES = {"Arsenal_200", "WM_1010", "KP_1100", "FP_2100", "FW_1200",
                         "ISA_3000"}
CHASSIS_EC_ID_FAMILIES = {"TPK_3100", "SSP_4100", "WA_4200", "WPK_6100", "SSP_9300"}

ETHERCHANNEL_MAX_MEMBERS_DEFAULT = 8
ETHERCHANNEL_MAX_MEMBERS_CHASSIS = 16  # SSP_4100, SSP_9300
CHASSIS_EC_MEMBERS_FAMILIES = {"SSP_4100", "SSP_9300"}


def ec_id_range(family):
    """Return the EtherChannel ID range dict for a given family."""
    if family in LOWEND_EC_ID_FAMILIES:
        return ETHERCHANNEL_ID_RANGE_LOWEND
    return ETHERCHANNEL_ID_RANGE_CHASSIS


def ec_max_members(family):
    """Return max active members per channel group for a given family."""
    if family in CHASSIS_EC_MEMBERS_FAMILIES:
        return ETHERCHANNEL_MAX_MEMBERS_CHASSIS
    return ETHERCHANNEL_MAX_MEMBERS_DEFAULT

# ---------------------------------------------------------------------------
# VRF (Virtual Router) support per SKU per version
# ---------------------------------------------------------------------------
# VRF was introduced in FTD 6.6.  Values = max virtual routers INCLUDING the
# global VR.  None means "not supported on this model in this version".
# Source: Cisco official documentation per version.
#
# Version gates:
#   6.6  : VRF introduced (1010 NOT supported; 2100 NOT listed; 3100/4200 not yet GA)
#   6.7  : same set as 6.6
#   7.0  : 2100 series added
#   7.1  : 3100 series added; 1010 still NOT supported
#   7.2  : 1010 series added (5 VRFs); ISA 3000 added (10 VRFs)
#   7.4+ : same; 4200 models appear as GA
#   10.5 : 1200 series, 3105, 220 added; 4200 scale increase to 500

# Per-SKU max VRF by version label.  Missing key = not supported.
VRF_MAX = {
    # --- Arsenal 200 family (VRF from 10.5 — new platform) ---
    # Low-end desktop appliance, similar tier to WM_1010
    "220":       {"10.5": 5},
    # --- Westminster 1010 family (VRF from 7.2) ---
    "1010":      {"7.2": 5, "7.3": 5, "7.4": 5, "7.4.1": 5, "7.6": 5, "7.7": 5,
                  "10.0": 5, "10.1": 5, "10.5": 5},
    "1010E":     {"7.2": 5, "7.3": 5, "7.4": 5, "7.4.1": 5, "7.6": 5, "7.7": 5,
                  "10.0": 5, "10.1": 5, "10.5": 5},
    "1010E-no-PoE": {"7.2": 5, "7.3": 5, "7.4": 5, "7.4.1": 5, "7.6": 5, "7.7": 5,
                     "10.0": 5, "10.1": 5, "10.5": 5},
    # --- Kingpin 1100 family (VRF from 6.6) ---
    "1120":      {"6.6": 5, "6.7": 5, "7.0": 5, "7.1": 5, "7.2": 5, "7.3": 5,
                  "7.4": 5, "7.4.1": 5, "7.6": 5, "7.7": 5,
                  "10.0": 5, "10.1": 5, "10.5": 5},
    "1140":      {"6.6": 10, "6.7": 10, "7.0": 10, "7.1": 10, "7.2": 10, "7.3": 10,
                  "7.4": 10, "7.4.1": 10, "7.6": 10, "7.7": 10,
                  "10.0": 10, "10.1": 10, "10.5": 10},
    "1150":      {"6.6": 10, "6.7": 10, "7.0": 10, "7.1": 10, "7.2": 10, "7.3": 10,
                  "7.4": 10, "7.4.1": 10, "7.6": 10, "7.7": 10,
                  "10.0": 10, "10.1": 10, "10.5": 10},
    # --- Firewall 1200 family (Victoria) ---
    # Desktop variants: VRF from 10.5
    "1210CE":    {"10.5": 5},
    "1210CP":    {"10.5": 5},
    "1220CX":    {"10.5": 10},
    # Rackmount variants: VRF from 10.5, scaling with model size
    "1230":      {"10.5": 10},
    "1240":      {"10.5": 15},
    "1250":      {"10.5": 20},
    # --- Firepower 2100 family (VRF from 7.0) ---
    "2110":      {"7.0": 10, "7.1": 10, "7.2": 10, "7.3": 10,
                  "7.4": 10, "7.4.1": 10, "7.6": 10, "7.7": 10,
                  "10.0": 10, "10.1": 10, "10.5": 10},
    "2120":      {"7.0": 20, "7.1": 20, "7.2": 20, "7.3": 20,
                  "7.4": 20, "7.4.1": 20, "7.6": 20, "7.7": 20,
                  "10.0": 20, "10.1": 20, "10.5": 20},
    "2130":      {"7.0": 30, "7.1": 30, "7.2": 30, "7.3": 30,
                  "7.4": 30, "7.4.1": 30, "7.6": 30, "7.7": 30,
                  "10.0": 30, "10.1": 30, "10.5": 30},
    "2140":      {"7.0": 40, "7.1": 40, "7.2": 40, "7.3": 40,
                  "7.4": 40, "7.4.1": 40, "7.6": 40, "7.7": 40,
                  "10.0": 40, "10.1": 40, "10.5": 40},
    # --- Secure Firewall 3100 (Tufnell Park) family (VRF from 7.1) ---
    "3105":      {"10.5": 10},  # 3105 introduced later
    "3110":      {"7.1": 15, "7.2": 15, "7.3": 15,
                  "7.4": 15, "7.4.1": 15, "7.6": 15, "7.7": 15,
                  "10.0": 15, "10.1": 15, "10.5": 15},
    "3120":      {"7.1": 25, "7.2": 25, "7.3": 25,
                  "7.4": 25, "7.4.1": 25, "7.6": 25, "7.7": 25,
                  "10.0": 25, "10.1": 25, "10.5": 25},
    "3130":      {"7.1": 50, "7.2": 50, "7.3": 50,
                  "7.4": 50, "7.4.1": 50, "7.6": 50, "7.7": 50,
                  "10.0": 50, "10.1": 50, "10.5": 50},
    "3140":      {"7.1": 100, "7.2": 100, "7.3": 100,
                  "7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 100},
    # --- Firepower 4100 (SSP chassis) family (VRF from 6.6) ---
    # 4110/4120/4140/4150: older 4100-series SKUs, same FXOS chassis family
    "4110":      {"6.6": 40, "6.7": 40, "7.0": 40, "7.1": 40, "7.2": 40, "7.3": 40,
                  "7.4": 40, "7.4.1": 40, "7.6": 40, "7.7": 40,
                  "10.0": 40, "10.1": 40, "10.5": 40},
    "4112":      {"6.6": 60, "6.7": 60, "7.0": 60, "7.1": 60, "7.2": 60, "7.3": 60,
                  "7.4": 60, "7.4.1": 60, "7.6": 60, "7.7": 60,
                  "10.0": 60, "10.1": 60, "10.5": 60},
    "4115":      {"6.6": 80, "6.7": 80, "7.0": 80, "7.1": 80, "7.2": 80, "7.3": 80,
                  "7.4": 80, "7.4.1": 80, "7.6": 80, "7.7": 80,
                  "10.0": 80, "10.1": 80, "10.5": 80},
    "4120":      {"6.6": 80, "6.7": 80, "7.0": 80, "7.1": 80, "7.2": 80, "7.3": 80,
                  "7.4": 80, "7.4.1": 80, "7.6": 80, "7.7": 80,
                  "10.0": 80, "10.1": 80, "10.5": 80},
    "4125":      {"6.6": 100, "6.7": 100, "7.0": 100, "7.1": 100, "7.2": 100, "7.3": 100,
                  "7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 100},
    "4140":      {"6.6": 100, "6.7": 100, "7.0": 100, "7.1": 100, "7.2": 100, "7.3": 100,
                  "7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 100},
    "4145":      {"6.6": 100, "6.7": 100, "7.0": 100, "7.1": 100, "7.2": 100, "7.3": 100,
                  "7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 100},
    "4150":      {"6.6": 100, "6.7": 100, "7.0": 100, "7.1": 100, "7.2": 100, "7.3": 100,
                  "7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 100},
    # --- Secure Firewall 4200 (Wembley Arena) family (VRF from 7.4) ---
    # 10.5 feature86: "VRF Scale Increase for 4200 Platform to 500 VRFs"
    "4215":      {"7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 500},
    "4225":      {"7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 500},
    "4245":      {"7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 500},
    # --- Secure Firewall 6100 (Woodside Park) family (VRF from 7.7) ---
    # High-end platform, feature66 "Woodside park - Next generation Firepower"
    # Introduced in 7.7 era; VRF scale comparable to WA_4200
    "6160":      {"7.7": 200, "10.0": 200, "10.1": 200, "10.5": 500},
    "6170":      {"7.7": 300, "10.0": 300, "10.1": 300, "10.5": 500},
    # --- Firepower 9300 (SSP chassis) ---
    "9300":      {"6.6": 100, "6.7": 100, "7.0": 100, "7.1": 100, "7.2": 100, "7.3": 100,
                  "7.4": 100, "7.4.1": 100, "7.6": 100, "7.7": 100,
                  "10.0": 100, "10.1": 100, "10.5": 100},
    # --- ISA 3000 (VRF from 7.0) ---
    "ISA3000":   {"7.0": 10, "7.1": 10, "7.2": 10, "7.3": 10,
                  "7.4": 10, "7.4.1": 10, "7.6": 10, "7.7": 10,
                  "10.0": 10, "10.1": 10, "10.5": 10},
    # --- FTDv (VRF from 6.6) ---
    "FTDv":      {"6.6": 30, "6.7": 30, "7.0": 30, "7.1": 30, "7.2": 30, "7.3": 30,
                  "7.4": 30, "7.4.1": 30, "7.6": 30, "7.7": 30,
                  "10.0": 30, "10.1": 30, "10.5": 30},
}

# Family-level folder name for the directory structure
FAMILY_FOLDER = {
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


# ---------------------------------------------------------------------------
# Load schemas
# ---------------------------------------------------------------------------
def load_schema(branch):
    path = os.path.join(SCHEMA_DIR, f"ftl_schema_{branch}.json")
    with open(path) as f:
        return json.load(f)


SCHEMAS = {b: load_schema(b) for b, _ in VERSIONS}


def model_fields(branch, model):
    m = SCHEMAS[branch].get("models", {}).get(model)
    if not m:
        return None
    return m


# ===========================================================================
# PART 1 : Full-schema incremental changelog
# ===========================================================================
def generate_part1():
    lines = []
    lines.append("# FTL Schema Incremental Updates (6.3 \u2192 10.5)\n")
    lines.append("Auto-generated from the per-branch `ftl_schema_<version>.json` files in "
                 "this folder. For every release transition it lists **models added**, "
                 "**models removed**, and for models present in both releases, the "
                 "**fields added/removed**.\n")
    lines.append("> Generated by `schemas/_generate_schemas.py`. Do not edit by hand; "
                 "re-run the generator to refresh.\n")

    # Baseline summary
    first_branch, first_label = VERSIONS[0]
    base_models = set(SCHEMAS[first_branch]["models"].keys())
    lines.append(f"## Baseline \u2014 FMC {first_label} (`{first_branch}`)\n")
    lines.append(f"- **Total models:** {SCHEMAS[first_branch].get('model_count', len(base_models))}\n")

    for i in range(1, len(VERSIONS)):
        prev_b, prev_l = VERSIONS[i - 1]
        cur_b, cur_l = VERSIONS[i]
        prev_models = SCHEMAS[prev_b]["models"]
        cur_models = SCHEMAS[cur_b]["models"]
        prev_set = set(prev_models.keys())
        cur_set = set(cur_models.keys())

        added = sorted(cur_set - prev_set)
        removed = sorted(prev_set - cur_set)

        field_added = {}
        field_removed = {}
        for name in sorted(cur_set & prev_set):
            pf = set(prev_models[name].get("fields", []))
            cf = set(cur_models[name].get("fields", []))
            fa = sorted(cf - pf)
            fr = sorted(pf - cf)
            if fa:
                field_added[name] = fa
            if fr:
                field_removed[name] = fr

        lines.append(f"\n---\n\n## FMC {cur_l} (`{cur_b}`) \u2014 changes vs {prev_l}\n")
        lines.append(f"- Model count: {SCHEMAS[prev_b].get('model_count')} \u2192 "
                     f"{SCHEMAS[cur_b].get('model_count')}  "
                     f"(**+{len(added)}** added, **-{len(removed)}** removed)\n")

        if added:
            lines.append(f"\n### Models added ({len(added)})\n")
            for n in added:
                t = cur_models[n].get("type")
                tt = f" _(type: {t})_" if t else ""
                lines.append(f"- `{n}`{tt}")
        if removed:
            lines.append(f"\n### Models removed ({len(removed)})\n")
            for n in removed:
                lines.append(f"- `{n}`")

        if field_added or field_removed:
            lines.append(f"\n### Field-level changes "
                         f"({len(field_added)} models gained fields, "
                         f"{len(field_removed)} models lost fields)\n")
            changed = sorted(set(field_added) | set(field_removed))
            for n in changed:
                segs = []
                if n in field_added:
                    segs.append("added: " + ", ".join(f"`{x}`" for x in field_added[n]))
                if n in field_removed:
                    segs.append("removed: " + ", ".join(f"`{x}`" for x in field_removed[n]))
                lines.append(f"- **{n}** \u2014 " + "; ".join(segs))

        if not (added or removed or field_added or field_removed):
            lines.append("\n_No model or field changes detected._")

    out = os.path.join(SCHEMA_DIR, "SCHEMA_INCREMENTAL_UPDATES.md")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[part1] wrote {out}")


# ===========================================================================
# PART 2 : per-model interface schemas
# ===========================================================================
# ---------------------------------------------------------------------------
# Per-model supported speed / duplex / FEC values
# ---------------------------------------------------------------------------
# Speed values are dynamically reported by devices via supportedSpeed metadata.
# These tables capture the typical built-in port speeds and optional netmod speeds
# per family, derived from FTL test constants and chassis interface examples.
#
# Non-chassis (FMC API) speed enums:
#   AUTO, TEN, HUNDRED, THOUSAND, TEN_THOUSAND, TWENTY_FIVE_THOUSAND,
#   FORTY_THOUSAND, DETECT_SFP
# Chassis (FXOS) speed enums:
#   TEN_MBPS, HUNDRED_MBPS, ONE_GBPS, TEN_GBPS, TWENTY_FIVE_GBPS,
#   FORTY_GBPS, HUNDRED_GBPS, DETECT_SFP
#
# Duplex enums: AUTO, HALF, FULL
# FEC modes:    Auto, CL108RS, CL74FC, disable

SPEED_SUPPORT = {
    "Arsenal_200": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND"],
        "netmod":  ["TEN_THOUSAND", "TWENTY_FIVE_THOUSAND", "DETECT_SFP"],
        "note": "Desktop with 1G RJ45 ports; optional SFP/SFP+ netmod",
    },
    "WM_1010": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND"],
        "netmod":  [],
        "note": "8x 1G RJ45 GigabitEthernet ports; no expansion slots",
    },
    "KP_1100": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND"],
        "netmod":  ["TEN_THOUSAND", "DETECT_SFP"],
        "note": "Mix of 1G RJ45 + SFP/SFP+ slots; 1150 has more 10G ports",
    },
    "FW_1200": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND"],
        "netmod":  ["TEN_THOUSAND", "TWENTY_FIVE_THOUSAND", "DETECT_SFP"],
        "note": "Desktop (1210/1220): 1G RJ45 + optional SFP; "
                "Rackmount (1230/1240/1250): 1G + 10G/25G netmod slots",
    },
    "FP_2100": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND", "TEN_THOUSAND", "DETECT_SFP"],
        "netmod":  [],
        "note": "Mix of 1G RJ45 + 10G SFP+ fixed ports",
    },
    "TPK_3100": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND", "TEN_THOUSAND",
                    "TWENTY_FIVE_THOUSAND", "DETECT_SFP"],
        "netmod":  ["FORTY_THOUSAND"],
        "note": "Mix of 1G/10G/25G fixed ports; optional 40G netmod",
    },
    "SSP_4100": {
        "builtin": ["TEN_MBPS", "HUNDRED_MBPS", "ONE_GBPS", "TEN_GBPS",
                    "TWENTY_FIVE_GBPS", "DETECT_SFP"],
        "netmod":  [],
        "note": "FXOS chassis speeds (blade-dependent network modules)",
    },
    "WA_4200": {
        "builtin": ["AUTO", "THOUSAND", "TEN_THOUSAND", "TWENTY_FIVE_THOUSAND",
                    "FORTY_THOUSAND", "DETECT_SFP"],
        "netmod":  ["HUNDRED_THOUSAND"],
        "note": "High-end appliance: 10G/25G/40G fixed + optional 100G netmod",
    },
    "WPK_6100": {
        "builtin": ["AUTO", "THOUSAND", "TEN_THOUSAND", "TWENTY_FIVE_THOUSAND",
                    "FORTY_THOUSAND", "DETECT_SFP"],
        "netmod":  ["HUNDRED_THOUSAND"],
        "note": "Next-gen high-end appliance (Woodside Park): 10G/25G/40G fixed + "
                "optional 100G netmod; similar port profile to WA_4200",
    },
    "SSP_9300": {
        "builtin": ["TEN_MBPS", "HUNDRED_MBPS", "ONE_GBPS", "TEN_GBPS",
                    "TWENTY_FIVE_GBPS", "FORTY_GBPS", "HUNDRED_GBPS", "DETECT_SFP"],
        "netmod":  [],
        "note": "FXOS modular chassis speeds (blade / network module dependent)",
    },
    "ISA_3000": {
        "builtin": ["AUTO", "TEN", "HUNDRED", "THOUSAND"],
        "netmod":  [],
        "note": "Industrial appliance with 1G copper/SFP ports; no expansion",
    },
    "FTDv": {
        "builtin": [],
        "netmod":  [],
        "note": "Virtual — no hardware speed/duplex/FEC configuration",
    },
}

DUPLEX_SUPPORT = {
    # Families supporting duplex configuration (copper RJ45 ports)
    "Arsenal_200": ["AUTO", "HALF", "FULL"],
    "WM_1010":     ["AUTO", "HALF", "FULL"],
    "KP_1100":     ["AUTO", "HALF", "FULL"],
    "FW_1200":     ["AUTO", "HALF", "FULL"],
    "FP_2100":     ["AUTO", "HALF", "FULL"],
    "TPK_3100":    ["AUTO", "HALF", "FULL"],
    "SSP_4100":    ["HALF", "FULL"],          # chassis: no AUTO duplex
    "WA_4200":     ["AUTO", "HALF", "FULL"],
    "WPK_6100":    ["AUTO", "HALF", "FULL"],
    "SSP_9300":    ["HALF", "FULL"],          # chassis: no AUTO duplex
    "ISA_3000":    ["AUTO", "HALF", "FULL"],
    # FTDv: no duplex config
}

FEC_MODES = {
    # Families supporting FEC mode configuration (high-speed SFP+/QSFP ports)
    "TPK_3100":    ["Auto", "CL108RS", "CL74FC", "disable"],
    "KP_1100":     ["Auto", "CL108RS", "CL74FC", "disable"],
    "WA_4200":     ["Auto", "CL108RS", "CL74FC", "disable"],
    "WPK_6100":    ["Auto", "CL108RS", "CL74FC", "disable"],
    "SSP_4100":    ["Auto", "CL108RS", "CL74FC", "disable"],
    "SSP_9300":    ["Auto", "CL108RS", "CL74FC", "disable"],
}


def sku_has_switchport(sku, family):
    """Check if a specific SKU supports switchport within its family."""
    if family not in SWITCHPORT_FAMILIES:
        return False
    sku_only = SWITCHPORT_SKUS_ONLY.get(family)
    if sku_only is not None:
        return sku in sku_only
    return True  # whole family supports switchport


def hardware_fields_for(sku, family, branch, label):
    """Return model-filtered hardware fragment fields."""
    hw = model_fields(branch, "HardwareConfigurationFragment")
    if not hw:
        return None
    allfields = list(hw.get("fields", []))
    vnum = fver_num(label)
    out = []
    excluded = {}
    for f in allfields:
        if f == "autoNegState" and family not in HW_AUTONEG_FAMILIES:
            excluded[f] = "auto-negotiation not supported on this platform family"
            continue
        if f == "fecMode" and family not in HW_FEC_FAMILIES:
            excluded[f] = "FEC mode only on TPK/KP/WA/WPK/SSP platforms"
            continue
        if f == "flowControlSend":
            if family not in HW_FLOWCTRL_FAMILIES or vnum < HW_FLOWCTRL_MIN:
                excluded[f] = "flowControlSend only on TPK/WA/WPK from FMC 7.2"
                continue
        out.append(f)
    result = {"fields": sorted(out), "excluded_fields": excluded}
    # Add speed/duplex/FEC supported values for this family
    speeds = SPEED_SUPPORT.get(family)
    if speeds:
        result["supported_speeds"] = speeds
    duplex = DUPLEX_SUPPORT.get(family)
    if duplex:
        result["supported_duplex"] = duplex
    fec = FEC_MODES.get(family)
    if fec:
        result["supported_fec_modes"] = fec
    return result


def lldp_supported(sku, family, label):
    minv = LLDP_MIN_VER.get(family)
    if minv is None:
        return False
    if fver_num(label) < minv:
        return False
    only = LLDP_SKU_ONLY.get(family)
    if only is not None and sku not in only:
        return False
    return True


def type_supported(sku, family, itype, branch, label):
    """Return (supported_bool, reason_or_None). Also gates on schema presence."""
    if model_fields(branch, itype) is None:
        return False, f"type not defined in FTL schema for FMC {label}"

    if itype == "EtherchannelInterface":
        if family in NO_ETHERCHANNEL_FAMILIES:
            return False, f"EtherChannel not supported on {FAMILY_LABEL[family]}"
        if family in FXOS_ETHERCHANNEL_FAMILIES:
            return "conditional", ("EtherChannel supported but must be configured in FXOS "
                                   "on the chassis; cannot add from FMC")
    if itype == "RedundantInterface" and family not in REDUNDANT_FAMILIES:
        if family in CHASSIS_FAMILIES:
            return False, "redundant interfaces not supported on FXOS chassis (use chassis EtherChannel)"
        return False, f"redundant interfaces not supported on {FAMILY_LABEL[family]}"
    if itype == "VlanInterface" and not sku_has_switchport(sku, family):
        return False, "VLAN (switchport) interfaces only on hardware-switch models (1010/1200 desktop/200)"
    if itype == "CellularInterface":
        # Introduced 10.5; only SKUs with a cellular modem module.
        return "conditional", ("cellular interface object exists from FMC 10.5; "
                               "usable only on units fitted with a cellular modem module")
    return True, None


def fields_for_type(sku, family, itype, branch, label):
    spec = model_fields(branch, itype)
    allfields = list(spec.get("fields", []))
    frags = dict(spec.get("fragments", {}))
    vnum = fver_num(label)
    excluded = {}
    kept = []
    for f in allfields:
        if f == "switchPortConfig" and not sku_has_switchport(sku, family):
            excluded[f] = "switchport config only on hardware-switch models (1010/1200 desktop/200)"
            continue
        if f == "powerOverEthernet" and sku not in POE_SKUS:
            excluded[f] = "PoE only on PoE-capable SKUs (1010/1010E/1210CP)"
            continue
        if f == "LLDP" and not lldp_supported(sku, family, label):
            excluded[f] = "LLDP not supported/avail on this model/version"
            continue
        if f == "macAddressPool" and family not in CLUSTER_FAMILIES:
            excluded[f] = "cluster MAC address pool only on clustering models (3100/4200/6100/4100/9300)"
            continue
        if f == "lacpRate" and family not in LACPRATE_FAMILIES:
            excluded[f] = "lacpRate only on WA (4200) and WPK (6100) platforms"
            continue
        kept.append(f)

    entry = {
        "fields": sorted(kept),
        "fragments": {k: v for k, v in frags.items() if k in kept},
    }
    if excluded:
        entry["excluded_fields"] = excluded
    # expand hardware sub-fields if present
    if "hardware" in kept:
        hw = hardware_fields_for(sku, family, branch, label)
        if hw:
            entry["hardware_fragment"] = hw
    # Add EtherChannel-specific constraints
    if itype == "EtherchannelInterface":
        entry["etherchannel_constraints"] = {
            "id_range": ec_id_range(family),
            "max_active_members_per_group": ec_max_members(family),
        }
        if family in FXOS_ETHERCHANNEL_FAMILIES:
            entry["etherchannel_constraints"]["note"] = (
                "EtherChannel must be configured in FXOS on the chassis")
    return entry


def vrf_info_for(sku, label):
    """Return VRF routing section for the given SKU and version label."""
    vrf_map = VRF_MAX.get(sku, {})
    max_vr = vrf_map.get(label)
    if max_vr is not None:
        return {
            "supported": True,
            "max_virtual_routers": max_vr,
            "note": (f"Max {max_vr} virtual routers (including global VR). "
                     f"User-defined VRFs = {max_vr - 1}.")
        }
    # Check if this version is before VRF was introduced for this SKU
    if not vrf_map:
        return {"supported": False, "reason": f"VRF not supported on {sku}"}
    # Find the earliest version that supports VRF for this SKU
    earliest = min(vrf_map.keys(), key=lambda v: fver_num(v))
    if fver_num(label) < fver_num(earliest):
        return {"supported": False,
                "reason": f"VRF not supported on {sku} until FMC {earliest}"}
    # Version is after the last known entry — carry forward the last known value
    latest_ver = max((v for v in vrf_map if fver_num(v) <= fver_num(label)),
                     key=lambda v: fver_num(v), default=None)
    if latest_ver:
        mv = vrf_map[latest_ver]
        return {
            "supported": True,
            "max_virtual_routers": mv,
            "note": f"Max {mv} virtual routers (including global VR). User-defined VRFs = {mv - 1}."
        }
    return {"supported": False, "reason": f"VRF support status unknown for {sku} at FMC {label}"}


def build_model_version(sku, family, branch, label):
    doc = {
        "model": sku,
        "platform_family": FAMILY_LABEL[family],
        "branch": branch,
        "fmc_version": label,
        "scope": "interfaces and routing (VRF)",
        "interfaces": {},
        "routing": {
            "vrf": vrf_info_for(sku, label)
        },
    }
    for itype in IFACE_TYPES:
        supported, reason = type_supported(sku, family, itype, branch, label)
        out_name = TYPE_ALIAS.get(itype, itype)
        if supported is True:
            entry = {"supported": True}
            entry.update(fields_for_type(sku, family, itype, branch, label))
            doc["interfaces"][out_name] = entry
        elif supported == "conditional":
            entry = {"supported": "conditional", "note": reason}
            entry.update(fields_for_type(sku, family, itype, branch, label))
            doc["interfaces"][out_name] = entry
        else:
            # only record unsupported if the type exists in this schema version
            if model_fields(branch, itype) is not None:
                doc["interfaces"][out_name] = {"supported": False, "reason": reason}
    return doc


def supported_set(doc):
    """set of (type, frozenset(fields)) signature for diffing across versions."""
    sig = {}
    for t, e in doc["interfaces"].items():
        if e.get("supported") in (True, "conditional"):
            sig[t] = set(e.get("fields", []))
        else:
            sig[t] = None  # explicitly unsupported
    return sig


def vrf_sig(doc):
    """Return VRF signature for diffing: (supported, max_vr)."""
    vrf = doc.get("routing", {}).get("vrf", {})
    return (vrf.get("supported", False), vrf.get("max_virtual_routers"))


def generate_model_incremental(sku, docs_by_branch, folder):
    lines = []
    lines.append(f"# {sku} \u2014 Interface & Routing Schema Incremental Updates\n")
    lines.append(f"Platform family: **{FAMILY_LABEL[SKU_FAMILY[sku]]}**\n")
    lines.append("Per-version changes to the interface-related schema and routing (VRF) "
                 "for this model (types enabled/disabled, fields added/removed, "
                 "VRF support changes).\n")

    prev_sig = None
    prev_vrf = None
    prev_label = None
    for branch, label in VERSIONS:
        doc = docs_by_branch[branch]
        sig = supported_set(doc)
        cur_vrf = vrf_sig(doc)
        if prev_sig is None:
            enabled = sorted([t for t, v in sig.items() if v is not None])
            lines.append(f"\n## FMC {label} (baseline)\n")
            lines.append("### Interfaces\n")
            lines.append("- **Supported interface types:** " +
                         (", ".join(f"`{t}`" for t in enabled) or "_none_"))
            # EtherChannel constraints
            family = SKU_FAMILY[sku]
            if family not in NO_ETHERCHANNEL_FAMILIES:
                ec_range = ec_id_range(family)
                max_m = ec_max_members(family)
                lines.append(f"- **EtherChannel ID range:** "
                             f"{ec_range['min']}-{ec_range['max']}")
                lines.append(f"- **Max active members per channel group:** {max_m}")
                if family in FXOS_ETHERCHANNEL_FAMILIES:
                    lines.append("- **Note:** EtherChannel configured in FXOS, not FMC")
            lines.append("\n### Routing\n")
            vrf_data = doc.get("routing", {}).get("vrf", {})
            if vrf_data.get("supported"):
                lines.append(f"- **VRF:** supported, max {vrf_data['max_virtual_routers']} "
                             f"virtual routers (incl. global)")
            else:
                reason = vrf_data.get("reason", "not supported")
                lines.append(f"- **VRF:** {reason}")
        else:
            seg = []
            # Interface type-level changes
            for t in sorted(set(sig) | set(prev_sig)):
                pv = prev_sig.get(t)
                cv = sig.get(t)
                if (pv is None or t not in prev_sig) and cv is not None:
                    seg.append(f"  - **+ type** `{t}` now supported")
                elif pv is not None and (cv is None or t not in sig):
                    seg.append(f"  - **- type** `{t}` no longer supported")
                elif pv is not None and cv is not None:
                    fa = sorted(cv - pv)
                    fr = sorted(pv - cv)
                    if fa:
                        seg.append(f"  - `{t}` +fields: " + ", ".join(f"`{x}`" for x in fa))
                    if fr:
                        seg.append(f"  - `{t}` -fields: " + ", ".join(f"`{x}`" for x in fr))
            # VRF changes
            vrf_seg = []
            if cur_vrf != prev_vrf:
                prev_sup, prev_max = prev_vrf
                cur_sup, cur_max = cur_vrf
                if not prev_sup and cur_sup:
                    vrf_seg.append(f"  - **+ VRF** now supported "
                                   f"(max {cur_max} virtual routers)")
                elif prev_sup and not cur_sup:
                    vrf_seg.append(f"  - **- VRF** no longer supported")
                elif prev_sup and cur_sup and prev_max != cur_max:
                    vrf_seg.append(f"  - **VRF scale change:** "
                                   f"{prev_max} \u2192 {cur_max} virtual routers")

            if seg or vrf_seg:
                lines.append(f"\n## FMC {label} \u2014 changes vs {prev_label}\n")
                if seg:
                    lines.append("### Interfaces\n")
                    lines.extend(seg)
                if vrf_seg:
                    lines.append("\n### Routing\n")
                    lines.extend(vrf_seg)
        prev_sig = sig
        prev_vrf = cur_vrf
        prev_label = label

    out = os.path.join(folder, f"{sku}_INCREMENTAL_UPDATES.md")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")


def generate_model_readme(sku, folder):
    family = SKU_FAMILY[sku]
    lines = []
    lines.append(f"# {sku} interface & routing schemas\n")
    lines.append(f"**Platform family:** {FAMILY_LABEL[family]}\n")
    lines.append("This folder contains the interface and routing schema for the "
                 f"`{sku}` model at each FMC version (`{sku}_interfaces_<ver>.json`) "
                 f"plus `{sku}_INCREMENTAL_UPDATES.md`.\n")
    lines.append("## Interface capability rules\n")
    caps = []
    sw_status = 'YES' if sku_has_switchport(sku, family) else 'no'
    caps.append(f"- Switchport / VLAN interfaces: {sw_status}")
    ec_status = 'no'
    if family not in NO_ETHERCHANNEL_FAMILIES:
        if family in FXOS_ETHERCHANNEL_FAMILIES:
            ec_status = 'YES (FXOS-managed only)'
        else:
            ec_status = 'YES'
    caps.append(f"- EtherChannel: {ec_status}")
    if family not in NO_ETHERCHANNEL_FAMILIES:
        ec_range = ec_id_range(family)
        max_m = ec_max_members(family)
        caps.append(f"  - ID range: {ec_range['min']}-{ec_range['max']}")
        caps.append(f"  - Max active members per group: {max_m}")
    caps.append(f"- Redundant interface: {'YES' if family in REDUNDANT_FAMILIES else 'no'}")
    caps.append(f"- PoE (powerOverEthernet): {'YES' if sku in POE_SKUS else 'no'}")
    caps.append(f"- LLDP: {'YES (version-gated)' if family in LLDP_MIN_VER else 'no'}")
    caps.append(f"- Cluster MAC pool (macAddressPool, 10.5+): "
                f"{'YES' if family in CLUSTER_FAMILIES else 'no'}")
    caps.append(f"- lacpRate (EtherChannel): {'YES' if family in LACPRATE_FAMILIES else 'no'}")
    caps.append(f"- Hardware autoNegState: {'YES' if family in HW_AUTONEG_FAMILIES else 'no'}")
    caps.append(f"- Hardware fecMode: {'YES' if family in HW_FEC_FAMILIES else 'no'}")
    caps.append(f"- Hardware flowControlSend (7.2+): "
                f"{'YES' if family in HW_FLOWCTRL_FAMILIES else 'no'}")
    lines.extend(caps)

    lines.append("\n## Routing capability rules\n")
    vrf_map = VRF_MAX.get(sku, {})
    if vrf_map:
        earliest = min(vrf_map.keys(), key=lambda v: fver_num(v))
        latest_max = vrf_map[max(vrf_map.keys(), key=lambda v: fver_num(v))]
        lines.append(f"- VRF: YES (from FMC {earliest})")
        lines.append(f"- Max virtual routers (latest): {latest_max} (incl. global VR)")
        # Show if scale changed
        unique_vals = sorted(set(vrf_map.values()))
        if len(unique_vals) > 1:
            lines.append(f"- VRF scale changes across versions: " +
                         ", ".join(str(v) for v in unique_vals))
    else:
        lines.append("- VRF: not supported")

    # Speed / Duplex / FEC section
    speeds = SPEED_SUPPORT.get(family)
    if speeds and (speeds["builtin"] or speeds["netmod"]):
        lines.append("\n## Supported hardware values\n")
        if speeds["builtin"]:
            lines.append(f"- **Built-in port speeds:** "
                         f"{', '.join(f'`{s}`' for s in speeds['builtin'])}")
        if speeds["netmod"]:
            lines.append(f"- **Network module speeds (additional):** "
                         f"{', '.join(f'`{s}`' for s in speeds['netmod'])}")
        lines.append(f"- _Note: {speeds['note']}_")
        duplex = DUPLEX_SUPPORT.get(family)
        if duplex:
            lines.append(f"- **Duplex values:** "
                         f"{', '.join(f'`{d}`' for d in duplex)}")
        fec = FEC_MODES.get(family)
        if fec:
            lines.append(f"- **FEC modes:** "
                         f"{', '.join(f'`{m}`' for m in fec)}")
    elif family == "FTDv":
        lines.append("\n## Supported hardware values\n")
        lines.append("- _Virtual platform — no hardware speed/duplex/FEC configuration._")

    lines.append("\n> Capability rules are derived from the FTL codebase "
                 "(`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) "
                 "and Cisco official documentation (VRF limits, EtherChannel guidelines). "
                 "SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from "
                 "hardware datasheets and may be adjusted as needed.\n")
    with open(os.path.join(folder, "README.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def generate_part2():
    # Clean old model_schemas directory to remove stale flat-SKU folders
    if os.path.exists(MODEL_DIR):
        shutil.rmtree(MODEL_DIR)
    os.makedirs(MODEL_DIR, exist_ok=True)

    for sku, family in SKU_FAMILY.items():
        fam_folder = os.path.join(MODEL_DIR, FAMILY_FOLDER[family])
        folder = os.path.join(fam_folder, sku)
        os.makedirs(folder, exist_ok=True)
        docs_by_branch = {}
        for branch, label in VERSIONS:
            doc = build_model_version(sku, family, branch, label)
            docs_by_branch[branch] = doc
            out = os.path.join(folder, f"{sku}_interfaces_{label}.json")
            with open(out, "w") as f:
                json.dump(doc, f, indent=2)
        generate_model_incremental(sku, docs_by_branch, folder)
        generate_model_readme(sku, folder)
        print(f"[part2] {FAMILY_FOLDER[family]}/{sku}: "
              f"{len(VERSIONS)} version files + changelog + readme")

    # top-level index
    idx = ["# Model-specific interface & routing schemas\n",
           "Organized by platform family. Each family folder contains per-SKU "
           "subfolders with interface and routing (VRF) schema files per FMC "
           "version plus incremental-updates changelogs.\n"]
    # Group by family
    families_seen = {}
    for sku, family in SKU_FAMILY.items():
        families_seen.setdefault(family, []).append(sku)
    for family in dict.fromkeys(SKU_FAMILY.values()):
        skus = families_seen[family]
        idx.append(f"\n## {FAMILY_LABEL[family]} (`{FAMILY_FOLDER[family]}/`)\n")
        for sku in skus:
            idx.append(f"- [`{sku}`]({FAMILY_FOLDER[family]}/{sku}/)")
    with open(os.path.join(MODEL_DIR, "README.md"), "w") as f:
        f.write("\n".join(idx) + "\n")


if __name__ == "__main__":
    generate_part1()
    generate_part2()
    print("done")
