"""Tests for the deterministic pre-push validation engine.

Run from the repo root:
    python3 -m pytest web_app/pre_push_validation/tests -q
"""
import os
import sys

import pytest

# Make the web_app package importable regardless of CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
_WEB_APP = os.path.dirname(os.path.dirname(_HERE))
if _WEB_APP not in sys.path:
    sys.path.insert(0, _WEB_APP)

from pre_push_validation import sanitize_config, validate_config  # noqa: E402
from pre_push_validation.model_resolver import (  # noqa: E402
    resolve_ftl_branch,
    resolve_model_label,
    resolve_sku,
)
from pre_push_validation.schema_loader import load_model_schema  # noqa: E402


# ── model_resolver ──

@pytest.mark.parametrize("model_string,expected", [
    ("Cisco Firepower 4145 Threat Defense", "4145"),
    ("Cisco Secure Firewall 3120 Threat Defense", "3120"),
    ("Cisco Firepower 1010 Threat Defense", "1010"),
    ("Cisco Firepower Threat Defense for VMware", "FTDv"),
    ("Cisco Firepower Threat Defense for KVM", "FTDv"),
    ("Cisco ISA3000 Threat Defense", "ISA3000"),
    ("Secure Firewall 9300", "9300"),
    ("Totally Unknown Box", None),
])
def test_resolve_sku(model_string, expected):
    assert resolve_sku(model_string) == expected


def test_resolve_model_label_exact_and_closest():
    assert resolve_model_label("7.4.1 (build 172)") == "7.4.1"
    assert resolve_model_label("7.2.0") == "7.2"
    # Between 7.4.1 and 7.6 -> rounds down to 7.4.1
    assert resolve_model_label("7.5.0") == "7.4.1"


def test_resolve_ftl_branch():
    assert resolve_ftl_branch("7.4") == "IMS_7_4_MAIN"
    assert resolve_ftl_branch("7.5") == "IMS_7_4_1_MAIN"


# ── model_validator (real 220 schema) ──

def _base_config():
    return {
        "physical_interfaces": [
            {
                "type": "PhysicalInterface", "name": "Ethernet1/1", "ifname": "outside",
                "hardware": {"speed": "THOUSAND", "fecMode": "AUTO"},
                "LLDP": {"transmit": True},
            },
            {"type": "PhysicalInterface", "name": "Ethernet9/9", "ifname": "mgmtx"},
        ],
        "routing": {"vrfs": [{"type": "VirtualRouter", "name": "vr1"}]},
    }


def test_model_schema_loads():
    assert load_model_schema("220", "7.4") is not None


def test_model_excluded_and_vrf_issues():
    rep = validate_config(
        _base_config(), [], raw_model="220", raw_version="7.4", fmc_version="7.4",
    )
    d = rep.to_dict()
    fields = {i["field"] for i in d["issues"]}
    # LLDP + powerOverEthernet excluded on 220; fecMode hardware excluded.
    assert "LLDP" in fields
    assert "hardware.fecMode" in fields
    # VRF not supported on 220 until 10.5.
    assert any(i["section"] == "routing.vrfs" for i in d["issues"])
    # Excluded-field issues are reported once per type, not per item.
    assert sum(1 for i in d["issues"] if i["field"] == "LLDP") == 1


# ── interface_validator ──

def test_interface_conflict_detection_and_suggestion():
    config = _base_config()
    target_ifaces = [
        {"type": "PhysicalInterface", "name": "Ethernet1/1"},
        {"type": "PhysicalInterface", "name": "Ethernet1/2"},
    ]
    rep = validate_config(
        config, target_ifaces, raw_model="220", raw_version="7.4", fmc_version="7.4",
    )
    d = rep.to_dict()
    names = {c["sourceName"] for c in d["interfaceConflicts"]}
    assert "Ethernet9/9" in names      # missing on target
    assert "Ethernet1/1" not in names  # present on target
    conflict = next(c for c in d["interfaceConflicts"] if c["sourceName"] == "Ethernet9/9")
    assert conflict["suggestedTarget"] in ("Ethernet1/1", "Ethernet1/2")


# ── oas_schema_validator (field-level validation) ──

def test_fmc_unknown_field_flagged():
    config = {
        "physical_interfaces": [
            {"type": "PhysicalInterface", "name": "Ethernet1/1", "ifname": "x",
             "totallyBogusField": 1},
        ],
    }
    rep = validate_config(
        config, [{"name": "Ethernet1/1"}], raw_model="4145", raw_version="7.4",
        fmc_version="7.4",
    )
    d = rep.to_dict()
    assert any(i["category"] == "fmc_field" and "totallyBogusField" in i["field"]
               for i in d["issues"])


# ── sanitizer ──

def test_sanitize_removes_fields_and_remaps_interfaces():
    config = _base_config()
    out = sanitize_config(
        config, raw_model="220", raw_version="7.4", fmc_version="7.4",
        interface_mappings={"Ethernet9/9": "Ethernet1/2"},
        accepted_issue_ids=None,  # apply all auto-fixes
    )
    sc = out["sanitized_config"]
    pi = sc["physical_interfaces"]
    # LLDP + hardware.fecMode removed.
    assert "LLDP" not in pi[0]
    assert "fecMode" not in pi[0].get("hardware", {})
    # VRF section removed.
    assert "vrfs" not in (sc.get("routing") or {})
    # Interface remapped.
    assert pi[1]["name"] == "Ethernet1/2"
    # Original input not mutated.
    assert config["physical_interfaces"][1]["name"] == "Ethernet9/9"
    assert "LLDP" in config["physical_interfaces"][0]
    # Diff + change list populated.
    assert out["diff"]
    assert any("Remapped interface" in c for c in out["changes"])


def test_sanitize_respects_accepted_ids():
    config = _base_config()
    out = sanitize_config(
        config, raw_model="220", raw_version="7.4", fmc_version="7.4",
        interface_mappings={},
        accepted_issue_ids=[],  # accept nothing -> no field removals
    )
    sc = out["sanitized_config"]
    assert "LLDP" in sc["physical_interfaces"][0]


def test_subinterface_parent_rename():
    config = {
        "subinterfaces": [
            {"type": "SubInterface", "name": "Ethernet9/9.100", "parentName": "Ethernet9/9"},
        ],
    }
    out = sanitize_config(
        config, raw_model="220", raw_version="7.4", fmc_version="7.4",
        interface_mappings={"Ethernet9/9": "Ethernet1/2"},
        accepted_issue_ids=[],
    )
    si = out["sanitized_config"]["subinterfaces"][0]
    assert si["name"] == "Ethernet1/2.100"
    assert si["parentName"] == "Ethernet1/2"
