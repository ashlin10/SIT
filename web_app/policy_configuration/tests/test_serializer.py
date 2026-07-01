"""Tests for YAML build/parse, round-trip fidelity, and structural validation.

The source YAML is a faithful JSON->YAML conversion of FMC payloads laid out in
the flat, Device-Configuration style (``access_policies`` + dependent-policy
subsections + a nested ``objects`` block). No synthetic/migration fields.
"""
import pytest

from policy_configuration.models.schema import (
    AcpModel, PolicyConfig, build_objects_block, ungroup_objects,
)
from policy_configuration.yaml.serializer import (
    build_yaml, parse_yaml, validate_structure, StructureError,
)


def _sample_config() -> PolicyConfig:
    acp = AcpModel(name="Corp-ACP", source_id="acp-1")
    acp.raw_base = {
        "id": "acp-1", "name": "Corp-ACP", "type": "AccessPolicy",
        "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"},
        "prefilterPolicySetting": {"id": "pf-1", "name": "PF", "type": "PrefilterPolicy"},
    }
    acp.access_rules = [{"id": "r-1", "name": "r1", "type": "AccessRule", "action": "ALLOW"}]
    acp.derive_from_raw()
    acp.fetched = True
    cfg = PolicyConfig()
    cfg.acps.append(acp)
    cfg.policies["prefilter_policies"] = [
        {"id": "pf-1", "name": "PF", "type": "PrefilterPolicy"},
    ]
    cfg.objects = [
        {"id": "h-1", "name": "web1", "type": "Host", "value": "10.0.0.1"},
        {"id": "p-1", "name": "FTP", "type": "ProtocolPortObject", "port": "21"},
    ]
    return cfg


def test_build_yaml_top_level_shape():
    cfg = _sample_config()
    text = build_yaml(cfg)
    assert "access_policies:" in text
    assert "Corp-ACP" in text
    assert "accessrules:" in text
    assert "prefilter_policies:" in text
    # Nested DC-style objects block.
    assert "objects:" in text
    assert "network:" in text
    assert "hosts:" in text
    assert "port:" in text
    # No legacy 'policy:' wrapper, no synthetic keys.
    assert not text.startswith("policy:")
    assert "source_id:" not in text
    assert "target_id:" not in text
    assert "action: pending" not in text


def test_round_trip_faithful():
    cfg = _sample_config()
    text1 = build_yaml(cfg)
    parsed = parse_yaml(text1)
    text2 = build_yaml(parsed)
    # Deterministic, byte-identical re-serialization.
    assert text1 == text2
    assert parsed.acps[0].name == "Corp-ACP"
    assert parsed.acps[0].rule_count() == 1
    # Raw ACP payload preserved verbatim (incl. id + assigned-policy ref).
    assert parsed.acps[0].raw_base["id"] == "acp-1"
    assert parsed.acps[0].raw_base["prefilterPolicySetting"]["id"] == "pf-1"
    # Derived (in-memory) assigned policy recovered on parse.
    assert parsed.acps[0].assigned_policies["prefilterPolicy"].name == "PF"
    # Dependent policies + objects recovered.
    assert parsed.policies["prefilter_policies"][0]["id"] == "pf-1"
    assert {o["type"] for o in parsed.objects} == {"Host", "ProtocolPortObject"}


def test_no_synthetic_fields_in_payloads():
    """Faithful payloads: every object keeps only source keys."""
    cfg = _sample_config()
    doc = cfg.to_yaml_doc()
    host = doc["objects"]["network"]["hosts"][0]
    assert set(host.keys()) == {"id", "name", "type", "value"}
    acp = doc["access_policies"][0]
    assert "source_id" not in acp and "_sourceId" not in acp
    assert "assignedPolicies" not in acp  # raw refs only, no synthetic wrapper


def test_objects_block_nested_layout():
    objs = [
        {"id": "1", "type": "Host", "name": "h1"},
        {"id": "2", "type": "Network", "name": "net1"},
        {"id": "3", "type": "ProtocolPortObject", "name": "p1"},
        {"id": "4", "type": "Application", "name": "AOL"},
        {"id": "5", "type": "SecurityZone", "name": "inside"},
    ]
    block = build_objects_block(objs)
    assert block["network"]["hosts"][0]["name"] == "h1"
    assert block["network"]["networks"][0]["name"] == "net1"
    assert block["port"]["objects"][0]["name"] == "p1"
    assert block["interface"]["security_zones"][0]["name"] == "inside"
    # ACP-specific category with no DC equivalent uses a flat snake_case key.
    assert block["applications"][0]["name"] == "AOL"
    # Round-trips back to a flat list.
    assert len(ungroup_objects(block)) == 5


def test_objects_block_dedup_by_id():
    objs = [
        {"id": "1", "type": "Host", "name": "h1"},
        {"id": "1", "type": "Host", "name": "h1-dup"},  # same id
    ]
    block = build_objects_block(objs)
    assert len(block["network"]["hosts"]) == 1


def test_validate_structure_missing_access_policies():
    with pytest.raises(StructureError):
        validate_structure({"objects": {}})


def test_validate_structure_duplicate_acp_names():
    doc = {"access_policies": [
        {"name": "A", "accessrules": []},
        {"name": "a", "accessrules": []},  # case-insensitive duplicate
    ]}
    with pytest.raises(StructureError) as ei:
        validate_structure(doc)
    assert any("duplicate" in e.lower() for e in ei.value.errors)


def test_validate_structure_bad_rule_type():
    doc = {"access_policies": [{"name": "A", "accessrules": {"not": "a list"}}]}
    with pytest.raises(StructureError):
        validate_structure(doc)


def test_validate_structure_bad_objects_type():
    doc = {"access_policies": [{"name": "A", "accessrules": []}], "objects": [1, 2]}
    with pytest.raises(StructureError):
        validate_structure(doc)


def test_parse_invalid_yaml():
    with pytest.raises(StructureError):
        parse_yaml(":\n  - [unbalanced")


def test_validate_structure_nested_objects_ok():
    doc = {"access_policies": [{"name": "A", "accessrules": []}],
           "objects": {"network": {"hosts": [{"type": "Host", "name": "h1", "id": "1"}]},
                       "applications": [{"type": "Application", "name": "AOL", "id": "2"}]}}
    warnings = validate_structure(doc)
    assert isinstance(warnings, list)


def test_legacy_policy_wrapper_still_parses():
    """A legacy ``policy:``-wrapped document is normalized + parsed."""
    text = (
        "policy:\n"
        "  accesspolicies:\n"
        "    - id: acp-9\n"
        "      name: Legacy-ACP\n"
        "      type: AccessPolicy\n"
        "      accessrules: []\n"
    )
    cfg = parse_yaml(text)
    assert cfg.acps[0].name == "Legacy-ACP"
    assert cfg.acps[0].raw_base["id"] == "acp-9"
