"""Tests for File + Intrusion policy creation / reuse-by-name (dependent_policies)."""
import copy

from policy_configuration.models.schema import (
    AcpModel, PolicyConfig, PushSummary,
)
from policy_configuration.dependency_resolution.resolver import DependencyResolver
from policy_configuration.services import dependent_policies as dp
from .conftest import FakeFmcClient


def _acp_with_rule(rule: dict, default_action: dict | None = None) -> AcpModel:
    acp = AcpModel(name="A", source_id="acp-1")
    acp.access_rules = [rule]
    acp.default_action = default_action or {}
    return acp


def _resolver(source, target) -> DependencyResolver:
    return DependencyResolver(source, target, log=lambda m: None)


def test_reuse_intrusion_policy_by_name():
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://t", data={
        "policy/intrusionpolicies": [{"id": "t-ips", "name": "Balanced", "type": "IntrusionPolicy"}],
    })
    resolver = _resolver(source, target)
    acp = _acp_with_rule(
        {"id": "r1", "name": "r1", "type": "AccessRule",
         "ipsPolicy": {"id": "ips-1", "name": "Balanced", "type": "IntrusionPolicy"}})
    summary = PushSummary()
    dp.ensure_rule_policies([acp], PolicyConfig(), source, target, resolver, summary, lambda m: None)
    # Reused, not created; remap points the source id at the target id.
    assert resolver.remap_table.get("ips-1") == "t-ips"
    assert not any("policy/intrusionpolicies" == c["suffix"] for c in target.created)


def test_create_intrusion_policy_from_base_policy():
    source = FakeFmcClient(data={
        "policy/intrusionpolicies": [
            {"id": "ips-1", "name": "Custom-IPS", "type": "IntrusionPolicy",
             "inspectionMode": "DETECTION",
             "basePolicy": {"id": "b-src", "name": "Balanced Security and Connectivity",
                            "type": "IntrusionPolicy"}},
        ],
    })
    target = FakeFmcClient(fmc_ip="https://t", data={
        # Base policy exists on target under the same name.
        "policy/intrusionpolicies": [
            {"id": "b-tgt", "name": "Balanced Security and Connectivity", "type": "IntrusionPolicy"},
        ],
    })
    resolver = _resolver(source, target)
    acp = _acp_with_rule(
        {"id": "r1", "name": "r1", "type": "AccessRule",
         "ipsPolicy": {"id": "ips-1", "name": "Custom-IPS", "type": "IntrusionPolicy"}})
    summary = PushSummary()
    dp.ensure_rule_policies([acp], PolicyConfig(), source, target, resolver, summary, lambda m: None)
    created = [c for c in target.created if c["suffix"] == "policy/intrusionpolicies"]
    assert created and created[0]["body"]["name"] == "Custom-IPS"
    # basePolicy remapped to the target id.
    assert created[0]["body"]["basePolicy"]["id"] == "b-tgt"
    assert resolver.remap_table.get("ips-1") == created[0]["id"]
    assert any("Custom-IPS" in n for n in summary.objects_created)


def test_intrusion_policy_skipped_when_base_absent():
    source = FakeFmcClient(data={
        "policy/intrusionpolicies": [
            {"id": "ips-1", "name": "Custom-IPS", "type": "IntrusionPolicy",
             "basePolicy": {"id": "b-src", "name": "Nonexistent Base", "type": "IntrusionPolicy"}},
        ],
    })
    target = FakeFmcClient(fmc_ip="https://t", data={})
    resolver = _resolver(source, target)
    acp = _acp_with_rule(
        {"id": "r1", "name": "r1", "type": "AccessRule",
         "ipsPolicy": {"id": "ips-1", "name": "Custom-IPS", "type": "IntrusionPolicy"}})
    summary = PushSummary()
    dp.ensure_rule_policies([acp], PolicyConfig(), source, target, resolver, summary, lambda m: None)
    assert "ips-1" not in resolver.remap_table
    assert not any(c["suffix"] == "policy/intrusionpolicies" for c in target.created)


def test_create_file_policy_clones_file_rules():
    source = FakeFmcClient(data={
        "policy/filepolicies": [
            {"id": "fp-1", "name": "Malware", "type": "FilePolicy", "description": "d"},
        ],
        "policy/filepolicies/fp-1/filerules": [
            {"id": "frr-1", "name": "rule-a", "type": "FileRule", "action": "BLOCK",
             "links": {"self": "x"}},
        ],
    })
    target = FakeFmcClient(fmc_ip="https://t", data={})
    resolver = _resolver(source, target)
    acp = _acp_with_rule(
        {"id": "r1", "name": "r1", "type": "AccessRule",
         "filePolicy": {"id": "fp-1", "name": "Malware", "type": "FilePolicy"}})
    summary = PushSummary()
    dp.ensure_rule_policies([acp], PolicyConfig(), source, target, resolver, summary, lambda m: None)
    fp_created = [c for c in target.created if c["suffix"] == "policy/filepolicies"]
    assert fp_created and fp_created[0]["body"]["name"] == "Malware"
    new_id = fp_created[0]["id"]
    # File rule cloned under the new policy, with server keys stripped.
    fr_created = [c for c in target.created
                  if c["suffix"] == f"policy/filepolicies/{new_id}/filerules"]
    assert fr_created and fr_created[0]["body"]["name"] == "rule-a"
    assert "id" not in fr_created[0]["body"] and "links" not in fr_created[0]["body"]
    assert resolver.remap_table.get("fp-1") == new_id


def test_match_assigned_policy_by_name():
    target = FakeFmcClient(fmc_ip="https://t", data={
        "policy/prefilterpolicies": [{"id": "pp-9", "name": "Corp-Prefilter", "type": "PrefilterPolicy"}],
    })
    assert dp.match_assigned_policy_by_name(target, ["policy/prefilterpolicies"], "Corp-Prefilter") == "pp-9"
    assert dp.match_assigned_policy_by_name(target, ["policy/prefilterpolicies"], "Missing") == ""
