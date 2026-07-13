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


def test_decryption_rules_preserve_refs_and_category():
    """Regression: cloning a Decryption policy must remap sourceNetworks /
    sourceZones to their target ids (not drop them) and recreate rules in their
    source category via the ?category= query parameter."""
    target = FakeFmcClient(fmc_ip="https://t", data={})
    resolver = _resolver(FakeFmcClient(data={}), target)
    # The objects the rule references were reused on the target already.
    resolver.register_remap("src-grp", "tgt-grp")
    resolver.register_remap("src-zone-a", "tgt-zone-a")
    resolver.register_remap("src-zone-b", "tgt-zone-b")

    cfg = PolicyConfig()
    cfg.policies["decryption_policies"] = [{
        "id": "dp-src", "name": "Goes - SSL / TLS Decrypt", "type": "DecryptionPolicy",
        "decryptionpolicyrules": [{
            "id": "dr-1", "name": "Inspect HTTP(S)", "type": "DecryptionPolicyRule",
            "ruleAction": "DECRYPT_RESIGN",
            "metadata": {"ruleIndex": 11, "category": {"name": "Outbound"}},
            "sourceNetworks": {"objects": [
                {"type": "NetworkGroup", "name": "grp.local", "id": "src-grp"}]},
            "sourceZones": {"objects": [
                {"type": "SecurityZone", "name": "zone.switch", "id": "src-zone-a"}]},
            "destinationZones": {"objects": [
                {"type": "SecurityZone", "name": "zone.firewall", "id": "src-zone-b"}]},
        }],
    }]
    summary = PushSummary()
    new_id = dp.create_assigned_policy(
        "DecryptionPolicy", "Goes - SSL / TLS Decrypt", "dp-src",
        cfg, target, resolver, lambda m: None, summary=summary)
    assert new_id

    rule_posts = [c for c in target.created if "decryptionpolicyrules" in c["suffix"]]
    assert len(rule_posts) == 1
    posted = rule_posts[0]
    # Rules are now bulk-pushed without category (FMC rejects ?category= on
    # bulk POST for decryption rules). Verify no category param is present.
    assert "category=" not in posted["suffix"]
    # References remapped to target ids and NOT dropped.
    body = posted["body"]
    assert body["sourceNetworks"]["objects"][0]["id"] == "tgt-grp"
    assert body["sourceZones"]["objects"][0]["id"] == "tgt-zone-a"
    # Zones are preserved as-is; reactive stripping only happens when the
    # FMC rejects the rule with a "same zone object" error.
    assert body["destinationZones"]["objects"][0]["id"] == "tgt-zone-b"


def test_decryption_rules_reactive_zone_strip():
    """When FMC rejects a decryption rule with the 'same zone object' error,
    the zones should be stripped and the rule retried successfully."""
    from policy_configuration.services.client import FmcApiError

    call_count = 0

    class ZoneErrorFmcClient(FakeFmcClient):
        """Raises the zone error on the first POST of a decryption rule,
        then accepts the retry (without zones)."""
        def post(self, path, body, *, bulk=False):
            nonlocal call_count
            if bulk:
                # Force per-rule fallback by failing the bulk POST.
                raise FmcApiError("bulk unsupported")
            if "decryptionpolicyrules" in self._suffix(path):
                call_count += 1
                if call_count == 1:
                    # First attempt: body still has zones → reject.
                    raise FmcApiError(
                        "You must use the same zone object for both "
                        "source and destination zones", status=400)
            return super().post(path, body, bulk=bulk)

    target = ZoneErrorFmcClient(fmc_ip="https://t", data={})
    resolver = _resolver(FakeFmcClient(data={}), target)
    resolver.register_remap("src-grp", "tgt-grp")
    resolver.register_remap("src-zone-a", "tgt-zone-a")
    resolver.register_remap("src-zone-b", "tgt-zone-b")

    cfg = PolicyConfig()
    cfg.policies["decryption_policies"] = [{
        "id": "dp-src", "name": "Dec-Test", "type": "DecryptionPolicy",
        "decryptionpolicyrules": [{
            "id": "dr-1", "name": "Zone-Mismatch-Rule", "type": "DecryptionPolicyRule",
            "ruleAction": "DECRYPT_RESIGN",
            "metadata": {"ruleIndex": 1},
            "sourceNetworks": {"objects": [
                {"type": "NetworkGroup", "name": "grp.local", "id": "src-grp"}]},
            "sourceZones": {"objects": [
                {"type": "SecurityZone", "name": "zone.switch", "id": "src-zone-a"}]},
            "destinationZones": {"objects": [
                {"type": "SecurityZone", "name": "zone.firewall", "id": "src-zone-b"}]},
        }],
    }]
    summary = PushSummary()
    logs = []
    new_id = dp.create_assigned_policy(
        "DecryptionPolicy", "Dec-Test", "dp-src",
        cfg, target, resolver, logs.append, summary=summary)
    assert new_id
    # The rule must have been pushed successfully on the retry.
    assert len(summary.dep_policy_rules_pushed) == 1
    assert len(summary.dep_policy_rules_failed) == 0
    # The retry should have been attempted (2 calls: first fail, second ok).
    assert call_count == 2
    # Verify the retried body has zones stripped.
    rule_posts = [c for c in target.created if "decryptionpolicyrules" in c["suffix"]]
    assert len(rule_posts) == 1
    body = rule_posts[0]["body"]
    assert "sourceZones" not in body
    assert "destinationZones" not in body
    # sourceNetworks should still be intact.
    assert body["sourceNetworks"]["objects"][0]["id"] == "tgt-grp"
    # Log should mention the zone strip.
    assert any("stripped zones" in l for l in logs)


def test_security_intelligence_policy_not_created():
    """SI policies are ACP-scoped (GET-only); create_assigned_policy must skip
    them cleanly instead of POSTing to a non-existent endpoint (HTTP 404)."""
    target = FakeFmcClient(fmc_ip="https://t", data={})
    resolver = _resolver(FakeFmcClient(data={}), target)
    cfg = PolicyConfig()
    cfg.policies["security_intelligence_policies"] = [
        {"id": "si-1", "name": "", "type": "SecurityIntelligencePolicy"}]
    new_id = dp.create_assigned_policy(
        "SecurityIntelligencePolicy", "", "si-1", cfg, target, resolver,
        lambda m: None, summary=PushSummary())
    assert new_id == ""
    assert not target.created


def test_match_assigned_policy_by_name():
    target = FakeFmcClient(fmc_ip="https://t", data={
        "policy/prefilterpolicies": [{"id": "pp-9", "name": "Corp-Prefilter", "type": "PrefilterPolicy"}],
    })
    assert dp.match_assigned_policy_by_name(target, ["policy/prefilterpolicies"], "Corp-Prefilter") == "pp-9"
    assert dp.match_assigned_policy_by_name(target, ["policy/prefilterpolicies"], "Missing") == ""
