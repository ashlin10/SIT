"""End-to-end push tests with mocked FMC: object creation, ACP create/update,
rule push, assigned-policy create/override mappings, conflicts, and summary."""
import copy

from policy_configuration.models.schema import PolicyConfig, PushSummary
from policy_configuration.services import acp_fetch
from policy_configuration.services import push as push_svc
from policy_configuration.services.client import FmcApiError
from .conftest import FakeFmcClient


def _config_from_source(source: FakeFmcClient) -> PolicyConfig:
    """Build a self-contained config the way a real fetch does: full object
    bodies + dependent-policy definitions embedded, so the push runs offline."""
    acp, policies, objects = acp_fetch.fetch_acp_full(source, "acp-1")
    cfg = PolicyConfig()
    cfg.upsert_acp(acp)
    for sub, items in policies.items():
        cfg.upsert_policies(sub, items)
    cfg.upsert_objects(objects)
    return cfg


def test_push_creates_objects_and_acp(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)

    result = push_svc.push(
        cfg, ["Corp-ACP"], source, target,
        validate=False, bulk=True,
    )
    assert result["success"] is True
    summary = result["summary"]
    assert "Corp-ACP" in summary["successful_acps"]
    # The two hosts + port object were created on the target.
    assert set(summary["objects_created"]) >= {"web1", "web2", "FTP"}
    # An ACP and its rules were posted to the target.
    posted_suffixes = [c["suffix"] for c in target.created]
    assert any(s.endswith("policy/accesspolicies") for s in posted_suffixes)
    assert any("accessrules" in s for s in posted_suffixes)


def test_push_offline_without_source(acp_base):
    """The push runs entirely from the fetched YAML: source=None, no source
    contact. Objects + ACP + rules are all created on the target."""
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    cfg = _config_from_source(source)  # self-contained config (full bodies)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})

    result = push_svc.push(cfg, ["Corp-ACP"], None, target, validate=False, bulk=True)
    assert result["success"] is True
    summary = result["summary"]
    assert "Corp-ACP" in summary["successful_acps"]
    assert set(summary["objects_created"]) >= {"web1", "web2", "FTP"}
    assert len(summary["rules_pushed"]) == 2


def test_push_offline_creates_file_policy_from_embedded_rules():
    """A File policy is created and its file rules cloned from the YAML-embedded
    ``fileRules`` — no source FMC access."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW",
             "logFiles": True,
             "filePolicy": {"id": "fp-1", "name": "Malware", "type": "FilePolicy"}},
        ],
        "policy/filepolicies": [{"id": "fp-1", "name": "Malware", "type": "FilePolicy"}],
        "policy/filepolicies/fp-1/filerules": [
            {"id": "fr-1", "name": "block-exe", "type": "FileRule", "action": "BLOCK"},
        ],
    }
    source = FakeFmcClient(data=data)
    cfg = _config_from_source(source)
    # Prove offline: no source client is passed to push.
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    result = push_svc.push(cfg, ["A"], None, target, validate=False, bulk=True)
    assert result["success"] is True
    fp_created = [c for c in target.created if c["suffix"] == "policy/filepolicies"]
    assert fp_created and fp_created[0]["body"]["name"] == "Malware"
    new_id = fp_created[0]["id"]
    fr_created = [c for c in target.created
                 if c["suffix"] == f"policy/filepolicies/{new_id}/filerules"]
    assert fr_created and fr_created[0]["body"]["name"] == "block-exe"


def test_access_rules_preserve_section_and_category():
    """Access rules are recreated in their source section/category: the user
    category is created on the ACP and rules are posted with ?category= (or
    ?section= for uncategorized Mandatory rules)."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "vpn-rule", "type": "AccessRule", "action": "ALLOW",
             "metadata": {"ruleIndex": 1, "section": "Mandatory",
                          "category": "Site-2-Site VPN"}},
            {"id": "r2", "name": "mand-rule", "type": "AccessRule", "action": "ALLOW",
             "metadata": {"ruleIndex": 2, "section": "Mandatory",
                          "category": "--Undefined--"}},
            {"id": "r3", "name": "default-rule", "type": "AccessRule", "action": "ALLOW",
             "metadata": {"ruleIndex": 3, "section": "Default",
                          "category": "--Undefined--"}},
        ],
    }
    source = FakeFmcClient(data=data)
    cfg = _config_from_source(source)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    result = push_svc.push(cfg, ["A"], None, target, validate=False, bulk=True)
    assert result["success"] is True

    # The user category was created on the ACP.
    cat_posts = [c for c in target.created if c["suffix"].endswith("/categories")]
    assert cat_posts and cat_posts[0]["body"]["name"] == "Site-2-Site VPN"

    rule_suffixes = [c["suffix"] for c in target.created if "accessrules" in c["suffix"]]
    # The VPN rule is posted into its category; the Mandatory-uncategorized rule
    # carries a section param; the Default rule carries neither.
    assert any("accessrules?category=Site-2-Site%20VPN" in s for s in rule_suffixes)
    assert any("accessrules?section=Mandatory" in s for s in rule_suffixes)
    assert any(s.endswith("accessrules") for s in rule_suffixes)
    # All three rules were recorded as pushed.
    assert len(result["summary"]["rules_pushed"]) == 3


def test_push_creates_assigned_policies_from_embedded_definitions():
    """Prefilter, Identity, and Decryption policies are created on the target
    from their embedded definitions when they don't already exist."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"},
             "prefilterPolicySetting": {"id": "pf-1", "name": "PF", "type": "PrefilterPolicy"},
             "identityPolicySetting": {"id": "ip-1", "name": "IP", "type": "IdentityPolicy"},
             "decryptionPolicySetting": {"id": "dp-1", "name": "DP", "type": "DecryptionPolicy"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW"},
        ],
        "policy/prefilterpolicies": [{"id": "pf-1", "name": "PF", "type": "PrefilterPolicy"}],
        "policy/prefilterpolicies/pf-1/prefilterrules": [
            {"id": "pr-1", "name": "pfr", "type": "PrefilterRule", "action": "ANALYZE"},
        ],
        "policy/identitypolicies": [{"id": "ip-1", "name": "IP", "type": "IdentityPolicy"}],
        "policy/identitypolicies/ip-1/identityrules": [
            {"id": "ir-1", "name": "idr", "type": "IdentityRule", "action": "PASSIVE_AUTH"},
        ],
        "policy/decryptionpolicies": [{"id": "dp-1", "name": "DP", "type": "DecryptionPolicy"}],
        "policy/decryptionpolicies/dp-1/decryptionpolicyrules": [
            {"id": "dr-1", "name": "decr", "type": "DecryptionRule", "action": "DO_NOT_DECRYPT"},
        ],
    }
    source = FakeFmcClient(data=data)
    cfg = _config_from_source(source)
    # IdentityPolicy POST is only available from FMC 10.0.
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={}, version="10.0.0")
    result = push_svc.push(cfg, ["A"], None, target, validate=False, bulk=True)
    assert result["success"] is True

    created_suffixes = [c["suffix"] for c in target.created]
    # Containers were created.
    assert any(s.endswith("policy/prefilterpolicies") for s in created_suffixes)
    assert any(s.endswith("policy/identitypolicies") for s in created_suffixes)
    assert any(s.endswith("policy/decryptionpolicies") for s in created_suffixes)
    # Rules were cloned under each created container.
    assert any("prefilterrules" in s for s in created_suffixes)
    assert any("identityrules" in s for s in created_suffixes)
    assert any("decryptionpolicyrules" in s for s in created_suffixes)
    # Summary should list them as created.
    summary = result["summary"]
    created_names = " ".join(summary["objects_created"])
    assert "PF" in created_names
    assert "IP" in created_names
    assert "DP" in created_names


def test_push_continues_when_dependent_policy_create_fails():
    """A dependent File policy that fails to create is skipped with a warning;
    the rest of the push still completes."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW",
             "filePolicy": {"id": "fp-1", "name": "Malware", "type": "FilePolicy"}},
        ],
        "policy/filepolicies": [{"id": "fp-1", "name": "Malware", "type": "FilePolicy"}],
    }
    source = FakeFmcClient(data=data)
    cfg = _config_from_source(source)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    orig_post = target.post

    def failing_post(path, body, *, bulk=False):
        if path.endswith("policy/filepolicies") and not bulk:
            raise FmcApiError("file policy create rejected", 422)
        return orig_post(path, body, bulk=bulk)

    target.post = failing_post
    result = push_svc.push(cfg, ["A"], None, target, validate=False, bulk=True)
    # ACP + its rule still push despite the file policy create failure.
    assert "A" in result["summary"]["successful_acps"]
    assert len(result["summary"]["rules_pushed"]) == 1
    skipped = " ".join(result["summary"]["skipped_settings"])
    assert "Malware" in skipped


def test_push_remaps_rule_object_ids(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False, bulk=True)
    # Find a pushed access rule and ensure its source host id was remapped.
    rule_posts = [c for c in target.created if "accessrules" in c["suffix"]]
    assert rule_posts
    for rp in rule_posts:
        body = rp["body"]
        for ref in (body.get("sourceNetworks", {}) or {}).get("objects", []):
            assert not str(ref.get("id", "")).startswith("h-")  # remapped away from source id


def test_push_creates_missing_file_policy(acp_base):
    """A referenced File policy absent on the target is created (not pruned),
    and the rule reference is remapped to the newly created target id."""
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False, bulk=True)
    summary = result["summary"]
    assert len(summary["rules_pushed"]) == 2
    # The File policy was created on the target.
    assert any("Block-Malware" in n for n in summary["objects_created"])
    fp_posts = [c for c in target.created if c["suffix"].endswith("policy/filepolicies")]
    assert fp_posts and fp_posts[0]["body"].get("name") == "Block-Malware"
    # rule-1's filePolicy was remapped away from the source id (fp-1), not pruned.
    rule_posts = [c for c in target.created if "accessrules" in c["suffix"]]
    fp_ids = [rp["body"].get("filePolicy", {}).get("id")
              for rp in rule_posts if rp["body"].get("filePolicy")]
    assert fp_ids and all(fid and fid != "fp-1" for fid in fp_ids)


def test_push_skips_identity_policy_create_below_10():
    """FMC < 10.0 has no POST on policy/identitypolicies: never attempt it."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"},
             "identityPolicySetting": {"id": "ip-1", "name": "IP", "type": "IdentityPolicy"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW"},
        ],
        "policy/identitypolicies": [{"id": "ip-1", "name": "IP", "type": "IdentityPolicy"}],
    }
    source = FakeFmcClient(data=data)
    cfg = _config_from_source(source)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={}, version="7.6.6")
    result = push_svc.push(cfg, ["A"], None, target, validate=False, bulk=True)
    assert "A" in result["summary"]["successful_acps"]
    assert not any(c["suffix"].endswith("policy/identitypolicies") for c in target.created)


def test_push_variable_set_is_reused_or_pruned_never_created():
    """VariableSet is GET-only in the FMC API: a missing one is pruned from the
    rule (never POSTed); an existing same-named one is reused/remapped."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW",
             "variableSet": {"id": "vs-9", "name": "Ghost-VarSet", "type": "VariableSet"}},
        ],
    }
    source = FakeFmcClient(data=data)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["A"], source, target, validate=False, bulk=True)
    summary = result["summary"]
    assert len(summary["rules_pushed"]) == 1
    assert not [c for c in target.created if "variablesets" in c["suffix"]]
    rule_posts = [c for c in target.created if "accessrules" in c["suffix"]]
    assert rule_posts and all("variableSet" not in rp["body"] for rp in rule_posts)

    # Present on the target by name -> reused and remapped.
    target2 = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "object/variablesets": [
            {"id": "tgt-vs", "name": "Ghost-VarSet", "type": "VariableSet"}]})
    push_svc.push(_config_from_source(source), ["A"], source, target2,
                  validate=False, bulk=True)
    rule_posts = [c for c in target2.created if "accessrules" in c["suffix"]]
    assert rule_posts and rule_posts[0]["body"]["variableSet"]["id"] == "tgt-vs"


def test_push_remaps_rule_policy_ref_when_present_on_target(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "policy/filepolicies": [{"id": "tgt-fp", "name": "Block-Malware", "type": "FilePolicy"}],
    })
    cfg = _config_from_source(source)
    push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False, bulk=True)
    rule_posts = [c for c in target.created if "accessrules" in c["suffix"]]
    fp = [rp["body"].get("filePolicy") for rp in rule_posts if rp["body"].get("filePolicy")]
    assert fp and all(f.get("id") == "tgt-fp" for f in fp)


def test_push_per_rule_fallback_records_failures(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    target.fail_bulk = True  # force bulk failure -> per-rule path
    orig_post = target.post

    def flaky_post(path, body, *, bulk=False):
        if not bulk and "accessrules" in path and isinstance(body, dict) \
                and body.get("name") == "Block-FTP":
            raise FmcApiError("rule rejected", 400)
        return orig_post(path, body, bulk=bulk)

    target.post = flaky_post
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False,
                           bulk=True, per_rule_fallback=True)
    summary = result["summary"]
    pushed = {r["name"] for r in summary["rules_pushed"]}
    failed = {r["name"] for r in summary["rules_failed"]}
    assert "Allow-Web" in pushed
    assert "Block-FTP" in failed
    assert summary["bulk_failed"] is True and summary["fallback_used"] is True
    assert result["success"] is False  # a rule failed


def test_push_bulk_failure_no_fallback_when_disabled(acp_base):
    """With per-rule fallback disabled (default), a bulk failure records the
    whole batch as failed and never submits rules individually."""
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    target.fail_bulk = True  # bulk POST raises
    per_rule_calls: list = []
    orig_post = target.post

    def tracking_post(path, body, *, bulk=False):
        if not bulk and "accessrules" in path:
            per_rule_calls.append(body.get("name"))
        return orig_post(path, body, bulk=bulk)

    target.post = tracking_post
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False,
                           bulk=True, per_rule_fallback=False)
    summary = result["summary"]
    # No per-rule submissions happened.
    assert per_rule_calls == []
    assert summary["rules_pushed"] == []
    assert summary["bulk_failed"] is True and summary["fallback_used"] is False
    # Both rules recorded as failed with a clear reason.
    assert {r["name"] for r in summary["rules_failed"]} == {"Allow-Web", "Block-FTP"}
    assert "fallback" in result["message"].lower()
    assert result["success"] is False


def test_push_bulk_success_records_no_fallback(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False,
                           bulk=True, per_rule_fallback=False)
    summary = result["summary"]
    assert summary["bulk_failed"] is False and summary["fallback_used"] is False
    assert len(summary["rules_pushed"]) == 2
    assert result["success"] is True


def _acp_with_rules(rules):
    return {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": rules,
    }


def test_push_bulk_failure_bisects_to_isolate_bad_rule():
    """With per-rule fallback disabled, a bulk batch rejected because of one
    bad rule is bisected so every other rule is still pushed, in order."""
    rules = [{"id": f"r{i}", "name": f"r{i}", "type": "AccessRule", "action": "ALLOW"}
             for i in range(1, 8)]
    source = FakeFmcClient(data=_acp_with_rules(rules))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    orig_post = target.post

    def picky_post(path, body, *, bulk=False):
        items = body if isinstance(body, list) else [body]
        if "accessrules" in path and any(b.get("name") == "r4" for b in items):
            raise FmcApiError("Object for Type TunnelTag and UUID x is not found", 400)
        return orig_post(path, body, bulk=bulk)

    target.post = picky_post
    result = push_svc.push(_config_from_source(source), ["A"], None, target,
                           validate=False, bulk=True, per_rule_fallback=False)
    summary = result["summary"]
    assert [r["name"] for r in summary["rules_failed"]] == ["r4"]
    assert "TunnelTag" in summary["rules_failed"][0]["error"]
    pushed = [c["body"]["name"] for c in target.created if "accessrules" in c["suffix"]]
    assert pushed == ["r1", "r2", "r3", "r5", "r6", "r7"]


def test_push_remaps_tunnel_tag_in_source_zones():
    """TunnelTag refs in rule sourceZones are discovered, reused by name on the
    target (or created) and remapped — never sent with the source UUID."""
    rules = [{"id": "r1", "name": "gre", "type": "AccessRule", "action": "ALLOW",
              "sourceZones": {"objects": [
                  {"id": "src-tt", "type": "TunnelTag", "name": "sit_gre"}]}},
             {"id": "r2", "name": "gre6", "type": "AccessRule", "action": "ALLOW",
              "sourceZones": {"objects": [
                  {"id": "src-tt6", "type": "TunnelTag", "name": "sit_gre_v6"}]}}]
    source = FakeFmcClient(data=_acp_with_rules(rules))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "object/tunneltags": [{"id": "tgt-tt", "name": "sit_gre", "type": "TunnelTag"}]})
    result = push_svc.push(_config_from_source(source), ["A"], None, target,
                           validate=False, bulk=True)
    assert len(result["summary"]["rules_pushed"]) == 2
    created_tt = [c for c in target.created if c["suffix"] == "object/tunneltags"]
    assert [c["body"]["name"] for c in created_tt] == ["sit_gre_v6"]
    zone_ids = {c["body"]["name"]: c["body"]["sourceZones"]["objects"][0]["id"]
                for c in target.created if "accessrules" in c["suffix"]}
    assert zone_ids["gre"] == "tgt-tt"
    assert zone_ids["gre6"] not in ("src-tt6", "")


def test_reconcile_rule_flags_clears_logfiles_without_filepolicy():
    # logFiles must be cleared when the file policy was pruned (FMC 400 otherwise).
    rb = {"name": "r", "logFiles": True}
    push_svc._reconcile_rule_flags(rb)
    assert rb["logFiles"] is False
    # Untouched when a file policy remains.
    rb2 = {"name": "r", "logFiles": True, "filePolicy": {"id": "x", "type": "FilePolicy"}}
    push_svc._reconcile_rule_flags(rb2)
    assert rb2["logFiles"] is True


def test_push_blocks_on_conflict(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    # Target already has 'web1' with a DIFFERENT value -> incompatible collision.
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "object/hosts": [{"id": "t-1", "name": "web1", "value": "9.9.9.9", "type": "Host"}],
    })
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False)
    assert result["success"] is False
    assert "collision" in result["message"].lower()


def test_override_requires_confirmation(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    mappings = {"Corp-ACP": {"prefilterPolicy": "existing-pf-id"}}
    # Without confirmation -> override is skipped.
    result = push_svc.push(cfg, ["Corp-ACP"], source, target,
                           validate=False, mappings=mappings, confirm_overrides=False)
    skipped = " ".join(result["summary"]["skipped_settings"])
    assert "requires confirmation" in skipped


def test_override_applied_with_confirmation(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    mappings = {"Corp-ACP": {"prefilterPolicy": "existing-pf-id"}}
    result = push_svc.push(cfg, ["Corp-ACP"], source, target,
                           validate=False, mappings=mappings, confirm_overrides=True)
    overridden = " ".join(result["summary"]["policies_overridden"])
    assert "prefilterPolicy" in overridden
    # The ACP body posted to target embeds the chosen prefilter id.
    acp_posts = [c for c in target.created if c["suffix"].endswith("policy/accesspolicies")]
    assert acp_posts
    body = acp_posts[0]["body"]
    assert body.get("prefilterPolicySetting", {}).get("id") == "existing-pf-id"


def test_push_updates_existing_acp(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "policy/accesspolicies": [{"id": "tgt-acp", "name": "Corp-ACP", "type": "AccessPolicy"}],
    })
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["Corp-ACP"], source, target, validate=False)
    assert result["success"] is True
    # Existing ACP -> PUT (update), not a fresh create.
    assert any(p["path"].endswith("/tgt-acp") for p in target.put_calls)


def test_preview_no_mutation(acp_base):
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    result = push_svc.preview(cfg, ["Corp-ACP"], source, target, validate=False)
    assert result["success"] is True
    assert result["selected_acps"] == ["Corp-ACP"]
    assert result["plan"]["to_create"]
    # Preview must not create anything on the target.
    assert target.created == []


def test_list_target_policies(acp_base):
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "policy/prefilterpolicies": [{"id": "pf-9", "name": "TargetPF", "type": "PrefilterPolicy"}],
    })
    pols = push_svc.list_target_policies(target, "prefilterPolicy")
    assert pols and pols[0]["name"] == "TargetPF"


# ── Resolution caching tests ──

def test_preview_caches_resolution_for_push(acp_base):
    """preview() stores cached resolution in ctx; push() reuses it."""
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    ctx: dict = {}

    # Preview populates cache.
    result = push_svc.preview(
        cfg, ["Corp-ACP"], source, target, validate=False, ctx=ctx,
    )
    assert result["success"] is True
    assert "_resolution_cache" in ctx

    # Push reuses the cached resolution (no duplicate discover+build_plan).
    logs: list = []
    result = push_svc.push(
        cfg, ["Corp-ACP"], source, target,
        validate=False, bulk=True, ctx=ctx,
        log=lambda m: logs.append(m),
    )
    assert result["success"] is True
    assert any("Reusing cached resolution" in m for m in logs)
    # Cache is cleared after push.
    assert "_resolution_cache" not in ctx


def test_cache_invalidated_on_input_change(acp_base):
    """Changing mappings between preview and push forces fresh resolution."""
    source = FakeFmcClient(data=copy.deepcopy(acp_base))
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    ctx: dict = {}

    push_svc.preview(cfg, ["Corp-ACP"], source, target, validate=False, ctx=ctx)
    assert "_resolution_cache" in ctx

    # Push with different mappings -> cache key mismatch, fresh resolution.
    logs: list = []
    push_svc.push(
        cfg, ["Corp-ACP"], source, target,
        validate=False, bulk=True, ctx=ctx,
        mappings={"Corp-ACP": {"prefilterPolicy": "different-id"}},
        log=lambda m: logs.append(m),
    )
    assert any("No cached resolution" in m for m in logs)


def test_clear_resolution_cache():
    """_clear_resolution_cache removes the cached entry."""
    ctx = {"_resolution_cache": "something", "other": True}
    push_svc._clear_resolution_cache(ctx)
    assert "_resolution_cache" not in ctx
    assert ctx["other"] is True
    # Safe on None.
    push_svc._clear_resolution_cache(None)


def test_seed_refs_includes_dependent_policy_rule_objects():
    """_seed_refs must harvest object references from embedded dependent-policy
    rules (decryption / prefilter / identity) — not just access rules.  Without
    this, objects only referenced in dependent-policy rules (e.g. grp.linux in a
    Decryption rule) are never discovered/resolved and cause FMC 400
    'Unable to load container' errors on the target."""
    from policy_configuration.models.schema import AcpModel, PolicyConfig

    cfg = PolicyConfig()
    acp = AcpModel(name="A", source_id="acp-1")
    acp.access_rules = [
        {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW",
         "sourceNetworks": {"objects": [
             {"type": "Host", "name": "access-host", "id": "host-access"}]}},
    ]
    acp.default_action = {}
    cfg.upsert_acp(acp)
    # A Decryption policy with rules referencing objects NOT in the access rules.
    cfg.policies["decryption_policies"] = [{
        "id": "dp-1", "name": "DP", "type": "DecryptionPolicy",
        "decryptionpolicyrules": [{
            "id": "dr-1", "name": "decr", "type": "DecryptionPolicyRule",
            "sourceNetworks": {"objects": [
                {"type": "NetworkGroup", "name": "grp.linux", "id": "ng-dec"}]},
            "sourceZones": {"objects": [
                {"type": "SecurityZone", "name": "zone.switch", "id": "sz-dec"}]},
        }],
    }]
    refs = push_svc._seed_refs([acp], config=cfg)
    ref_keys = {(r.type, r.name) for r in refs}
    # Access rule ref must be present.
    assert ("Host", "access-host") in ref_keys
    # Decryption rule refs must also be discovered.
    assert ("NetworkGroup", "grp.linux") in ref_keys
    assert ("SecurityZone", "zone.switch") in ref_keys


def test_push_resolves_decryption_rule_objects():
    """End-to-end: objects only referenced in Decryption policy rules are
    discovered, resolved, and remapped — preventing FMC 400 errors."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"},
             "decryptionPolicySetting": {"id": "dp-1", "name": "DP", "type": "DecryptionPolicy"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW"},
        ],
        "policy/decryptionpolicies": [
            {"id": "dp-1", "name": "DP", "type": "DecryptionPolicy"}],
        "policy/decryptionpolicies/dp-1/decryptionpolicyrules": [
            {"id": "dr-1", "name": "decr", "type": "DecryptionPolicyRule",
             "ruleAction": "DO_NOT_DECRYPT",
             "sourceNetworks": {"objects": [
                 {"type": "NetworkGroup", "name": "grp.linux",
                  "id": "src-ng-1"}]},
             "metadata": {"ruleIndex": 1}},
        ],
        # The NetworkGroup definition (so discovery can resolve it offline).
        "object/networkgroups": [
            {"id": "src-ng-1", "name": "grp.linux", "type": "NetworkGroup",
             "objects": []}],
    }
    source = FakeFmcClient(data=data)
    cfg = _config_from_source(source)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    result = push_svc.push(cfg, ["A"], None, target, validate=False, bulk=True)
    assert result["success"] is True
    # grp.linux was created on the target.
    ng_created = [c for c in target.created
                  if c["suffix"] == "object/networkgroups"]
    assert ng_created and ng_created[0]["body"]["name"] == "grp.linux"
    # The decryption rule was pushed with the remapped target id.
    dr_created = [c for c in target.created if "decryptionpolicyrules" in c["suffix"]]
    assert dr_created
    body = dr_created[0]["body"]
    src_objs = (body.get("sourceNetworks") or {}).get("objects") or []
    assert src_objs and src_objs[0]["id"] != "src-ng-1"


def test_decryption_rules_pushed_in_bulk():
    """Decryption policy rules with >1 rule in a category group should be
    pushed via bulk POST, not sequential per-rule POST."""
    from policy_configuration.dependency_resolution.resolver import DependencyResolver
    from policy_configuration.services import dependent_policies as dp

    target = FakeFmcClient(fmc_ip="https://t", data={})
    resolver = DependencyResolver(FakeFmcClient(data={}), target, log=lambda m: None)

    cfg = PolicyConfig()
    cfg.policies["decryption_policies"] = [{
        "id": "dp-src", "name": "DP", "type": "DecryptionPolicy",
        "decryptionpolicyrules": [
            {"id": "dr-1", "name": "rule-a", "type": "DecryptionPolicyRule",
             "ruleAction": "DO_NOT_DECRYPT",
             "metadata": {"ruleIndex": 1}},
            {"id": "dr-2", "name": "rule-b", "type": "DecryptionPolicyRule",
             "ruleAction": "DO_NOT_DECRYPT",
             "metadata": {"ruleIndex": 2}},
            {"id": "dr-3", "name": "rule-c", "type": "DecryptionPolicyRule",
             "ruleAction": "DO_NOT_DECRYPT",
             "metadata": {"ruleIndex": 3}},
        ],
    }]
    summary = PushSummary()
    new_id = dp.create_assigned_policy(
        "DecryptionPolicy", "DP", "dp-src",
        cfg, target, resolver, lambda m: None, summary=summary)
    assert new_id
    # Rules should have been posted via bulk (single call with list body).
    bulk_posts = [c for c in target.bulk_created
                  if "decryptionpolicyrules" in c["suffix"]]
    assert bulk_posts, "rules should be pushed in bulk"
    assert len(bulk_posts[0]["body"]) == 3
