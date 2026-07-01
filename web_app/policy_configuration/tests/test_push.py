"""End-to-end push tests with mocked FMC: object creation, ACP create/update,
rule push, assigned-policy create/override mappings, conflicts, and summary."""
import copy

from policy_configuration.models.schema import PolicyConfig
from policy_configuration.services import acp_fetch
from policy_configuration.services import push as push_svc
from policy_configuration.services.client import FmcApiError
from .conftest import FakeFmcClient


def _config_from_source(source: FakeFmcClient) -> PolicyConfig:
    acp, deps = acp_fetch.fetch_acp(source, "acp-1")
    cfg = PolicyConfig()
    cfg.upsert_acp(acp)
    cfg.upsert_objects([d.to_dict() for d in deps])
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


def test_push_prunes_truly_unresolvable_rule_policy_ref():
    """A rule policy reference that cannot be reused or created is pruned so the
    rule still pushes without a stale source id (root cause of the FMC 500)."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW",
             # VariableSet is reuse-by-name only (never created); absent on target.
             "variableSet": {"id": "vs-9", "name": "Ghost-VarSet", "type": "VariableSet"}},
        ],
    }
    source = FakeFmcClient(data=data)
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    cfg = _config_from_source(source)
    result = push_svc.push(cfg, ["A"], source, target, validate=False, bulk=True)
    summary = result["summary"]
    assert len(summary["rules_pushed"]) == 1
    dropped = [d for d in summary["dropped_references"] if d["type"] == "VariableSet"]
    assert dropped and dropped[0]["name"] == "Ghost-VarSet"
    rule_posts = [c for c in target.created if "accessrules" in c["suffix"]]
    for rp in rule_posts:
        assert "variableSet" not in rp["body"]


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
