"""Tests for ACP listing, faithful fetch, dependent-policy fetch, recursive objects."""
from policy_configuration.services import acp_fetch
from policy_configuration.services.client import FmcApiError
from policy_configuration.models.schema import DependencyRef
from .conftest import FakeFmcClient


def test_list_acps(acp_base):
    client = FakeFmcClient(data=acp_base)
    rows = acp_fetch.list_acps(client)
    assert len(rows) == 1
    assert rows[0]["name"] == "Corp-ACP"
    assert rows[0]["id"] == "acp-1"


def test_fetch_acp_faithful_base(acp_base):
    client = FakeFmcClient(data=acp_base)
    acp, deps = acp_fetch.fetch_acp(client, "acp-1")
    assert acp.name == "Corp-ACP"
    assert acp.fetched is True
    assert acp.rule_count() == 2
    # raw_base is a faithful payload: keeps id, drops transport-only keys.
    assert acp.raw_base["id"] == "acp-1"
    assert "links" not in acp.raw_base
    assert "metadata" not in acp.raw_base
    # Rules are faithful too (top-level links stripped, id and metadata kept).
    r = acp.access_rules[0]
    assert r["id"] == "rule-1"
    assert "links" not in r
    # Derived in-memory fields work for the UI/push.
    assert acp.default_action.get("action") == "BLOCK"
    assert acp.assigned_policies["prefilterPolicy"].name == "Default Prefilter"


def test_harvest_excludes_policy_types(acp_base):
    """File/Intrusion policies must NOT be harvested as objects."""
    client = FakeFmcClient(data=acp_base)
    _, deps = acp_fetch.fetch_acp(client, "acp-1")
    types = sorted(d.type for d in deps)
    names = sorted(d.name for d in deps)
    assert "Host" in types and "ProtocolPortObject" in types
    assert "FilePolicy" not in types
    assert "IntrusionPolicy" not in types
    assert names == ["FTP", "web1", "web2"]


def test_collect_policy_refs(acp_base):
    client = FakeFmcClient(data=acp_base)
    acp, _ = acp_fetch.fetch_acp(client, "acp-1")
    refs = acp_fetch.collect_policy_refs(acp)
    by_type = {r.type for r in refs}
    # Prefilter (base), Intrusion (defaultAction), File (rule) all discovered.
    assert by_type == {"PrefilterPolicy", "IntrusionPolicy", "FilePolicy"}


def test_fetch_dependent_policies(acp_base):
    client = FakeFmcClient(data=acp_base)
    acp, _ = acp_fetch.fetch_acp(client, "acp-1")
    refs = acp_fetch.collect_policy_refs(acp)
    by_sub, _objrefs = acp_fetch.fetch_dependent_policies(client, refs)
    assert set(by_sub.keys()) == {
        "prefilter_policies", "intrusion_policies", "file_policies",
    }
    pf = by_sub["prefilter_policies"][0]
    assert pf["id"] == "pf-1"
    # Full payload fetched + faithfully stripped of transport-only keys.
    assert "links" not in pf and "metadata" not in pf
    assert pf["defaultAction"]["action"] == "ANALYZE_TUNNELS"


def test_fetch_dependent_policies_embeds_subrules():
    """Every rule of a rule-bearing dependent policy is embedded in its body so
    the exported YAML is self-contained (prefilter + file rules here)."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"},
             "prefilterPolicySetting": {"id": "pf-1", "name": "PF", "type": "PrefilterPolicy"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule",
             "filePolicy": {"id": "fp-1", "name": "FP", "type": "FilePolicy"}},
        ],
        "policy/prefilterpolicies": [{"id": "pf-1", "name": "PF", "type": "PrefilterPolicy"}],
        "policy/prefilterpolicies/pf-1/prefilterrules": [
            {"id": "pr-1", "name": "pfr", "type": "PrefilterRule", "action": "ANALYZE",
             "links": {"self": "x"}},
        ],
        "policy/filepolicies": [{"id": "fp-1", "name": "FP", "type": "FilePolicy"}],
        "policy/filepolicies/fp-1/filerules": [
            {"id": "fr-1", "name": "block-exe", "type": "FileRule", "action": "BLOCK"},
        ],
    }
    client = FakeFmcClient(data=data)
    acp, _ = acp_fetch.fetch_acp(client, "acp-1")
    refs = acp_fetch.collect_policy_refs(acp)
    by_sub, _ = acp_fetch.fetch_dependent_policies(client, refs)
    pf = by_sub["prefilter_policies"][0]
    assert [r["name"] for r in pf["prefilterrules"]] == ["pfr"]
    # Transport-only keys are stripped from embedded rules too.
    assert "links" not in pf["prefilterrules"][0]
    fp = by_sub["file_policies"][0]
    assert [r["name"] for r in fp["fileRules"]] == ["block-exe"]


def test_fetch_dependent_policies_embeds_identity_and_decryption_subrules():
    """Identity and decryption policy rules are embedded with the correct
    FMC API sub-resource paths (identityrules, decryptionpolicyrules)."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"},
             "identityPolicySetting": {"id": "ip-1", "name": "IP", "type": "IdentityPolicy"},
             "decryptionPolicySetting": {"id": "dp-1", "name": "DP", "type": "DecryptionPolicy"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [],
        "policy/identitypolicies": [{"id": "ip-1", "name": "IP", "type": "IdentityPolicy"}],
        "policy/identitypolicies/ip-1/identityrules": [
            {"id": "ir-1", "name": "id-rule-1", "type": "IdentityRule", "action": "PASSIVE_AUTH"},
        ],
        "policy/decryptionpolicies": [{"id": "dp-1", "name": "DP", "type": "DecryptionPolicy"}],
        "policy/decryptionpolicies/dp-1/decryptionpolicyrules": [
            {"id": "dr-1", "name": "dec-rule-1", "type": "DecryptionRule", "action": "DO_NOT_DECRYPT"},
        ],
    }
    client = FakeFmcClient(data=data)
    acp, _ = acp_fetch.fetch_acp(client, "acp-1")
    refs = acp_fetch.collect_policy_refs(acp)
    by_sub, _ = acp_fetch.fetch_dependent_policies(client, refs)
    ip = by_sub["identity_policies"][0]
    assert [r["name"] for r in ip["identityrules"]] == ["id-rule-1"]
    dp = by_sub["decryption_policies"][0]
    assert [r["name"] for r in dp["decryptionpolicyrules"]] == ["dec-rule-1"]


def test_fetch_dependent_policies_dedup():
    """A policy referenced by multiple rules is fetched/stored once."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "A", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule",
             "filePolicy": {"id": "fp-1", "name": "FP", "type": "FilePolicy"}},
            {"id": "r2", "name": "r2", "type": "AccessRule",
             "filePolicy": {"id": "fp-1", "name": "FP", "type": "FilePolicy"}},
        ],
        "policy/filepolicies": [{"id": "fp-1", "name": "FP", "type": "FilePolicy"}],
    }
    client = FakeFmcClient(data=data)
    acp, _ = acp_fetch.fetch_acp(client, "acp-1")
    refs = acp_fetch.collect_policy_refs(acp)
    by_sub, _ = acp_fetch.fetch_dependent_policies(client, refs)
    assert len(by_sub["file_policies"]) == 1


def test_fetch_full_objects_faithful(acp_base):
    """fetch_full_objects returns faithful payloads, no synthetic fields."""
    client = FakeFmcClient(data=acp_base)
    _, deps = acp_fetch.fetch_acp(client, "acp-1")
    full = acp_fetch.fetch_full_objects(client, deps)
    assert len(full) == 3
    by_name = {o["name"]: o for o in full}
    assert by_name["web1"]["value"] == "10.0.0.1"
    assert by_name["FTP"]["protocol"] == "TCP"
    for o in full:
        # Faithful: real id kept, transport-only + synthetic keys absent.
        assert o.get("id")
        assert "links" not in o and "metadata" not in o
        assert "source_id" not in o
        assert "target_id" not in o
        assert "action" not in o


def test_fetch_full_objects_recursive_groups():
    """Groups' member objects are recursively fetched."""
    data = {
        "policy/accesspolicies": [
            {"id": "acp-1", "name": "G-ACP", "type": "AccessPolicy",
             "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction"}},
        ],
        "policy/accesspolicies/acp-1/accessrules": [
            {"id": "r1", "name": "r1", "type": "AccessRule", "action": "ALLOW",
             "sourceNetworks": {"objects": [{"type": "NetworkGroup", "name": "grp1", "id": "ng-1"}]}},
        ],
        "object/networkgroups": [
            {"id": "ng-1", "name": "grp1", "type": "NetworkGroup",
             "objects": [{"type": "Host", "name": "member1", "id": "h-99"}]},
        ],
        "object/hosts": [
            {"id": "h-99", "name": "member1", "value": "1.2.3.4", "type": "Host"},
        ],
    }
    client = FakeFmcClient(data=data)
    _, deps = acp_fetch.fetch_acp(client, "acp-1")
    full = acp_fetch.fetch_full_objects(client, deps)
    names = sorted(o["name"] for o in full)
    assert "grp1" in names
    assert "member1" in names


def test_fetch_acp_full_orchestrator(acp_base):
    """End-to-end: ACP + grouped dependent policies + recursive objects."""
    client = FakeFmcClient(data=acp_base)
    acp, policies, objects = acp_fetch.fetch_acp_full(client, "acp-1")
    assert acp.name == "Corp-ACP"
    # Three dependent-policy types fetched + grouped.
    assert set(policies.keys()) == {
        "prefilter_policies", "intrusion_policies", "file_policies",
    }
    # All three referenced objects fetched as full payloads.
    assert {o["name"] for o in objects} == {"web1", "web2", "FTP"}


def test_is_system_object_reads_metadata():
    system = {"type": "Host", "name": "any-ipv4", "id": "1",
              "metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}}
    rbac = {"type": "Host", "name": "x", "id": "2",
            "metadata": {"readOnly": {"state": True, "reason": "RBAC"}}}
    user = {"type": "Host", "name": "web1", "id": "3", "value": "10.0.0.1"}
    assert acp_fetch._is_system_object(system) is True   # predefined
    assert acp_fetch._is_system_object(rbac) is False     # read-only, but not system
    assert acp_fetch._is_system_object(user) is False     # user-created


def test_fetch_full_objects_readonly_types_kept_as_reference_without_fetch():
    """Predefined/reuse-only types (READONLY_TYPES) are kept as name references
    and never fetched — even if a full body exists on the source — matching the
    push resolver. User-defined types are fetched in full."""
    calls: list[str] = []
    data = {
        "object/applications": [
            {"id": "4023", "name": "QUIC", "type": "Application", "risk": "HIGH"},
        ],
        "object/hosts": [
            {"id": "usr-h", "name": "web1", "type": "Host", "value": "10.0.0.1"},
        ],
    }
    client = FakeFmcClient(data=data)
    orig = client.get_objects_by_names

    def tracking(suffix, names, obj_type, **kw):
        calls.append(obj_type)
        return orig(suffix, names, obj_type, **kw)

    client.get_objects_by_names = tracking
    deps = [
        DependencyRef(type="Application", name="QUIC", source_id="4023"),
        DependencyRef(type="Host", name="web1", source_id="usr-h"),
    ]
    objs = acp_fetch.fetch_full_objects(client, deps)
    by_name = {o["name"]: o for o in objs}
    # Application is READONLY -> minimal reference, and NOT fetched at all.
    assert by_name["QUIC"] == {"type": "Application", "name": "QUIC", "id": "4023"}
    assert "Application" not in calls
    # Host is user-defined -> fetched in full.
    assert by_name["web1"].get("value") == "10.0.0.1"


def test_fetch_full_objects_predefined_member_of_creatable_type_via_metadata():
    """A predefined member of a *creatable* type (Host here) is still stored as a
    reference when its metadata says so."""
    data = {
        "object/hosts": [
            {"id": "sys-h", "name": "any-ipv4", "type": "Host", "value": "0.0.0.0/0",
             "metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}},
            {"id": "usr-h", "name": "web1", "type": "Host", "value": "10.0.0.1"},
        ],
    }
    client = FakeFmcClient(data=data)
    deps = [
        DependencyRef(type="Host", name="any-ipv4", source_id="sys-h"),
        DependencyRef(type="Host", name="web1", source_id="usr-h"),
    ]
    objs = acp_fetch.fetch_full_objects(client, deps)
    by_name = {o["name"]: o for o in objs}
    assert by_name["any-ipv4"] == {"type": "Host", "name": "any-ipv4", "id": "sys-h"}
    assert by_name["web1"].get("value") == "10.0.0.1"


def test_is_minimal_helper():
    assert acp_fetch._is_minimal({}) is True
    assert acp_fetch._is_minimal({"type": "Host", "name": "a", "id": "1"}) is True
    assert acp_fetch._is_minimal({"type": "Host", "name": "a", "id": "1", "value": "1.2.3.4"}) is False


def test_fetch_full_objects_retry_recovers_transient_failure(acp_base):
    """When the bulk list omits an object (transient/partial page), the retry
    pass re-fetches it directly by id so the payload is still complete."""
    client = FakeFmcClient(data=acp_base)
    _, deps = acp_fetch.fetch_acp(client, "acp-1")

    orig_paginated = client.get_paginated

    def partial_paginated(path, **kwargs):
        items = orig_paginated(path, **kwargs)
        if path.endswith("/object/hosts"):
            # Simulate a partial catalog that misses web1 (h-1).
            return [o for o in items if o.get("id") != "h-1"]
        return items

    client.get_paginated = partial_paginated
    full = acp_fetch.fetch_full_objects(client, deps)
    by_name = {o["name"]: o for o in full}
    # web1 recovered a full payload via the by-id retry despite the partial list.
    assert by_name["web1"].get("value") == "10.0.0.1"


def test_fetch_acp_missing_raises(acp_base):
    client = FakeFmcClient(data=acp_base)
    try:
        acp_fetch.fetch_acp(client, "does-not-exist")
        assert False, "expected FmcApiError"
    except FmcApiError:
        pass
