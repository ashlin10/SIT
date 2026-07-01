"""Tests for dependency discovery, dedup, cycle detection, leveling, target
matching (reuse/conflict), creation in order, and id remapping."""
from policy_configuration.models.schema import DependencyRef
from policy_configuration.dependency_resolution.resolver import DependencyResolver
from policy_configuration.services.client import FmcApiError
from .conftest import FakeFmcClient


def _hosts(*specs):
    return [{"id": i, "name": n, "value": v, "type": "Host"} for (n, v, i) in specs]


def test_discovery_and_leveling_with_group():
    source = FakeFmcClient(data={
        "object/hosts": _hosts(("web1", "10.0.0.1", "h-1"), ("web2", "10.0.0.2", "h-2")),
        "object/networkgroups": [{
            "id": "g-1", "name": "WebGroup", "type": "NetworkGroup",
            "objects": [{"type": "Host", "name": "web1", "id": "h-1"},
                        {"type": "Host", "name": "web2", "id": "h-2"}],
        }],
    })
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="NetworkGroup", name="WebGroup", source_id="g-1")])
    levels = r.compute_levels()
    # Hosts (leaves) come before the group that references them.
    # Level keys are normalized (lowercase) ref keys, e.g. "networkgroup::webgroup".
    group_level = next(i for i, lvl in enumerate(levels)
                       if any("webgroup" in k.lower() for k in lvl))
    host_level = next(i for i, lvl in enumerate(levels)
                      if any("web1" in k.lower() for k in lvl))
    assert host_level < group_level


def test_dedup_shared_dependency():
    source = FakeFmcClient(data={
        "object/hosts": _hosts(("shared", "10.0.0.9", "h-1")),
    })
    target = FakeFmcClient(data={})
    r = DependencyResolver(source, target)
    # Seed the same host twice.
    r.discover([
        DependencyRef(type="Host", name="shared", source_id="h-1"),
        DependencyRef(type="Host", name="shared", source_id="h-1"),
    ])
    plan = r.build_plan()
    assert len(plan.to_create) == 1


def test_cycle_detection():
    source = FakeFmcClient(data={
        "object/networkgroups": [
            {"id": "a", "name": "A", "type": "NetworkGroup",
             "objects": [{"type": "NetworkGroup", "name": "B", "id": "b"}]},
            {"id": "b", "name": "B", "type": "NetworkGroup",
             "objects": [{"type": "NetworkGroup", "name": "A", "id": "a"}]},
        ],
    })
    target = FakeFmcClient(data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="NetworkGroup", name="A", source_id="a")])
    cycles = r.detect_cycles()
    assert cycles, "expected a cycle to be detected"
    plan = r.build_plan()
    assert plan.has_blocking is True
    assert plan.cycles


def test_reuse_compatible_target_object():
    source = FakeFmcClient(data={"object/hosts": _hosts(("web1", "10.0.0.1", "h-1"))})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com",
                           data={"object/hosts": _hosts(("web1", "10.0.0.1", "t-1"))})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="Host", name="web1", source_id="h-1")])
    plan = r.build_plan()
    assert len(plan.to_reuse) == 1
    assert not plan.to_create
    # Remap maps source id -> target id.
    assert r.remap_table.get("h-1") == "t-1"


def test_incompatible_name_collision_is_conflict():
    source = FakeFmcClient(data={"object/hosts": _hosts(("web1", "10.0.0.1", "h-1"))})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com",
                           data={"object/hosts": _hosts(("web1", "192.168.1.1", "t-1"))})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="Host", name="web1", source_id="h-1")])
    plan = r.build_plan()
    assert plan.conflicts
    assert plan.has_blocking is True


def test_create_and_remap():
    source = FakeFmcClient(data={"object/hosts": _hosts(("web1", "10.0.0.1", "h-1"))})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="Host", name="web1", source_id="h-1")])
    plan = r.build_plan()
    assert len(plan.to_create) == 1
    created, partial = r.apply(plan, bulk=True)
    assert created == ["web1"]
    assert not partial
    # Remap now points at the created target id.
    new_id = r.remap_table["h-1"]
    rule = {"sourceNetworks": {"objects": [{"type": "Host", "name": "web1", "id": "h-1"}]}}
    r.remap_references(rule)
    assert rule["sourceNetworks"]["objects"][0]["id"] == new_id


def test_bulk_fallback_to_per_item():
    source = FakeFmcClient(data={
        "object/hosts": _hosts(("a", "10.0.0.1", "h-1"), ("b", "10.0.0.2", "h-2")),
    })
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    target.fail_bulk = True  # force per-item path
    r = DependencyResolver(source, target)
    r.discover([
        DependencyRef(type="Host", name="a", source_id="h-1"),
        DependencyRef(type="Host", name="b", source_id="h-2"),
    ])
    plan = r.build_plan()
    created, partial = r.apply(plan, bulk=True)
    assert sorted(created) == ["a", "b"]
    assert not partial


def test_readonly_type_matched_by_name_and_remapped():
    # ISESecurityGroupTag is predefined but NOT global-id: matched by name,
    # target lookup needed for id remap.
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "object/isesecuritygrouptags": [{"id": "t-sgt", "name": "PCI_Servers", "type": "ISESecurityGroupTag"}],
    })
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="ISESecurityGroupTag", name="PCI_Servers", source_id="s-sgt")])
    plan = r.build_plan()
    assert [x.name for x in plan.to_reuse] == ["PCI_Servers"]
    assert r.remap_table.get("s-sgt") == "t-sgt"
    assert plan.to_reuse[0].match_method == "name"
    assert "s-sgt" not in r.unresolved_source_ids


def test_global_id_type_skips_target_lookup():
    # URLCategory has globally consistent ids — no target lookup, source id kept.
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="URLCategory", name="Gambling", source_id="s-cat")])
    plan = r.build_plan()
    assert [x.name for x in plan.to_reuse] == ["Gambling"]
    assert plan.to_reuse[0].match_method == "global_id"
    assert plan.to_reuse[0].target_id == "s-cat"
    assert "s-cat" not in r.unresolved_source_ids


def test_readonly_type_missing_is_unresolved():
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="ISESecurityGroupTag", name="sgt_1", source_id="s-sgt")])
    plan = r.build_plan()
    assert plan.unresolved and plan.unresolved[0]["type"] == "ISESecurityGroupTag"
    assert plan.unresolved[0]["source_id"] == "s-sgt"
    assert "s-sgt" in r.unresolved_source_ids


def test_resolve_target_id_by_name_for_policy():
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={
        "policy/intrusionpolicies": [{"id": "t-ips", "name": "Balanced", "type": "IntrusionPolicy"}],
    })
    r = DependencyResolver(source, target)
    # Hit: resolves + records remap.
    assert r.resolve_target_id("IntrusionPolicy", "Balanced", "s-ips") == "t-ips"
    assert r.remap_table.get("s-ips") == "t-ips"
    # Miss: records unresolved.
    assert r.resolve_target_id("FilePolicy", "Nope", "s-fp") == ""
    assert "s-fp" in r.unresolved_source_ids


def test_partial_failure_recorded(monkeypatch):
    source = FakeFmcClient(data={
        "object/hosts": _hosts(("good", "10.0.0.1", "h-1"), ("bad", "10.0.0.2", "h-2")),
    })
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    target.fail_bulk = True

    orig_post = target.post

    def flaky_post(path, body, *, bulk=False):
        if not bulk and isinstance(body, dict) and body.get("name") == "bad":
            raise FmcApiError("boom")
        return orig_post(path, body, bulk=bulk)

    target.post = flaky_post
    r = DependencyResolver(source, target)
    r.discover([
        DependencyRef(type="Host", name="good", source_id="h-1"),
        DependencyRef(type="Host", name="bad", source_id="h-2"),
    ])
    plan = r.build_plan()
    created, partial = r.apply(plan, bulk=True)
    assert "good" in created
    assert "bad" in partial
