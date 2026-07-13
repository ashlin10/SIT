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


def test_resolve_and_prune_refs_keeps_remapped_refs():
    """Regression: a single-pass resolve/prune must rewrite remapped references
    to their target id and KEEP them — it must not treat an already-remapped
    target id as unresolvable and drop it (the root cause of empty
    sourceNetworks / sourceZones on cloned dependent-policy rules)."""
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    # grp.local was reused on the target; zone was reused; a predefined port
    # keeps the same id on both FMCs (source == target).
    r.register_remap("src-grp", "tgt-grp")
    r.register_remap("src-zone", "tgt-zone")
    r.register_remap("port-https", "port-https")

    rule = {
        "sourceNetworks": {"objects": [
            {"type": "NetworkGroup", "name": "grp.local", "id": "src-grp"}]},
        "sourceZones": {"objects": [
            {"type": "SecurityZone", "name": "zone.switch", "id": "src-zone"}]},
        "destinationPorts": {"objects": [
            {"type": "ProtocolPortObject", "name": "HTTPS", "id": "port-https"}]},
    }
    r.resolve_and_prune_refs(rule)
    assert rule["sourceNetworks"]["objects"][0]["id"] == "tgt-grp"
    assert rule["sourceZones"]["objects"][0]["id"] == "tgt-zone"
    assert rule["destinationPorts"]["objects"][0]["id"] == "port-https"


def test_resolve_and_prune_refs_drops_unresolvable_only():
    """Only references with no valid target equivalent are pruned; the drop
    callback is invoked for each removed reference."""
    source = FakeFmcClient(data={})
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.register_remap("src-net", "tgt-net")
    # Mark a readonly ISE SGT (36-char UUID, not global-id) as unresolvable.
    r._unresolved_ids.add("11111111-1111-1111-1111-111111111111")
    dropped = []
    rule = {
        "sourceNetworks": {"objects": [
            {"type": "Network", "name": "keep", "id": "src-net"},
            {"type": "ISESecurityGroupTag", "name": "gone",
             "id": "11111111-1111-1111-1111-111111111111"}]},
    }
    r.resolve_and_prune_refs(rule, on_drop=lambda n: dropped.append(n.get("name")))
    objs = rule["sourceNetworks"]["objects"]
    assert [o["name"] for o in objs] == ["keep"]
    assert objs[0]["id"] == "tgt-net"
    assert dropped == ["gone"]


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
    created, partial = r.apply(plan, bulk=True, per_item_fallback=True)
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


def test_discover_batches_source_fetch_not_per_id():
    """A large policy must resolve with a handful of batched name lookups —
    NOT one GET-per-object (the root cause of the Push HTTP 429 storm)."""
    # 60 hosts sharing a common prefix, referenced by one NetworkGroup.
    hosts = _hosts(*[(f"web_host_{i:03d}", f"10.0.0.{i}", f"h-{i}") for i in range(60)])
    group_members = [{"type": "Host", "name": h["name"], "id": h["id"]} for h in hosts]
    source = FakeFmcClient(data={
        "object/hosts": hosts,
        "object/networkgroups": [{
            "id": "g-1", "name": "BigGroup", "type": "NetworkGroup",
            "objects": group_members,
        }],
    })
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    source.reset_request_stats()
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="NetworkGroup", name="BigGroup", source_id="g-1")])

    # All 60 hosts + the group were discovered.
    assert len(r._refs) == 61
    # Batched: total source requests must be far below the naive per-id count
    # (61). Two waves × (few grouped wildcard queries) → well under 10.
    total = source.request_stats()["total"]
    assert total < 10, f"expected batched fetch, issued {total} source requests"


def test_discover_falls_back_to_get_by_id_for_id_only_ref():
    """A group member with an id but no name (name filter can't match) is
    resolved via the per-id GET fallback."""
    source = FakeFmcClient(data={
        "object/hosts": [{"id": "h-1", "name": "namedhost", "value": "10.0.0.1", "type": "Host"}],
        "object/networkgroups": [{
            "id": "g-1", "name": "Grp", "type": "NetworkGroup",
            # Member carries only an id (no name) → forces GET-by-id fallback.
            "objects": [{"type": "Host", "id": "h-1"}],
        }],
    })
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="NetworkGroup", name="Grp", source_id="g-1")])
    # The id-only host was resolved via the per-id GET fallback: its full
    # source body (name "namedhost") is now in the discovered graph.
    host_key = next(k for k in r._refs if k.lower().startswith("host::"))
    fetched = r._source_objs.get(host_key)
    assert fetched and fetched.get("name") == "namedhost"


def test_discover_unresolved_when_source_body_missing():
    """A referenced object absent from the source (name + id miss) leaves no
    source body; it is still recorded as a ref and handled downstream."""
    source = FakeFmcClient(data={
        "object/networkgroups": [{
            "id": "g-1", "name": "Grp", "type": "NetworkGroup",
            "objects": [{"type": "Host", "name": "ghost", "id": "h-missing"}],
        }],
    })
    target = FakeFmcClient(fmc_ip="https://tgt.example.com", data={})
    r = DependencyResolver(source, target)
    r.discover([DependencyRef(type="NetworkGroup", name="Grp", source_id="g-1")])
    # The missing host is a discovered ref but has no fetched source body.
    host_keys = [k for k in r._refs if k.lower().startswith("host::")]
    assert host_keys
    assert all(k not in r._source_objs for k in host_keys)


def test_discover_graph_matches_expected_edges():
    """No regression: batched discovery builds the same reference graph
    (edges group -> members) as the prior DFS implementation."""
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
    group_key = next(k for k in r._edges if "webgroup" in k.lower())
    # The group has exactly two child edges (its two host members).
    assert len(r._edges[group_key]) == 2


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
    created, partial = r.apply(plan, bulk=True, per_item_fallback=True)
    assert "good" in created
    assert "bad" in partial
