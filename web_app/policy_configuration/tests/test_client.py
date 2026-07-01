"""Tests for PolicyFmcClient helpers: wildcard grouping, pagination (>1000),
secret redaction, and object lookup caching."""
from policy_configuration.models.schema import redact
from policy_configuration.services.client import PolicyFmcClient


def _client():
    return PolicyFmcClient("https://fmc.example.com", {"X-auth-access-token": "t"}, "dom-1")


def test_redact_masks_secrets():
    payload = {
        "username": "admin", "password": "s3cr3t",
        "headers": {"X-auth-access-token": "abc", "Content-Type": "application/json"},
        "nested": [{"token": "xyz", "keep": 1}],
    }
    safe = redact(payload)
    assert safe["password"] == "***"
    assert safe["headers"]["X-auth-access-token"] == "***"
    assert safe["nested"][0]["token"] == "***"
    assert safe["nested"][0]["keep"] == 1
    assert safe["username"] == "admin"
    # Original is unchanged.
    assert payload["password"] == "s3cr3t"


def test_compute_wildcard_queries_groups_common_prefix():
    names = ["hub_sgt_client1", "hub_sgt_client2", "hub_sgt_client3", "lonely"]
    qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
    assert "hub_sgt_client" in qs
    assert "lonely" in qs
    # The three prefixed names collapse to a single query.
    assert len([q for q in qs if q.startswith("hub")]) == 1


def test_cfg_path_builds_domain_path():
    c = _client()
    assert c.cfg_path("policy/accesspolicies") == \
        "/api/fmc_config/v1/domain/dom-1/policy/accesspolicies"
    assert c.cfg_path("/object/hosts") == "/api/fmc_config/v1/domain/dom-1/object/hosts"


def test_get_paginated_follows_metadata_beyond_1000(monkeypatch):
    c = _client()
    # Simulate 2500 items across 3 pages of 1000 using offset arithmetic.
    total = 2500
    page_size = 1000

    def fake_get_json(path, params=None):
        if params and "offset" in params:
            offset = params["offset"]
            limit = params["limit"]
            batch = [{"id": str(i), "name": f"o{i}"} for i in range(offset, min(offset + limit, total))]
            return {"items": batch, "paging": {"count": total, "limit": limit}}
        return {"items": []}

    monkeypatch.setattr(c, "get_json", fake_get_json)
    items = c.get_paginated("/x", page_size=page_size)
    assert len(items) == total


def test_get_paginated_follows_next_links(monkeypatch):
    c = _client()
    pages = {
        "/start": {"items": [{"id": "1"}], "paging": {"next": ["/p2"]}},
        "/p2": {"items": [{"id": "2"}], "paging": {"next": ["/p3"]}},
        "/p3": {"items": [{"id": "3"}], "paging": {}},
    }

    def fake_get_json(path, params=None):
        return pages.get(path, {"items": []})

    monkeypatch.setattr(c, "get_json", fake_get_json)
    items = c.get_paginated("/start")
    assert [i["id"] for i in items] == ["1", "2", "3"]
