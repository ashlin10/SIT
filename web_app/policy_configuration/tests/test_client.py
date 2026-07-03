"""Tests for PolicyFmcClient helpers: wildcard grouping, pagination (>1000),
secret redaction, object lookup caching, request counting, and rate-limit
(HTTP 429 / Retry-After) handling."""
import policy_configuration.services.client as client_mod
from policy_configuration.models.schema import redact
from policy_configuration.services.client import PolicyFmcClient, FmcApiError


def _client():
    return PolicyFmcClient("https://fmc.example.com", {"X-auth-access-token": "t"}, "dom-1")


class _FakeResp:
    def __init__(self, status_code, json_data=None, text="", headers=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._json


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


def test_compute_wildcard_queries_rejects_broad_prefix():
    """TCP_3306 + TCP_8305 share prefix 'TCP_' but it's only 50% of avg name
    length — too broad (would match 15 000 FMC objects).  They must stay
    individual."""
    names = ["TCP_3306", "TCP_8305"]
    qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
    assert "TCP_3306" in qs
    assert "TCP_8305" in qs
    assert "TCP_" not in qs


def test_compute_wildcard_queries_groups_common_substring():
    """D1FRPWR01 and D2FRPWR01 don't share a long prefix, but share
    substring 'FRPWR01' (>50% of avg name length) → should be grouped."""
    names = ["D1FRPWR01", "D2FRPWR01"]
    qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
    assert len(qs) == 1
    assert "FRPWR01" in qs[0]


def test_compute_wildcard_queries_mixed_scenario():
    """Real-world mix: some names share prefix, some share substring,
    some are too broad, some are loners."""
    names = [
        "DNS_over_UDP", "HTTP", "HTTPS", "NTP-TCP", "NTP-UDP",
        "SSH", "TACACS_TCP_49", "TCP_3306", "TCP_8305",
    ]
    qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
    # HTTP / HTTPS should be grouped under 'HTTP'
    assert "HTTP" in qs
    # NTP-TCP / NTP-UDP should be grouped under 'NTP-'
    assert any(q.startswith("NTP") for q in qs)
    # TCP_3306 and TCP_8305 must NOT be grouped under 'TCP_'
    assert "TCP_" not in qs
    # Each should appear individually
    assert "TCP_3306" in qs
    assert "TCP_8305" in qs


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


def test_request_counting_tracks_methods(monkeypatch):
    c = _client()

    def fake_request(method, url, **kwargs):
        return _FakeResp(200, {"ok": True})

    monkeypatch.setattr(client_mod.requests, "request", fake_request)
    c.reset_request_stats()
    c.get_json("/a")
    c.get_json("/b")
    c.post("/c", {"x": 1})
    c.put("/d", {"y": 2})
    stats = c.request_stats()
    assert stats["GET"] == 2
    assert stats["POST"] == 1
    assert stats["PUT"] == 1
    assert stats["total"] == 4
    assert stats["retries"] == 0


def test_http_429_retries_then_succeeds(monkeypatch):
    """A 429 is retried with backoff, then succeeds; the retry is counted."""
    c = _client()
    calls = {"n": 0}
    sleeps = []
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: sleeps.append(s))

    def fake_request(method, url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResp(429, text="rate limited")
        return _FakeResp(200, {"ok": True})

    monkeypatch.setattr(client_mod.requests, "request", fake_request)
    c.reset_request_stats()
    out = c.get_json("/x")
    assert out == {"ok": True}
    assert calls["n"] == 2
    # First attempt counts as GET, the retry counts under 'retries'.
    stats = c.request_stats()
    assert stats["GET"] == 1
    assert stats["retries"] == 1
    assert sleeps, "expected a backoff sleep before retry"


def test_http_429_respects_retry_after_header(monkeypatch):
    """When FMC supplies Retry-After, the client waits that many seconds."""
    c = _client()
    calls = {"n": 0}
    sleeps = []
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: sleeps.append(s))

    def fake_request(method, url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResp(429, headers={"Retry-After": "7"})
        return _FakeResp(200, {"ok": True})

    monkeypatch.setattr(client_mod.requests, "request", fake_request)
    out = c.get_json("/x")
    assert out == {"ok": True}
    # Slept for ~7s (+ up to 0.25s jitter) as instructed by Retry-After.
    assert sleeps and 7.0 <= sleeps[0] <= 7.5


def test_http_429_exhausts_retries_raises(monkeypatch):
    """When retries are exhausted the error surfaces (never silently skipped)."""
    c = _client()
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

    def fake_request(method, url, **kwargs):
        return _FakeResp(429, text="always limited")

    monkeypatch.setattr(client_mod.requests, "request", fake_request)
    try:
        c.get_json("/x")
        assert False, "expected FmcApiError after exhausting retries"
    except FmcApiError as e:
        assert e.status == 429


def test_get_paginated_stops_early_when_wanted_names_found(monkeypatch):
    """Broad substring queries stop paginating once every wanted name is seen,
    instead of scanning the whole (huge) result set."""
    c = _client()
    # 5 pages of 1000; the two wanted names are on page 1.
    total_pages = 5
    page_size = 1000

    calls = {"pages": 0}

    def fake_get_json(path, params=None):
        calls["pages"] += 1
        offset = (params or {}).get("offset", 0)
        idx = offset // page_size
        items = []
        if idx == 0:
            items = [{"id": "1", "name": "want_a"}, {"id": "2", "name": "want_b"}]
            items += [{"id": f"noise{j}", "name": f"noise_{j}"} for j in range(page_size - 2)]
        else:
            items = [{"id": f"n{idx}_{j}", "name": f"noise_{idx}_{j}"} for j in range(page_size)]
        return {"items": items, "paging": {"count": total_pages * page_size, "limit": page_size}}

    monkeypatch.setattr(c, "get_json", fake_get_json)
    items = c.get_paginated(
        "/x", page_size=page_size,
        stop_names={"want_a", "want_b"},
    )
    # Both wanted names landed on page 1 → we stop after one page.
    assert calls["pages"] == 1
    names = {i["name"] for i in items}
    assert {"want_a", "want_b"} <= names


def test_get_paginated_full_scan_when_names_on_last_page(monkeypatch):
    """Safety: when a wanted name only appears on the last page, early-stop
    degrades to a full scan (never drops the object)."""
    c = _client()
    total_pages = 3
    page_size = 1000

    def fake_get_json(path, params=None):
        offset = (params or {}).get("offset", 0)
        idx = offset // page_size
        if idx == total_pages - 1:
            items = [{"id": "z", "name": "want_last"}]
        else:
            items = [{"id": f"n{idx}_{j}", "name": f"noise_{idx}_{j}"} for j in range(page_size)]
        return {"items": items, "paging": {"count": (total_pages - 1) * page_size + 1,
                                           "limit": page_size}}

    monkeypatch.setattr(c, "get_json", fake_get_json)
    items = c.get_paginated("/x", page_size=page_size, stop_names={"want_last"})
    assert any(i["name"] == "want_last" for i in items)


def test_get_objects_by_names_uses_cache_on_second_call(monkeypatch):
    """A second lookup of an already-fetched object is served from cache with
    no additional request (cache_hits incremented)."""
    c = _client()
    pages = {"items": [{"id": "1", "name": "web1", "type": "Host"}]}

    def fake_get_json(path, params=None):
        return pages

    monkeypatch.setattr(c, "get_json", fake_get_json)
    first = c.get_objects_by_names("object/hosts", ["web1"], "Host")
    assert "web1" in first
    c.reset_request_stats()
    second = c.get_objects_by_names("object/hosts", ["web1"], "Host")
    assert "web1" in second
    stats = c.request_stats()
    # Served from cache: no GET issued, one cache hit recorded.
    assert stats.get("GET", 0) == 0
    assert stats["cache_hits"] >= 1
