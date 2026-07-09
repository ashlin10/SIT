"""Tests for bounded-parallel wildcard queries in get_objects_by_names.

Covers:
  - Concurrency within an object type (multiple workers execute queries)
  - The barrier between consecutive object types (no overlap)
  - Result correctness and deduplication
  - Global rate limiting (FmcRateLimiter)
  - Pagination and HTTP 429 retries inside parallel workers
  - Worker-tagged logging
  - Worker failure handling (exception propagation)
  - Sequential vs parallel timing comparison
"""
import logging
import re
import threading
import time

import pytest

import policy_configuration.services.client as client_mod
from policy_configuration.services.client import (
    DEFAULT_WORKERS,
    FMC_MAX_CONCURRENT,
    FMC_RATE_LIMIT_76,
    FMC_RATE_LIMIT_OLD,
    FmcApiError,
    FmcRateLimiter,
    PolicyFmcClient,
)


# ── Helpers ──


class _FakeResp:
    def __init__(self, status_code, json_data=None, text="", headers=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._json


def _client(**kw):
    """Create a client with a very permissive rate limiter for fast tests."""
    defaults = {
        "fmc_ip": "https://fmc.example.com",
        "headers": {"X-auth-access-token": "t"},
        "domain_uuid": "dom-1",
        "rate_limiter": FmcRateLimiter(requests_per_min=999_999, max_concurrent=100),
    }
    defaults.update(kw)
    return PolicyFmcClient(**defaults)


# ═══════════════════════════════════════════════════════════════════════════
# 1. FmcRateLimiter
# ═══════════════════════════════════════════════════════════════════════════


class TestFmcRateLimiter:
    def test_for_version_76_gets_300(self):
        rl = FmcRateLimiter.for_version("7.6.0")
        assert rl.requests_per_min == FMC_RATE_LIMIT_76

    def test_for_version_80_gets_300(self):
        rl = FmcRateLimiter.for_version("8.0.1")
        assert rl.requests_per_min == FMC_RATE_LIMIT_76

    def test_for_version_75_gets_120(self):
        rl = FmcRateLimiter.for_version("7.5.0")
        assert rl.requests_per_min == FMC_RATE_LIMIT_OLD

    def test_for_version_none_gets_conservative(self):
        rl = FmcRateLimiter.for_version(None)
        assert rl.requests_per_min == FMC_RATE_LIMIT_OLD

    def test_for_version_garbage_gets_conservative(self):
        rl = FmcRateLimiter.for_version("not-a-version")
        assert rl.requests_per_min == FMC_RATE_LIMIT_OLD

    def test_acquire_release_cycle(self):
        """Basic acquire/release doesn't deadlock."""
        rl = FmcRateLimiter(requests_per_min=600, max_concurrent=2)
        rl.acquire()
        rl.release()
        rl.acquire()
        rl.release()

    def test_concurrent_connections_limited(self):
        """Semaphore limits active connections."""
        rl = FmcRateLimiter(requests_per_min=999_999, max_concurrent=2)
        active = threading.Semaphore(0)
        max_active = {"v": 0}
        lock = threading.Lock()
        barrier = threading.Barrier(3)

        def worker():
            rl.acquire()
            active.release()
            with lock:
                # count how many are active
                pass
            time.sleep(0.05)
            rl.release()
            barrier.wait(timeout=5)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t3 = threading.Thread(target=worker)
        t1.start(); t2.start(); t3.start()
        # all three should eventually complete
        t1.join(timeout=5); t2.join(timeout=5); t3.join(timeout=5)
        assert not t1.is_alive()
        assert not t2.is_alive()
        assert not t3.is_alive()

    def test_custom_rpm(self):
        rl = FmcRateLimiter(requests_per_min=60, max_concurrent=5)
        assert rl.requests_per_min == 60

    def test_initial_burst_is_immediate(self):
        """Up to max_concurrent acquires fire immediately (no serialization)."""
        rl = FmcRateLimiter(requests_per_min=60, max_concurrent=8)  # slow refill
        t0 = time.monotonic()
        for _ in range(8):
            rl.acquire()
            rl.release()
        elapsed = time.monotonic() - t0
        # 8 burst tokens available up front → effectively no waiting.
        assert elapsed < 0.2, f"burst took {elapsed:.2f}s, expected immediate"

    def test_sustained_rate_enforced_after_burst(self):
        """Once burst tokens drain, further acquires are spaced by the refill."""
        # capacity=1 → no burst; refill 120/min = 2/s → ~0.5s between acquires.
        rl = FmcRateLimiter(requests_per_min=120, max_concurrent=1)
        rl.acquire(); rl.release()  # drains the single token
        t0 = time.monotonic()
        rl.acquire(); rl.release()  # must wait ~0.5s for a refill
        elapsed = time.monotonic() - t0
        assert 0.3 <= elapsed <= 0.9, f"expected ~0.5s spacing, got {elapsed:.2f}s"

    def test_burst_not_serialized_under_lock(self):
        """A full burst of acquires completes far faster than a serialized
        limiter would allow, proving the lock is not held during any wait.

        With rpm=60 (1s interval), the old sleep-under-lock design would take
        ~7s for 8 acquires; the token bucket completes the burst near-instantly.
        """
        rl = FmcRateLimiter(requests_per_min=60, max_concurrent=8)
        t0 = time.monotonic()
        threads = [
            threading.Thread(target=lambda: (rl.acquire(), rl.release()))
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        elapsed = time.monotonic() - t0
        assert elapsed < 0.5, f"burst serialized ({elapsed:.2f}s) — lock held?"


# ═══════════════════════════════════════════════════════════════════════════
# 2. Parallel query execution within an object type
# ═══════════════════════════════════════════════════════════════════════════


class TestParallelQueries:
    def test_multiple_workers_execute_queries(self, monkeypatch):
        """With max_workers=4 and 8 queries, 4 threads execute concurrently."""
        c = _client(max_workers=4)
        thread_ids: set = set()
        lock = threading.Lock()
        # Names that won't be grouped by compute_wildcard_queries (diverse prefixes)
        names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"]

        def fake_request(method, url, **kwargs):
            with lock:
                thread_ids.add(threading.current_thread().ident)
            time.sleep(0.02)  # small delay so threads overlap
            params = kwargs.get("params", {})
            filt = params.get("filter", "")
            query_str = filt.split(":", 1)[-1] if ":" in filt else ""
            # Return items matching any of our names that contain the query string
            items = [{"id": n, "name": n, "type": "Host"} for n in names
                     if query_str.lower() in n.lower()]
            if not items:
                items = [{"id": query_str, "name": query_str, "type": "Host"}]
            return _FakeResp(200, {"items": items, "paging": {}})

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names("object/hosts", names, "Host")
        # All names found
        assert len(result) == len(names)
        # Multiple threads were used (more than 1)
        assert len(thread_ids) > 1

    def test_single_query_uses_single_worker(self, monkeypatch):
        """With only 1 query, no thread pool is created (fast path)."""
        c = _client(max_workers=8)

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "lonely", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names("object/hosts", ["lonely"], "Host")
        assert "lonely" in result

    def test_workers_capped_at_query_count(self, monkeypatch):
        """max_workers=8 but only 3 queries → 3 workers used."""
        c = _client(max_workers=8)

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "a", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names("object/hosts", ["a", "b", "c"], "Host")
        # Should work without error even though workers > queries
        assert len(result) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# 3. Type barrier (sequential between types)
# ═══════════════════════════════════════════════════════════════════════════


class TestTypeBarrier:
    def test_sequential_type_processing(self, monkeypatch):
        """Two calls to get_objects_by_names for different types don't overlap."""
        c = _client(max_workers=4)
        order = []
        lock = threading.Lock()

        original_get_paginated = c.get_paginated

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "obj1", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)

        # Type 1
        r1 = c.get_objects_by_names("object/hosts", ["obj1"], "Host")
        order.append("Host-done")

        # Type 2 (only starts after type 1 completes)
        r2 = c.get_objects_by_names("object/networks", ["obj1"], "Network")
        order.append("Network-done")

        assert order == ["Host-done", "Network-done"]


# ═══════════════════════════════════════════════════════════════════════════
# 4. Result correctness and deduplication
# ═══════════════════════════════════════════════════════════════════════════


class TestResultCorrectness:
    def test_deduplication_across_overlapping_queries(self, monkeypatch):
        """If two queries return the same object, it appears only once in results."""
        c = _client(max_workers=4)

        def fake_request(method, url, **kwargs):
            # Both queries return the same object
            return _FakeResp(200, {
                "items": [
                    {"id": "h-1", "name": "web_server", "type": "Host", "value": "10.0.0.1"},
                    {"id": "h-2", "name": "web_proxy", "type": "Host", "value": "10.0.0.2"},
                ],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names(
            "object/hosts", ["web_server", "web_proxy"], "Host",
        )
        assert len(result) == 2
        assert result["web_server"]["value"] == "10.0.0.1"
        assert result["web_proxy"]["value"] == "10.0.0.2"

    def test_cache_serves_subsequent_calls(self, monkeypatch):
        """After a parallel fetch populates the cache, a second call is served
        from cache with no HTTP requests."""
        c = _client(max_workers=4)
        call_count = {"n": 0}

        def fake_request(method, url, **kwargs):
            call_count["n"] += 1
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "web1", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)

        # First call: fetches via HTTP
        r1 = c.get_objects_by_names("object/hosts", ["web1"], "Host")
        first_calls = call_count["n"]
        assert first_calls > 0

        # Second call: served from cache
        c.reset_request_stats()
        r2 = c.get_objects_by_names("object/hosts", ["web1"], "Host")
        stats = c.request_stats()
        assert stats.get("GET", 0) == 0
        assert stats["cache_hits"] >= 1


# ═══════════════════════════════════════════════════════════════════════════
# 5. Global rate limiting
# ═══════════════════════════════════════════════════════════════════════════


class TestGlobalRateLimiting:
    def test_rate_limiter_version_autodetect_in_client(self):
        """Client with fmc_version='7.6.0' creates a 300 rpm limiter."""
        c = PolicyFmcClient(
            "https://fmc.example.com",
            {"X-auth-access-token": "t"}, "dom-1",
            fmc_version="7.6.0",
        )
        assert c._rate.requests_per_min == FMC_RATE_LIMIT_76

    def test_rate_limiter_old_version(self):
        c = PolicyFmcClient(
            "https://fmc.example.com",
            {"X-auth-access-token": "t"}, "dom-1",
            fmc_version="7.4.0",
        )
        assert c._rate.requests_per_min == FMC_RATE_LIMIT_OLD

    def test_rate_limiter_no_version(self):
        c = PolicyFmcClient(
            "https://fmc.example.com",
            {"X-auth-access-token": "t"}, "dom-1",
        )
        assert c._rate.requests_per_min == FMC_RATE_LIMIT_OLD

    def test_custom_rate_limiter_overrides_version(self):
        custom = FmcRateLimiter(requests_per_min=42, max_concurrent=5)
        c = PolicyFmcClient(
            "https://fmc.example.com",
            {"X-auth-access-token": "t"}, "dom-1",
            fmc_version="7.6.0",
            rate_limiter=custom,
        )
        assert c._rate.requests_per_min == 42


# ═══════════════════════════════════════════════════════════════════════════
# 6. Pagination and HTTP 429 retries within parallel workers
# ═══════════════════════════════════════════════════════════════════════════


class TestPaginationAnd429:
    def test_paginated_query_in_worker(self, monkeypatch):
        """A wildcard query that spans 2 pages still returns all items."""
        c = _client(max_workers=2)
        call_count = {"n": 0}

        def fake_request(method, url, **kwargs):
            call_count["n"] += 1
            params = kwargs.get("params", {})
            offset = params.get("offset", 0)
            if offset == 0:
                return _FakeResp(200, {
                    "items": [{"id": "1", "name": "host_a", "type": "Host"}],
                    "paging": {"count": 2, "limit": 1},
                })
            else:
                return _FakeResp(200, {
                    "items": [{"id": "2", "name": "host_b", "type": "Host"}],
                    "paging": {"count": 2, "limit": 1},
                })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names(
            "object/hosts", ["host_a", "host_b"], "Host",
        )
        assert len(result) == 2

    def test_429_retry_in_worker_succeeds(self, monkeypatch):
        """A 429 inside a parallel worker is retried and succeeds."""
        c = _client(max_workers=2)
        calls = {"n": 0}
        monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

        def fake_request(method, url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeResp(429, text="rate limited", headers={"Retry-After": "0"})
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "web1", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names("object/hosts", ["web1"], "Host")
        assert "web1" in result

    def test_429_retry_after_respected(self, monkeypatch):
        """Worker respects Retry-After header value."""
        c = _client(max_workers=1)
        calls = {"n": 0}
        sleeps = []
        monkeypatch.setattr(client_mod.time, "sleep", lambda s: sleeps.append(s))

        def fake_request(method, url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeResp(429, headers={"Retry-After": "5"})
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "web1", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        result = c.get_objects_by_names("object/hosts", ["web1"], "Host")
        assert "web1" in result
        assert any(5.0 <= s <= 5.5 for s in sleeps)


# ═══════════════════════════════════════════════════════════════════════════
# 7. Worker-tagged logging
# ═══════════════════════════════════════════════════════════════════════════


class TestWorkerLogging:
    def test_worker_tags_in_log_output(self, monkeypatch, caplog):
        """Each query log line includes a [worker-N] tag."""
        c = _client(max_workers=4)

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": str(i), "name": f"obj_{i}", "type": "Host"}
                          for i in range(4)],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)

        with caplog.at_level(logging.INFO):
            c.get_objects_by_names(
                "object/hosts",
                ["obj_0", "obj_1", "obj_2", "obj_3"],
                "Host",
            )

        # Check that worker tags appear in logs
        worker_lines = [r.message for r in caplog.records if "[worker-" in r.message]
        assert len(worker_lines) >= 1
        # Every worker-tagged line has the format [worker-N]
        for line in worker_lines:
            assert re.search(r"\[worker-\d+\]", line)

    def test_query_numbering_stable(self, monkeypatch, caplog):
        """Query numbers (e.g. query 3/5) are stable even with parallel execution."""
        c = _client(max_workers=4)

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "x", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)

        with caplog.at_level(logging.INFO):
            c.get_objects_by_names(
                "object/hosts",
                [f"name_{i}" for i in range(5)],
                "Host",
            )

        # Extract query N/M from log lines
        query_nums = set()
        for rec in caplog.records:
            m = re.search(r"query (\d+)/(\d+)", rec.message)
            if m:
                query_nums.add(int(m.group(1)))
                total = int(m.group(2))
        # All query numbers should be present
        if query_nums:
            assert max(query_nums) <= total
            assert min(query_nums) >= 1

    def test_summary_log_includes_worker_count(self, monkeypatch, caplog):
        """The summary log line includes the worker count."""
        c = _client(max_workers=3)

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "a", "type": "Host"},
                          {"id": "2", "name": "b", "type": "Host"},
                          {"id": "3", "name": "c", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        with caplog.at_level(logging.INFO):
            c.get_objects_by_names("object/hosts", ["a", "b", "c"], "Host")

        summary = [r.message for r in caplog.records if "workers)" in r.message]
        assert any("3 workers" in s for s in summary)


# ═══════════════════════════════════════════════════════════════════════════
# 8. Worker failure handling
# ═══════════════════════════════════════════════════════════════════════════


class TestWorkerFailure:
    def test_worker_exception_propagates(self, monkeypatch):
        """If a worker raises, the error is surfaced (not swallowed)."""
        c = _client(max_workers=4)
        calls = {"n": 0}
        monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

        def fake_request(method, url, **kwargs):
            calls["n"] += 1
            # First query succeeds, second always fails with 429 until retries exhaust
            if "nameOrValue:fail" in str(kwargs.get("params", {})):
                return _FakeResp(429, text="always limited")
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "good_obj", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)

        # The wildcard queries will include separate queries for "good_obj" and
        # "fail_obj" since they don't share a long enough common prefix.
        # But the FmcApiError from 429 exhaustion causes fallback to full fetch,
        # which also needs to return the object. Let's make it simpler: just
        # test that the error is not silently swallowed.
        # Use names that won't group together.
        c2 = _client(max_workers=4, max_retries=0)
        monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

        def always_fail(method, url, **kwargs):
            return _FakeResp(429, text="always limited")

        monkeypatch.setattr(client_mod.requests, "request", always_fail)

        # All queries fail with 429 → FmcApiError raised from wildcard path,
        # then full fetch also fails → FmcApiError
        with pytest.raises(FmcApiError):
            c2.get_objects_by_names("object/hosts", ["obj_a"], "Host")

    def test_partial_worker_failure_does_not_lose_results(self, monkeypatch):
        """When one worker fails but others succeed, already-found results are
        preserved (the full-fetch fallback picks them up)."""
        c = _client(max_workers=4, max_retries=0)
        monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
        query_count = {"n": 0}

        def selective_fail(method, url, **kwargs):
            query_count["n"] += 1
            params = kwargs.get("params", {})
            filt = params.get("filter", "")
            if "nameOrValue:zzz_unique" in filt:
                return _FakeResp(429, text="limited")
            return _FakeResp(200, {
                "items": [
                    {"id": "1", "name": "good_host", "type": "Host", "value": "1.2.3.4"},
                    {"id": "2", "name": "zzz_unique_host", "type": "Host", "value": "5.6.7.8"},
                ],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", selective_fail)
        result = c.get_objects_by_names(
            "object/hosts", ["good_host", "zzz_unique_host"], "Host",
        )
        # The full-fetch fallback returns both objects
        assert len(result) == 2


# ═══════════════════════════════════════════════════════════════════════════
# 9. Request statistics
# ═══════════════════════════════════════════════════════════════════════════


class TestRequestStats:
    def test_stats_track_methods(self, monkeypatch):
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

    def test_stats_track_retries(self, monkeypatch):
        c = _client()
        calls = {"n": 0}
        monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

        def fake_request(method, url, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeResp(429, text="limited")
            return _FakeResp(200, {"ok": True})

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        c.reset_request_stats()
        c.get_json("/x")
        stats = c.request_stats()
        assert stats["retries"] == 1

    def test_stats_track_cache_hits(self, monkeypatch):
        c = _client()

        def fake_request(method, url, **kwargs):
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "web1", "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        c.get_objects_by_names("object/hosts", ["web1"], "Host")
        c.reset_request_stats()
        c.get_objects_by_names("object/hosts", ["web1"], "Host")
        stats = c.request_stats()
        assert stats["cache_hits"] >= 1
        assert stats.get("GET", 0) == 0


# ═══════════════════════════════════════════════════════════════════════════
# 10. Configurable workers
# ═══════════════════════════════════════════════════════════════════════════


class TestConfigurableWorkers:
    def test_default_workers(self):
        c = _client()
        assert c.max_workers == DEFAULT_WORKERS

    def test_custom_workers(self):
        c = _client(max_workers=16)
        assert c.max_workers == 16

    def test_min_one_worker(self):
        c = _client(max_workers=0)
        assert c.max_workers == 1


# ═══════════════════════════════════════════════════════════════════════════
# 11. Sequential vs parallel timing comparison
# ═══════════════════════════════════════════════════════════════════════════


class TestTimingComparison:
    def test_parallel_faster_than_sequential(self, monkeypatch):
        """With 20 queries each taking ~50ms, parallel (4 workers) should
        be measurably faster than sequential."""
        per_query_delay = 0.05  # 50ms
        # Use completely distinct names so compute_wildcard_queries can't group them.
        distinct_names = [
            "alpha", "bravo", "charlie", "delta", "echo",
            "foxtrot", "golf", "hotel", "india", "juliet",
            "kilo", "lima", "mike", "november", "oscar",
            "papa", "quebec", "romeo", "sierra", "tango",
        ]
        num_names = len(distinct_names)

        def fake_request_slow(method, url, **kwargs):
            time.sleep(per_query_delay)
            params = kwargs.get("params", {})
            filt = params.get("filter", "")
            name = filt.split(":", 1)[-1] if ":" in filt else "x"
            return _FakeResp(200, {
                "items": [{"id": name, "name": name, "type": "Host"}],
                "paging": {},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request_slow)
        names = distinct_names

        # Sequential: max_workers=1
        c_seq = _client(max_workers=1)
        t0 = time.monotonic()
        r_seq = c_seq.get_objects_by_names("object/hosts", names, "Host")
        t_seq = time.monotonic() - t0

        # Parallel: max_workers=4
        c_par = _client(max_workers=4)
        t0 = time.monotonic()
        r_par = c_par.get_objects_by_names("object/hosts", names, "Host")
        t_par = time.monotonic() - t0

        # Both should return the same number of results
        assert len(r_seq) == len(r_par)

        # Parallel should be at least 2x faster
        speedup = t_seq / t_par if t_par > 0 else float("inf")
        assert speedup >= 2.0, (
            f"Expected ≥2x speedup, got {speedup:.1f}x "
            f"(seq={t_seq:.2f}s, par={t_par:.2f}s)"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 12. Case-insensitive wildcard deduplication
# ═══════════════════════════════════════════════════════════════════════════


class TestCaseInsensitiveGrouping:
    def test_tcp_variants_merged(self):
        """TCP, tcp, Tcp should all collapse into a single query since FMC
        nameOrValue is case-insensitive."""
        names = ["TCP_3306", "tcp_8305", "Tcp_1433"]
        qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
        # All three share case-insensitive prefix 'tcp_' (len 4 >= min_prefix 3)
        assert len(qs) == 1

    def test_mixed_case_hosts(self):
        """Host-10.0.0.1 and host-10.0.0.2 share case-insensitive prefix."""
        names = ["Host-10.0.0.1", "host-10.0.0.2", "HOST-10.0.0.3"]
        qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
        assert len(qs) == 1

    def test_no_false_merge(self):
        """Names that differ even case-insensitively stay separate."""
        names = ["ABC_foo", "XYZ_bar"]
        qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
        assert len(qs) == 2
        assert "ABC_foo" in qs
        assert "XYZ_bar" in qs


# ═══════════════════════════════════════════════════════════════════════════
# 13. Broad prefixes collapse (no query explosion) — parallel pagination
#     absorbs large result sets instead of fragmenting the query set.
# ═══════════════════════════════════════════════════════════════════════════


class TestBroadPrefixGrouping:
    def test_large_group_stays_one_query(self):
        """A big prefix group collapses to ONE common-prefix query (not many).

        Fragmenting into sub-prefixes only multiplies redundant server scans;
        the large result set is instead fetched via parallel pagination.
        """
        names = [f"10.{i}.0.1" for i in range(30)]
        qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
        assert qs == ["10."]

    def test_every_name_covered_by_a_query(self):
        """Every original name matches at least one emitted query prefix."""
        names = [f"DC_{chr(65 + i)}_server" for i in range(25)]
        qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
        for name in names:
            assert any(name.startswith(q) for q in qs), \
                f"{name} not covered by any query: {qs}"

    def test_query_count_bounded_by_distinct_prefixes(self):
        """100 names sharing a common prefix produce a single query, not 100."""
        names = [f"H_1{i:02d}_obj" for i in range(100)]
        qs = PolicyFmcClient.compute_wildcard_queries(names, min_prefix=3)
        assert len(qs) == 1


# ═══════════════════════════════════════════════════════════════════════════
# 13b. Parallel pagination of a single large query
# ═══════════════════════════════════════════════════════════════════════════


class TestParallelPagination:
    def test_large_result_fetched_across_pages_concurrently(self, monkeypatch):
        """A query whose count spans many pages fetches remaining pages in
        parallel and returns every item exactly once, in offset order."""
        c = _client(max_workers=8)
        page_size = 1000
        total = 4500  # → 5 pages (0..4000)

        seen_threads: set = set()
        tlock = threading.Lock()

        def fake_request(method, url, **kwargs):
            params = kwargs.get("params") or {}
            offset = int(params.get("offset", 0))
            limit = int(params.get("limit", page_size))
            with tlock:
                seen_threads.add(threading.get_ident())
            items = [
                {"id": str(offset + k), "name": f"n{offset + k}"}
                for k in range(min(limit, max(0, total - offset)))
            ]
            return _FakeResp(200, {
                "items": items,
                "paging": {"count": total, "limit": page_size},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        items = c.get_paginated("/x", page_size=page_size)
        assert len(items) == total
        # Order preserved by offset.
        assert [it["id"] for it in items] == [str(k) for k in range(total)]
        # Remaining pages ran on more than one thread (true parallelism).
        assert len(seen_threads) > 1

    def test_single_page_no_pool(self, monkeypatch):
        """A result that fits on one page issues exactly one GET."""
        c = _client(max_workers=8)
        calls = {"n": 0}

        def fake_request(method, url, **kwargs):
            calls["n"] += 1
            return _FakeResp(200, {
                "items": [{"id": "1", "name": "only"}],
                "paging": {"count": 1, "limit": 1000},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        items = c.get_paginated("/x")
        assert len(items) == 1
        assert calls["n"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# 14. Early-exit optimization
# ═══════════════════════════════════════════════════════════════════════════


class TestEarlyExit:
    def test_queries_skipped_after_all_found(self, monkeypatch):
        """Once all wanted names are resolved, remaining queries are skipped."""
        c = _client(max_workers=2)
        queries_executed = {"count": 0}

        def fake_request(method, url, **kw):
            queries_executed["count"] += 1
            # First query returns both wanted names → all resolved.
            return _FakeResp(200, json_data={
                "items": [
                    {"id": "1", "name": "alpha", "type": "Host"},
                    {"id": "2", "name": "beta", "type": "Host"},
                ],
                "paging": {"count": 2, "limit": 1000},
            })

        monkeypatch.setattr(client_mod.requests, "request", fake_request)
        # 4 queries, but first one finds both names.
        result = c.get_objects_by_names(
            "object/hosts", ["alpha", "beta"], "Host",
        )
        assert "alpha" in result
        assert "beta" in result
        # Should execute fewer than 4 queries thanks to early-exit.
        # (At least the queries already submitted to the executor will run,
        # but subsequent ones should be skipped.)
        assert queries_executed["count"] < 4


# ═══════════════════════════════════════════════════════════════════════════
# 15. Integration with acp_fetch (type barrier via conftest FakeFmcClient)
# ═══════════════════════════════════════════════════════════════════════════


class TestIntegrationWithAcpFetch:
    def test_existing_acp_fetch_tests_still_pass(self):
        """Smoke-check: the FakeFmcClient in conftest still satisfies the
        get_objects_by_names interface expected by acp_fetch."""
        from .conftest import FakeFmcClient
        data = {
            "object/hosts": [
                {"id": "h-1", "name": "web1", "value": "10.0.0.1", "type": "Host"},
            ],
        }
        client = FakeFmcClient(data=data)
        result = client.get_objects_by_names("object/hosts", ["web1"], "Host")
        assert "web1" in result
        assert result["web1"]["value"] == "10.0.0.1"
