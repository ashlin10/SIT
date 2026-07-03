"""Instance-scoped FMC REST client for the policy replication feature.

Why a dedicated client instead of ``utils.fmc_api``?
``utils.fmc_api`` keeps a single module-global ``_auth_state`` (token/headers),
which makes it unsafe to talk to a *source* and a *target* FMC simultaneously.
``PolicyFmcClient`` holds its own ``fmc_ip``/``headers``/``domain_uuid`` so the
two connections never contend, while replicating the proven behaviour of
``utils.fmc_api._fmc_request``: GET rate limiting, retry/backoff, one-time 401
re-auth, secret redaction in debug logs, and pagination.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Set

import requests
from requests.auth import HTTPBasicAuth

from ..models.schema import redact, normalize_name

logger = logging.getLogger(__name__)

# Silence noisy InsecureRequestWarning (FMC uses self-signed certs).
try:  # pragma: no cover - best effort
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


class FmcApiError(Exception):
    """Raised for non-recoverable FMC API errors with an actionable message."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


# ── FMC rate-limit constants ──
FMC_RATE_LIMIT_76 = 300   # GET requests/min for FMC 7.6+
FMC_RATE_LIMIT_OLD = 120  # GET requests/min for FMC < 7.6
FMC_MAX_CONCURRENT = 10   # max concurrent connections per client IP (all versions)
DEFAULT_WORKERS = 8        # default parallel workers for wildcard queries


class FmcRateLimiter:
    """Global, thread-safe token-bucket rate limiter for FMC GET requests.

    Enforces both a per-minute request cap (derived from FMC version) and a
    concurrent-connection semaphore.  Tokens are released with small random
    jitter so parallel workers don't burst simultaneously.
    """

    def __init__(self, requests_per_min: int = FMC_RATE_LIMIT_OLD,
                 max_concurrent: int = FMC_MAX_CONCURRENT):
        self._rpm = max(1, requests_per_min)
        self._min_interval = 60.0 / self._rpm
        self._lock = threading.Lock()
        self._last = 0.0
        self._semaphore = threading.Semaphore(max_concurrent)

    @property
    def requests_per_min(self) -> int:
        return self._rpm

    def acquire(self) -> None:
        """Block until both the rate-limit slot and a connection slot are free."""
        self._semaphore.acquire()
        try:
            with self._lock:
                now = time.monotonic()
                wait = self._min_interval - (now - self._last)
                if wait > 0:
                    # add small jitter to stagger parallel workers
                    wait += random.uniform(0, self._min_interval * 0.1)
                    time.sleep(wait)
                self._last = time.monotonic()
        except BaseException:
            self._semaphore.release()
            raise

    def release(self) -> None:
        """Release the connection slot after the request completes."""
        self._semaphore.release()

    @classmethod
    def for_version(cls, version_str: Optional[str] = None,
                    max_concurrent: int = FMC_MAX_CONCURRENT) -> "FmcRateLimiter":
        """Create a limiter with the correct rate for the given FMC version."""
        rpm = FMC_RATE_LIMIT_OLD  # conservative default
        if version_str:
            try:
                parts = version_str.split(".")
                major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
                if (major, minor) >= (7, 6):
                    rpm = FMC_RATE_LIMIT_76
            except (ValueError, IndexError):
                pass
        return cls(requests_per_min=rpm, max_concurrent=max_concurrent)


class PolicyFmcClient:
    """A thin, instance-scoped FMC REST client.

    Parameters
    ----------
    fmc_ip:
        Base URL including scheme and optional port, e.g. ``https://10.0.0.1:443``.
    headers:
        Auth headers (must contain ``X-auth-access-token``).
    domain_uuid:
        Domain UUID for ``/api/fmc_config/v1/domain/{uuid}`` paths.
    credentials:
        Optional ``(username, password)`` used for a single re-auth on 401/419.
    debug:
        When True, request/response lines are logged (with secrets redacted).
    """

    def __init__(
        self,
        fmc_ip: str,
        headers: Dict[str, str],
        domain_uuid: str,
        credentials: Optional[tuple] = None,
        debug: bool = False,
        max_retries: int = 2,
        timeout: float = 60.0,
        fmc_version: Optional[str] = None,
        max_workers: int = DEFAULT_WORKERS,
        rate_limiter: Optional[FmcRateLimiter] = None,
    ):
        self.fmc_ip = (fmc_ip or "").rstrip("/")
        self.headers = dict(headers or {})
        self.domain_uuid = domain_uuid or ""
        self._credentials = credentials
        self.debug = debug
        self.max_retries = max_retries
        self.timeout = timeout
        self.fmc_version = fmc_version
        self.max_workers = max(1, max_workers)
        self._rate = rate_limiter or FmcRateLimiter.for_version(fmc_version)
        # Per-operation object cache: {(type, normalized_name): object_dict}
        self._obj_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        # Capability flags discovered at runtime, e.g. {"bulk:hosts": False}
        self._capabilities: Dict[str, bool] = {}
        # Thread-safe re-auth gate: only one thread re-authenticates at a time.
        self._reauth_lock = threading.Lock()
        # Request counters (thread-safe).
        self._stats_lock = threading.Lock()
        self._request_counts: Dict[str, int] = {}
        self._retry_count = 0
        self._cache_hit_count = 0

    # ── URL building ──

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.fmc_ip}{path}"

    def cfg_path(self, suffix: str) -> str:
        """Build a /api/fmc_config/v1/domain/{uuid}/<suffix> path."""
        suffix = suffix.lstrip("/")
        return f"/api/fmc_config/v1/domain/{self.domain_uuid}/{suffix}"

    # ── Core request ──

    def _reauth(self) -> bool:
        if not self._credentials:
            return False
        with self._reauth_lock:
            user, pwd = self._credentials
            try:
                auth_url = f"{self.fmc_ip}/api/fmc_platform/v1/auth/generatetoken"
                r = requests.post(
                    auth_url, headers={"Content-Type": "application/json"},
                    auth=HTTPBasicAuth(user, pwd), verify=False, timeout=self.timeout,
                )
                r.raise_for_status()
                token = r.headers.get("X-auth-access-token")
                if not token:
                    return False
                self.headers["X-auth-access-token"] = token
                self.headers.setdefault("Content-Type", "application/json")
                logger.info("Re-authenticated to FMC after 401/419.")
                return True
            except Exception as ex:  # pragma: no cover - network failure path
                logger.error(f"Re-authentication failed: {ex}")
                return False

    def request(
        self, method: str, path: str, *,
        json: Optional[Any] = None, params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        url = self._url(path)
        method = method.upper()
        is_get = method == "GET"
        if is_get:
            self._rate.acquire()

        if self.debug:
            logger.info(f"[POLICY DEBUG] >>> {method} {url}")
            if json is not None:
                logger.info(f"[POLICY DEBUG]     Payload: {redact(json)}")
            if params:
                logger.info(f"[POLICY DEBUG]     Params: {params}")

        with self._stats_lock:
            self._request_counts[method] = self._request_counts.get(method, 0) + 1

        backoff = 1.0
        last_resp: Optional[requests.Response] = None
        try:
            for attempt in range(self.max_retries + 1):
                try:
                    resp = requests.request(
                        method=method, url=url, headers=self.headers,
                        json=json, params=params, verify=False, timeout=self.timeout,
                    )
                except requests.exceptions.Timeout as e:
                    if attempt >= self.max_retries:
                        raise FmcApiError(f"Request to {url} timed out") from e
                    with self._stats_lock:
                        self._retry_count += 1
                    time.sleep(min(backoff * (2 ** attempt), 30.0))
                    continue
                except requests.exceptions.RequestException as e:
                    if attempt >= self.max_retries:
                        raise FmcApiError(f"Connection error to {url}: {e}") from e
                    with self._stats_lock:
                        self._retry_count += 1
                    time.sleep(min(backoff * (2 ** attempt), 30.0))
                    continue

                status = resp.status_code
                if self.debug:
                    preview = (resp.text or "")[:500]
                    logger.info(f"[POLICY DEBUG] <<< {status} {method} {url}: {preview}")

                if 200 <= status < 300:
                    return resp

                if status in (401, 419) and attempt < self.max_retries:
                    with self._stats_lock:
                        self._retry_count += 1
                    if self._reauth():
                        continue
                    raise FmcApiError("FMC session expired and re-authentication failed.", status)

                if status in (429, 500, 502, 503, 504, 408):
                    last_resp = resp
                    if attempt >= self.max_retries:
                        break
                    with self._stats_lock:
                        self._retry_count += 1
                    retry_after = resp.headers.get("Retry-After")
                    try:
                        sleep_for = float(retry_after) if retry_after else min(backoff * (2 ** attempt), 30.0)
                    except ValueError:
                        sleep_for = min(backoff * (2 ** attempt), 30.0)
                    sleep_for += random.uniform(0, 0.25)
                    logger.warning(f"HTTP {status} on {method} {url}; retrying in {sleep_for:.2f}s")
                    time.sleep(sleep_for)
                    continue

                # Other 4xx: surface the error description.
                raise FmcApiError(self._error_text(resp), status)

            if last_resp is not None:
                raise FmcApiError(self._error_text(last_resp), last_resp.status_code)
            raise FmcApiError(f"Request to {url} failed after retries")
        finally:
            if is_get:
                self._rate.release()

    @staticmethod
    def _error_text(resp: requests.Response) -> str:
        try:
            data = resp.json()
            msgs = (data.get("error") or {}).get("messages") or []
            if msgs and isinstance(msgs, list):
                return f"FMC {resp.status_code}: {msgs[0].get('description', resp.text[:200])}"
        except Exception:
            pass
        return f"FMC {resp.status_code}: {(resp.text or '')[:200]}"

    # ── High-level helpers ──

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = self.request("GET", path, params=params)
        try:
            return resp.json()
        except Exception:
            return {}

    def get_paginated(
        self, path: str, *, expanded: bool = True, page_size: int = 1000,
        params: Optional[Dict[str, Any]] = None, max_pages: int = 10000,
    ) -> List[Dict[str, Any]]:
        """Fetch ALL items across pages.

        Follows the FMC ``paging`` metadata (``paging.next`` URLs when present,
        otherwise ``offset``+``count``/``pages``). Never assumes a 1000 cap.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        base_params = dict(params or {})
        if expanded:
            base_params.setdefault("expanded", "true")
        next_url: Optional[str] = None
        page = 0
        while page < max_pages:
            page += 1
            if next_url:
                data = self.get_json(next_url)
            else:
                p = dict(base_params)
                p["offset"] = offset
                p["limit"] = page_size
                data = self.get_json(path, params=p)
            batch = data.get("items") or []
            items.extend(batch)
            paging = data.get("paging") or {}
            # Prefer explicit next link.
            nxt = paging.get("next")
            if isinstance(nxt, list) and nxt:
                next_url = nxt[0]
                continue
            if isinstance(nxt, str) and nxt:
                next_url = nxt
                continue
            next_url = None
            # Fallback: offset arithmetic using count/pages metadata.
            count = paging.get("count")
            limit = paging.get("limit", page_size)
            if not batch or (isinstance(count, int) and len(items) >= count):
                break
            if len(batch) < (limit or page_size):
                break
            offset += (limit or page_size)
        return items

    def post(self, path: str, body: Any, *, bulk: bool = False) -> Any:
        params = {"bulk": "true"} if bulk else None
        resp = self.request("POST", path, json=body, params=params)
        try:
            return resp.json()
        except Exception:
            return {}

    def put(self, path: str, body: Any) -> Any:
        resp = self.request("PUT", path, json=body)
        try:
            return resp.json()
        except Exception:
            return {}

    def delete(self, path: str) -> Any:
        resp = self.request("DELETE", path)
        try:
            return resp.json()
        except Exception:
            return {}

    # ── Request statistics ──

    def reset_request_stats(self) -> None:
        with self._stats_lock:
            self._request_counts.clear()
            self._retry_count = 0
            self._cache_hit_count = 0

    def request_stats(self) -> Dict[str, int]:
        with self._stats_lock:
            stats = dict(self._request_counts)
            stats["total"] = sum(self._request_counts.values())
            stats["retries"] = self._retry_count
            stats["cache_hits"] = self._cache_hit_count
            return stats

    # ── Object cache + wildcard retrieval ──

    def cache_get(self, obj_type: str, name: str) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            hit = self._obj_cache.get(f"{obj_type}::{normalize_name(name)}")
        if hit is not None:
            with self._stats_lock:
                self._cache_hit_count += 1
        return hit

    def cache_put(self, obj_type: str, obj: Dict[str, Any]) -> None:
        nm = obj.get("name")
        if nm:
            with self._cache_lock:
                self._obj_cache[f"{obj_type}::{normalize_name(nm)}"] = obj

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._obj_cache.clear()

    @staticmethod
    def compute_wildcard_queries(names: List[str], min_prefix: int = 3) -> List[str]:
        """Group names by common prefix to minimise nameOrValue queries.

        Mirrors ``utils.fmc_api._compute_wildcard_queries`` intent: names sharing
        a >= ``min_prefix`` char prefix collapse into a single wildcard query.
        """
        clean = sorted({n for n in names if n})
        if not clean:
            return []
        queries: List[str] = []
        used = [False] * len(clean)
        for i, n in enumerate(clean):
            if used[i]:
                continue
            prefix = n
            group = [i]
            for j in range(i + 1, len(clean)):
                if used[j]:
                    continue
                common = _common_prefix(prefix, clean[j])
                if len(common) >= min_prefix:
                    prefix = common
                    group.append(j)
            if len(group) > 1 and len(prefix) >= min_prefix:
                for g in group:
                    used[g] = True
                queries.append(prefix)
            else:
                used[i] = True
                queries.append(n)
        return queries

    def get_objects_by_names(
        self, object_suffix: str, names: List[str], obj_type: str,
        *, supports_filter: bool = True, expanded: bool = True,
        prefer_full_fetch: bool = False,
    ) -> Dict[str, Dict[str, Any]]:
        """Fetch objects of one type matching *names*, by normalized name.

        Uses ``nameOrValue`` wildcard grouping when supported; otherwise falls
        back to a full paginated fetch + local filter. Results are cached.

        Wildcard queries within a single object type are executed concurrently
        using up to ``self.max_workers`` threads. Different object types are
        always processed sequentially (callers handle the type-level loop).

        Parameters
        ----------
        expanded:
            When False, list pages are fetched without ``expanded=true``. Name
            matching only needs ``id``/``name``, so predefined catalogs
            (applications, URL categories, SGTs, …) are matched from tiny
            records instead of megabytes of expanded payload.
        prefer_full_fetch:
            When True, skip the per-name ``nameOrValue`` wildcard loop and do a
            single catalog fetch, matching locally. This avoids issuing dozens
            of catalog-sized requests for large predefined types (e.g.
            ``object/applications``), which is the dominant cost of resolution.
        """
        want = {normalize_name(n): n for n in names if n}
        found: Dict[str, Dict[str, Any]] = {}
        # Serve from cache first.
        remaining = {}
        for nn, original in want.items():
            cached = self.cache_get(obj_type, original)
            if cached:
                found[nn] = cached
            else:
                remaining[nn] = original
        if not remaining:
            return found

        path = self.cfg_path(object_suffix)
        if supports_filter and not prefer_full_fetch:
            try:
                queries = self.compute_wildcard_queries(list(remaining.values()))
                total_q = len(queries)
                workers = min(self.max_workers, total_q)
                logger.info(f"  [objects] Fetching {obj_type}: {len(remaining)} name(s) "
                            f"→ {total_q} wildcard quer{'y' if total_q == 1 else 'ies'} "
                            f"({workers} worker{'s' if workers != 1 else ''})")
                t0 = time.monotonic()
                # Thread-safe containers for parallel workers.
                found_lock = threading.Lock()
                errors: List[Exception] = []

                def _run_query(qi: int, q: str, worker_id: int) -> None:
                    """Execute a single wildcard query (runs in a worker thread)."""
                    tag = f"[worker-{worker_id}]"
                    tq = time.monotonic()
                    try:
                        items = self.get_paginated(
                            path, params={"filter": f"nameOrValue:{q}"},
                            expanded=expanded,
                        )
                    except FmcApiError:
                        raise
                    except Exception as exc:
                        errors.append(exc)
                        logger.error(f"    [objects] {tag} {obj_type} query {qi}/{total_q}: "
                                     f"nameOrValue:{q!r} FAILED: {exc}")
                        raise
                    local_matched = 0
                    for it in items:
                        self.cache_put(obj_type, it)
                        nn = normalize_name(it.get("name"))
                        if nn in remaining:
                            with found_lock:
                                found[nn] = it
                            local_matched += 1
                    dt = time.monotonic() - tq
                    with found_lock:
                        matched_so_far = len(found)
                    logger.info(f"    [objects] {tag} {obj_type} query {qi}/{total_q}: "
                                f"nameOrValue:{q!r} → {len(items)} item(s), "
                                f"{matched_so_far}/{len(want)} matched ({dt:.2f}s)")

                if workers <= 1:
                    # Single-worker fast path: no thread overhead.
                    for qi, q in enumerate(queries, 1):
                        _run_query(qi, q, 1)
                else:
                    with ThreadPoolExecutor(max_workers=workers,
                                            thread_name_prefix="fmc-obj") as pool:
                        futures = {}
                        for qi, q in enumerate(queries, 1):
                            worker_id = ((qi - 1) % workers) + 1
                            fut = pool.submit(_run_query, qi, q, worker_id)
                            futures[fut] = qi
                        # Wait for ALL workers before proceeding (type barrier).
                        for fut in as_completed(futures):
                            exc = fut.exception()
                            if exc is not None and exc not in errors:
                                errors.append(exc)

                # Surface first worker error clearly.
                if errors:
                    first = errors[0]
                    if isinstance(first, FmcApiError):
                        raise first
                    raise FmcApiError(
                        f"Worker error fetching {obj_type}: {first}"
                    ) from first

                logger.info(f"  [objects] {obj_type}: {len(found)}/{len(want)} resolved "
                            f"via {total_q} quer{'y' if total_q == 1 else 'ies'} "
                            f"({workers} workers) in {time.monotonic() - t0:.1f}s")
                if len(found) == len(want):
                    return found
            except FmcApiError:
                pass  # fall through to full fetch

        # Full fetch fallback (types without nameOrValue, filter failure, or a
        # large predefined catalog where a single non-expanded list is cheaper).
        logger.info(f"  [objects] {obj_type}: full catalog fetch ({object_suffix})")
        tf = time.monotonic()
        items = self.get_paginated(path, expanded=expanded)
        for it in items:
            self.cache_put(obj_type, it)
            nn = normalize_name(it.get("name"))
            if nn in want:
                found[nn] = it
        logger.info(f"  [objects] {obj_type}: full fetch returned {len(items)} item(s), "
                    f"{len(found)}/{len(want)} matched ({time.monotonic() - tf:.1f}s)")
        return found


def _common_prefix(a: str, b: str) -> str:
    out = []
    for ca, cb in zip(a, b):
        if ca == cb:
            out.append(ca)
        else:
            break
    return "".join(out)
