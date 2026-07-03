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
from typing import Any, Callable, Dict, List, Optional

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


class _RateLimiter:
    """Token-bucket-ish limiter shared per client instance for GET calls."""

    def __init__(self, max_per_sec: float = 8.0):
        self._min_interval = 1.0 / max_per_sec if max_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()


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
    ):
        self.fmc_ip = (fmc_ip or "").rstrip("/")
        self.headers = dict(headers or {})
        self.domain_uuid = domain_uuid or ""
        self._credentials = credentials
        self.debug = debug
        self.max_retries = max_retries
        self.timeout = timeout
        self._rate = _RateLimiter()
        # Per-operation object cache: {(type, normalized_name): object_dict}
        self._obj_cache: Dict[str, Dict[str, Any]] = {}
        # Capability flags discovered at runtime, e.g. {"bulk:hosts": False}
        self._capabilities: Dict[str, bool] = {}

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
        if method == "GET":
            self._rate.acquire()

        if self.debug:
            logger.info(f"[POLICY DEBUG] >>> {method} {url}")
            if json is not None:
                logger.info(f"[POLICY DEBUG]     Payload: {redact(json)}")
            if params:
                logger.info(f"[POLICY DEBUG]     Params: {params}")

        backoff = 1.0
        last_resp: Optional[requests.Response] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.request(
                    method=method, url=url, headers=self.headers,
                    json=json, params=params, verify=False, timeout=self.timeout,
                )
            except requests.exceptions.Timeout as e:
                if attempt >= self.max_retries:
                    raise FmcApiError(f"Request to {url} timed out") from e
                time.sleep(min(backoff * (2 ** attempt), 30.0))
                continue
            except requests.exceptions.RequestException as e:
                if attempt >= self.max_retries:
                    raise FmcApiError(f"Connection error to {url}: {e}") from e
                time.sleep(min(backoff * (2 ** attempt), 30.0))
                continue

            status = resp.status_code
            if self.debug:
                preview = (resp.text or "")[:500]
                logger.info(f"[POLICY DEBUG] <<< {status} {method} {url}: {preview}")

            if 200 <= status < 300:
                return resp

            if status in (401, 419) and attempt < self.max_retries:
                if self._reauth():
                    continue
                raise FmcApiError("FMC session expired and re-authentication failed.", status)

            if status in (429, 500, 502, 503, 504, 408):
                last_resp = resp
                if attempt >= self.max_retries:
                    break
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

    # ── Object cache + wildcard retrieval ──

    def cache_get(self, obj_type: str, name: str) -> Optional[Dict[str, Any]]:
        return self._obj_cache.get(f"{obj_type}::{normalize_name(name)}")

    def cache_put(self, obj_type: str, obj: Dict[str, Any]) -> None:
        nm = obj.get("name")
        if nm:
            self._obj_cache[f"{obj_type}::{normalize_name(nm)}"] = obj

    def clear_cache(self) -> None:
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
                logger.info(f"  [objects] Fetching {obj_type}: {len(remaining)} name(s) "
                            f"→ {len(queries)} wildcard quer{'y' if len(queries) == 1 else 'ies'}")
                t0 = time.monotonic()
                for qi, q in enumerate(queries, 1):
                    tq = time.monotonic()
                    items = self.get_paginated(
                        path, params={"filter": f"nameOrValue:{q}"}, expanded=expanded,
                    )
                    for it in items:
                        self.cache_put(obj_type, it)
                        nn = normalize_name(it.get("name"))
                        if nn in remaining:
                            found[nn] = it
                    dt = time.monotonic() - tq
                    logger.info(f"    [objects] {obj_type} query {qi}/{len(queries)}: "
                                f"nameOrValue:{q!r} → {len(items)} item(s), "
                                f"{len(found)}/{len(want)} matched ({dt:.2f}s)")
                logger.info(f"  [objects] {obj_type}: {len(found)}/{len(want)} resolved "
                            f"via {len(queries)} quer{'y' if len(queries) == 1 else 'ies'} "
                            f"in {time.monotonic() - t0:.1f}s")
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
