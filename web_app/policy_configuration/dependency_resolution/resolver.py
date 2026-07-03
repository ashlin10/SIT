"""Dependency discovery + resolution for ACP replication.

Mirrors the Device Configuration Push Config approach:
  * recursively discover dependent objects from the source FMC,
  * deduplicate shared dependencies,
  * detect circular references,
  * order objects into dependency *levels* derived from the reference graph,
  * match existing target objects by (type, normalized name) and verify
    compatibility before reuse,
  * create missing objects in dependency order,
  * remap every source reference id to the resolved target id.

The number of levels is derived from the graph, not hardcoded.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..models.schema import DependencyRef, ResolutionPlan, normalize_name
from ..services.client import PolicyFmcClient, FmcApiError

logger = logging.getLogger(__name__)


class CircularDependencyError(Exception):
    def __init__(self, cycles: List[List[str]]):
        super().__init__(f"Circular dependency detected: {cycles}")
        self.cycles = cycles


# Object type -> FMC object endpoint suffix (under domain/).
OBJECT_ENDPOINTS: Dict[str, str] = {
    "Host": "object/hosts",
    "Network": "object/networks",
    "Range": "object/ranges",
    "FQDN": "object/fqdns",
    "NetworkGroup": "object/networkgroups",
    "ProtocolPortObject": "object/protocolportobjects",
    "PortObjectGroup": "object/portobjectgroups",
    "ICMPV4Object": "object/icmpv4objects",
    "ICMPV6Object": "object/icmpv6objects",
    "SecurityZone": "object/securityzones",
    "InterfaceGroup": "object/interfacegroups",
    "Url": "object/urls",
    "UrlGroup": "object/urlgroups",
    "VlanTag": "object/vlantags",
    "VlanGroupTag": "object/vlangrouptags",
    "ApplicationFilter": "object/applicationfilters",
    "TimeRange": "object/timeranges",
    "DNSServerGroup": "object/dnsservergroups",
    "SLAMonitor": "object/slamonitors",
}

# Types that are predefined/read-only on FMC: matched by name, never created.
READONLY_TYPES: Set[str] = {
    "Application", "URLCategory", "ContinentObject", "CountryObject",
    "GeolocationObject", "SecurityGroupTag", "ISESecurityGroupTag",
    "EndPointDeviceType", "SecurityIntelligence", "SIURLList", "SIURLFeed",
    "IntrusionPolicy", "FilePolicy", "VariableSet",
}

# Subset of READONLY_TYPES whose ids are globally consistent across all FMC
# instances (populated from VDB / geolocation feed).  No target lookup is
# needed — the source id is already valid on any target FMC.
GLOBAL_ID_TYPES: Set[str] = {
    "Application", "URLCategory", "ContinentObject", "CountryObject",
    "GeolocationObject",
}

# Name-lookup endpoints for predefined/read-only types. These have no create
# endpoint (they are never created), but the target copy must be *matched by
# name* so rule references can be remapped to the target id instead of leaving a
# stale source id that FMC rejects (HTTP 500) on rule push.
READONLY_ENDPOINTS: Dict[str, str] = {
    "Application": "object/applications",
    "URLCategory": "object/urlcategories",
    "ContinentObject": "object/continents",
    "CountryObject": "object/countries",
    "GeolocationObject": "object/geolocations",
    "SecurityGroupTag": "object/securitygrouptags",
    "ISESecurityGroupTag": "object/isesecuritygrouptags",
    "EndPointDeviceType": "object/endpointdevicetypes",
    "VariableSet": "object/variablesets",
    "IntrusionPolicy": "policy/intrusionpolicies",
    "FilePolicy": "policy/filepolicies",
    "SIURLList": "object/siurlfeeds",
    "SIURLFeed": "object/siurlfeeds",
}


def target_endpoint(obj_type: str) -> Optional[str]:
    """Return the endpoint used to look up *obj_type* on the target FMC."""
    return OBJECT_ENDPOINTS.get(obj_type) or READONLY_ENDPOINTS.get(obj_type)

# Group types whose children we recurse into for discovery + leveling.
_GROUP_MEMBER_FIELDS = {
    "NetworkGroup": ["objects", "literals"],
    "PortObjectGroup": ["objects", "literals"],
    "UrlGroup": ["objects", "literals"],
    "VlanGroupTag": ["objects", "literals"],
    "InterfaceGroup": ["interfaces"],
}

# Per-type significant fields for compatibility comparison.
_SIGNIFICANT_FIELDS: Dict[str, List[str]] = {
    "Host": ["value"],
    "Network": ["value"],
    "Range": ["value"],
    "FQDN": ["value"],
    "ProtocolPortObject": ["protocol", "port"],
    "ICMPV4Object": ["icmpType", "code"],
    "ICMPV6Object": ["icmpType", "code"],
    "Url": ["url"],
    "VlanTag": ["data"],
    "SecurityZone": ["interfaceMode"],
}


class DependencyResolver:
    def __init__(
        self,
        source_client: PolicyFmcClient,
        target_client: PolicyFmcClient,
        log: Optional[Callable[[str], None]] = None,
    ):
        self.source = source_client
        self.target = target_client
        self._log = log or (lambda m: logger.info(m))
        # Discovered source objects keyed by ref.key -> full source body.
        self._source_objs: Dict[str, Dict[str, Any]] = {}
        # ref.key -> DependencyRef
        self._refs: Dict[str, DependencyRef] = {}
        # Graph edges: ref.key -> set(child ref.key)
        self._edges: Dict[str, Set[str]] = {}
        # source_id -> target_id remap.
        self._remap: Dict[str, str] = {}
        # Source ids that could NOT be resolved on the target (predefined object
        # missing, unsupported type, conflict). Used by the push layer to prune
        # stale references from rule bodies before submitting them.
        self._unresolved_ids: Set[str] = set()
        # Cache of ad-hoc target lookups by (type, normalized name) -> id.
        self._target_id_cache: Dict[str, str] = {}

    # ── Discovery ──

    def discover(self, seed_refs: List[DependencyRef]) -> None:
        """Recursively discover all dependencies starting from *seed_refs*.

        Fetching is **batched by type per wave** using the same optimized
        ``nameOrValue`` wildcard mechanism as the Fetch workflow
        (:func:`acp_fetch.fetch_full_objects`): for every object type in a wave
        one grouped, cached, paginated set of queries fetches *only* the
        referenced objects — instead of a GET-per-id, which was the root cause
        of the HTTP 429 storm during Push on large policies.

        A per-id GET is retained as a *fallback* only for refs a name filter
        cannot resolve (id-only refs or filter misses). Rate-limit handling
        (exponential backoff + jitter, ``Retry-After``) still applies at the
        client layer.
        """
        pending: Dict[str, DependencyRef] = {}
        for r in seed_refs:
            pending.setdefault(r.key, r)

        t_start = time.monotonic()
        req_before = self._source_request_count()
        wave = 0
        per_id_fallbacks = 0

        while pending:
            batch = [r for k, r in pending.items() if k not in self._refs]
            for r in batch:
                self._refs[r.key] = r
                self._edges.setdefault(r.key, set())
            by_type: Dict[str, List[DependencyRef]] = {}
            for r in batch:
                by_type.setdefault(r.type, []).append(r)

            if wave > 0 and batch:
                self._log(f"[discover] Wave {wave}: resolving {len(batch)} nested "
                          f"reference(s): {_fmt_type_breakdown(batch)}")

            children: Dict[str, DependencyRef] = {}
            for obj_type, refs in by_type.items():
                # Predefined/reuse-only catalogs need no source body (never
                # created); matched by name on the target in build_plan.
                if obj_type in READONLY_TYPES:
                    continue
                suffix = OBJECT_ENDPOINTS.get(obj_type)
                if not suffix:
                    continue

                self._log(f"[discover]   {obj_type}: fetching {len(refs)} object(s)...")
                t_type = time.monotonic()
                req_type_before = self._source_request_count()
                index = self._fetch_source_index(obj_type, suffix, refs)
                resolved = 0
                fb_this_type = 0
                for ref in refs:
                    body, used_fallback = self._lookup_source_index(index, ref, suffix)
                    if used_fallback:
                        fb_this_type += 1
                    if body:
                        resolved += 1
                        self._source_objs[ref.key] = body
                        for child in self._child_refs(obj_type, body):
                            self._edges[ref.key].add(child.key)
                            if child.key not in self._refs and child.key not in children:
                                children[child.key] = child
                per_id_fallbacks += fb_this_type
                req_type = self._source_request_count() - req_type_before
                self._log(
                    f"[discover]   {obj_type}: resolved {resolved}/{len(refs)} "
                    f"via batched name lookup ({req_type} source request(s)"
                    f"{f', {fb_this_type} per-id fallback(s)' if fb_this_type else ''}"
                    f", {time.monotonic() - t_type:.1f}s)"
                )

            pending = children
            wave += 1

        readonly_count = sum(1 for r in self._refs.values() if r.type in READONLY_TYPES)
        user_count = len(self._refs) - readonly_count
        req_issued = self._source_request_count() - req_before
        stats = self.source.request_stats() if hasattr(self.source, "request_stats") else {}
        # Requests a naive GET-per-object would have issued (user-defined refs
        # actually needing a body fetch), vs. what the batched approach issued.
        naive = user_count
        self._log(
            f"Discovered {len(self._refs)} unique dependent object(s) "
            f"({user_count} user-defined, {readonly_count} system-defined/skipped)"
        )
        self._log(
            f"[discover] Batched source fetch: {req_issued} request(s) issued "
            f"vs. ~{naive} for GET-per-object "
            f"(~{max(0, naive - req_issued)} avoided), "
            f"{per_id_fallbacks} per-id fallback(s), "
            f"{stats.get('cache_hits', 0)} cache hit(s), "
            f"{stats.get('retries', 0)} rate-limit retry(ies) in "
            f"{time.monotonic() - t_start:.1f}s"
        )

    def _source_request_count(self) -> int:
        """Total source-client HTTP sends so far (0 when unsupported)."""
        if hasattr(self.source, "request_stats"):
            try:
                return self.source.request_stats().get("total", 0)
            except Exception:  # pragma: no cover - defensive
                return 0
        return 0

    def _fetch_source_index(
        self, obj_type: str, suffix: str, refs: List[DependencyRef],
    ) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Fetch only the referenced objects of *obj_type* by name (batched).

        Uses ``get_objects_by_names`` (``nameOrValue`` wildcard grouping +
        pagination + per-operation cache) so a whole type resolves in a handful
        of requests instead of one-per-object. Returns an index keyed by
        normalized name and by id.
        """
        names = [r.name for r in refs if r.name]
        total_names = len(names)
        by_name: Dict[str, Dict[str, Any]] = {}
        if names:
            def _progress(q_idx, q_total, matched, elapsed, query="", items=0, dt_q=0.0):
                if q_total > 0:
                    # Emit every 5th query, plus first and last, to avoid flooding.
                    if q_idx == 1 or q_idx == q_total or q_idx % 5 == 0:
                        self._log(
                            f"[discover]     {obj_type}: query {q_idx}/{q_total} "
                            f"(matched {matched}/{total_names}, {elapsed:.1f}s)"
                        )
                else:
                    self._log(
                        f"[discover]     {obj_type}: full fetch complete "
                        f"(matched {matched}/{total_names}, {elapsed:.1f}s)"
                    )
            try:
                by_name = self.source.get_objects_by_names(
                    suffix, names, obj_type, progress_cb=_progress,
                )
            except FmcApiError as e:
                self._log(f"  Batched source lookup failed for {obj_type}: {e}")
        by_id = {
            str(o.get("id")): o for o in by_name.values()
            if isinstance(o, dict) and o.get("id")
        }
        return {"by_name": by_name, "by_id": by_id}

    def _lookup_source_index(
        self, index: Dict[str, Dict[str, Dict[str, Any]]], ref: DependencyRef,
        suffix: str,
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """Resolve *ref* from the batched index, or via a per-id GET fallback.

        Returns ``(body, used_fallback)``. The fallback (a single GET-by-id) is
        only used for id-only refs or filter misses — never as the primary path.
        """
        if ref.name:
            body = index["by_name"].get(normalize_name(ref.name))
            if body is not None:
                return body, False
        if ref.source_id:
            body = index["by_id"].get(str(ref.source_id))
            if body is not None:
                return body, False
        # Fallback: targeted GET-by-id for refs a name filter couldn't resolve.
        if ref.source_id:
            try:
                path = self.source.cfg_path(f"{suffix}/{ref.source_id}")
                body = self.source.get_json(path)
                if isinstance(body, dict) and body.get("id"):
                    return body, True
            except FmcApiError as e:
                self._log(f"  Could not fetch source body for {ref.type} "
                          f"'{ref.name}': {e}")
        return None, True

    def _child_refs(self, parent_type: str, body: Dict[str, Any]) -> List[DependencyRef]:
        out: List[DependencyRef] = []
        for fld in _GROUP_MEMBER_FIELDS.get(parent_type, []):
            members = body.get(fld)
            if not isinstance(members, list):
                continue
            for m in members:
                if isinstance(m, dict) and m.get("type") and (m.get("name") or m.get("id")):
                    out.append(DependencyRef(
                        type=str(m["type"]), name=str(m.get("name", "")),
                        source_id=str(m.get("id", "")),
                    ))
        return out

    # ── Cycle detection ──

    def detect_cycles(self) -> List[List[str]]:
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {k: WHITE for k in self._edges}
        cycles: List[List[str]] = []
        path: List[str] = []

        def dfs(node: str) -> None:
            color[node] = GRAY
            path.append(node)
            for nb in self._edges.get(node, ()):  # noqa
                if color.get(nb, 0) == GRAY:
                    # back-edge -> cycle
                    if nb in path:
                        cycles.append(path[path.index(nb):] + [nb])
                elif color.get(nb, 0) == WHITE:
                    dfs(nb)
            path.pop()
            color[node] = BLACK

        for n in list(self._edges.keys()):
            if color.get(n, 0) == WHITE:
                dfs(n)
        return cycles

    # ── Leveling (topological) ──

    def compute_levels(self) -> List[List[str]]:
        """Return ordered levels: leaves first (no outgoing deps) up to roots.

        Level i contains nodes all of whose children are in levels < i.
        """
        remaining = set(self._edges.keys())
        levels: List[List[str]] = []
        placed: Set[str] = set()
        guard = 0
        while remaining and guard <= len(self._edges) + 1:
            guard += 1
            current = []
            for node in sorted(remaining):
                children = self._edges.get(node, set())
                if all((c in placed or c not in self._refs) for c in children):
                    current.append(node)
            if not current:
                # Remaining nodes are part of a cycle; stop.
                break
            for n in current:
                remaining.discard(n)
                placed.add(n)
            levels.append(current)
        return levels

    # ── Target matching + classification ──

    def build_plan(self) -> ResolutionPlan:
        plan = ResolutionPlan()
        cycles = self.detect_cycles()
        if cycles:
            plan.cycles = [[self._refs[k].name or k for k in cyc if k in self._refs] for cyc in cycles]
        plan.levels = [[self._refs[k].name or k for k in lvl] for lvl in self.compute_levels()]

        # Group remaining refs by type for batched target lookups.
        by_type: Dict[str, List[DependencyRef]] = {}
        for ref in self._refs.values():
            by_type.setdefault(ref.type, []).append(ref)

        type_count = len(by_type)
        for type_idx, (obj_type, refs) in enumerate(by_type.items(), 1):
            readonly = obj_type in READONLY_TYPES
            global_id = obj_type in GLOBAL_ID_TYPES

            # Global-id types (Applications, URL categories, geolocation) have
            # the same id on every FMC instance — skip the target lookup
            # entirely and keep the source id as-is.
            if global_id:
                self._log(f"  [{type_idx}/{type_count}] Skipping {len(refs)} {obj_type} "
                          f"ref(s) (system-defined, globally consistent ids)")
                for ref in refs:
                    ref.action = "reuse"
                    ref.match_method = "global_id"
                    ref.target_id = ref.source_id or ""
                    plan.to_reuse.append(ref)
                continue

            self._log(f"  [{type_idx}/{type_count}] Matching {len(refs)} {obj_type} "
                      f"ref(s) on target{' (system-defined, name-only)' if readonly else ''}")
            create_suffix = OBJECT_ENDPOINTS.get(obj_type)
            lookup_suffix = target_endpoint(obj_type)
            names = [r.name for r in refs if r.name]
            target_by_name: Dict[str, Dict[str, Any]] = {}
            if lookup_suffix and names:
                # Remaining read-only catalogs (SGTs, IntrusionPolicy, …) are
                # matched by name only: a single non-expanded catalog fetch is
                # dramatically cheaper than dozens of per-name expanded filter
                # queries.
                try:
                    target_by_name = self.target.get_objects_by_names(
                        lookup_suffix, names, obj_type,
                        expanded=not readonly, prefer_full_fetch=readonly,
                    )
                except FmcApiError as e:
                    self._log(f"  Target lookup failed for {obj_type}: {e}")

            for ref in refs:
                tgt = target_by_name.get(normalize_name(ref.name))
                if readonly:
                    if tgt:
                        ref.action = "reuse"
                        ref.match_method = "name"
                        ref.target_id = str(tgt.get("id", ""))
                        if ref.source_id and ref.target_id:
                            self._remap[ref.source_id] = ref.target_id
                        plan.to_reuse.append(ref)
                    else:
                        plan.unresolved.append({
                            "type": obj_type, "name": ref.name, "source_id": ref.source_id,
                            "reason": "predefined object not found on target FMC",
                        })
                        ref.action = "unresolved"
                        if ref.source_id:
                            self._unresolved_ids.add(ref.source_id)
                    continue

                if not create_suffix:
                    plan.unresolved.append({
                        "type": obj_type, "name": ref.name, "source_id": ref.source_id,
                        "reason": "unsupported object type (no target endpoint)",
                    })
                    ref.action = "unresolved"
                    if ref.source_id:
                        self._unresolved_ids.add(ref.source_id)
                    continue

                if tgt:
                    src_body = self._source_objs.get(ref.key) or {}
                    if self._compatible(obj_type, src_body, tgt):
                        ref.action = "reuse"
                        ref.match_method = "value" if obj_type in _SIGNIFICANT_FIELDS else "name"
                        ref.target_id = str(tgt.get("id", ""))
                        if ref.source_id and ref.target_id:
                            self._remap[ref.source_id] = ref.target_id
                        plan.to_reuse.append(ref)
                    else:
                        ref.action = "conflict"
                        if ref.source_id:
                            self._unresolved_ids.add(ref.source_id)
                        plan.conflicts.append({
                            "type": obj_type, "name": ref.name,
                            "reason": "existing target object has same name but incompatible content",
                            "source": _significant(obj_type, src_body),
                            "target": _significant(obj_type, tgt),
                        })
                else:
                    ref.action = "create"
                    plan.to_create.append(ref)

        self._log(
            f"Resolution plan: create={len(plan.to_create)}, reuse={len(plan.to_reuse)}, "
            f"conflicts={len(plan.conflicts)}, unresolved={len(plan.unresolved)}, "
            f"cycles={len(plan.cycles)}"
        )
        return plan

    @staticmethod
    def _compatible(obj_type: str, source: Dict[str, Any], target: Dict[str, Any]) -> bool:
        if not source:
            # No source body to compare (e.g. couldn't fetch); be safe and reuse
            # only when names match — caller already matched by name.
            return True
        fields = _SIGNIFICANT_FIELDS.get(obj_type)
        if fields:
            for f in fields:
                if str(source.get(f, "")).strip().lower() != str(target.get(f, "")).strip().lower():
                    return False
            return True
        # Group types: compare member name sets.
        if obj_type in _GROUP_MEMBER_FIELDS:
            return _member_names(source) == _member_names(target)
        return True  # unknown type: trust name match

    # ── Apply (create missing in dependency order, remap) ──

    def apply(self, plan: ResolutionPlan, *, bulk: bool = True) -> Tuple[List[str], List[str]]:
        """Create the to_create objects in dependency order. Returns
        (created_names, partial_failures). Updates the source->target remap.
        """
        created: List[str] = []
        partial: List[str] = []
        to_create_keys = {self._ref_key(r): r for r in plan.to_create}
        order = self.compute_levels()
        for level_idx, level in enumerate(order, 1):
            # Objects in this level that need creating, grouped by type.
            by_type: Dict[str, List[DependencyRef]] = {}
            for key in level:
                ref = self._refs.get(key)
                if ref and ref.action == "create":
                    by_type.setdefault(ref.type, []).append(ref)
            for obj_type, refs in by_type.items():
                suffix = OBJECT_ENDPOINTS.get(obj_type)
                if not suffix:
                    continue
                bodies = [self._build_create_body(r) for r in refs]
                self._log(f"  [L{level_idx}] Creating {len(bodies)} {obj_type} object(s)")
                ok, fail = self._create_objects(obj_type, suffix, refs, bodies, bulk=bulk)
                created.extend(ok)
                partial.extend(fail)
        return created, partial

    def _create_objects(
        self, obj_type: str, suffix: str, refs: List[DependencyRef],
        bodies: List[Dict[str, Any]], *, bulk: bool,
    ) -> Tuple[List[str], List[str]]:
        created: List[str] = []
        failed: List[str] = []
        path = self.target.cfg_path(suffix)
        # Try bulk first when more than one and allowed.
        if bulk and len(bodies) > 1:
            try:
                resp = self.target.post(path, bodies, bulk=True)
                items = resp.get("items") if isinstance(resp, dict) else resp
                if isinstance(items, list):
                    for ref, item in zip(refs, items):
                        tid = item.get("id")
                        if tid:
                            ref.target_id = str(tid)
                            if ref.source_id:
                                self._remap[ref.source_id] = str(tid)
                            self.target.cache_put(obj_type, item)
                            created.append(ref.name)
                    return created, failed
            except FmcApiError as e:
                self._log(f"    Bulk create for {obj_type} failed ({e}); falling back to per-item")
        # Per-item.
        for ref, body in zip(refs, bodies):
            try:
                item = self.target.post(path, body)
                tid = item.get("id") if isinstance(item, dict) else None
                if tid:
                    ref.target_id = str(tid)
                    if ref.source_id:
                        self._remap[ref.source_id] = str(tid)
                    self.target.cache_put(obj_type, item)
                    created.append(ref.name)
                else:
                    failed.append(ref.name)
            except FmcApiError as e:
                self._log(f"    Failed to create {obj_type} '{ref.name}': {e}")
                failed.append(ref.name)
        return created, failed

    def _build_create_body(self, ref: DependencyRef) -> Dict[str, Any]:
        body = dict(self._source_objs.get(ref.key) or {})
        for k in ("id", "links", "metadata"):
            body.pop(k, None)
        body.setdefault("type", ref.type)
        body.setdefault("name", ref.name)
        # Remap member references within groups.
        self.remap_references(body)
        return body

    @staticmethod
    def _ref_key(ref: DependencyRef) -> str:
        return ref.key

    # ── Reference remapping ──

    @property
    def remap_table(self) -> Dict[str, str]:
        return dict(self._remap)

    @property
    def unresolved_source_ids(self) -> Set[str]:
        """Source ids with no valid target equivalent (prune from rule bodies)."""
        return set(self._unresolved_ids)

    def register_remap(self, source_id: str, target_id: str) -> None:
        """Record a source->target id remap discovered outside the object graph.

        Used by the push layer after creating/reusing a rule-referenced policy
        (File / Intrusion) so subsequent reference remapping rewrites the rule
        body to the target id instead of pruning it. Clears any prior
        "unresolved" mark for the id.
        """
        if source_id and target_id:
            self._remap[source_id] = target_id
            self._unresolved_ids.discard(source_id)

    def resolve_target_id(self, obj_type: str, name: str, source_id: str = "") -> str:
        """Resolve a single reference to a target id by name (cached).

        Used for rule-referenced policies/objects that are not part of the object
        dependency graph (e.g. IntrusionPolicy / FilePolicy / VariableSet). On a
        hit the source->target remap is recorded; on a miss the source id is
        marked unresolved so the push layer can prune the reference.
        Returns the target id, or "" when it cannot be resolved.
        """
        if source_id and source_id in self._remap:
            return self._remap[source_id]
        nn = normalize_name(name)
        cache_key = f"{obj_type}::{nn}"
        if cache_key in self._target_id_cache:
            tid = self._target_id_cache[cache_key]
            if not tid and source_id:
                self._unresolved_ids.add(source_id)
            return tid
        suffix = target_endpoint(obj_type)
        tid = ""
        if suffix and name:
            try:
                found = self.target.get_objects_by_names(suffix, [name], obj_type)
                match = found.get(nn)
                if match:
                    tid = str(match.get("id", ""))
            except FmcApiError as e:
                self._log(f"  Target lookup failed for {obj_type} '{name}': {e}")
        self._target_id_cache[cache_key] = tid
        if tid:
            if source_id:
                self._remap[source_id] = tid
        elif source_id:
            self._unresolved_ids.add(source_id)
        return tid

    def remap_references(self, node: Any) -> None:
        """Rewrite every source object id to the resolved target id in-place.

        Only ids present in the remap table are changed. Names are preserved.
        """
        if isinstance(node, dict):
            sid = node.get("id")
            if isinstance(sid, str) and sid in self._remap:
                node["id"] = self._remap[sid]
            for v in node.values():
                self.remap_references(v)
        elif isinstance(node, list):
            for it in node:
                self.remap_references(it)


def _fmt_type_breakdown(refs: List[DependencyRef]) -> str:
    """Compact ``Type×N, …`` breakdown of a ref batch (most frequent first)."""
    counts: Dict[str, int] = {}
    for r in refs:
        counts[r.type] = counts.get(r.type, 0) + 1
    if not counts:
        return "none"
    return ", ".join(f"{t}×{n}" for t, n in sorted(counts.items(), key=lambda kv: -kv[1]))


def _member_names(body: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for fld in ("objects", "literals", "interfaces"):
        for m in (body.get(fld) or []):
            if isinstance(m, dict):
                names.add(normalize_name(m.get("name") or m.get("value") or ""))
    return {n for n in names if n}


def _significant(obj_type: str, body: Dict[str, Any]) -> Dict[str, Any]:
    fields = _SIGNIFICANT_FIELDS.get(obj_type)
    if fields:
        return {f: body.get(f) for f in fields}
    if obj_type in _GROUP_MEMBER_FIELDS:
        return {"members": sorted(_member_names(body))}
    return {}
