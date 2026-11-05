"""Fetch Access Control Policies (ACPs) and their dependencies from a source FMC.

The source representation is a *faithful JSON->YAML* conversion of the FMC API
payloads (only the transport-only ``links``/``metadata`` keys are dropped, as
in the Device Configuration workflow). No synthetic/migration fields are added.

Three layers are assembled per ACP:
  * ``fetch_acp``               - the ACP base + all access rules (raw payloads).
  * ``fetch_dependent_policies``- complete payloads of every referenced policy
                                  (Prefilter / SecurityIntelligence / Identity /
                                  Decryption / File / Intrusion), deduplicated and
                                  grouped by type.
  * ``fetch_full_objects``      - complete payloads of every referenced object,
                                  fetched recursively through nested groups.

``fetch_acp_full`` orchestrates all three and returns the pieces the API layer
stores into the :class:`PolicyConfig`.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..dependency_resolution.resolver import (
    CONCRETE_NETWORK_TYPES, GENERIC_NETWORK_TYPE, READONLY_TYPES,
    resolve_generic_network,
)
from ..models.schema import AcpModel, DependencyRef, normalize_name
from .client import PolicyFmcClient, FmcApiError

logger = logging.getLogger(__name__)


# ── Dependent policy types (treated as policies, NOT objects) ──

# FMC policy type -> YAML subsection name.
POLICY_TYPE_TO_SUBSECTION: Dict[str, str] = {
    "PrefilterPolicy": "prefilter_policies",
    "SecurityIntelligencePolicy": "security_intelligence_policies",
    "IdentityPolicy": "identity_policies",
    "DecryptionPolicy": "decryption_policies",
    "SSLPolicy": "decryption_policies",
    "FilePolicy": "file_policies",
    "IntrusionPolicy": "intrusion_policies",
}

# FMC policy type -> candidate config endpoints (full payload fetch by id).
POLICY_TYPE_TO_ENDPOINTS: Dict[str, List[str]] = {
    "PrefilterPolicy": ["policy/prefilterpolicies"],
    "SecurityIntelligencePolicy": ["policy/securityintelligencepolicies"],
    "IdentityPolicy": ["policy/identitypolicies"],
    "DecryptionPolicy": ["policy/decryptionpolicies", "policy/sslpolicies"],
    "SSLPolicy": ["policy/sslpolicies", "policy/decryptionpolicies"],
    "FilePolicy": ["policy/filepolicies"],
    "IntrusionPolicy": ["policy/intrusionpolicies"],
}

# FMC policy type -> the container endpoint prefix + the sub-resource(s) that
# hold that policy's rules. Each entry is (container_suffix, rule_subpath,
# embed_key). ``embed_key`` is the field the fetched rule list is stored under
# inside the (sanitized) policy body so the exported YAML is self-contained and
# the push can recreate every rule *offline* without re-contacting the source.
# Only rule-bearing policy types are listed; IntrusionPolicy is recreated from
# its base policy (matched by name on the target) so its rules are not cloned.
POLICY_TYPE_TO_SUBRULES: Dict[str, List[Tuple[str, str, str]]] = {
    "PrefilterPolicy": [("policy/prefilterpolicies", "prefilterrules", "prefilterrules")],
    "FilePolicy": [("policy/filepolicies", "filerules", "fileRules")],
    "DecryptionPolicy": [
        ("policy/decryptionpolicies", "decryptionpolicyrules", "decryptionpolicyrules"),
    ],
    "IdentityPolicy": [("policy/identitypolicies", "identityrules", "identityrules")],
}

POLICY_TYPES = set(POLICY_TYPE_TO_SUBSECTION.keys())

# Object types that count as ACP/rule dependencies worth replicating. Policy
# types (File/Intrusion/Prefilter/...) are intentionally excluded — they are
# fetched as dependent policies, not objects.
KNOWN_OBJECT_TYPES = {
    "Host", "Network", "Range", "FQDN", "NetworkGroup",
    "ProtocolPortObject", "PortObjectGroup", "AnyProtocolPortObject",
    "ICMPV4Object", "ICMPV6Object",
    "SecurityZone", "InterfaceGroup", "TunnelTag",
    "Url", "UrlGroup", "URLCategory",
    "Application", "ApplicationFilter",
    "VlanTag", "VlanGroupTag",
    "SecurityGroupTag", "ISESecurityGroupTag", "EndPointDeviceType",
    "ContinentObject", "CountryObject", "GeolocationObject",
    "SecurityIntelligence", "SIURLList", "SIURLFeed",
    "DNSServerGroup", "SLAMonitor", "TimeRange", "TimeZoneObject",
    "VariableSet", "SnmpAlert", "SyslogAlert",
}

# ── System-defined object classification ──
#
# An object is "system-defined" when it is a predefined / reuse-only FMC object
# that has no create endpoint and is matched on the target by name at push time
# (never recreated). Classification uses two signals, in order:
#
#  1. **Type** — ``ref.type in READONLY_TYPES``. This is the *same* set the push
#     resolver uses (``dependency_resolution.resolver.READONLY_TYPES``), so fetch
#     and push agree by construction. It is authoritative and version-robust:
#     these types (Application, URLCategory, ISE/SGT tags, Geolocation, Security
#     Intelligence, …) are always predefined. It also avoids fetching
#     them at all — the dominant cost — since only a name reference is kept.
#  2. **Metadata** — ``metadata.readOnly.reason == "SYSTEM"``. A secondary catch
#     for a *predefined member of a creatable type* (e.g. the built-in ``HTTP``
#     port object) when FMC actually populates the flag. NOTE: FMC does not
#     reliably set ``readOnly`` on list payloads for the predefined *catalog*
#     types above, which is why type (signal 1) — not metadata — is primary.
#
# System-defined objects are stored as a minimal reference (type + name + id).


def _is_system_object(body: Any) -> bool:
    """True when an object's own FMC metadata marks it as system-defined.

    Secondary signal only; the primary signal is ``ref.type in READONLY_TYPES``
    (see :data:`READONLY_TYPES`), checked before any fetch is attempted.
    """
    if not isinstance(body, dict):
        return False
    read_only = (body.get("metadata") or {}).get("readOnly") or {}
    return str(read_only.get("reason") or "").upper() == "SYSTEM"


def list_acps(client: PolicyFmcClient) -> List[Dict[str, Any]]:
    """Return lightweight ACP rows. Follows full pagination (no 1000 cap)."""
    path = client.cfg_path("policy/accesspolicies")
    items = client.get_paginated(path, expanded=True)
    rows: List[Dict[str, Any]] = []
    for it in items:
        rows.append({
            "id": it.get("id", ""),
            "name": it.get("name", ""),
            "type": it.get("type", "AccessPolicy"),
            "description": it.get("description", ""),
            "rule_count_hint": _safe_rule_count(it),
        })
    logger.info(f"Listed {len(rows)} Access Control Policy(ies) from source FMC")
    return rows


def _safe_rule_count(acp_base: Dict[str, Any]) -> Any:
    rules = acp_base.get("rules")
    if isinstance(rules, dict):
        ref = rules.get("refCount")
        if isinstance(ref, int):
            return ref
    return None


def fetch_acp(client: PolicyFmcClient, acp_id: str) -> Tuple[AcpModel, List[DependencyRef]]:
    """Fetch one ACP (base + all access rules) as faithful raw payloads.

    Returns ``(AcpModel, [object DependencyRef, ...])``. The ``AcpModel`` stores
    the raw base payload (``raw_base``) and raw ``access_rules``; in-memory
    derived fields (assigned policies / settings / default action) are populated
    for the UI and push, but are NOT part of the serialized source YAML.

    Raises FmcApiError if the base ACP cannot be fetched; rule-fetch failures
    are recorded but non-fatal.
    """
    base_path = client.cfg_path(f"policy/accesspolicies/{acp_id}")
    base = client.get_json(base_path)
    if not base or not base.get("id"):
        raise FmcApiError(f"Access Control Policy {acp_id} not found on source FMC")

    acp = AcpModel(name=str(base.get("name", "")), source_id=str(base.get("id", "")))
    acp.raw_base = _sanitize(base, drop=("links", "metadata", "rules"))

    # ── Access rules (all, paginated) — faithful payloads ──
    try:
        rules_path = client.cfg_path(f"policy/accesspolicies/{acp_id}/accessrules")
        raw_rules = client.get_paginated(rules_path, expanded=True)
        acp.access_rules = [_sanitize(r, drop=("links",)) for r in raw_rules]
        logger.info(f"  Fetched {len(acp.access_rules)} access rule(s) for ACP '{acp.name}'")
    except FmcApiError as e:
        acp.fetch_error = f"rules: {e}"
        logger.warning(f"  Failed to fetch rules for ACP '{acp.name}': {e}")

    acp.fetched = True
    acp.derive_from_raw()

    # ── Harvest object dependency references ──
    deps = harvest_object_refs(acp.raw_base, acp.access_rules)
    logger.info(f"  Harvested {len(deps)} dependent object reference(s) for ACP '{acp.name}'")
    return acp, deps


# Backwards-compatible alias used by the push workflow's seed harvesting.
def harvest_dependencies(acp: AcpModel) -> List[DependencyRef]:
    """Return object dependency refs for *acp* (rules + base)."""
    return harvest_object_refs(acp.raw_base, acp.access_rules)


def harvest_object_refs(*nodes: Any) -> List[DependencyRef]:
    """Walk arbitrary payload nodes, returning deduped object dependency refs.

    Only types in :data:`KNOWN_OBJECT_TYPES` are recorded — policy types are
    handled separately by :func:`collect_policy_refs`.
    """
    found: Dict[str, DependencyRef] = {}

    def _record(d: Dict[str, Any]) -> None:
        t = d.get("type")
        if not isinstance(t, str) or t not in KNOWN_OBJECT_TYPES:
            return
        name = str(d.get("name", ""))
        sid = str(d.get("id", ""))
        if not name and not sid:
            return
        ref = DependencyRef(type=t, name=name, source_id=sid)
        found.setdefault(ref.key, ref)

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            _record(node)
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for it in node:
                _walk(it)

    for n in nodes:
        _walk(n)
    return list(found.values())


def collect_policy_refs(acp: AcpModel) -> List[DependencyRef]:
    """Find every referenced dependent-policy (the six tracked types).

    Walks the ACP base (prefilter / decryption / identity / SI assignments) and
    every access rule + default action (file / intrusion policy references).
    Deduplicates by (type, id|name).
    """
    found: Dict[Tuple[str, str], DependencyRef] = {}

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            t = node.get("type")
            if isinstance(t, str) and t in POLICY_TYPES and (node.get("id") or node.get("name")):
                ref = DependencyRef(type=t, name=str(node.get("name", "")),
                                    source_id=str(node.get("id", "")))
                found.setdefault((t, ref.source_id or normalize_name(ref.name)), ref)
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for it in node:
                _walk(it)

    _walk(acp.raw_base)
    for rule in acp.access_rules:
        _walk(rule)
    return list(found.values())


def fetch_dependent_policies(
    client: PolicyFmcClient, refs: List[DependencyRef], log: Callable[[str], None] | None = None,
    *, acp_id: str = "",
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[DependencyRef]]:
    """Fetch complete payloads for *refs*, grouped by YAML subsection.

    Returns ``(policies_by_subsection, extra_object_refs)`` where the extra
    object refs are dependencies discovered *inside* the fetched policy bodies
    (e.g. an Intrusion policy's variable set, an SI policy's networks/feeds).
    """
    log = log or (lambda m: logger.info(m))
    by_sub: Dict[str, List[Dict[str, Any]]] = {}
    obj_refs: Dict[str, DependencyRef] = {}
    seen: set = set()

    # Deduplicate up-front so the progress count reflects real work.
    unique: List[DependencyRef] = []
    for ref in refs:
        key = (ref.type, ref.source_id or normalize_name(ref.name))
        if key in seen:
            continue
        seen.add(key)
        unique.append(ref)

    log(f"[policies] Fetching {len(unique)} dependent policy payload(s): "
        f"{_fmt_breakdown(unique)}")
    t_start = time.monotonic()
    ok = 0
    for idx, ref in enumerate(unique, 1):
        t0 = time.monotonic()
        body = _fetch_policy_body(client, ref, acp_id=acp_id)
        dt = time.monotonic() - t0
        if not body:
            log(f"  [policies] {idx}/{len(unique)} could not fetch {ref.type} "
                f"'{ref.name or ref.source_id}' ({dt:.2f}s)")
            continue
        clean = _sanitize(body)
        actual_type = str(clean.get("type") or ref.type)
        sub = POLICY_TYPE_TO_SUBSECTION.get(actual_type) or POLICY_TYPE_TO_SUBSECTION.get(ref.type)
        if not sub:
            continue
        # Embed every rule belonging to this dependent policy so the exported
        # YAML is self-contained (the push recreates rules offline). Rules are
        # harvested for object refs alongside the policy body.
        rule_total = _embed_policy_subrules(client, actual_type, str(clean.get("id") or ref.source_id),
                                            clean, log)
        by_sub.setdefault(sub, []).append(clean)
        extra = 0
        for oref in harvest_object_refs(clean):
            if oref.key not in obj_refs:
                obj_refs[oref.key] = oref
                extra += 1
        ok += 1
        log(f"  [policies] {idx}/{len(unique)} fetched {actual_type} "
            f"'{clean.get('name', ref.name)}' ({dt:.2f}s"
            f"{f', {rule_total} rule(s)' if rule_total else ''}"
            f"{f', +{extra} object ref(s)' if extra else ''})")

    total = sum(len(v) for v in by_sub.values())
    log(f"[policies] Fetched {total} dependent policy payload(s) across "
        f"{len(by_sub)} type(s) in {time.monotonic() - t_start:.1f}s "
        f"({len(obj_refs)} nested object ref(s) discovered)")
    return by_sub, list(obj_refs.values())


def _fetch_policy_body(client: PolicyFmcClient, ref: DependencyRef,
                       *, acp_id: str = "") -> Any:
    """Fetch a dependent policy's full body by id, trying candidate endpoints.

    SecurityIntelligencePolicy is ACP-scoped on FMC, so the ACP-scoped
    endpoint is tried first when *acp_id* is available.
    """
    if not ref.source_id:
        return None
    # SI policies are ACP-scoped — try the scoped endpoint first.
    if ref.type == "SecurityIntelligencePolicy" and acp_id:
        scoped = (f"policy/accesspolicies/{acp_id}"
                  f"/securityintelligencepolicies/{ref.source_id}")
        try:
            body = client.get_json(client.cfg_path(scoped))
            if isinstance(body, dict) and body.get("id"):
                return body
        except FmcApiError as e:
            logger.debug(f"  {ref.type} ACP-scoped fetch failed: {e}")
    for suffix in POLICY_TYPE_TO_ENDPOINTS.get(ref.type, []):
        try:
            body = client.get_json(client.cfg_path(f"{suffix}/{ref.source_id}"))
            if isinstance(body, dict) and body.get("id"):
                return body
        except FmcApiError as e:
            logger.debug(f"  {ref.type} fetch via {suffix} failed: {e}")
    return None


def _embed_policy_subrules(
    client: PolicyFmcClient, policy_type: str, policy_id: str,
    body: Dict[str, Any], log: Callable[[str], None],
) -> int:
    """Fetch and embed a dependent policy's rules into *body* (in place).

    Walks the candidate rule sub-resources for *policy_type* and stores the
    faithful (sanitized) rule list under its native ``embed_key`` so the
    exported YAML contains every rule and can be replayed on the target FMC
    without re-contacting the source. Best-effort and non-fatal: a missing or
    unsupported sub-resource is skipped. Returns the number of rules embedded.
    """
    if not policy_id:
        return 0
    total = 0
    for container, subpath, embed_key in POLICY_TYPE_TO_SUBRULES.get(policy_type, []):
        try:
            rules = client.get_paginated(
                client.cfg_path(f"{container}/{policy_id}/{subpath}"), expanded=True)
        except FmcApiError as e:
            logger.debug(f"  {policy_type} {subpath} fetch failed: {e}")
            continue
        if not rules:
            continue
        body[embed_key] = [_sanitize(r, drop=("links",)) for r in rules]
        total += len(rules)
    return total


def fetch_acp_full(
    client: PolicyFmcClient, acp_id: str, log: Callable[[str], None] | None = None,
) -> Tuple[AcpModel, Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """Orchestrate a complete faithful fetch of one ACP.

    Returns ``(acp, policies_by_subsection, objects)`` ready to be merged into a
    :class:`PolicyConfig`. Objects are fetched recursively (including via nested
    groups and references found inside dependent policies).
    """
    log = log or (lambda m: logger.info(m))
    t_start = time.monotonic()

    log(f"[fetch] Stage 1/3: fetching ACP base + access rules for '{acp_id}'")
    acp, obj_deps = fetch_acp(client, acp_id)

    log("[fetch] Stage 2/3: fetching referenced dependent policies")
    policy_refs = collect_policy_refs(acp)
    policies, extra_obj_refs = fetch_dependent_policies(
        client, policy_refs, log, acp_id=acp.source_id)

    # Merge ACP-level and policy-level object references, then fetch recursively.
    seed: Dict[str, DependencyRef] = {r.key: r for r in obj_deps}
    for r in extra_obj_refs:
        seed.setdefault(r.key, r)
    log(f"[fetch] Stage 3/3: fetching {len(seed)} referenced object definition(s)")
    objects = fetch_full_objects(client, list(seed.values()), log)

    # ── Realm objects (fetched with expanded=true for offline creation) ──
    realm_ids = _collect_realm_ids(acp, policies)
    if realm_ids:
        log(f"[fetch] Fetching {len(realm_ids)} referenced realm(s) with expanded=true")
        realms = _fetch_realms_expanded(client, realm_ids, log)
        if realms:
            policies.setdefault("realms", []).extend(realms)
            log(f"[fetch] Stored {len(realms)} expanded realm object(s)")

    log(f"[fetch] Complete: ACP '{acp.name}' — {acp.rule_count()} rule(s), "
        f"{sum(len(v) for v in policies.values())} dependent policy(ies), "
        f"{len(objects)} object(s) in {time.monotonic() - t_start:.1f}s")
    return acp, policies, objects


def _collect_realm_ids(
    acp: AcpModel, policies: Dict[str, List[Dict[str, Any]]],
) -> List[str]:
    """Collect unique realm source IDs from ACP rules, identity rules, and
    decryption rules. These are needed to fetch expanded realm objects."""
    seen: Dict[str, str] = {}  # id -> name

    def _record(rid: str, name: str = "") -> None:
        if rid and rid not in seen:
            seen[rid] = name

    # ACP access rules: users.objects with type Realm, or nested realm.id
    for rule in acp.access_rules or []:
        users_block = rule.get("users")
        if isinstance(users_block, dict):
            for obj in users_block.get("objects") or []:
                if isinstance(obj, dict):
                    if obj.get("type") == "Realm":
                        _record(str(obj.get("id", "")), str(obj.get("name", "")))
                    realm = obj.get("realm")
                    if isinstance(realm, dict):
                        _record(str(realm.get("id", "")), str(realm.get("name", "")))

    # Identity policy rules: top-level realm field
    for ip in policies.get("identity_policies") or []:
        for rule in ip.get("identityrules") or []:
            realm = rule.get("realm")
            if isinstance(realm, dict):
                _record(str(realm.get("id", "")), str(realm.get("name", "")))

    # Decryption policy rules: users.objects
    for dp in policies.get("decryption_policies") or []:
        for rule in dp.get("decryptionpolicyrules") or []:
            users_block = rule.get("users")
            if isinstance(users_block, dict):
                for obj in users_block.get("objects") or []:
                    if isinstance(obj, dict):
                        if obj.get("type") == "Realm":
                            _record(str(obj.get("id", "")), str(obj.get("name", "")))
                        realm = obj.get("realm")
                        if isinstance(realm, dict):
                            _record(str(realm.get("id", "")), str(realm.get("name", "")))

    return [rid for rid in seen if rid]


def _fetch_realms_expanded(
    client: PolicyFmcClient, realm_ids: List[str],
    log: Callable[[str], None],
) -> List[Dict[str, Any]]:
    """Fetch realm objects from the source FMC with expanded=true.

    Returns sanitized realm objects suitable for offline creation on the target.
    """
    result: List[Dict[str, Any]] = []
    id_set = set(realm_ids)
    try:
        path = client.cfg_path("object/realms")
        raw = client.get_paginated(path, expanded=True)
        for r in raw:
            if isinstance(r, dict) and str(r.get("id", "")) in id_set:
                clean = _sanitize(r, drop=("links",))
                result.append(clean)
    except FmcApiError as e:
        log(f"  [realms] failed to fetch expanded realms: {e}")
    return result


# Object type -> FMC config list/GET endpoint suffix. ``fetch_full_objects``
# uses this to fetch one bulk expanded list per referenced type (indexed by id)
# and to fall back to a direct GET-by-id when a list fails. Every object — even
# a predefined catalog type — is listed here so its metadata can be read and
# each object classified individually; system-defined objects are then stored as
# minimal references. Types absent from this map fall back to a minimal record
# built from the reference itself.
_OBJECT_ENDPOINTS: Dict[str, str] = {
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
    "TunnelTag": "object/tunneltags",
    "Url": "object/urls",
    "UrlGroup": "object/urlgroups",
    "URLCategory": "object/urlcategories",
    "VlanTag": "object/vlantags",
    "VlanGroupTag": "object/vlangrouptags",
    "Application": "object/applications",
    "ApplicationFilter": "object/applicationfilters",
    "ISESecurityGroupTag": "object/isesecuritygrouptags",
    "SecurityGroupTag": "object/securitygrouptags",
    "EndPointDeviceType": "object/endpointdevicetypes",
    "ContinentObject": "object/continents",
    "CountryObject": "object/countries",
    "GeolocationObject": "object/geolocations",
    "SecurityIntelligence": "object/securityintelligence",
    "SIURLList": "object/siurlfeeds",
    "SIURLFeed": "object/siurlfeeds",
    "VariableSet": "object/variablesets",
    "TimeRange": "object/timeranges",
    "TimeZoneObject": "object/timezoneobjects",
    "DNSServerGroup": "object/dnsservergroups",
    "SLAMonitor": "object/slamonitors",
}

# Group member fields for recursive child discovery.
_GROUP_MEMBERS = {
    "NetworkGroup": ["objects", "literals"],
    "PortObjectGroup": ["objects", "literals"],
    "UrlGroup": ["objects", "literals"],
    "VlanGroupTag": ["objects", "literals"],
    "InterfaceGroup": ["interfaces"],
}


def fetch_full_objects(
    client: PolicyFmcClient,
    seed_deps: List[DependencyRef],
    log: Any = None,
) -> List[Dict[str, Any]]:
    """Fetch complete source payloads for all dependencies (recursive).

    Returns a flat list of faithful object payloads (FMC JSON minus the
    transport-only ``links``/``metadata`` keys) for *user-defined* objects, and a
    minimal reference (``type``/``name``/``id``) for *system-defined* ones.

    Three design points make this both fast and correct:

    * **Skip predefined catalogs.** Refs whose type is in :data:`READONLY_TYPES`
      (Applications, URL categories, ISE/SGT tags, …) are kept as a
      name reference and never fetched — the same classification the push resolver
      uses, and the bulk of the work (typically ~80% of refs).
    * **Targeted per-type fetch.** For the remaining *user-defined* types, only
      the referenced objects are fetched via ``nameOrValue`` wildcard-filter
      queries (grouped by common prefix, cached) — the same approach used by
      Device Configuration — instead of listing whole catalogs or GET-per-id.
    * **Per-object metadata catch.** A fetched object is still stored as a
      reference if its own metadata marks it system-defined
      (``metadata.readOnly.reason == "SYSTEM"``) — catches a predefined member of
      a creatable type. User-defined objects are stored in full; nested groups
      are walked recursively.
    """
    log = log or (lambda m: logger.info(m))
    seen: Dict[str, Dict[str, Any]] = {}       # key -> stored record ({} placeholder)
    system_keys: Set[str] = set()              # keys classified system-defined
    pending: Dict[str, DependencyRef] = {}
    for r in seed_deps:
        pending.setdefault(r.key, r)

    if not pending:
        log("[objects] No dependent objects to fetch")
        return []

    total_seed = len(pending)
    log(f"[objects] Resolving {total_seed} reference(s): {_fmt_breakdown(pending.values())}")
    t_start = time.monotonic()
    refs_processed = 0          # cumulative references dispatched
    t_last_progress = t_start   # last time a progress line was emitted
    iteration = 0               # batch iteration (0 = seed, 1+ = children)

    while pending:
        batch = [r for k, r in pending.items() if k not in seen]
        for r in batch:
            seen[r.key] = {}  # reserve so children aren't re-queued
        by_type: Dict[str, List[DependencyRef]] = {}
        for r in batch:
            by_type.setdefault(r.type, []).append(r)

        if iteration > 0 and batch:
            log(f"  [objects] Recursing into {len(batch)} child reference(s): "
                f"{_fmt_breakdown(batch)}")

        children: Dict[str, DependencyRef] = {}
        for obj_type, refs in by_type.items():
            # Predefined/reuse-only catalog types (same set as the push resolver)
            # are kept as name references and never fetched — this skips the bulk
            # of the work (Applications, URL categories, SGTs, …).
            if obj_type in READONLY_TYPES:
                for ref in refs:
                    seen[ref.key] = _minimal_record(ref)
                    system_keys.add(ref.key)
                refs_processed += len(refs)
                log(f"  [objects] {obj_type}×{len(refs)}: predefined — kept as reference (not fetched)")
                continue
            index = _fetch_type_index(client, obj_type, refs)
            for ref in refs:
                body = _lookup_index(index, ref, client)
                if not isinstance(body, dict) or not body.get("id"):
                    seen[ref.key] = _minimal_record(ref)  # unresolved
                    continue
                # Secondary catch: a predefined member of a creatable type.
                if _is_system_object(body):
                    seen[ref.key] = _minimal_record_from(body, ref)
                    system_keys.add(ref.key)
                    continue
                _concretize_generic_members(client, obj_type, body, log)
                seen[ref.key] = _sanitize(body)
                for child_ref in _discover_children(obj_type, body):
                    if child_ref.key not in seen:
                        children.setdefault(child_ref.key, child_ref)
            refs_processed += len(refs)

            # Emit progress after each type batch (if ≥5s since last progress)
            now = time.monotonic()
            if now - t_last_progress >= 5.0:
                _resolved = [v for v in seen.values() if v]
                _unresolved = [k for k, v in seen.items() if v and _is_minimal(v) and k not in system_keys]
                _full = len(_resolved) - len(system_keys) - len(_unresolved)
                log(f"  [objects] Progress: {refs_processed}/{total_seed} seed references processed, "
                    f"{len(_resolved)} objects resolved — "
                    f"{_full} full, {len(system_keys)} reference, {len(_unresolved)} unresolved "
                    f"({now - t_start:.1f}s elapsed, last batch: {obj_type}×{len(refs)})")
                t_last_progress = now

        # Update total to account for discovered children
        if children:
            total_seed += len(children)
        pending = children
        iteration += 1

    result = [v for v in seen.values() if v]
    unresolved = [k for k, v in seen.items() if v and _is_minimal(v) and k not in system_keys]
    full = len(result) - len(system_keys) - len(unresolved)
    log(f"[objects] Resolved {len(result)} object(s) in {time.monotonic() - t_start:.1f}s: "
        f"{full} full (user-defined), {len(system_keys)} reference (system-defined), "
        f"{len(unresolved)} unresolved")
    return result


def _fetch_object_body(
    client: PolicyFmcClient, ref: DependencyRef, suffix: str | None,
) -> Any:
    """Fetch a single object's full body from the source FMC."""
    if not suffix:
        return None
    try:
        if ref.source_id:
            path = client.cfg_path(f"{suffix}/{ref.source_id}")
            body = client.get_json(path)
            if isinstance(body, dict) and body.get("id"):
                return body
        # Fallback: look up by name.
        if ref.name:
            found = client.get_objects_by_names(suffix, [ref.name], ref.type)
            return found.get(normalize_name(ref.name))
    except FmcApiError as e:
        logger.debug(f"  Could not fetch {ref.type} '{ref.name}': {e}")
    return None


def _fetch_type_index(
    client: PolicyFmcClient, obj_type: str, refs: List[DependencyRef],
) -> Optional[Dict[str, Dict[str, Dict[str, Any]]]]:
    """Fetch only the referenced objects of *obj_type* (by name), indexed by
    normalized name and id.

    Uses ``get_objects_by_names``, which issues ``nameOrValue`` wildcard-filter
    queries (grouped by common prefix) so only the referenced objects are
    fetched — never the whole catalog. Returns ``None`` for types without an
    endpoint (the caller then keeps a minimal reference). Refs that carry only
    an id are resolved by a direct GET-by-id fallback in :func:`_lookup_index`.
    """
    suffix = _OBJECT_ENDPOINTS.get(obj_type)
    if not suffix:
        return None
    names = [r.name for r in refs if r.name]
    by_name: Dict[str, Dict[str, Any]] = {}
    if names:
        try:
            by_name = client.get_objects_by_names(suffix, names, obj_type)
        except FmcApiError as e:
            logger.debug(f"  name-filter fetch failed for {obj_type}: {e}")
    by_id = {str(o.get("id")): o for o in by_name.values() if isinstance(o, dict) and o.get("id")}
    return {"by_name": by_name, "by_id": by_id}


def _lookup_index(
    index: Optional[Dict[str, Dict[str, Dict[str, Any]]]], ref: DependencyRef,
    client: Optional[PolicyFmcClient] = None,
) -> Any:
    """Resolve *ref*'s full body from the fetched index, or a direct GET-by-id."""
    if index is not None:
        if ref.name:
            body = index["by_name"].get(normalize_name(ref.name))
            if body is not None:
                return body
        if ref.source_id:
            body = index["by_id"].get(str(ref.source_id))
            if body is not None:
                return body
    # Not matched by name (id-only ref, or filter miss) -> targeted GET-by-id.
    return _fetch_object_body(client, ref, _OBJECT_ENDPOINTS.get(ref.type))


def _minimal_record(ref: DependencyRef) -> Dict[str, Any]:
    """Faithful minimal record sourced from the reference itself."""
    rec: Dict[str, Any] = {"type": ref.type}
    if ref.name:
        rec["name"] = ref.name
    if ref.source_id:
        rec["id"] = ref.source_id
    return rec


def _minimal_record_from(body: Dict[str, Any], ref: DependencyRef) -> Dict[str, Any]:
    """Minimal reference for a system-defined object, preferring the real body."""
    rec: Dict[str, Any] = {"type": body.get("type") or ref.type}
    name = body.get("name") or ref.name
    if name:
        rec["name"] = name
    oid = body.get("id") or ref.source_id
    if oid:
        rec["id"] = oid
    return rec


def _is_minimal(body: Any) -> bool:
    """True when *body* is a reference-only record (no fields beyond type/name/id)."""
    if not isinstance(body, dict) or not body:
        return True
    return set(body.keys()) <= {"type", "name", "id"}


def _type_breakdown(refs: Iterable[DependencyRef]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in refs:
        counts[r.type] = counts.get(r.type, 0) + 1
    return counts


def _fmt_breakdown(refs: Iterable[DependencyRef]) -> str:
    counts = _type_breakdown(refs)
    if not counts:
        return "none"
    return ", ".join(f"{t}×{n}" for t, n in sorted(counts.items(), key=lambda kv: -kv[1]))


def _concretize_generic_members(
    client: PolicyFmcClient, parent_type: str, body: Dict[str, Any], log: Any,
) -> None:
    """Rewrite generic ``NetworkObject`` group members (in place) to their
    concrete Host/Network/Range/FQDN type so they are fetched in full."""
    for fld in _GROUP_MEMBERS.get(parent_type, []):
        for m in body.get(fld) or []:
            if not (isinstance(m, dict) and m.get("type") == GENERIC_NETWORK_TYPE):
                continue
            found = resolve_generic_network(
                client, str(m.get("id") or ""), str(m.get("name") or ""))
            if found and found.get("type") in CONCRETE_NETWORK_TYPES:
                m["type"] = found["type"]
                log(f"  [objects] generic NetworkObject '{m.get('name', '')}' "
                    f"resolved as {m['type']}")
            else:
                log(f"  [objects] generic NetworkObject '{m.get('name', '')}' "
                    "not found on source as Host/Network/Range/FQDN")


def _discover_children(parent_type: str, body: Dict[str, Any]) -> List[DependencyRef]:
    """Extract child dependency refs from a group object body."""
    out: List[DependencyRef] = []
    for fld in _GROUP_MEMBERS.get(parent_type, []):
        members = body.get(fld)
        if not isinstance(members, list):
            continue
        for m in members:
            if isinstance(m, dict) and m.get("type") and (m.get("name") or m.get("id")):
                t = str(m["type"])
                if t in KNOWN_OBJECT_TYPES:
                    out.append(DependencyRef(
                        type=t,
                        name=str(m.get("name", "")),
                        source_id=str(m.get("id", "")),
                    ))
    return out


# ── helpers ──

def _sanitize(d: Any, drop: Tuple[str, ...] = ("links", "metadata")) -> Dict[str, Any]:
    """Return a faithful copy of *d* with only transport-only keys removed.

    Mirrors the Device Configuration ``_sanitize`` convention: drops the
    top-level ``links``/``metadata`` (and, for an ACP base, ``rules``) keys
    while preserving every other key/value verbatim (including ``id``).
    """
    if not isinstance(d, dict):
        return d
    return {k: v for k, v in d.items() if k not in drop}
