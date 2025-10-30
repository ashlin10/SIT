import logging
from typing import Any, Dict, List, Optional

from . import fmc_api

logger = logging.getLogger(__name__)


class DependencyResolver:
    """
    Minimal resolver skeleton for interface-centric flows.
    - Resolves device interface references (by name -> id)
    - Resolves SecurityZone references (by name -> id)
    """

    def __init__(self, fmc_ip: str, headers: Dict[str, str], domain_uuid: str, device_id: str):
        self.fmc_ip = fmc_ip
        self.headers = headers
        self.domain_uuid = domain_uuid
        self.device_id = device_id
        # Device interface maps
        self._phys_map: Dict[str, str] = {}
        self._eth_map: Dict[str, str] = {}
        self._sub_map: Dict[str, str] = {}
        self._vti_map: Dict[str, str] = {}
        self._loop_map: Dict[str, str] = {}
        self._bgi_map: Dict[str, str] = {}
        self._inline_map: Dict[str, str] = {}
        # Security zones map
        self._sec_zones: Dict[str, str] = {}

    def prime_device_interfaces(self, ftd_name: Optional[str] = None) -> None:
        """Fetch and cache device interface maps by name."""
        def _norm(s: str) -> str:
            try:
                k = str(s).strip()
                return k.lower().replace("-", "").replace("_", "").replace(" ", "")
            except Exception:
                return str(s)
        phys = fmc_api.get_physical_interfaces(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        self._phys_map = {}
        for it in phys:
            for k in [it.get("name"), it.get("ifname")]:
                if it.get("id") and k:
                    key = str(k).strip()
                    self._phys_map[key] = it["id"]
                    lk = key.lower()
                    if lk != key:
                        self._phys_map[lk] = it["id"]
                    nk = _norm(key)
                    if nk not in (key, lk):
                        self._phys_map[nk] = it["id"]

        eths = fmc_api.get_etherchannel_interfaces(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        self._eth_map = {}
        for it in eths:
            nm = it.get("name")
            if it.get("id") and nm:
                key = str(nm).strip()
                self._eth_map[key] = it["id"]
                lk = key.lower()
                if lk != key:
                    self._eth_map[lk] = it["id"]
                nk = _norm(key)
                if nk not in (key, lk):
                    self._eth_map[nk] = it["id"]

        subs = fmc_api.get_subinterfaces(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        self._sub_map = {}
        for it in subs:
            sid = it.get("id")
            if not sid:
                continue
            # Map both name and ifname (when present)
            nm = it.get("name")
            ifname = it.get("ifname") or it.get("ifName")
            if nm:
                key = str(nm).strip()
                self._sub_map[key] = sid
                lk = key.lower()
                if lk != key:
                    self._sub_map[lk] = sid
                nk = _norm(key)
                if nk not in (key, lk):
                    self._sub_map[nk] = sid
            if ifname:
                key = str(ifname).strip()
                self._sub_map[key] = sid
                lk = key.lower()
                if lk != key:
                    self._sub_map[lk] = sid
            # Map parent.subIntfId form using best available parent identifier
            parent_if = (it.get("parentInterface") or {})
            parent = parent_if.get("name") or parent_if.get("ifname") or parent_if.get("ifName")
            sub_id = it.get("subIntfId")
            if parent and (sub_id is not None):
                base = f"{parent}.{sub_id}"
                key = str(base).strip()
                self._sub_map[key] = sid
                lk = key.lower()
                if lk != key:
                    self._sub_map[lk] = sid
                nk = _norm(key)
                if nk not in (key, lk):
                    self._sub_map[nk] = sid
            else:
                # Parent not provided by FMC. Still create a dotted key using the best available label.
                # Prefer the interface 'name' (e.g., 'Port-channel10') and append '.<subId>' so lookups like
                # 'Port-channel10.584' succeed when OSPF payloads refer to dotted names.
                if sub_id is not None:
                    try:
                        parent_label = None
                        if isinstance(nm, str) and nm.strip():
                            parent_label = nm.strip()
                        # As a secondary fallback, derive parent from nm if it already contains a dot and ends with the subId
                        if (not parent_label) and isinstance(nm, str) and "." in nm:
                            left, right = nm.rsplit(".", 1)
                            if right.isdigit() and int(right) == int(sub_id):
                                parent_label = left
                        if parent_label:
                            base = f"{parent_label}.{int(sub_id)}"
                            key = str(base).strip()
                            self._sub_map[key] = sid
                            lk = key.lower()
                            if lk != key:
                                self._sub_map[lk] = sid
                            nk = _norm(key)
                            if nk not in (key, lk):
                                self._sub_map[nk] = sid
                    except Exception:
                        pass
        try:
            logger.info(f"Primed interface maps: physical={len(self._phys_map)}, etherchannel={len(self._eth_map)}, sub={len(self._sub_map)}, vti={len(self._vti_map)}, loopback={len(self._loop_map)}, bridge={len(self._bgi_map)}, inline_set={len(self._inline_map)}")
        except Exception:
            pass

        vtis = fmc_api.get_vti_interfaces(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        self._vti_map = {}
        for it in vtis:
            for k in [it.get("name"), it.get("ifname")]:
                if it.get("id") and k:
                    key = str(k).strip()
                    self._vti_map[key] = it["id"]
                    lk = key.lower()
                    if lk != key:
                        self._vti_map[lk] = it["id"]
                    nk = _norm(key)
                    if nk not in (key, lk):
                        self._vti_map[nk] = it["id"]

        loops = fmc_api.get_loopback_interfaces(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        self._loop_map = {}
        for it in loops:
            for k in [it.get("name"), it.get("ifname")]:
                if it.get("id") and k:
                    key = str(k).strip()
                    self._loop_map[key] = it["id"]
                    lk = key.lower()
                    if lk != key:
                        self._loop_map[lk] = it["id"]
                    nk = _norm(key)
                    if nk not in (key, lk):
                        self._loop_map[nk] = it["id"]

        # Bridge Group Interfaces
        try:
            bgis = fmc_api.get_bridge_group_interfaces(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        except Exception:
            bgis = []
        self._bgi_map = {str(it.get("name")): it.get("id") for it in (bgis or []) if it.get("id") and it.get("name")}

        # Inline Sets
        try:
            inlines = fmc_api.get_inline_sets(self.fmc_ip, self.headers, self.domain_uuid, self.device_id, ftd_name)
        except Exception:
            inlines = []
        self._inline_map = {str(it.get("name")): it.get("id") for it in (inlines or []) if it.get("id") and it.get("name")}

        try:
            logger.info(f"Updated interface maps (post inline/bgi): bridge={len(self._bgi_map)}, inline_set={len(self._inline_map)}")
        except Exception:
            pass

    def prime_security_zones(self) -> None:
        zones = get_security_zones(self.fmc_ip, self.headers, self.domain_uuid)
        self._sec_zones = {str(z.get("name")): z.get("id") for z in zones if z.get("id") and z.get("name")}

    def resolve_interfaces_in_payload(self, payload: Any) -> None:
        """Resolve interface and security zone references in-place within payload (dict or list)."""
        try:
            fmc_api.update_interface_ids(
                payload,
                dest_phys_map=self._phys_map,
                dest_etherchannel_map=self._eth_map,
                dest_subint_map=self._sub_map,
                dest_vti_map=self._vti_map,
                dest_loopback_map=self._loop_map,
                dest_bridge_map=self._bgi_map,
            )
        except Exception as e:
            logger.warning(f"Interface resolution failed: {e}")
        self._resolve_security_zones(payload)

    def _resolve_security_zones(self, obj: Any) -> None:
        if isinstance(obj, dict):
            if (obj.get("type") == "SecurityZone") and obj.get("name"):
                nm = str(obj.get("name"))
                zid = self._sec_zones.get(nm)
                if zid:
                    existing = obj.get("id")
                    if existing and existing != zid:
                        logger.info(f"Correcting SecurityZone id for '{nm}' from {existing} to {zid}")
                    if (not existing) or (existing != zid) or (isinstance(existing, str) and existing.upper().startswith("PLACEHOLDER")):
                        obj["id"] = zid
                else:
                    logger.warning(f"SecurityZone not found by name: {nm}")
            for v in obj.values():
                self._resolve_security_zones(v)
        elif isinstance(obj, list):
            for it in obj:
                self._resolve_security_zones(it)

    def ensure_security_zones(self, definitions: Optional[List[Dict[str, Any]]], required_names: "set[str]") -> List[Dict[str, Any]]:
        """Create missing SecurityZones needed by the config.

        - Looks up existing zones in cache (call prime_security_zones() before this).
        - Uses provided definitions (objects.security_zones) to create when available by name.
        - If no matching definition, creates a minimal zone with interfaceMode=ROUTED.
        Returns list of created zone JSONs.
        """
        created: List[Dict[str, Any]] = []
        defs_by_name = {str(d.get("name")): d for d in (definitions or []) if d.get("name")}
        missing = [n for n in (required_names or set()) if n not in self._sec_zones]
        if not missing:
            return created
        for name in missing:
            body = dict(defs_by_name.get(name) or {})
            body.setdefault("name", name)
            body.setdefault("type", "SecurityZone")
            body.setdefault("interfaceMode", body.get("interfaceMode", "ROUTED"))
            try:
                res = fmc_api.post_security_zone(self.fmc_ip, self.headers, self.domain_uuid, body)
                zid = res.get("id")
                if zid:
                    self._sec_zones[name] = zid
                created.append(res)
                logger.info(f"Created SecurityZone '{name}' (id={zid})")
            except Exception as e:
                logger.error(f"Failed to create SecurityZone '{name}': {e}")
        return created


# Local import-safe helper to avoid circular import of fmc_api trying to import us.
from .fmc_api import get_security_zones  # noqa: E402
