import argparse
import logging
import sys
import ipaddress
import requests
import yaml
from typing import Optional

from utils.fmc_api import (
    authenticate,
    get_ftd_uuid,
    get_subinterfaces,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_yaml(filepath: str) -> dict:
    with open(filepath, "r") as f:
        return yaml.safe_load(f) or {}


def ipv4_cidr_to_addr_netmask(cidr: str):
    if not cidr:
        return None, None
    iface = ipaddress.ip_interface(cidr)
    return str(iface.ip), str(iface.network.netmask)


def parse_ipv6_cidr(cidr: str):
    if not cidr:
        return None, None
    iface = ipaddress.ip_interface(cidr)
    return str(iface.ip), str(iface.network.prefixlen)


def get_security_zone_map(fmc_ip: str, headers: dict, domain_uuid: str) -> dict:
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/object/securityzones?limit=1000"
    logger.info("Fetching Security Zones...")
    resp = requests.get(url, headers=headers, verify=False)
    try:
        resp.raise_for_status()
    except Exception:
        logger.error("Failed to fetch security zones: %s", getattr(resp, "text", ""))
        raise
    zones = resp.json().get("items", [])
    return {z.get("name"): {"id": z.get("id"), "name": z.get("name"), "type": "SecurityZone"} for z in zones}


def build_subint_lookup(items: list) -> dict:
    lookup = {}
    for it in items:
        name = it.get("name")  # Parent interface name e.g., Port-channel10
        vlan_id = it.get("vlanId")
        key = f"{name}.{vlan_id}" if name is not None and vlan_id is not None else None
        if key:
            lookup[key] = it
    return lookup


def sanitize_for_put(obj: dict) -> dict:
    payload = dict(obj)
    payload.pop("links", None)
    payload.pop("metadata", None)
    return payload


def update_subinterface(
    fmc_ip: str,
    headers: dict,
    domain_uuid: str,
    ftd_uuid: str,
    existing_obj: dict,
    logical_name: Optional[str],
    zone_obj: Optional[dict],
    ipv4_cidr: Optional[str],
    ipv6_cidr: Optional[str],
    dry_run: bool = False,
    display_key: Optional[str] = None,
):
    obj_id = existing_obj.get("id")
    payload = sanitize_for_put(existing_obj)

    if logical_name:
        payload["ifname"] = logical_name

    if zone_obj:
        payload["securityZone"] = zone_obj

    if ipv4_cidr:
        addr, mask = ipv4_cidr_to_addr_netmask(ipv4_cidr)
        if addr and mask:
            payload.setdefault("ipv4", {})
            payload["ipv4"]["static"] = {"address": addr, "netmask": mask}

    if ipv6_cidr:
        v6addr, v6prefix = parse_ipv6_cidr(ipv6_cidr)
        if v6addr and v6prefix:
            ipv6 = payload.setdefault("ipv6", {})
            ipv6["enableIPV6"] = True
            ipv6["addresses"] = [{"address": v6addr, "prefix": str(v6prefix), "enforceEUI64": False}]

    # Build a readable subinterface identifier like ParentName.VLAN, or use provided YAML key
    if display_key:
        subif_key = display_key
    else:
        parent_name = existing_obj.get("name")
        vlan_id = existing_obj.get("vlanId") or existing_obj.get("subIntfId")
        subif_key = f"{parent_name}.{vlan_id}" if parent_name and vlan_id is not None else parent_name or "<unknown>"

    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/subinterfaces/{obj_id}"
    if dry_run:
        logger.info("[DRY-RUN] Would PUT %s for SubInterface %s (ifname=%s) with payload: %s", url, subif_key, existing_obj.get("ifname"), payload)
        return None

    logger.info("Updating SubInterface %s (ifname=%s)", subif_key, existing_obj.get("ifname"))
    resp = requests.put(url, headers=headers, json=payload, verify=False)
    if resp.status_code not in [200, 201]:
        logger.error("Failed to update SubInterface %s: %s", obj_id, resp.text)
        resp.raise_for_status()
    return resp.json()


def process_device(
    fmc_ip: str,
    headers: dict,
    domain_uuid: str,
    ftd_name: str,
    device_cfg: dict,
    zone_map: dict,
    dry_run: bool,
):
    try:
        ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, ftd_name)
    except Exception as e:
        logger.warning("Device %s not found in FMC; skipping. Details: %s", ftd_name, e)
        return
    items = get_subinterfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name)
    lookup = build_subint_lookup(items)

    interfaces = (device_cfg or {}).get("interfaces", {})
    for key, cfg in interfaces.items():
        if (cfg or {}).get("type") != "subinterface":
            continue
        logical_name = cfg.get("logical_name")
        zone_name = cfg.get("zone")
        ipv4 = cfg.get("ipv4")
        ipv6 = cfg.get("ipv6")

        existing = lookup.get(key)
        if not existing:
            logger.warning("SubInterface %s not found on device %s; skipping.", key, ftd_name)
            continue

        zone_obj = None
        if zone_name:
            zone_obj = zone_map.get(zone_name)
            if not zone_obj:
                logger.warning("Security Zone '%s' not found; skipping zone update for %s.", zone_name, key)

        try:
            update_subinterface(
                fmc_ip,
                headers,
                domain_uuid,
                ftd_uuid,
                existing,
                logical_name,
                zone_obj,
                ipv4,
                ipv6,
                dry_run=dry_run,
                display_key=key,
            )
        except Exception as e:
            logger.error("Error updating %s on %s: %s", key, ftd_name, e)


def main():
    parser = argparse.ArgumentParser(description="Update existing subinterfaces on FMC-managed FTDs per YAML topology")
    parser.add_argument("--fmc_data", required=True, help="Path to scale_mi_interface.yaml (with fmc_data and topology)")
    parser.add_argument("--dry-run", action="store_true", help="Log intended changes without sending PUTs")
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="Device name to resume from (inclusive). Example: --resume wa-1-app1",
    )
    args = parser.parse_args()

    try:
        data = load_yaml(args.fmc_data)
    except Exception as e:
        logger.error("Failed to read YAML: %s", e)
        sys.exit(1)

    fmc = (data or {}).get("fmc_data", {})
    topo = (data or {}).get("topology", {})
    if not fmc or not topo:
        logger.error("YAML must include 'fmc_data' and 'topology'")
        sys.exit(1)

    fmc_ip = fmc.get("fmc_ip")
    username = fmc.get("username")
    password = fmc.get("password")
    if not all([fmc_ip, username, password]):
        logger.error("fmc_data must include fmc_ip, username, password")
        sys.exit(1)

    domain_uuid, headers = authenticate(fmc_ip, username, password)
    zone_map = get_security_zone_map(fmc_ip, headers, domain_uuid)

    # Handle resume option: skip devices until we reach the resume target
    resume_target = args.resume
    resume_hit = resume_target is None
    seen_resume = False
    if resume_target:
        logger.info("Resume requested from device: %s", resume_target)

    for ftd_name, device_cfg in topo.items():
        if not resume_hit:
            if ftd_name != resume_target:
                logger.debug("Skipping device %s (before resume point %s)", ftd_name, resume_target)
                continue
            resume_hit = True
            seen_resume = True

        logger.info("Processing device: %s", ftd_name)
        process_device(
            fmc_ip=fmc_ip,
            headers=headers,
            domain_uuid=domain_uuid,
            ftd_name=ftd_name,
            device_cfg=device_cfg,
            zone_map=zone_map,
            dry_run=args.dry_run,
        )

    if resume_target and not seen_resume:
        logger.warning("Resume device '%s' not found in topology; no devices processed after resume.", resume_target)


if __name__ == "__main__":
    main()