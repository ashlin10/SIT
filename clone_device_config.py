import argparse
import yaml
import logging
from utils.fmc_api import (
    authenticate,
    get_ftd_uuid,
    get_loopback_interfaces,
    create_loopback_interface,
    get_physical_interfaces,
    get_etherchannel_interfaces,
    get_subinterfaces,
    get_vti_interfaces,
    put_physical_interface,
    post_etherchannel_interface,
    post_subinterface,
    post_vti_interface,
    get_bfd_policies,
    post_bfd_policy,
    get_ospfv2_policies,
    post_ospfv2_policy,
    get_ospfv2_interfaces,
    post_ospfv2_interface,
    get_ospfv3_policies,
    post_ospfv3_policy,
    get_ospfv3_interfaces,
    post_ospfv3_interface,
    get_eigrp_policies,
    post_eigrp_policy,
    update_interface_ids,
    replace_masked_eigrp_passwords,
    get_pbr_policies,
    post_pbr_policy,
    get_ipv4_static_routes,
    post_ipv4_static_route,
    get_ipv6_static_routes,
    post_ipv6_static_route,
    get_bgp_general_settings,
    post_bgp_general_settings,
    get_bgp_policies,
    post_bgp_policy,
    get_ecmp_zones,
    post_ecmp_zone,
    get_vrfs,
    post_vrf,
    get_inline_sets,
    post_inline_set,
    build_dest_interface_maps,
    get_vpn_topologies,
    get_vpn_endpoints,
    post_vpn_topology,
    post_vpn_endpoint,
    replace_vpn_endpoint,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_yaml(filepath):
    with open(filepath, "r") as f:
        return yaml.safe_load(f)

# List of config types and their get/post functions
VRF_CONFIGS = [
    ("bfd_policies", get_bfd_policies, post_bfd_policy),
    ("ospfv2_policies", get_ospfv2_policies, post_ospfv2_policy),
    ("ospfv2_interfaces", get_ospfv2_interfaces, post_ospfv2_interface),
    ("ipv4_static_routes", get_ipv4_static_routes, post_ipv4_static_route),
    ("ipv6_static_routes", get_ipv6_static_routes, post_ipv6_static_route),
    ("bgp_policies", get_bgp_policies, post_bgp_policy),
    ("ecmp_zones", get_ecmp_zones, post_ecmp_zone),
    # Add more as needed
]

def fetch_config_from_source(fmc_data):
    fmc_ip = fmc_data['fmc_ip']
    username = fmc_data['username']
    password = fmc_data['password']
    source_ftd = fmc_data['source_ftd']

    domain_uuid, headers = authenticate(fmc_ip, username, password)
    source_ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, source_ftd)
    logger.info(f"Source FTD '{source_ftd}' UUID: {source_ftd_uuid}")

    config = {}
    config['loopbacks'] = get_loopback_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['physicals'] = get_physical_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['etherchannels'] = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['subinterfaces'] = get_subinterfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['vtis'] = get_vti_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['bfd_policies'] = get_bfd_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ospfv2_policies'] = get_ospfv2_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ospfv2_interfaces'] = get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ospfv3_policies'] = get_ospfv3_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ospfv3_interfaces'] = get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['eigrp_policies'] = get_eigrp_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['pbr_policies'] = get_pbr_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ipv4_static_routes'] = get_ipv4_static_routes(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ipv6_static_routes'] = get_ipv6_static_routes(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['bgp_general_settings'] = get_bgp_general_settings(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['bgp_policies'] = get_bgp_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['ecmp_zones'] = get_ecmp_zones(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['vrfs'] = get_vrfs(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    config['inline_sets'] = get_inline_sets(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)

    # VRF-specific configs
    config['vrf_specific'] = {}
    for vrf in config['vrfs']:
        if vrf.get("name") == "Global":
            continue
        vrf_id = vrf["id"]
        vrf_name = vrf["name"]
        config['vrf_specific'][vrf_id] = {}
        for key, get_func, _ in VRF_CONFIGS:
            config['vrf_specific'][vrf_id][key] = get_func(
                fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd, vrf_id=vrf_id, vrf_name=vrf_name
            )
    return config

def apply_config_to_destination(fmc_data, config):
    fmc_ip = fmc_data['fmc_ip']
    username = fmc_data['username']
    password = fmc_data['password']
    destination_ftd = fmc_data['destination_ftd']

    domain_uuid, headers = authenticate(fmc_ip, username, password)
    destination_ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, destination_ftd)
    logger.info(f"Destination FTD '{destination_ftd}' UUID: {destination_ftd_uuid}")

    # Loopbacks
    for lb in config.get('loopbacks', []):
        try:
            create_loopback_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, lb)
        except Exception as e:
            logger.error(f"Failed to create loopback interface {lb.get('ifname')}: {e}")

    # Build destination interface maps for all types
    maps = build_dest_interface_maps(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_loopback_map = maps["dest_loopback_map"]
    dest_phys_map = maps["dest_phys_map"]
    dest_etherchannel_map = maps["dest_etherchannel_map"]
    dest_subint_map = maps["dest_subint_map"]
    dest_vti_map = maps["dest_vti_map"]

    # Physical Interfaces
    for iface in config.get('physicals', []):
        name = iface.get('name')
        dest_obj_id = dest_phys_map.get(name)
        if not dest_obj_id:
            logger.warning(f"Physical interface {name} not found on destination FTD, skipping.")
            continue
        payload = dict(iface)
        payload.pop("links", None)
        payload.pop("metadata", None)
        payload.pop("hardware", None)
        payload.pop("channelGroupId", None)
        payload.pop("lacpMode", None)
        if payload.get("mode") == "INLINE":
            payload.pop("securityZone", None)
        payload["mode"] = "NONE"
        payload["id"] = dest_obj_id
        try:
            put_physical_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, dest_obj_id, payload)
        except Exception as e:
            logger.error(f"Failed to PUT PhysicalInterface {name}: {e}")

    # EtherChannel Interfaces
    for iface in config.get('etherchannels', []):
        payload = dict(iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        payload.pop("hardware", None)
        if iface.get("mode") == "INLINE":
            payload.pop("securityZone", None)
        payload["mode"] = "NONE"
        if "selectedInterfaces" in payload and isinstance(payload["selectedInterfaces"], list):
            for member in payload["selectedInterfaces"]:
                member_name = member.get("name")
                dest_member_id = dest_phys_map.get(member_name)
                if dest_member_id:
                    member["id"] = dest_member_id
                else:
                    logger.warning(f"Member interface {member_name} not found on destination FTD, skipping this member.")
        try:
            post_etherchannel_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST EtherChannelInterface {iface.get('name')}: {e}")

    # SubInterfaces
    for iface in config.get('subinterfaces', []):
        payload = dict(iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        subintf_name = f"{payload.get('name')}.{payload.get('subIntfId')}"
        logger.info(f"Creating SubInterface {subintf_name}")
        try:
            post_subinterface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST SubInterface {subintf_name}: {e}")

    # Update destination interface maps for all types
    maps = build_dest_interface_maps(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_loopback_map = maps["dest_loopback_map"]
    dest_phys_map = maps["dest_phys_map"]
    dest_etherchannel_map = maps["dest_etherchannel_map"]
    dest_subint_map = maps["dest_subint_map"]
    dest_vti_map = maps["dest_vti_map"]

    # VTI Interfaces
    for iface in config.get('vtis', []):
        payload = dict(iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        payload.pop("managementOnly", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_vti_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST VTIInterface {iface.get('name')}: {e}")

    # Update destination interface maps for all types
    maps = build_dest_interface_maps(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_loopback_map = maps["dest_loopback_map"]
    dest_phys_map = maps["dest_phys_map"]
    dest_etherchannel_map = maps["dest_etherchannel_map"]
    dest_subint_map = maps["dest_subint_map"]
    dest_vti_map = maps["dest_vti_map"]

    # BFD Policies
    for bfd in config.get('bfd_policies', []):
        payload = dict(bfd)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_bfd_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST BFDPolicy for interface {payload.get('interface', {}).get('name')}: {e}")

    # OSPFv2 Policies
    for ospf in config.get('ospfv2_policies', []):
        payload = dict(ospf)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ospfv2_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST OSPFv2 policy with processId {payload.get('processId')}: {e}")

    # OSPFv2 Interfaces
    for ospf_iface in config.get('ospfv2_interfaces', []):
        payload = dict(ospf_iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ospfv2_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST OSPFv2 interface for {payload.get('deviceInterface', {}).get('name')}: {e}")

    # OSPFv3 Policies
    for ospf in config.get('ospfv3_policies', []):
        payload = dict(ospf)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        timers = payload.get("processConfiguration", {}).get("timers", {})
        timers["lsaThrottleTimer"] = {
            "initialDelay": 5000,
            "minimumDelay": 10000,
            "maximumDelay": 10000
        }
        timers["spfThrottleTimer"] = {
            "initialDelay": 5000,
            "minimumHoldTime": 10000,
            "maximumWaitTime": 10000
        }
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ospfv3_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST OSPFv3 policy with processId {payload.get('processId')}: {e}")

    # OSPFv3 Interfaces
    for ospf_iface in config.get('ospfv3_interfaces', []):
        payload = dict(ospf_iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ospfv3_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST OSPFv3 interface for {payload.get('deviceInterface', {}).get('name')}: {e}")

    # EIGRP Policies
    for eigrp in config.get('eigrp_policies', []):
        payload = dict(eigrp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        replace_masked_eigrp_passwords(payload)
        try:
            post_eigrp_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST EIGRP policy with asNumber {payload.get('asNumber')}: {e}")

    # PBR Policies
    for pbr in config.get('pbr_policies', []):
        payload = dict(pbr)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_pbr_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST PBR policy: {e}")

    # IPv4 Static Routes
    for route in config.get('ipv4_static_routes', []):
        payload = dict(route)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ipv4_static_route(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST IPv4 static route for interface {payload.get('interfaceName')}: {e}")

    # IPv6 Static Routes
    for route in config.get('ipv6_static_routes', []):
        payload = dict(route)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ipv6_static_route(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST IPv6 static route for interface {payload.get('interfaceName')}: {e}")

    # BGP General Settings
    for bgp in config.get('bgp_general_settings', []):
        payload = dict(bgp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_bgp_general_settings(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST BGP general settings with asNumber {payload.get('asNumber')}: {e}")

    # BGP Policies
    for bgp in config.get('bgp_policies', []):
        payload = dict(bgp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_bgp_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST BGP policy with asNumber {payload.get('asNumber')}: {e}")

    # ECMP Zones
    for ecmp in config.get('ecmp_zones', []):
        payload = dict(ecmp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_ecmp_zone(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST ECMP zone {payload.get('name')}: {e}")

    # Inline Sets
    for inline_set in config.get('inline_sets', []):
        payload = dict(inline_set)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_inline_set(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST Inline Set {payload.get('name')}: {e}")

    # VRFs and VRF-specific configs
    vrf_id_map = {}

    # Fetch existing VRFs on destination
    existing_vrfs = get_vrfs(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    existing_vrf_names = {vrf['name']: vrf['id'] for vrf in existing_vrfs}

    for vrf in config.get('vrfs', []):
        if vrf.get("name") == "Global":
            logger.info("Skipping Global VRF.")
            continue
        payload = dict(vrf)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        vrf_name = payload.get("name")
        src_vrf_id = vrf.get("id")

        # Check if VRF already exists
        if vrf_name in existing_vrf_names:
            logger.info(f"VRF {vrf_name} already exists on destination, skipping creation.")
            dest_vrf_id = existing_vrf_names[vrf_name]
            vrf_id_map[src_vrf_id] = dest_vrf_id
        else:
            # Try to create VRF, retrying if interfaces are already in use
            interfaces = payload.get("interfaces", [])
            while True:
                try:
                    vrf_resp = post_vrf(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
                    dest_vrf_id = vrf_resp.get("id")
                    vrf_id_map[src_vrf_id] = dest_vrf_id
                    break
                except Exception as e:
                    # Check for interface usage error
                    err_msg = str(e)
                    if "Invalid Interface Usage" in err_msg:
                        # Parse out interface names from error message
                        import re
                        used = re.findall(r"interface\(s\) ([^)]+)", err_msg)
                        if used:
                            used_ifaces = [i.split(" (")[0] for i in used[0].split(", ")]
                            logger.warning(f"Interfaces already in use for VRF {vrf_name}: {used_ifaces}")
                            # Remove these interfaces from payload and retry
                            interfaces = [iface for iface in interfaces if iface.get("name") not in used_ifaces]
                            if not interfaces:
                                logger.warning(f"All interfaces for VRF {vrf_name} are already in use. Skipping VRF.")
                                dest_vrf_id = None
                                break
                            payload["interfaces"] = interfaces
                            continue
                    logger.error(f"Failed to POST VRF {vrf_name}: {e}")
                    dest_vrf_id = None
                    break

        # Apply VRF-specific configs if present and VRF was created or exists
        if dest_vrf_id:
            vrf_cfg = config.get("vrf_specific", {}).get(src_vrf_id, {})
            vrf_name = payload.get("name")
            for key, _, post_func in VRF_CONFIGS:
                for item in vrf_cfg.get(key, []):
                    item_payload = dict(item)
                    item_payload.pop("id", None)
                    item_payload.pop("links", None)
                    item_payload.pop("metadata", None)
                    update_interface_ids(
                        item_payload,
                        dest_phys_map,
                        dest_etherchannel_map,
                        dest_subint_map,
                        dest_vti_map,
                        dest_loopback_map
                    )
                    try:
                        post_func(
                            fmc_ip, headers, domain_uuid, destination_ftd_uuid,
                            item_payload, vrf_id=dest_vrf_id, vrf_name=vrf_name
                        )
                    except Exception as e:
                        logger.error(f"Failed to POST {key} for VRF {vrf_name}: {e}")


def main():
    parser = argparse.ArgumentParser(description="FTD Config Manager: clone, export, or import FTD configs")
    parser.add_argument("--fmc_data", help="Path to fmc_data.yaml", required=True)
    parser.add_argument("--config", help="Path to config YAML file")
    parser.add_argument("--replace_vpn_endpoints", action="store_true", help="Only fetch and update VPN endpoint configs")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--get", action="store_true", help="Export config from source FTD to --config")
    group.add_argument("--post", action="store_true", help="Import config in --config to destination FTD")
    args = parser.parse_args()

    fmc_data = load_yaml(args.fmc_data)['fmc_data']

    # Replace VPN endpoints
    if args.replace_vpn_endpoints:
        fmc_ip = fmc_data['fmc_ip']
        username = fmc_data['username']
        password = fmc_data['password']
        source_ftd = fmc_data['source_ftd']
        destination_ftd = fmc_data['destination_ftd']
        domain_uuid, headers = authenticate(fmc_ip, username, password)
        # Fetch VPN topologies and endpoints from FMC
        vpn_topologies = get_vpn_topologies(fmc_ip, headers, domain_uuid)
        vpn_configs = []
        for vpn in vpn_topologies:
            vpn_id = vpn.get("id")
            vpn_name = vpn.get("name")
            endpoints = get_vpn_endpoints(fmc_ip, headers, domain_uuid, vpn_id, vpn_name=vpn_name)
            vpn_copy = dict(vpn)
            vpn_copy["endpoints"] = endpoints
            vpn_configs.append(vpn_copy)
        # Replace VPN endpoints
        replace_vpn_endpoint(fmc_ip, headers, domain_uuid, source_ftd, destination_ftd, vpn_configs)
        logger.info("VPN endpoint update complete.")
        return

    if args.get and args.config:
        config = fetch_config_from_source(fmc_data)
        with open(args.config, 'w') as f:
            yaml.safe_dump(config, f)
        logger.info(f"Exported source FTD config to {args.config}")
    elif args.post and args.config:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        apply_config_to_destination(fmc_data, config)
    else:
        config = fetch_config_from_source(fmc_data)
        apply_config_to_destination(fmc_data, config)

if __name__ == "__main__":
    main()