import argparse
import yaml
import logging
import requests
import json
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
    build_dest_interface_maps
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_yaml(filepath):
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Clone device config from source FTD to destination FTD on FMC")
    parser.add_argument("--fmc_data", help="Path to fmc_data.yaml", required=True)
    args = parser.parse_args()

    # Load FMC credentials and device info
    fmc_data = load_yaml(args.fmc_data)['fmc_data']
    fmc_ip = fmc_data['fmc_ip']
    username = fmc_data['username']
    password = fmc_data['password']
    source_ftd = fmc_data['source_ftd']
    destination_ftd = fmc_data['destination_ftd']

    # Authenticate to FMC
    domain_uuid, headers = authenticate(fmc_ip, username, password)

    # Get UUIDs for source and destination FTDs
    source_ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, source_ftd)
    destination_ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, destination_ftd)

    logger.info(f"Source FTD '{source_ftd}' UUID: {source_ftd_uuid}")
    logger.info(f"Destination FTD '{destination_ftd}' UUID: {destination_ftd_uuid}")

    # Fetch loopback interfaces from source FTD
    loopbacks = get_loopback_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid)
    logger.info(f"Found {len(loopbacks)} loopback interfaces on source FTD.")

    if loopbacks:
        for lb in loopbacks:
            logger.info(f"Cloning loopback interface: {lb.get('ifname')}")
            try:
                create_loopback_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, lb)
            except requests.exceptions.HTTPError as e:
                # Try to extract the error message from the response body
                error_text = str(e)
                response = getattr(e, 'response', None)
                duplicate = False
                if response is not None:
                    try:
                        error_json = response.json()
                        # Get all error descriptions
                        descriptions = [
                            msg.get("description", "")
                            for msg in error_json.get("error", {}).get("messages", [])
                        ]
                        error_text_full = " ".join(descriptions)
                        if (
                            "Duplicate" in error_text_full
                            or "already exists" in error_text_full
                            or "overlaps" in error_text_full
                        ):
                            logger.warning(f"Interface {lb.get('ifname')} already exists or overlaps. Skipping.")
                            duplicate = True
                    except Exception:
                        pass
                if not duplicate:
                    logger.error(f"Failed to create loopback interface {lb.get('ifname')}: {error_text}")
                    raise
    else:
        logger.info("No loopback interfaces to clone.")

    # Fetch interfaces from source FTD using individual GETs
    physicals = get_physical_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    etherchannels = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    subinterfaces = get_subinterfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)

    logger.info(f"Found {len(physicals)} PhysicalInterfaces, {len(etherchannels)} EtherChannelInterfaces, {len(subinterfaces)} SubInterfaces, {len(vtis)} VTIInterfaces on source FTD.")

    # Build destination interface maps for all types
    maps = build_dest_interface_maps(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_loopback_map = maps["dest_loopback_map"]
    dest_phys_map = maps["dest_phys_map"]
    dest_etherchannel_map = maps["dest_etherchannel_map"]
    dest_subint_map = maps["dest_subint_map"]
    dest_vti_map = maps["dest_vti_map"]

    # Restore PhysicalInterfaces (PUT)
    for iface in physicals:
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
        # If mode is INLINE, remove securityZone
        if payload.get("mode") == "INLINE":
            payload.pop("securityZone", None)
        # Set "mode" to "NONE" (required)
        payload["mode"] = "NONE"
        payload["id"] = dest_obj_id
        try:
            put_physical_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, dest_obj_id, payload)
        except Exception as e:
            logger.error(f"Failed to PUT PhysicalInterface {name}: {e}")

    # Restore EtherChannel Interfaces (POST)
    for iface in etherchannels:
        payload = dict(iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        payload.pop("hardware", None)
        # If mode is INLINE, remove securityZone
        if iface.get("mode") == "INLINE":
            payload.pop("securityZone", None)
        # Set "mode" to "NONE" (required)
        payload["mode"] = "NONE"
        # Update selectedInterfaces IDs to use destination FTD's physical interface IDs
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

    # Restore SubInterfaces (POST)
    for iface in subinterfaces:
        payload = dict(iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Compose subinterface name as "name.subIntfId"
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

    # Restore VTI Interfaces (POST)
    for iface in vtis:
        payload = dict(iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        payload.pop("managementOnly", None)

        # Automatically update all interface references in the payload
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

    # Fetch BFD policies from source FTD
    bfd_policies = get_bfd_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(bfd_policies)} BFD policies on source FTD.")

    for bfd in bfd_policies:
        payload = dict(bfd)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch OSPFv2 policies from source FTD
    ospfv2_policies = get_ospfv2_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ospfv2_policies)} OSPFv2 policies on source FTD.")

    for ospf in ospfv2_policies:
        payload = dict(ospf)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch OSPFv3 policies from source FTD
    ospfv3_policies = get_ospfv3_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ospfv3_policies)} OSPFv3 policies on source FTD.")

    for ospf in ospfv3_policies:
        payload = dict(ospf)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Replace lsaThrottleTimer and spfThrottleTimer with specified values
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
        # Automatically update all interface references in the payload
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

    # Fetch OSPFv2 interfaces from source FTD
    ospfv2_interfaces = get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ospfv2_interfaces)} OSPFv2 interfaces on source FTD.")

    for ospf_iface in ospfv2_interfaces:
        payload = dict(ospf_iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch OSPFv3 interfaces from source FTD
    ospfv3_interfaces = get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ospfv3_interfaces)} OSPFv3 interfaces on source FTD.")

    for ospf_iface in ospfv3_interfaces:
        payload = dict(ospf_iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch EIGRP policies from source FTD
    eigrp_policies = get_eigrp_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(eigrp_policies)} EIGRP policies on source FTD.")

    for eigrp in eigrp_policies:
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

    # Fetch PBR policies from source FTD
    pbr_policies = get_pbr_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(pbr_policies)} PBR policies on source FTD.")

    for pbr in pbr_policies:
        payload = dict(pbr)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch IPv4 static routes from source FTD
    ipv4_static_routes = get_ipv4_static_routes(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ipv4_static_routes)} IPv4 static routes on source FTD.")

    for route in ipv4_static_routes:
        payload = dict(route)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch IPv6 static routes from source FTD
    ipv6_static_routes = get_ipv6_static_routes(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ipv6_static_routes)} IPv6 static routes on source FTD.")

    for route in ipv6_static_routes:
        payload = dict(route)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch BGP general settings from source FTD
    bgp_general_settings = get_bgp_general_settings(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(bgp_general_settings)} BGP general settings on source FTD.")

    for bgp in bgp_general_settings:
        payload = dict(bgp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch BGP policies from source FTD
    bgp_policies = get_bgp_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(bgp_policies)} BGP policies on source FTD.")

    for bgp in bgp_policies:
        payload = dict(bgp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Pop out maximumPaths from addressFamilyIPv4 and addressFamilyIPv6 if present
        if "addressFamilyIPv4" in payload and isinstance(payload["addressFamilyIPv4"], dict):
            payload["addressFamilyIPv4"].pop("maximumPaths", None)
        if "addressFamilyIPv6" in payload and isinstance(payload["addressFamilyIPv6"], dict):
            payload["addressFamilyIPv6"].pop("maximumPaths", None)
        # Automatically update all interface references in the payload
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

    # Fetch ECMP zones from source FTD
    ecmp_zones = get_ecmp_zones(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ecmp_zones)} ECMP zones on source FTD.")

    for ecmp in ecmp_zones:
        payload = dict(ecmp)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Automatically update all interface references in the payload
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

    # Fetch VRFs from source FTD
    vrfs = get_vrfs(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(vrfs)} VRFs on source FTD.")

    for vrf in vrfs:
        # Skip the Global VRF
        if vrf.get("name") == "Global":
            logger.info("Skipping Global VRF.")
            continue
        payload = dict(vrf)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Update all interface references in the VRF payload
        update_interface_ids(
            payload,
            dest_phys_map,
            dest_etherchannel_map,
            dest_subint_map,
            dest_vti_map,
            dest_loopback_map
        )
        try:
            post_vrf(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST VRF {payload.get('name')}: {e}")


if __name__ == "__main__":
    main()
