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

    # # Fetch loopback interfaces from source FTD
    # loopbacks = get_loopback_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid)
    # logger.info(f"Found {len(loopbacks)} loopback interfaces on source FTD.")

    # if loopbacks:
    #     for lb in loopbacks:
    #         logger.info(f"Cloning loopback interface: {lb.get('ifname')}")
    #         try:
    #             create_loopback_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, lb)
    #         except requests.exceptions.HTTPError as e:
    #             # Try to extract the error message from the response body
    #             error_text = str(e)
    #             response = getattr(e, 'response', None)
    #             duplicate = False
    #             if response is not None:
    #                 try:
    #                     error_json = response.json()
    #                     # Get all error descriptions
    #                     descriptions = [
    #                         msg.get("description", "")
    #                         for msg in error_json.get("error", {}).get("messages", [])
    #                     ]
    #                     error_text_full = " ".join(descriptions)
    #                     if (
    #                         "Duplicate" in error_text_full
    #                         or "already exists" in error_text_full
    #                         or "overlaps" in error_text_full
    #                     ):
    #                         logger.warning(f"Interface {lb.get('ifname')} already exists or overlaps. Skipping.")
    #                         duplicate = True
    #                 except Exception:
    #                     pass
    #             if not duplicate:
    #                 logger.error(f"Failed to create loopback interface {lb.get('ifname')}: {error_text}")
    #                 raise
    # else:
    #     logger.info("No loopback interfaces to clone.")

    # Fetch interfaces from source FTD using individual GETs
    physicals = get_physical_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid)
    etherchannels = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid)
    subinterfaces = get_subinterfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid)
    vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid)

    logger.info(f"Found {len(physicals)} PhysicalInterfaces, {len(etherchannels)} EtherChannelInterfaces, {len(subinterfaces)} SubInterfaces, {len(vtis)} VTIInterfaces on source FTD.")

    # Build destination interface maps for all types
    dest_loopbacks = get_loopback_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid)
    dest_loopback_map = {iface['name']: iface['id'] for iface in dest_loopbacks}

    dest_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid)
    dest_phys_map = {iface['name']: iface['id'] for iface in dest_phys if iface.get('type') == 'PhysicalInterface'}

    dest_etherchannels = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid)
    dest_etherchannel_map = {iface['name']: iface['id'] for iface in dest_etherchannels if iface.get('type') == 'EtherChannelInterface'}

    dest_subints = get_subinterfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid)
    dest_subint_map = {f"{iface['name']}.{iface['subIntfId']}": iface['id'] for iface in dest_subints}

    dest_vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid)
    dest_vti_map = {iface['name']: iface['id'] for iface in dest_vtis if 'name' in iface and 'id' in iface}

    # # Restore PhysicalInterfaces (PUT)
    # for iface in physicals:
    #     name = iface.get('name')
    #     dest_obj_id = dest_phys_map.get(name)
    #     if not dest_obj_id:
    #         logger.warning(f"Physical interface {name} not found on destination FTD, skipping.")
    #         continue
    #     payload = dict(iface)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     payload.pop("hardware", None)
    #     payload.pop("channelGroupId", None)
    #     payload.pop("lacpMode", None)
    #     # If mode is INLINE, remove securityZone
    #     if payload.get("mode") == "INLINE":
    #         payload.pop("securityZone", None)
    #     # Set "mode" to "NONE" (required)
    #     payload["mode"] = "NONE"
    #     payload["id"] = dest_obj_id
    #     try:
    #         put_physical_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, dest_obj_id, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to PUT PhysicalInterface {name}: {e}")

    # # Restore EtherChannel Interfaces (POST)
    # for iface in etherchannels:
    #     payload = dict(iface)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     payload.pop("hardware", None)
    #     # If mode is INLINE, remove securityZone
    #     if iface.get("mode") == "INLINE":
    #         payload.pop("securityZone", None)
    #     # Set "mode" to "NONE" (required)
    #     payload["mode"] = "NONE"
    #     # Update selectedInterfaces IDs to use destination FTD's physical interface IDs
    #     if "selectedInterfaces" in payload and isinstance(payload["selectedInterfaces"], list):
    #         for member in payload["selectedInterfaces"]:
    #             member_name = member.get("name")
    #             dest_member_id = dest_phys_map.get(member_name)
    #             if dest_member_id:
    #                 member["id"] = dest_member_id
    #             else:
    #                 logger.warning(f"Member interface {member_name} not found on destination FTD, skipping this member.")
    #     try:
    #         post_etherchannel_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST EtherChannelInterface {iface.get('name')}: {e}")

    # # Restore SubInterfaces (POST)
    # for iface in subinterfaces:
    #     payload = dict(iface)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     # Compose subinterface name as "name.subIntfId"
    #     subintf_name = f"{payload.get('name')}.{payload.get('subIntfId')}"
    #     logger.info(f"Creating SubInterface {subintf_name}")
    #     try:
    #         post_subinterface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST SubInterface {subintf_name}: {e}")

    # # Restore VTI Interfaces (POST)
    # for iface in vtis:
    #     payload = dict(iface)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     payload.pop("managementOnly", None)

    #     # Update tunnelSource id
    #     if "tunnelSource" in payload and isinstance(payload["tunnelSource"], dict):
    #         ts = payload["tunnelSource"]
    #         ts_name = ts.get("name")
    #         ts_type = ts.get("type")
    #         if ts_type == "LoopbackInterface":
    #             new_id = dest_loopback_map.get(ts_name)
    #         elif ts_type == "PhysicalInterface":
    #             new_id = dest_phys_map.get(ts_name)
    #         elif ts_type == "EtherChannelInterface":
    #             new_id = dest_etherchannel_map.get(ts_name)
    #         elif ts_type == "SubInterface":
    #             # For subinterfaces, use "name.subIntfId" as key
    #             subintf_key = f"{ts.get('name')}.{ts.get('subIntfId')}"
    #             new_id = dest_subint_map.get(subintf_key)
    #         else:
    #             new_id = None
    #         if new_id:
    #             payload["tunnelSource"]["id"] = new_id
    #         else:
    #             logger.warning(f"tunnelSource {ts_name} of type {ts_type} not found on destination FTD.")

    #     # Update borrowIPfrom id
    #     if "borrowIPfrom" in payload and isinstance(payload["borrowIPfrom"], dict):
    #         bif = payload["borrowIPfrom"]
    #         bif_name = bif.get("name")
    #         bif_type = bif.get("type")
    #         if bif_type == "LoopbackInterface":
    #             new_id = dest_loopback_map.get(bif_name)
    #         elif bif_type == "PhysicalInterface":
    #             new_id = dest_phys_map.get(bif_name)
    #         elif bif_type == "EtherChannelInterface":
    #             new_id = dest_etherchannel_map.get(bif_name)
    #         elif bif_type == "SubInterface":
    #             subintf_key = f"{bif.get('name')}.{bif.get('subIntfId')}"
    #             new_id = dest_subint_map.get(subintf_key)
    #         else:
    #             new_id = None
    #         if new_id:
    #             payload["borrowIPfrom"]["id"] = new_id
    #         else:
    #             logger.warning(f"borrowIPfrom {bif_name} of type {bif_type} not found on destination FTD.")

    #     try:
    #         post_vti_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST VTIInterface {iface.get('name')}: {e}")

    # # Fetch BFD policies from source FTD
    # bfd_policies = get_bfd_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    # logger.info(f"Found {len(bfd_policies)} BFD policies on source FTD.")

    # for bfd in bfd_policies:
    #     payload = dict(bfd)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     # Update interface id to destination FTD's interface id
    #     if "interface" in payload and isinstance(payload["interface"], dict):
    #         intf = payload["interface"]
    #         intf_type = intf.get("type")
    #         if intf_type == "PhysicalInterface":
    #             new_id = dest_phys_map.get(intf.get("name"))
    #         elif intf_type == "EtherChannelInterface":
    #             new_id = dest_etherchannel_map.get(intf.get("name"))
    #         elif intf_type == "SubInterface":
    #             subintf_key = f"{intf.get('name')}"
    #             # If you use name.subIntfId as key in your map, adjust accordingly:
    #             if 'subIntfId' in intf:
    #                 subintf_key = f"{intf.get('name')}.{intf.get('subIntfId')}"
    #             new_id = dest_subint_map.get(subintf_key)
    #         else:
    #             new_id = None
    #         if new_id:
    #             payload["interface"]["id"] = new_id
    #         else:
    #             logger.warning(f"BFDPolicy interface {intf.get('name')} of type {intf_type} not found on destination FTD. Skipping.")
    #             continue
    #     try:
    #         post_bfd_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST BFDPolicy for interface {payload.get('interface', {}).get('name')}: {e}")

    # # Fetch OSPFv2 policies from source FTD
    # ospfv2_policies = get_ospfv2_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    # logger.info(f"Found {len(ospfv2_policies)} OSPFv2 policies on source FTD.")

    # for ospf in ospfv2_policies:
    #     payload = dict(ospf)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     try:
    #         post_ospfv2_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST OSPFv2 policy with processId {payload.get('processId')}: {e}")

    # # Fetch OSPFv3 policies from source FTD
    # ospfv3_policies = get_ospfv3_policies(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    # logger.info(f"Found {len(ospfv3_policies)} OSPFv3 policies on source FTD.")

    # for ospf in ospfv3_policies:
    #     payload = dict(ospf)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)

    #     # Replace lsaThrottleTimer and spfThrottleTimer with specified values
    #     timers = payload.get("processConfiguration", {}).get("timers", {})
    #     timers["lsaThrottleTimer"] = {
    #         "initialDelay": 5000,
    #         "minimumDelay": 10000,
    #         "maximumDelay": 10000
    #     }
    #     timers["spfThrottleTimer"] = {
    #         "initialDelay": 5000,
    #         "minimumHoldTime": 10000,
    #         "maximumWaitTime": 10000
    #     }

    #     try:
    #         post_ospfv3_policy(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST OSPFv3 policy with processId {payload.get('processId')}: {e}")

    # # Fetch OSPFv2 interfaces from source FTD
    # ospfv2_interfaces = get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    # logger.info(f"Found {len(ospfv2_interfaces)} OSPFv2 interfaces on source FTD.")

    # for ospf_iface in ospfv2_interfaces:
    #     payload = dict(ospf_iface)
    #     payload.pop("id", None)
    #     payload.pop("links", None)
    #     payload.pop("metadata", None)
    #     # Update deviceInterface id to destination FTD's interface id
    #     if "deviceInterface" in payload and isinstance(payload["deviceInterface"], dict):
    #         intf = payload["deviceInterface"]
    #         intf_type = intf.get("type")
    #         if intf_type == "PhysicalInterface":
    #             new_id = dest_phys_map.get(intf.get("name"))
    #         elif intf_type == "EtherChannelInterface":
    #             new_id = dest_etherchannel_map.get(intf.get("name"))
    #         elif intf_type == "SubInterface":
    #             subintf_key = f"{intf.get('name')}"
    #             if 'subIntfId' in intf:
    #                 subintf_key = f"{intf.get('name')}.{intf.get('subIntfId')}"
    #             new_id = dest_subint_map.get(subintf_key)
    #         elif intf_type == "VTIInterface":
    #             new_id = dest_vti_map.get(intf.get("name"))
    #         else:
    #             new_id = None
    #         if new_id:
    #             payload["deviceInterface"]["id"] = new_id
    #         else:
    #             logger.warning(f"OSPFv2 interface {intf.get('name')} of type {intf_type} not found on destination FTD. Skipping.")
    #             continue
    #     try:
    #         post_ospfv2_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
    #     except Exception as e:
    #         logger.error(f"Failed to POST OSPFv2 interface for {payload.get('deviceInterface', {}).get('name')}: {e}")

    # Fetch OSPFv3 interfaces from source FTD
    ospfv3_interfaces = get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, source_ftd_uuid, source_ftd)
    logger.info(f"Found {len(ospfv3_interfaces)} OSPFv3 interfaces on source FTD.")

    for ospf_iface in ospfv3_interfaces:
        payload = dict(ospf_iface)
        payload.pop("id", None)
        payload.pop("links", None)
        payload.pop("metadata", None)
        # Update deviceInterface id to destination FTD's interface id
        if "deviceInterface" in payload and isinstance(payload["deviceInterface"], dict):
            intf = payload["deviceInterface"]
            intf_type = intf.get("type")
            if intf_type == "PhysicalInterface":
                new_id = dest_phys_map.get(intf.get("name"))
            elif intf_type == "EtherChannelInterface":
                new_id = dest_etherchannel_map.get(intf.get("name"))
            elif intf_type == "SubInterface":
                subintf_key = f"{intf.get('name')}"
                if 'subIntfId' in intf:
                    subintf_key = f"{intf.get('name')}.{intf.get('subIntfId')}"
                new_id = dest_subint_map.get(subintf_key)
            elif intf_type == "VTIInterface":
                new_id = dest_vti_map.get(intf.get("name"))
            else:
                new_id = None
            if new_id:
                payload["deviceInterface"]["id"] = new_id
            else:
                logger.warning(f"OSPFv3 interface {intf.get('name')} of type {intf_type} not found on destination FTD. Skipping.")
                continue
        # Update neighbor.deviceInterface id if present
        if "neighbor" in payload and isinstance(payload["neighbor"], dict):
            neighbor = payload["neighbor"].get("deviceInterface")
            if neighbor:
                n_type = neighbor.get("type")
                if n_type == "PhysicalInterface":
                    n_id = dest_phys_map.get(neighbor.get("name"))
                elif n_type == "EtherChannelInterface":
                    n_id = dest_etherchannel_map.get(neighbor.get("name"))
                elif n_type == "SubInterface":
                    n_key = f"{neighbor.get('name')}"
                    if 'subIntfId' in neighbor:
                        n_key = f"{neighbor.get('name')}.{neighbor.get('subIntfId')}"
                    n_id = dest_subint_map.get(n_key)
                elif n_type == "VTIInterface":
                    n_id = dest_vti_map.get(neighbor.get("name"))
                else:
                    n_id = None
                if n_id:
                    payload["neighbor"]["deviceInterface"]["id"] = n_id
                else:
                    logger.warning(f"OSPFv3 neighbor interface {neighbor.get('name')} of type {n_type} not found on destination FTD. Skipping.")
                    continue
        try:
            post_ospfv3_interface(fmc_ip, headers, domain_uuid, destination_ftd_uuid, payload)
        except Exception as e:
            logger.error(f"Failed to POST OSPFv3 interface for {payload.get('deviceInterface', {}).get('name')}: {e}")


if __name__ == "__main__":
    main()
