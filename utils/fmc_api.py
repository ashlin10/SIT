import requests
import logging
from requests.auth import HTTPBasicAuth
import time

import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress warnings
warnings.simplefilter("ignore", InsecureRequestWarning)

logger = logging.getLogger(__name__)

def extract_error_description(response):
    try:
        error_data = response.json()
        return error_data.get("error", {}).get("messages", [{}])[0].get("description", "No description available")
    except Exception:
        return "No description available"

def authenticate(fmc_ip, username, password):
    AUTH_URL = f"{fmc_ip}/api/fmc_platform/v1/auth/generatetoken"
    headers = {"Content-Type": "application/json"}

    try:
        logger.info("Authenticating to FMC...")
        response = requests.post(AUTH_URL, headers=headers, auth=HTTPBasicAuth(username, password), verify=False)
        response.raise_for_status()

        token = response.headers.get("X-auth-access-token")
        if not token:
            raise Exception("Authentication failed: No token received")

        domain_uuid = response.headers.get("DOMAIN_UUID")
        if not domain_uuid:
            raise Exception("Authentication failed: No domain UUID received")

        headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
        logger.info("Authentication successful.")
        return domain_uuid, headers

    except requests.exceptions.RequestException as e:
        description = extract_error_description(e.response) if e.response else str(e)
        logger.error(f"Authentication failed: {e}. Description: {description}")
        raise Exception("Authentication failed.")

def get_ftd_uuid(fmc_ip, headers, domain_uuid, ftd_name):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords"
    logger.info(f"Fetching FTD UUID for device: {ftd_name}")
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch FTD UUID. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    devices = response.json().get('items', [])
    for device in devices:
        if device['name'] == ftd_name:
            logger.info(f"Found FTD UUID for {ftd_name}: {device['id']}")
            return device['id']
    logger.error(f"FMC device {ftd_name} not found.")
    raise Exception(f"FMC device {ftd_name} not found.")

def get_interface_uuid_map(fmc_ip, headers, domain_uuid, ftd_uuid):
    interface_types = ["physicalinterfaces", "subinterfaces", "etherchannelinterfaces"]
    interface_map = {}

    for int_type in interface_types:
        url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/{int_type}?expanded=true&limit=1000"
        logger.info(f"Fetching {int_type}...")
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code != 200:
            description = extract_error_description(response)
            logger.error(f"Failed to fetch {int_type}. Description: {description}")
            response.raise_for_status()

        items = response.json().get('items', [])
        logger.info(f"Found {len(items)} {int_type}(s).")

        for iface in items:
            ifname = iface.get('ifname')
            if ifname:
                interface_map[ifname] = iface['id']
                logger.info(f"Found interface: {ifname}, UUID: {iface['id']}")

    return interface_map

def get_vrf_uuid_by_name(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_name):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch VRF UUID. Description: {description}")
        response.raise_for_status()

    vrfs = response.json().get('items', [])
    for vrf in vrfs:
        if vrf.get('name') == vrf_name:
            return vrf.get('id')

    logger.error(f"VRF {vrf_name} not found.")
    return None

def create_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_name, vrf_description, interfaces, interface_map):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters"
    payload = {
        "type": "VirtualRouter",
        "name": vrf_name,
        "description": vrf_description,
        "interfaces": [
            {"id": interface_map[iface['name']], "type": iface['type'], "name": iface['name']}
            for iface in interfaces
        ]
    }

    logger.info(f"Creating VRF {vrf_name}...")
    response = requests.post(url, headers=headers, json=payload, verify=False)

    if response.status_code != 201:
        description = extract_error_description(response)
        logger.error(f"Failed to create VRF {vrf_name}. Description: {description}")
        response.raise_for_status()

    logger.info(f"Created VRF {vrf_name} with status code {response.status_code}.")

def delete_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_uuid):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters/{vrf_uuid}"
    logger.info(f"Deleting VRF with UUID {vrf_uuid}...")
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to delete VRF {vrf_uuid}. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    logger.info(f"Deleted VRF with UUID {vrf_uuid} with status code {response.status_code}.")

def get_bgp_and_af_uuids(fmc_ip, headers, domain_uuid, ftd_uuid):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp?expanded=true"
    logger.info(f"Fetching BGP and address family UUIDs for FTD: {ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch BGP info. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    items = response.json().get("items", [])
    if not items:
        logger.error("No BGP configuration found on device.")
        raise Exception("No BGP configuration found on device.")
    bgp = items[0]
    bgp_uuid = bgp.get("id")
    af_ipv4_uuid = bgp.get("addressFamilyIPv4", {}).get("id")
    af_ipv6_uuid = bgp.get("addressFamilyIPv6", {}).get("id")
    logger.info(f"Fetched BGP UUID: {bgp_uuid}, IPv4 AF UUID: {af_ipv4_uuid}, IPv6 AF UUID: {af_ipv6_uuid}")
    return bgp_uuid, af_ipv4_uuid, af_ipv6_uuid, bgp  # Return the full BGP config as well

def remove_key_recursive(obj, key_to_remove):
    if isinstance(obj, dict):
        return {k: remove_key_recursive(v, key_to_remove)
                for k, v in obj.items() if k != key_to_remove}
    elif isinstance(obj, list):
        return [remove_key_recursive(item, key_to_remove) for item in obj]
    else:
        return obj

def update_bgp_peers(
    fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid, af_ipv4_uuid, af_ipv6_uuid,
    ipv4_peers=None, ipv6_peers=None, current_bgp_config=None
):
    # Start with the current config as the base payload
    payload = dict(current_bgp_config) if current_bgp_config else {"id": bgp_uuid}

    # Helper to merge neighbors by address (avoiding duplicates)
    def merge_neighbors(existing, new, addr_key):
        existing_map = {n[addr_key]: n for n in existing}
        for n in new:
            existing_map[n[addr_key]] = {
                **n,
                "neighborGeneral": {"shutdown": False, "enableAddress": True},
            }
        return list(existing_map.values())

    # IPv4
    if ipv4_peers is not None:
        af_ipv4 = payload.get("addressFamilyIPv4", {})
        af_ipv4["id"] = af_ipv4_uuid
        existing_v4 = af_ipv4.get("neighbors", [])
        merged_v4 = merge_neighbors(existing_v4, ipv4_peers, "ipv4Address")
        af_ipv4["neighbors"] = merged_v4
        payload["addressFamilyIPv4"] = af_ipv4

    # IPv6
    if ipv6_peers is not None:
        af_ipv6 = payload.get("addressFamilyIPv6", {})
        af_ipv6["id"] = af_ipv6_uuid
        existing_v6 = af_ipv6.get("neighbors", [])
        merged_v6 = merge_neighbors(existing_v6, ipv6_peers, "ipv6Address")
        af_ipv6["neighbors"] = merged_v6
        payload["addressFamilyIPv6"] = af_ipv6

    # Remove fields not accepted by PUT (if any, e.g., 'links')
    payload.pop("links", None)

    # Remove all 'maximumPaths' before sending
    payload = remove_key_recursive(payload, "maximumPaths")

    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp/{bgp_uuid}"
    logger.info(f"Sending PUT to {url} with merged BGP config")
    response = requests.put(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to update BGP peers. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully updated BGP peers. Status: {response.status_code}. Response: {response.text}")

def delete_bgp_peers(
    fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid, af_ipv4_uuid, af_ipv6_uuid,
    current_bgp_config, ipv4_peers=None, ipv6_peers=None
):
    payload = dict(current_bgp_config) if current_bgp_config else {"id": bgp_uuid}

    # Build sets of addresses to remove
    ipv4_to_remove = set(peer["ipv4Address"] for peer in (ipv4_peers or []))
    ipv6_to_remove = set(peer["ipv6Address"] for peer in (ipv6_peers or []))

    # Remove matching IPv4 neighbors
    if "addressFamilyIPv4" in payload and "neighbors" in payload["addressFamilyIPv4"]:
        payload["addressFamilyIPv4"]["neighbors"] = [
            n for n in payload["addressFamilyIPv4"]["neighbors"]
            if n.get("ipv4Address") not in ipv4_to_remove
        ]
        payload["addressFamilyIPv4"]["id"] = af_ipv4_uuid

    # Remove matching IPv6 neighbors
    if "addressFamilyIPv6" in payload and "neighbors" in payload["addressFamilyIPv6"]:
        payload["addressFamilyIPv6"]["neighbors"] = [
            n for n in payload["addressFamilyIPv6"]["neighbors"]
            if n.get("ipv6Address") not in ipv6_to_remove
        ]
        payload["addressFamilyIPv6"]["id"] = af_ipv6_uuid

    payload.pop("links", None)
    payload = remove_key_recursive(payload, "maximumPaths")

    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp/{bgp_uuid}"
    logger.info(f"Sending PUT to {url} to remove specified BGP neighbors but keep other config")
    response = requests.put(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to remove specified BGP peers. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully removed specified BGP peers. Status: {response.status_code}. Response: {response.text}")

def get_loopback_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching loopback interfaces for FTD: {ftd_name}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/loopbackinterfaces?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        description = extract_error_description(response)
        logger.error(f"Failed to fetch loopback interfaces. Status: {response.status_code}. Description: {description}")
        response.raise_for_status()
    items = response.json().get("items", [])
    post_payloads = []
    for item in items:
        payload = dict(item)
        payload.pop("links", None)
        payload.pop("metadata", None)
        post_payloads.append(payload)
    return post_payloads



def create_loopback_interface(fmc_ip, headers, domain_uuid, ftd_uuid, loopback_payload):
    """
    Create a loopback interface on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/loopbackinterfaces"
    logger.info(f"Creating loopback interface {loopback_payload.get('ifname')}")
    response = requests.post(url, headers=headers, json=loopback_payload, verify=False)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to create loopback interface. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully created loopback interface {loopback_payload.get('ifname')}. Status: {response.status_code}")
    return response.json()

def get_all_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid):
    """
    Fetch all interfaces from the source FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/ftdallinterfaces?offset=0&expanded=true"
    logger.info(f"Fetching all interfaces for FTD: {ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def get_physical_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching PhysicalInterfaces for FTD: {ftd_name}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/physicalinterfaces?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def put_physical_interface(fmc_ip, headers, domain_uuid, ftd_uuid, obj_id, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/physicalinterfaces/{obj_id}"
    logger.info(f"Updating PhysicalInterface {payload.get('name')}")
    response = requests.put(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update PhysicalInterface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching EtherChannelInterfaces for FTD: {ftd_name}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/etherchannelinterfaces?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_etherchannel_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/etherchannelinterfaces"
    logger.info(f"Creating EtherChannelInterface {payload.get('name')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create EtherChannelInterface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_subinterfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching SubInterfaces for FTD: {ftd_name}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/subinterfaces?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_subinterface(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/subinterfaces"
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create SubInterface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_vti_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching VTIInterfaces for FTD: {ftd_name}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/virtualtunnelinterfaces?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_vti_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/virtualtunnelinterfaces"
    logger.info(f"Creating VTIInterface {payload.get('name')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VTIInterface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_bfd_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bfdpolicies?expanded=true")
    if vrf_id:
        logger.info(f"Fetching BFD policies for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching BFD policies for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_bfd_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bfdpolicies")
    if vrf_id:
        logger.info(f"Creating BFD policy for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating BFD policy for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create BFDPolicy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv2_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfv2routes?expanded=true")
    if vrf_id:
        logger.info(f"Fetching OSPFv2 policies for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching OSPFv2 policies for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ospfv2_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfv2routes")
    if vrf_id:
        logger.info(f"Creating OSPFv2 policy for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating OSPFv2 policy for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv2 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv2_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfinterface?expanded=true")
    if vrf_id:
        logger.info(f"Fetching OSPFv2 interfaces for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching OSPFv2 interfaces for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ospfv2_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ospfinterface")
    if vrf_id:
        logger.info(f"Creating OSPFv2 interface for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating OSPFv2 interface for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv2 interface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv3_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching OSPFv3 policies for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3routes?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ospfv3_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3routes"
    logger.info(f"Creating OSPFv3 policy with processId {payload.get('processId')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv3 policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ospfv3_interfaces(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    logger.info(f"Fetching OSPFv3 interfaces for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3interfaces?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ospfv3_interface(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/ospfv3interfaces"
    logger.info(f"Creating OSPFv3 interface for deviceInterface {payload.get('deviceInterface', {}).get('name')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create OSPFv3 interface: {response.text}")
        response.raise_for_status()
    return response.json()

def get_eigrp_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all EIGRP policies for the given FTD.
    """
    logger.info(f"Fetching EIGRP policies for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/eigrproutes?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_eigrp_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates an EIGRP policy on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/eigrproutes"
    logger.info(f"Creating EIGRP policy with asNumber {payload.get('asNumber')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create EIGRP policy: {response.text}")
        response.raise_for_status()
    return response.json()

def update_interface_ids(obj, dest_phys_map, dest_etherchannel_map, dest_subint_map, dest_vti_map, dest_loopback_map=None):
    """
    Recursively update interface 'id' fields in the given object using the destination interface maps.
    Only updates PhysicalInterface, EtherChannelInterface, SubInterface, VTIInterface, and LoopbackInterface.
    """
    valid_types = {"PhysicalInterface", "EtherChannelInterface", "SubInterface", "VTIInterface", "LoopbackInterface"}
    if isinstance(obj, dict):
        # Only update if this dict is a supported interface reference
        if "type" in obj and "name" in obj and obj["type"] in valid_types:
            intf_type = obj["type"]
            name = obj["name"]
            if intf_type == "PhysicalInterface":
                new_id = dest_phys_map.get(name)
            elif intf_type == "EtherChannelInterface":
                new_id = dest_etherchannel_map.get(name)
            elif intf_type == "SubInterface":
                subintf_key = name
                if "subIntfId" in obj:
                    subintf_key = f"{name}.{obj['subIntfId']}"
                new_id = dest_subint_map.get(subintf_key)
            elif intf_type == "VTIInterface":
                new_id = dest_vti_map.get(name)
            elif intf_type == "LoopbackInterface" and dest_loopback_map is not None:
                new_id = dest_loopback_map.get(name)
            else:
                new_id = None
            if new_id:
                obj["id"] = new_id
            else:
                logger.warning(f"Interface {name} of type {intf_type} not found on destination FTD.")
        # Recurse into all dict values
        for v in obj.values():
            update_interface_ids(v, dest_phys_map, dest_etherchannel_map, dest_subint_map, dest_vti_map, dest_loopback_map)
    elif isinstance(obj, list):
        for item in obj:
            update_interface_ids(item, dest_phys_map, dest_etherchannel_map, dest_subint_map, dest_vti_map, dest_loopback_map)

def replace_masked_eigrp_passwords(obj):
    """
    Recursively replace masked EIGRP authentication passwords ('******') with 'cisco'.
    """
    if isinstance(obj, dict):
        # Check for EIGRP authentication password
        if (
            "authentication" in obj
            and isinstance(obj["authentication"], dict)
            and obj["authentication"].get("password") == "******"
        ):
            obj["authentication"]["password"] = "cisco"
        # Recurse into all dict values
        for v in obj.values():
            replace_masked_eigrp_passwords(v)
    elif isinstance(obj, list):
        for item in obj:
            replace_masked_eigrp_passwords(item)

def get_pbr_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all Policy-Based Routing (PBR) policies for the given FTD.
    """
    logger.info(f"Fetching PBR policies for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/policybasedroutes?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_pbr_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates a Policy-Based Routing (PBR) policy on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/policybasedroutes"
    logger.info(f"Creating PBR policy")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create PBR policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ipv4_static_routes(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv4staticroutes?expanded=true")
    if vrf_id:
        logger.info(f"Fetching IPv4 static routes for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching IPv4 static routes for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ipv4_static_route(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv4staticroutes")
    if vrf_id:
        logger.info(f"Creating IPv4 static route for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating IPv4 static route for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create IPv4 static route: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ipv6_static_routes(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv6staticroutes?expanded=true")
    if vrf_id:
        logger.info(f"Fetching IPv6 static routes for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching IPv6 static routes for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ipv6_static_route(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ipv6staticroutes")
    if vrf_id:
        logger.info(f"Creating IPv6 static route for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating IPv6 static route for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create IPv6 static route: {response.text}")
        response.raise_for_status()
    return response.json()

def get_bgp_general_settings(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all BGP general settings for the given FTD.
    """
    logger.info(f"Fetching BGP general settings for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgpgeneralsettings?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_bgp_general_settings(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates BGP general settings on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgpgeneralsettings"
    logger.info(f"Creating BGP general settings with asNumber {payload.get('asNumber')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create BGP general settings: {response.text}")
        response.raise_for_status()
    return response.json()

def get_bgp_policies(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bgp?expanded=true")
    if vrf_id:
        logger.info(f"Fetching BGP policies for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching BGP policies for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_bgp_policy(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "bgp")
    # Remove deprecated maximumPaths before POST
    if "addressFamilyIPv4" in payload and isinstance(payload["addressFamilyIPv4"], dict):
        payload["addressFamilyIPv4"].pop("maximumPaths", None)
    if "addressFamilyIPv6" in payload and isinstance(payload["addressFamilyIPv6"], dict):
        payload["addressFamilyIPv6"].pop("maximumPaths", None)
    if vrf_id:
        logger.info(f"Creating BGP policy for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating BGP policy for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create BGP policy: {response.text}")
        response.raise_for_status()
    return response.json()

def get_ecmp_zones(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ecmpzones?expanded=true")
    if vrf_id:
        logger.info(f"Fetching ECMP zones for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Fetching ECMP zones for FTD: {ftd_name or ftd_uuid}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_ecmp_zone(fmc_ip, headers, domain_uuid, ftd_uuid, payload, vrf_id=None, vrf_name=None):
    url = _vrf_url(fmc_ip, domain_uuid, ftd_uuid, vrf_id, "ecmpzones")
    if vrf_id:
        logger.info(f"Creating ECMP zone for VRF {vrf_name or vrf_id}")
    else:
        logger.info(f"Creating ECMP zone for FTD")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create ECMP zone: {response.text}")
        response.raise_for_status()
    return response.json()

def get_vrfs(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all VRFs (Virtual Routers) for the given FTD.
    """
    logger.info(f"Fetching VRFs for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates a VRF (Virtual Router) on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters"
    logger.info(f"Creating VRF {payload.get('name')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VRF: {response.text}")
        response.raise_for_status()
    return response.json()

def build_dest_interface_maps(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd):
    """
    Build and return all destination interface maps as a dictionary.
    """
    dest_loopbacks = get_loopback_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_loopback_map = {iface['name']: iface['id'] for iface in dest_loopbacks}

    dest_phys = get_physical_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_phys_map = {iface['name']: iface['id'] for iface in dest_phys if iface.get('type') == 'PhysicalInterface'}

    dest_etherchannels = get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_etherchannel_map = {iface['name']: iface['id'] for iface in dest_etherchannels if iface.get('type') == 'EtherChannelInterface'}

    dest_subints = get_subinterfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_subint_map = {f"{iface['name']}.{iface['subIntfId']}": iface['id'] for iface in dest_subints}

    dest_vtis = get_vti_interfaces(fmc_ip, headers, domain_uuid, destination_ftd_uuid, destination_ftd)
    dest_vti_map = {iface['name']: iface['id'] for iface in dest_vtis if 'name' in iface and 'id' in iface}

    return {
        "dest_loopback_map": dest_loopback_map,
        "dest_phys_map": dest_phys_map,
        "dest_etherchannel_map": dest_etherchannel_map,
        "dest_subint_map": dest_subint_map,
        "dest_vti_map": dest_vti_map
    }

def get_inline_sets(fmc_ip, headers, domain_uuid, ftd_uuid, ftd_name=None):
    """
    Fetches all Inline Sets for the given FTD.
    """
    logger.info(f"Fetching Inline Sets for FTD: {ftd_name or ftd_uuid}")
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/inlinesets?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_inline_set(fmc_ip, headers, domain_uuid, ftd_uuid, payload):
    """
    Creates an Inline Set on the destination FTD.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/inlinesets"
    logger.info(f"Creating Inline Set {payload.get('name')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create Inline Set: {response.text}")
        response.raise_for_status()
    return response.json()

def get_vpn_topologies(fmc_ip, headers, domain_uuid):
    """
    Fetch all VPN topologies from FMC.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns?expanded=true"
    logger.info("Fetching VPN topologies from FMC")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def get_vpn_endpoints(fmc_ip, headers, domain_uuid, vpn_id, vpn_name=None):
    """
    Fetch all endpoints for a given VPN topology.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints?expanded=true&limit=1000"
    logger.info(f"Fetching endpoints for VPN topology {vpn_name or vpn_id}")
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("items", [])

def post_vpn_topology(fmc_ip, headers, domain_uuid, payload):
    """
    Create a VPN topology on the destination FMC.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns"
    logger.info(f"Creating VPN topology {payload.get('name')}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VPN topology: {response.text}")
        response.raise_for_status()
    return response.json()

def post_vpn_endpoint(fmc_ip, headers, domain_uuid, vpn_id, payload):
    """
    Create a VPN endpoint under a given VPN topology.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints"
    logger.info(f"Creating VPN endpoint {payload.get('name')} for VPN {vpn_id}")
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to create VPN endpoint: {response.text}")
        response.raise_for_status()
    return response.json()

def put_vpn_endpoint(fmc_ip, headers, domain_uuid, vpn_id, endpoint_id, payload, vpn_name=None):
    """
    Update a VPN endpoint under a given VPN topology.
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/policy/ftds2svpns/{vpn_id}/endpoints/{endpoint_id}"
    response = requests.put(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        logger.error(f"Failed to update VPN endpoint: {response.text}")
        response.raise_for_status()
    return response.json()

def replace_vpn_endpoint(fmc_ip, headers, domain_uuid, source_ftd, dest_ftd_name, vpn_configs):
    """
    For each VPN topology, update any endpoint whose name matches the source FTD,
    replacing its name, device info, and interface UUIDs with the destination FTD's.
    For all interface types, use the destination FTD's ifname for 'name' and UUID for 'id'.
    """
    # Get destination FTD UUID for device replacement
    dest_ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, dest_ftd_name)
    # Build full maps: {ifname: (id, ifname)}
    dest_phys_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_physical_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_ether_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_etherchannel_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_subint_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_subinterfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_vti_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_vti_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}
    dest_loop_full_map = {iface.get('ifname', 'NONE'): (iface['id'], iface.get('ifname', 'NONE')) for iface in get_loopback_interfaces(fmc_ip, headers, domain_uuid, dest_ftd_uuid, dest_ftd_name) if 'id' in iface}

    for vpn in vpn_configs:
        vpn_id = vpn.get("id")
        vpn_name = vpn.get("name")
        endpoints = vpn.get("endpoints", [])
        logger.info(f"Checking endpoints for VPN topology {vpn_name}")
        for ep in endpoints:
            ep_payload = dict(ep)
            endpoint_id = ep_payload.get("id")
            ep_payload.pop("links", None)
            ep_payload.pop("metadata", None)
            if ep.get("name") == source_ftd:
                logger.info(f"Updating endpoint {source_ftd} to {dest_ftd_name} for VPN topology {vpn_name}")
                ep_payload["name"] = dest_ftd_name
                if "device" in ep_payload and isinstance(ep_payload["device"], dict):
                    ep_payload["device"]["name"] = dest_ftd_name
                    ep_payload["device"]["id"] = dest_ftd_uuid
                # Update interface reference for all supported types
                if "interface" in ep_payload and isinstance(ep_payload["interface"], dict):
                    intf = ep_payload["interface"]
                    intf_type = intf.get("type")
                    intf_ifname = intf.get("name")
                    if intf_type == "PhysicalInterface" and intf_ifname in dest_phys_full_map:
                        dest_id, dest_ifname = dest_phys_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "EtherChannelInterface" and intf_ifname in dest_ether_full_map:
                        dest_id, dest_ifname = dest_ether_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "SubInterface" and intf_ifname in dest_subint_full_map:
                        dest_id, dest_ifname = dest_subint_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "VTI" and intf_ifname in dest_vti_full_map:
                        dest_id, dest_ifname = dest_vti_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    elif intf_type == "LoopbackInterface" and intf_ifname in dest_loop_full_map:
                        dest_id, dest_ifname = dest_loop_full_map[intf_ifname]
                        intf["id"] = dest_id
                        intf["name"] = dest_ifname
                    else:
                        logger.warning(f"{intf_type} interface {intf_ifname} not found on destination FTD for VPN endpoint {dest_ftd_name}")
                put_vpn_endpoint(
                    fmc_ip, headers, domain_uuid, vpn_id, endpoint_id, ep_payload, vpn_name=vpn_name
                )

def _vrf_url(base, domain_uuid, ftd_uuid, vrf_id, resource):
    if vrf_id:
        return f"{base}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/virtualrouters/{vrf_id}/{resource}"
    else:
        return f"{base}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/{resource}"