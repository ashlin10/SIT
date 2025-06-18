import requests
import logging
from requests.auth import HTTPBasicAuth
import time

import warnings
from urllib3.exceptions import InsecureRequestWarning, NotOpenSSLWarning

# Suppress warnings
warnings.simplefilter("ignore", InsecureRequestWarning)
warnings.simplefilter("ignore", NotOpenSSLWarning)

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
    return bgp_uuid, af_ipv4_uuid, af_ipv6_uuid

def update_bgp_peers(fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid, af_ipv4_uuid, af_ipv6_uuid, ipv4_peers=None, ipv6_peers=None):
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp/{bgp_uuid}"
    payload = {"id": bgp_uuid}
    if ipv4_peers is not None:
        payload["addressFamilyIPv4"] = {
            "id": af_ipv4_uuid,
            "neighbors": [
                {
                    "ipv4Address": peer["ipv4Address"],
                    "neighborGeneral": {
                        "shutdown": False,
                        "enableAddress": True
                    },
                    "remoteAs": peer["remoteAS"]
                }
                for peer in ipv4_peers
            ]
        }
    if ipv6_peers is not None:
        payload["addressFamilyIPv6"] = {
            "id": af_ipv6_uuid,
            "neighbors": [
                {
                    "ipv6Address": peer["ipv6Address"],
                    "neighborGeneral": {
                        "shutdown": False,
                        "enableAddress": True
                    },
                    "remoteAs": peer["remoteAS"]
                }
                for peer in ipv6_peers
            ]
        }
    logger.info(f"Sending PUT to {url} with {len(ipv4_peers or [])} IPv4 and {len(ipv6_peers or [])} IPv6 peers")
    response = requests.put(url, headers=headers, json=payload, verify=False)
    if response.status_code not in [200, 201]:
        description = extract_error_description(response)
        logger.error(f"Failed to update BGP peers. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully updated BGP peers. Status: {response.status_code}. Response: {response.text}")

def delete_bgp_peers(fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid):
    """
    Deletes the BGP configuration object (removes all BGP peers and config).
    """
    url = f"{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords/{ftd_uuid}/routing/bgp/{bgp_uuid}"
    logger.info(f"Deleting BGP configuration with UUID {bgp_uuid} using DELETE {url}")
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code not in [200, 204]:
        description = extract_error_description(response)
        logger.error(f"Failed to delete BGP peers. Status: {response.status_code}. Description: {description}")
        logger.error(f"Response: {response.text}")
        response.raise_for_status()
    logger.info(f"Successfully deleted BGP peers. Status: {response.status_code}.")