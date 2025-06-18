import argparse
import yaml
import logging
from utils.fmc_api import (
    authenticate,
    get_ftd_uuid,
    get_bgp_and_af_uuids,
    update_bgp_peers,
    delete_bgp_peers,
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_yaml(filepath):
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Scale BGP peers on FMC-managed FTDs")
    parser.add_argument("--config", help="Path to scale_bgp_config.yaml", required=True)
    parser.add_argument("--fmc_data", help="Path to fmc_data.yaml", required=True)
    parser.add_argument("--delete", action="store_true", help="Delete BGP peers instead of creating")
    args = parser.parse_args()

    # Load FMC credentials and target info
    fmc_data = load_yaml(args.fmc_data)['scale_vrf']
    fmc_ip = fmc_data['fmc_ip']
    username = fmc_data['username']
    password = fmc_data['password']
    ftd_name = fmc_data['ftd_name']

    # Authenticate to FMC
    domain_uuid, headers = authenticate(fmc_ip, username, password)

    # Get FTD UUID
    ftd_uuid = get_ftd_uuid(fmc_ip, headers, domain_uuid, ftd_name)

    # Get BGP and address family UUIDs
    bgp_uuid, af_ipv4_uuid, af_ipv6_uuid = get_bgp_and_af_uuids(fmc_ip, headers, domain_uuid, ftd_uuid)

    # Load BGP peers from config
    config = load_yaml(args.config)
    ipv4_peers = config.get('ipv4_peers', [])
    ipv6_peers = config.get('ipv6_peers', [])

    if args.delete:
        logger.info(f"Deleting all specified BGP peers...")
        delete_bgp_peers(
            fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid
        )
    else:
        logger.info(f"Creating/Updating BGP peers...")
        update_bgp_peers(
            fmc_ip, headers, domain_uuid, ftd_uuid, bgp_uuid, af_ipv4_uuid, af_ipv6_uuid,
            ipv4_peers=ipv4_peers, ipv6_peers=ipv6_peers
        )


if __name__ == "__main__":
    main()
# This script is designed to scale BGP peers (IPv4 and IPv6) on FMC-managed FTDs, allowing for both creation and deletion of peers based on a configuration file.
# Ensure the utils.fmc_api module contains the necessary functions for FMC API interactions.
