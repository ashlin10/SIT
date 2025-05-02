import argparse
import yaml
import logging
from utils.fmc_api import (
    authenticate,
    get_ftd_uuid,
    get_interface_uuid_map,
    create_vrf,
    delete_vrf,
    get_vrf_uuid_by_name,
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_yaml(filepath):
    with open(filepath, "r") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Scale VRFs on FMC-managed FTDs")
    parser.add_argument("--config", help="Path to scale_vrf_config.yaml", required=False)
    parser.add_argument("--fmc_data", help="Path to fmc_data.yaml", required=True)
    parser.add_argument("--delete", action="store_true", help="Delete VRFs instead of creating")
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

    # Get interface UUID map (only for creation, not needed for delete)
    interface_map = get_interface_uuid_map(fmc_ip, headers, domain_uuid, ftd_uuid) if not args.delete else {}

    # Determine VRFs to process
    vrfs = []
    if args.config:
        vrfs = load_yaml(args.config)['vrfs']
    else:
        logger.error("No config file provided. Exiting.")
        return

    # Create or delete VRFs
    for vrf in vrfs:
        vrf_name = vrf['name']
        interfaces = vrf.get('interfaces', [])

        if args.delete:
            # Fetch the VRF UUID using the name
            logger.info(f"Fetching UUID for VRF {vrf_name}...")
            vrf_uuid = get_vrf_uuid_by_name(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_name)

            if vrf_uuid:
                logger.info(f"Deleting VRF {vrf_name} with UUID {vrf_uuid}...")
                delete_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_uuid)
            else:
                logger.error(f"VRF {vrf_name} not found, skipping delete.")
        else:
            # Create VRF
            logger.info(f"Creating VRF {vrf_name}...")
            create_vrf(fmc_ip, headers, domain_uuid, ftd_uuid, vrf_name, vrf.get('description', vrf_name), interfaces,
                       interface_map)


if __name__ == "__main__":
    main()
