# SIT Automation Scripts

This repository contains scripts to automate scaling of VRFs and BGP IPv4/IPv6 neighbors on FMC-managed FTDs.

---

## Installation

1. **Clone the repository** (if you haven't already):

    ```bash
    git clone <your-repo-url>
    cd SIT
    ```

2. **Install required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```

---

## Scaling VRFs

The script `scale_vrf.py` allows you to create or delete multiple VRFs on a target FTD.

### **Creating VRFs**

1. Prepare your VRF configuration YAML file (e.g., `inputs/scale_vrf_config.yaml`).
2. Run the script:

    ```bash
    python3 scale_vrf.py --config inputs/scale_vrf_config.yaml --fmc_data inputs/fmc_data.yaml
    ```

### **Deleting VRFs**

1. Use the same config file as above.
2. Add the `--delete` flag:

    ```bash
    python3 scale_vrf.py --config inputs/scale_vrf_config.yaml --fmc_data inputs/fmc_data.yaml --delete
    ```

---

## Scaling BGP IPv4 and IPv6 Neighbors

The script `scale_bgp.py` allows you to create or delete multiple BGP IPv4 and IPv6 neighbors on a target FTD.

### **Creating/Updating BGP Neighbors**

1. Prepare your BGP configuration YAML file (e.g., `inputs/scale_bgp_config.yaml`) with `ipv4_peers` and `ipv6_peers` sections.
2. Run the script:

    ```bash
    python3 scale_bgp.py --config inputs/scale_bgp_config.yaml --fmc_data inputs/fmc_data.yaml
    ```

### **Deleting All BGP Neighbors**

1. Use the same config file as above.
2. Add the `--delete` flag:

    ```bash
    python3 scale_bgp.py --config inputs/scale_bgp_config.yaml --fmc_data inputs/fmc_data.yaml --delete
    ```

---

**Note:**  
- Make sure your `fmc_data.yaml` contains the correct FMC connection and device information.
- For BGP, the script will replace the entire neighbor list with the contents of your YAML file.