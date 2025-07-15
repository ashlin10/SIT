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

## Clone FTD Configuration

The script `clone_device_config.py` allows you to clone the entire configuration from a source FTD to a destination FTD, both registered to the same FMC. This includes interfaces, routing protocols, static routes, VRFs, and more.

### **How It Works**

- The script reads the `source_ftd` and `destination_ftd` values from your `inputs/fmc_data.yaml` file.
- It fetches all supported configuration objects from the source FTD and recreates them on the destination FTD, updating all interface references as needed.
- The process includes:
  - Loopback, physical, EtherChannel, subinterfaces, and VTI interfaces
  - BFD, OSPFv2, OSPFv3, EIGRP, BGP, PBR, ECMP, and VRF configurations
  - IPv4 and IPv6 static routes

### **Usage**

1. Prepare your FMC data YAML file (e.g., `inputs/fmc_data.yaml`) with the correct `source_ftd` and `destination_ftd` names.
2. Run the script:

    ```bash
    python3 clone_device_config.py --fmc_data inputs/fmc_data.yaml
    ```
    
---

**General Notes:**  
- Ensure your `fmc_data.yaml` contains the correct FMC connection and device information.
- For BGP, the script will replace the entire neighbor list with the contents of your YAML file.