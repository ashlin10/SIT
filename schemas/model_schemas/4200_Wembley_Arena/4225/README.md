# 4225 interface & routing schemas

**Platform family:** Secure Firewall 4200 series (Wembley Arena)

This folder contains the interface and routing schema for the `4225` model at each FMC version (`4225_interfaces_<ver>.json`) plus `4225_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: no
- EtherChannel: YES
  - ID range: 1-48
  - Max active members per group: 8
- Redundant interface: YES
- PoE (powerOverEthernet): no
- LLDP: YES (version-gated)
- Cluster MAC pool (macAddressPool, 10.5+): YES
- lacpRate (EtherChannel): YES
- Hardware autoNegState: YES
- Hardware fecMode: YES
- Hardware flowControlSend (7.2+): YES

## Routing capability rules

- VRF: YES (from FMC 7.4)
- Max virtual routers (latest): 500 (incl. global VR)
- VRF scale changes across versions: 100, 500

## Supported hardware values

- **Built-in port speeds:** `AUTO`, `THOUSAND`, `TEN_THOUSAND`, `TWENTY_FIVE_THOUSAND`, `FORTY_THOUSAND`, `DETECT_SFP`
- **Network module speeds (additional):** `HUNDRED_THOUSAND`
- _Note: High-end appliance: 10G/25G/40G fixed + optional 100G netmod_
- **Duplex values:** `AUTO`, `HALF`, `FULL`
- **FEC modes:** `Auto`, `CL108RS`, `CL74FC`, `disable`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

