# 1150 interface & routing schemas

**Platform family:** Firepower 1100 series (Kingpin)

This folder contains the interface and routing schema for the `1150` model at each FMC version (`1150_interfaces_<ver>.json`) plus `1150_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: no
- EtherChannel: YES
  - ID range: 1-8
  - Max active members per group: 8
- Redundant interface: YES
- PoE (powerOverEthernet): no
- LLDP: YES (version-gated)
- Cluster MAC pool (macAddressPool, 10.5+): no
- lacpRate (EtherChannel): no
- Hardware autoNegState: YES
- Hardware fecMode: YES
- Hardware flowControlSend (7.2+): no

## Routing capability rules

- VRF: YES (from FMC 6.6)
- Max virtual routers (latest): 10 (incl. global VR)

## Supported hardware values

- **Built-in port speeds:** `AUTO`, `TEN`, `HUNDRED`, `THOUSAND`
- **Network module speeds (additional):** `TEN_THOUSAND`, `DETECT_SFP`
- _Note: Mix of 1G RJ45 + SFP/SFP+ slots; 1150 has more 10G ports_
- **Duplex values:** `AUTO`, `HALF`, `FULL`
- **FEC modes:** `Auto`, `CL108RS`, `CL74FC`, `disable`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

