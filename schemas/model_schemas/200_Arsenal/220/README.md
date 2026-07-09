# 220 interface & routing schemas

**Platform family:** Secure Firewall 200 series (Arsenal)

This folder contains the interface and routing schema for the `220` model at each FMC version (`220_interfaces_<ver>.json`) plus `220_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: YES
- EtherChannel: YES
  - ID range: 1-8
  - Max active members per group: 8
- Redundant interface: no
- PoE (powerOverEthernet): no
- LLDP: no
- Cluster MAC pool (macAddressPool, 10.5+): no
- lacpRate (EtherChannel): no
- Hardware autoNegState: YES
- Hardware fecMode: no
- Hardware flowControlSend (7.2+): no

## Routing capability rules

- VRF: YES (from FMC 10.5)
- Max virtual routers (latest): 5 (incl. global VR)

## Supported hardware values

- **Built-in port speeds:** `AUTO`, `TEN`, `HUNDRED`, `THOUSAND`
- **Network module speeds (additional):** `TEN_THOUSAND`, `TWENTY_FIVE_THOUSAND`, `DETECT_SFP`
- _Note: Desktop with 1G RJ45 ports; optional SFP/SFP+ netmod_
- **Duplex values:** `AUTO`, `HALF`, `FULL`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

