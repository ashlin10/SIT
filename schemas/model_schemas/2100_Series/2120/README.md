# 2120 interface & routing schemas

**Platform family:** Firepower 2100 series

This folder contains the interface and routing schema for the `2120` model at each FMC version (`2120_interfaces_<ver>.json`) plus `2120_INCREMENTAL_UPDATES.md`.

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
- Hardware autoNegState: no
- Hardware fecMode: no
- Hardware flowControlSend (7.2+): no

## Routing capability rules

- VRF: YES (from FMC 7.0)
- Max virtual routers (latest): 20 (incl. global VR)

## Supported hardware values

- **Built-in port speeds:** `AUTO`, `TEN`, `HUNDRED`, `THOUSAND`, `TEN_THOUSAND`, `DETECT_SFP`
- _Note: Mix of 1G RJ45 + 10G SFP+ fixed ports_
- **Duplex values:** `AUTO`, `HALF`, `FULL`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

