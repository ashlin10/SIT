# 1010E interface & routing schemas

**Platform family:** Secure Firewall 1010 (Westminster)

This folder contains the interface and routing schema for the `1010E` model at each FMC version (`1010E_interfaces_<ver>.json`) plus `1010E_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: YES
- EtherChannel: YES
  - ID range: 1-8
  - Max active members per group: 8
- Redundant interface: no
- PoE (powerOverEthernet): YES
- LLDP: no
- Cluster MAC pool (macAddressPool, 10.5+): no
- lacpRate (EtherChannel): no
- Hardware autoNegState: YES
- Hardware fecMode: no
- Hardware flowControlSend (7.2+): no

## Routing capability rules

- VRF: YES (from FMC 7.2)
- Max virtual routers (latest): 5 (incl. global VR)

## Supported hardware values

- **Built-in port speeds:** `AUTO`, `TEN`, `HUNDRED`, `THOUSAND`
- _Note: 8x 1G RJ45 GigabitEthernet ports; no expansion slots_
- **Duplex values:** `AUTO`, `HALF`, `FULL`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

