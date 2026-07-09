# FTDv interface & routing schemas

**Platform family:** FTD Virtual (FTDv/vFTD)

This folder contains the interface and routing schema for the `FTDv` model at each FMC version (`FTDv_interfaces_<ver>.json`) plus `FTDv_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: no
- EtherChannel: no
- Redundant interface: no
- PoE (powerOverEthernet): no
- LLDP: no
- Cluster MAC pool (macAddressPool, 10.5+): no
- lacpRate (EtherChannel): no
- Hardware autoNegState: no
- Hardware fecMode: no
- Hardware flowControlSend (7.2+): no

## Routing capability rules

- VRF: YES (from FMC 6.6)
- Max virtual routers (latest): 30 (incl. global VR)

## Supported hardware values

- _Virtual platform — no hardware speed/duplex/FEC configuration._

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

