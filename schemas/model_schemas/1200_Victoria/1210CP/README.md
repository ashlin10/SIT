# 1210CP interface & routing schemas

**Platform family:** Secure Firewall 1200 series (Victoria)

This folder contains the interface and routing schema for the `1210CP` model at each FMC version (`1210CP_interfaces_<ver>.json`) plus `1210CP_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: YES
- EtherChannel: YES
  - ID range: 1-8
  - Max active members per group: 8
- Redundant interface: no
- PoE (powerOverEthernet): YES
- LLDP: YES (version-gated)
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
- _Note: Desktop (1210/1220): 1G RJ45 + optional SFP; Rackmount (1230/1240/1250): 1G + 10G/25G netmod slots_
- **Duplex values:** `AUTO`, `HALF`, `FULL`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

