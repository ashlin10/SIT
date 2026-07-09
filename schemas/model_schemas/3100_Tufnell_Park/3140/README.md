# 3140 interface & routing schemas

**Platform family:** Secure Firewall 3100 series (Tufnell Park)

This folder contains the interface and routing schema for the `3140` model at each FMC version (`3140_interfaces_<ver>.json`) plus `3140_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: no
- EtherChannel: YES
  - ID range: 1-48
  - Max active members per group: 8
- Redundant interface: YES
- PoE (powerOverEthernet): no
- LLDP: YES (version-gated)
- Cluster MAC pool (macAddressPool, 10.5+): YES
- lacpRate (EtherChannel): no
- Hardware autoNegState: YES
- Hardware fecMode: YES
- Hardware flowControlSend (7.2+): YES

## Routing capability rules

- VRF: YES (from FMC 7.1)
- Max virtual routers (latest): 100 (incl. global VR)

## Supported hardware values

- **Built-in port speeds:** `AUTO`, `TEN`, `HUNDRED`, `THOUSAND`, `TEN_THOUSAND`, `TWENTY_FIVE_THOUSAND`, `DETECT_SFP`
- **Network module speeds (additional):** `FORTY_THOUSAND`
- _Note: Mix of 1G/10G/25G fixed ports; optional 40G netmod_
- **Duplex values:** `AUTO`, `HALF`, `FULL`
- **FEC modes:** `Auto`, `CL108RS`, `CL74FC`, `disable`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

