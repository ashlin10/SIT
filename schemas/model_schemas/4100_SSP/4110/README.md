# 4110 interface & routing schemas

**Platform family:** Firepower 4100 series (FXOS chassis, Queen's Park)

This folder contains the interface and routing schema for the `4110` model at each FMC version (`4110_interfaces_<ver>.json`) plus `4110_INCREMENTAL_UPDATES.md`.

## Interface capability rules

- Switchport / VLAN interfaces: no
- EtherChannel: YES (FXOS-managed only)
  - ID range: 1-48
  - Max active members per group: 16
- Redundant interface: no
- PoE (powerOverEthernet): no
- LLDP: no
- Cluster MAC pool (macAddressPool, 10.5+): YES
- lacpRate (EtherChannel): no
- Hardware autoNegState: no
- Hardware fecMode: YES
- Hardware flowControlSend (7.2+): no

## Routing capability rules

- VRF: YES (from FMC 6.6)
- Max virtual routers (latest): 40 (incl. global VR)

## Supported hardware values

- **Built-in port speeds:** `TEN_MBPS`, `HUNDRED_MBPS`, `ONE_GBPS`, `TEN_GBPS`, `TWENTY_FIVE_GBPS`, `DETECT_SFP`
- _Note: FXOS chassis speeds (blade-dependent network modules)_
- **Duplex values:** `HALF`, `FULL`
- **FEC modes:** `Auto`, `CL108RS`, `CL74FC`, `disable`

> Capability rules are derived from the FTL codebase (`SwitchPortModels`, `LLDPEnabledModels`, interface model comments) and Cisco official documentation (VRF limits, EtherChannel guidelines). SKU-variant distinctions (e.g. PoE vs non-PoE) are inferred from hardware datasheets and may be adjusted as needed.

