# 4125 — Interface & Routing Schema Incremental Updates

Platform family: **Firepower 4100 series (FXOS chassis, Queen's Park)**

Per-version changes to the interface-related schema and routing (VRF) for this model (types enabled/disabled, fields added/removed, VRF support changes).


## FMC 6.3 (baseline)

### Interfaces

- **Supported interface types:** `BridgeGroupInterface (BVI)`, `EtherChannelInterface`, `InlineSet (Inline Pair)`, `PhysicalInterface`, `SubInterface`
- **EtherChannel ID range:** 1-48
- **Max active members per channel group:** 16
- **Note:** EtherChannel configured in FXOS, not FMC

### Routing

- **VRF:** VRF not supported on 4125 until FMC 6.6

## FMC 6.6 — changes vs 6.5

### Interfaces

  - `BridgeGroupInterface (BVI)` -fields: `ipAddress`

### Routing

  - **+ VRF** now supported (max 100 virtual routers)

## FMC 6.7 — changes vs 6.6

### Interfaces

  - `PhysicalInterface` +fields: `fmcAccessConfig`
  - **+ type** `VirtualTunnelInterface (VTI)` now supported

## FMC 7.0 — changes vs 6.7

### Interfaces

  - `VirtualTunnelInterface (VTI)` +fields: `ipsecMode`, `ipv6`, `tunnelSourceIPv6InterfaceAddress`

## FMC 7.1 — changes vs 7.0

### Interfaces

  - `EtherChannelInterface` +fields: `enableSGTPropagate`, `priority`
  - `PhysicalInterface` +fields: `channelGroupId`, `enableSGTPropagate`, `nveOnly`, `priority`
  - `SubInterface` +fields: `enableSGTPropagate`, `priority`
  - **+ type** `VNIInterface (VXLAN/VTEP)` now supported
  - `VirtualTunnelInterface (VTI)` +fields: `priority`

## FMC 7.2 — changes vs 7.1

### Interfaces

  - `BridgeGroupInterface (BVI)` +fields: `pathMonitoring`
  - `EtherChannelInterface` +fields: `pathMonitoring`
  - **+ type** `LoopbackInterface` now supported
  - `PhysicalInterface` +fields: `pathMonitoring`
  - `SubInterface` +fields: `pathMonitoring`
  - `VirtualTunnelInterface (VTI)` +fields: `borrowIPfrom`, `pathMonitoring`, `tunnelSrcIPv6IntfAddr`, `tunnelType`
  - `VirtualTunnelInterface (VTI)` -fields: `tunnelSourceIPv6InterfaceAddress`

## FMC 7.4 — changes vs 7.3

### Interfaces

  - `BridgeGroupInterface (BVI)` +fields: `applicationMonitoring`
  - `EtherChannelInterface` +fields: `applicationMonitoring`
  - `PhysicalInterface` +fields: `applicationMonitoring`
  - `SubInterface` +fields: `applicationMonitoring`

## FMC 7.6 — changes vs 7.4.1

### Interfaces

  - `PhysicalInterface` +fields: `macAddressPool`

## FMC 10.0 — changes vs 7.7

### Interfaces

  - `VirtualTunnelInterface (VTI)` +fields: `enableSGTPropagate`

## FMC 10.5 — changes vs 10.1

### Interfaces

  - **+ type** `CellularInterface` now supported
