# Push Config: Order of Operations

This document explains how **Push Config** works when applying configuration to FTD devices.

## High-Level Flow

```
Frontend (fmc_configuration.html) → POST /api/fmc-config/config/apply → _apply_config_sync()
```

---

## Order of Operations Overview

| Phase | What | Progress |
|-------|------|----------|
| 1 | Objects (Level 1 & 2) | 5% → 25% |
| 2 | Interfaces | 25% → 50% |
| 3 | Objects (Level 3 & 4) | 50% → 65% |
| 4 | Routing (Two-Pass) | 65% → 95% |

---

## Phase 1: Objects (Level 1 & 2) — 5% → 25%

Objects are applied **first** because interfaces and routing configs reference them.

### Level 1: Base Objects (No Dependencies)
Objects that don't depend on other objects:

- **Network Objects**: Host, Range, Network, FQDN
- **Port Objects**: ProtocolPortObject
- **BFD Templates** (with auth override support)
- **AS Path Lists**
- **Key Chains**
- **Community Lists** (Community, Extended)
- **Prefix Lists** (IPv4, IPv6)
- **Address Pools** (IPv4, IPv6, MAC)

### After Level 1: Refresh Object Maps
```python
resolver.prime_object_maps()  # Re-fetch all FMC objects to get new UUIDs
```

### Level 2: Objects That Depend on Level 1
- **Network Groups** (can contain Hosts, Networks, Ranges)
- **SLA Monitors** (can reference Network objects)

### After Level 2: Refresh Object Maps Again
```python
resolver.prime_object_maps()  # Ensure Level 2 objects are available for resolution
```

**Note**: Level 3 (Access Lists) and Level 4 (Route Maps) are deferred to Phase 3 because they may reference interface-derived network objects.

---

## Phase 2: Interfaces — 25% → 50%

Interfaces are applied in dependency order (parent interfaces before child interfaces).

### Interface Application Order:

1. **Loopback Interfaces** (27%) — Independent, created first
2. **Physical Interfaces** (30%) — Updated via PUT (already exist on device)
3. **EtherChannel Interfaces** (35%) — Depend on Physical interfaces as members
4. **Subinterfaces** (40%) — Depend on Physical/EtherChannel as parent
5. **VTI Interfaces** (43%) — May borrow IP from other interfaces
6. **Inline Sets** (46%) — Group physical interfaces for IPS mode
7. **Bridge Group Interfaces** (48%) — Group interfaces for L2 bridging

### Interface UUID Remapping

After each interface type is created, the resolver refreshes its interface maps:

```python
resolver.prime_device_interfaces(device_name)
```

This ensures subsequent interface types can reference newly created interfaces.

---

## Phase 3: Objects (Level 3 & 4) — 50% → 65%

Access Lists and Route Maps are applied **after interfaces** because they may reference:
- Network objects derived from interface IPs
- Interface-specific configurations

### Level 3: Access Lists
- **Extended Access Lists**
- **Standard Access Lists**

### After Level 3: Refresh Object Maps
```python
resolver.prime_object_maps()  # Ensure ACLs are available for Route Maps
```

### Level 4: Route Maps
- **Route Maps** (reference Access Lists, Prefix Lists, Community Lists)

### After Level 4: Refresh Object Maps
```python
resolver.prime_object_maps()  # Ensure Route Maps are available for routing policies
```

---

## Phase 4: Routing (Two-Pass) — 65% → 95%

Routing protocols use a **two-pass approach** to handle redistribution dependencies.

### Why Two Passes?

Redistribution creates circular dependencies:
- BGP can redistribute from OSPF
- OSPF can redistribute from BGP
- You can't reference a protocol that doesn't exist yet

### Pass 1: Base Protocols (Without Redistribution)

All routing protocols are created **without** their `redistributeProtocols` configuration:

```python
if has_redistribute_protocols(payload):
    clean_p, redist_data = strip_redistribute_protocols(payload)
    result = post_ospfv2_policy(..., clean_p)  # POST without redistribution
    protocols_to_update.append(("ospfv2", result.get("id"), result, redist_data, ...))
else:
    post_ospfv2_policy(..., payload)  # POST as-is (no redistribution)
```

**Pass 1 Order:**

1. **BGP General Settings** (67%) — No redistribution
2. **BFD Policies** (69%)
3. **OSPFv2 Policies** (71%)
4. **OSPFv3 Policies** (73%)
5. **EIGRP Policies** (75%)
6. **BGP Policies** (77%) — Applied after IGPs
7. **OSPFv2 Interfaces** (79%) — No redistribution
8. **OSPFv3 Interfaces** (81%) — No redistribution
9. **PBR Policies** — Bulk supported
10. **ECMP Zones** (87%)
11. **IPv4 Static Routes** (88%) — Bulk supported
12. **IPv6 Static Routes** (89%) — Bulk supported
13. **VRFs** (91%) — Including VRF-specific routing

### Pass 2: Redistribution Updates (93%)

After all protocols exist, update them with redistribution configuration:

```python
for protocol_type, obj_id, post_response, redist_data, vrf_id, vrf_name, ui_auth in protocols_to_update:
    # Use POST response as base (has FMC-assigned IDs)
    p = restore_redistribute_protocols(post_response, redist_data)
    
    # Resolve object references in redistribution config
    resolver.resolve_all_in_payload(p)
    
    # PUT to update with redistribution
    put_bgp_policy(..., obj_id, p)  # or put_ospfv2_policy, etc.
```

---

## UUID Remapping Deep Dive

### Interface UUID Remapping

When pushing config to a different FTD, interface UUIDs are different. The system remaps them by **name**.

```python
# From utils/fmc_api.py - update_interface_ids()

def update_interface_ids(obj, dest_phys_map, dest_etherchannel_map, dest_subint_map, ...):
    """Recursively update interface 'id' fields using destination interface maps."""
    
    if obj["type"] == "PhysicalInterface":
        new_id = dest_phys_map.get(name) or dest_phys_map.get(ifname)
    elif obj["type"] == "SubInterface":
        # Build parent.subId key for lookup
        subintf_key = f"{parent_name}.{sub_id_val}"
        new_id = dest_subint_map.get(ifname) or dest_subint_map.get(subintf_key)
    # ... etc for other types
    
    if new_id:
        obj["id"] = new_id
        logger.info(f"Interface remap: name={name} old_id={old_id} -> new_id={new_id}")
```

**Interface Map Structure:**
```python
phys_map = {"GigabitEthernet0/0": "uuid-123", "inside": "uuid-123"}
eth_map = {"Port-channel1": "uuid-456"}
sub_map = {"GigabitEthernet0/0.100": "uuid-789", "outside": "uuid-789"}
```

### Object UUID Remapping

FMC objects (Networks, Hosts, Route Maps, etc.) are remapped by **name + type**.

```python
# From utils/fmc_api.py - update_object_ids()

def update_object_ids(obj, dest_obj_maps: dict):
    """Recursively update object 'id' fields using destination object maps."""
    
    t = obj.get("type")  # e.g., "Host", "Network", "RouteMap"
    n = obj.get("name")  # e.g., "my-network"
    
    canon = _canon_type(t)  # Normalize type name
    mp = dest_obj_maps.get(canon) or {}
    new_id = mp.get(n) or mp.get(n.lower())
    
    if new_id:
        obj["id"] = new_id
        logger.info(f"Object remap: type={canon} name={n} old_id={old_id} -> new_id={new_id}")
```

**Object Map Structure:**
```python
dest_obj_maps = {
    "Host": {"server1": "uuid-aaa", "server2": "uuid-bbb"},
    "Network": {"internal-net": "uuid-ccc"},
    "RouteMap": {"BGP-IN": "uuid-ddd"},
    "IPv4PrefixList": {"ALLOWED-PREFIXES": "uuid-eee"},
    # ... etc
}
```

### DependencyResolver Class

The `DependencyResolver` orchestrates all resolution:

```python
# From utils/dependency_resolver.py

class DependencyResolver:
    def __init__(self, fmc_ip, headers, domain_uuid, device_id):
        self._phys_map = {}    # Physical interfaces
        self._eth_map = {}     # EtherChannel interfaces
        self._sub_map = {}     # Subinterfaces
        self._vti_map = {}     # VTI interfaces
        self._loop_map = {}    # Loopback interfaces
        self._bgi_map = {}     # Bridge Group interfaces
        self._sec_zones = {}   # Security Zones
        self._obj_maps = {}    # All FMC objects by type
    
    def prime_device_interfaces(self):
        """Fetch and cache device interface maps by name."""
        phys = get_physical_interfaces(...)
        self._phys_map = {it.get("name"): it["id"] for it in phys}
        # ... same for other interface types
    
    def prime_security_zones(self):
        """Fetch and cache security zones."""
        zones = get_security_zones(...)
        self._sec_zones = {z.get("name"): z["id"] for z in zones}
    
    def prime_object_maps(self):
        """Fetch and cache FMC objects by type."""
        self._obj_maps = build_dest_object_maps(...)
    
    def resolve_all_in_payload(self, payload):
        """Resolve interfaces, security zones, and objects in-place."""
        self.resolve_interfaces_in_payload(payload)
        self.resolve_objects_in_payload(payload)
```

---

## Redistribution Functions

### Check for Redistribution
```python
def has_redistribute_protocols(payload):
    """Check if a routing protocol payload has redistributeProtocols configured."""
    # Check direct (OSPF, EIGRP)
    if payload.get("redistributeProtocols"):
        return True
    # Check within address families (BGP)
    for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
        if payload.get(af_key, {}).get("redistributeProtocols"):
            return True
    return False
```

### Strip Redistribution for Pass 1
```python
def strip_redistribute_protocols(payload):
    """Remove redistributeProtocols, return (clean_payload, redist_data)"""
    clean = copy.deepcopy(payload)
    redist_data = {}
    
    # Strip direct (OSPF, EIGRP)
    if "redistributeProtocols" in clean:
        redist_data["redistributeProtocols"] = clean.pop("redistributeProtocols")
    
    # Strip from address families (BGP)
    for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
        if clean.get(af_key, {}).get("redistributeProtocols"):
            redist_data[af_key] = {"redistributeProtocols": clean[af_key].pop("redistributeProtocols")}
    
    return clean, redist_data
```

### Restore Redistribution for Pass 2
```python
def restore_redistribute_protocols(payload, redist_data):
    """Restore redistributeProtocols to a payload."""
    updated = copy.deepcopy(payload)
    
    # Restore direct
    if "redistributeProtocols" in redist_data:
        updated["redistributeProtocols"] = redist_data["redistributeProtocols"]
    
    # Restore to address families
    for af_key in ["addressFamilyIPv4", "addressFamilyIPv6"]:
        if redist_data.get(af_key, {}).get("redistributeProtocols"):
            updated.setdefault(af_key, {})["redistributeProtocols"] = redist_data[af_key]["redistributeProtocols"]
    
    return updated
```

---

## Existing Object Handling

Before creating objects, the system checks if they already exist:

```python
# Fetch all existing objects to validate before POSTing
existing_objects = {}
existing_objects["Host"] = {o.get("name") for o in get_hosts(...)}
existing_objects["Network"] = {o.get("name") for o in get_networks(...)}
# ... etc

# During _post_list():
for item in items:
    name = item.get("name")
    if name in existing_objects[object_type]:
        skipped.append(f"{applied_key} {name}: Object already exists")
        continue
    # Otherwise, POST the object
```

---

## Summary Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PUSH CONFIG WORKFLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 1: Objects (Level 1 & 2)                           [5% - 25%] │   │
│  │                                                                      │   │
│  │  Level 1: Host, Range, Network, FQDN, Port, BFD, ASPath, KeyChain,  │   │
│  │           Community, Prefix, AddressPools                            │   │
│  │                        ↓                                             │   │
│  │              prime_object_maps()                                     │   │
│  │                        ↓                                             │   │
│  │  Level 2: NetworkGroup, SLAMonitor                                  │   │
│  │                        ↓                                             │   │
│  │              prime_object_maps()                                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                  ↓                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 2: Interfaces                                     [25% - 50%] │   │
│  │                                                                      │   │
│  │  1. Loopback → prime_device_interfaces()                            │   │
│  │  2. Physical → prime_device_interfaces()                            │   │
│  │  3. EtherChannel → prime_device_interfaces()                        │   │
│  │  4. Subinterfaces → prime_device_interfaces()                       │   │
│  │  5. VTI → prime_device_interfaces()                                 │   │
│  │  6. Inline Sets → prime_device_interfaces()                         │   │
│  │  7. Bridge Groups → prime_device_interfaces()                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                  ↓                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 3: Objects (Level 3 & 4)                          [50% - 65%] │   │
│  │                                                                      │   │
│  │  Level 3: ExtendedAccessList, StandardAccessList                    │   │
│  │                        ↓                                             │   │
│  │              prime_object_maps()                                     │   │
│  │                        ↓                                             │   │
│  │  Level 4: RouteMap                                                  │   │
│  │                        ↓                                             │   │
│  │              prime_object_maps()                                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                  ↓                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 4: Routing (Two-Pass)                             [65% - 95%] │   │
│  │                                                                      │   │
│  │  PASS 1: Create protocols WITHOUT redistribution                    │   │
│  │    • BGP General Settings                                           │   │
│  │    • BFD, OSPFv2, OSPFv3, EIGRP, BGP Policies                       │   │
│  │    • OSPF Interfaces, PBR, ECMP, Static Routes, VRFs                │   │
│  │                        ↓                                             │   │
│  │  PASS 2: UPDATE protocols WITH redistribution (PUT)                 │   │
│  │    • Restore redistributeProtocols to stored responses              │   │
│  │    • Resolve object references in redistribution config             │   │
│  │    • PUT to update each protocol                                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Files

- **Frontend**: `web_app/templates/fmc_configuration.html` (lines 2261-2405)
- **Backend API**: `web_app/app.py` - `/api/fmc-config/config/apply` endpoint
- **Core Logic**: `web_app/app.py` - `_apply_config_sync()` function (lines 2827-4176)
- **Interface UUID Remap**: `utils/fmc_api.py` - `update_interface_ids()` (lines 1445-1592)
- **Object UUID Remap**: `utils/fmc_api.py` - `update_object_ids()` (lines 2967-3026)
- **Dependency Resolver**: `utils/dependency_resolver.py` - `DependencyResolver` class
- **Redistribution Helpers**: `utils/fmc_api.py` - `has_redistribute_protocols()`, `strip_redistribute_protocols()`, `restore_redistribute_protocols()` (lines 1245-1302)
