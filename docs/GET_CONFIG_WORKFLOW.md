# Get Config: Order of Operations

Based on the codebase, here's how **Get Config** works when fetching FTD device configurations:

## High-Level Flow

```
Frontend (fmc_configuration.html) → POST /api/fmc-config/config/get → _export_config_sync()
```

---

## Order of Operations

### **Phase 1: Interfaces** (5% → 33%)
Fetches all interface types from the selected FTD device:

1. **Loopback Interfaces** (8%)
2. **Physical Interfaces** (12%)
3. **EtherChannel Interfaces** (16%)
4. **Subinterfaces** (20%)
5. **VTI Interfaces** (24%)
6. **Inline Sets** (28%)
7. **Bridge Group Interfaces** (31%)

After fetching, it:
- Strips non-portable keys (`links`, `metadata`)
- Fills missing `securityZone.name` using `securityZone.id` by querying all SecurityZones
- **Scans for dependent objects** by walking the JSON tree and collecting any embedded objects with recognizable `type` fields

---

### **Phase 2: Routing** (35% → 68%)
Fetches routing configuration:

1. **BGP General Settings** (38%)
2. **BGP Policies** (41%)
3. **BFD Policies** (44%)
4. **OSPFv2 Policies** (47%)
5. **OSPFv2 Interfaces** (50%)
6. **OSPFv3 Policies** (53%)
7. **OSPFv3 Interfaces** (55%)
8. **EIGRP Policies** (57%)
9. **PBR Policies** (59%)
10. **IPv4 Static Routes** (62%)
11. **IPv6 Static Routes** (65%)
12. **ECMP Zones** (67%)
13. **VRFs** (69%)

For each VRF (excluding Global), it also fetches VRF-specific routing configs.

After fetching, it **scans for additional dependent objects** and adds them to the aggregated dependency table.

---

### **Phase 3: Objects - Selective Fetch** (70% → 95%)

This is where **dependent objects are updated**. The system only fetches objects that are **actually referenced** by the interfaces/routing configs.

#### Dependency Discovery Process:

```python
def _scan_deps_rows(obj):
    # Walks the entire config tree
    # Collects any dict with "type" matching known object types
    # Records: [name, type, id]
```

#### Fetch Order (Reverse Dependency Order - Level 4 → Level 1):

**Level 4: Route Maps**
- Fetches `RouteMap` objects by ID/name from dependency table
- **Rescans fetched objects** to discover nested dependencies (e.g., prefix lists inside route maps)

**Level 3: Access Lists**
- `ExtendedAccessList`
- `StandardAccessList`
- **Rescans** to find more nested dependencies

**Level 2: Container Objects**
- `NetworkGroup` (may contain Hosts/Networks)
- `SLAMonitor`
- **Rescans** for nested dependencies

**Level 1: Base Objects**
- `SecurityZone`
- `Host`, `Range`, `Network`, `FQDN`
- `ProtocolPortObject`
- `BFDTemplate`, `ASPathList`, `KeyChain`
- `CommunityList`, `ExtendedCommunityList`
- `IPv4PrefixList`, `IPv6PrefixList`
- `IPv4AddressPool`, `IPv6AddressPool`, `MacAddressPool`

---

## How Dependent Objects Are Updated

```python
# From _export_config_sync():

# 1. Build dependency tracking structures
dep_ids_by_type: Dict[str, Set[str]] = {}    # type → {id1, id2, ...}
dep_names_by_type: Dict[str, Set[str]] = {}  # type → {name1, name2, ...}

# 2. After each phase, scan and ingest dependencies
_ingest_rows(dedup_rows)  # Adds name/type/id to tracking tables

# 3. Fetch objects ONLY if they appear in dependency table
def _fetch_for_type(t: str):
    # First: Fetch by IDs from dep_ids_by_type[t]
    items_by_id = get_objects_by_type_and_ids(fmc_ip, headers, domain_uuid, t, idset)
    
    # Second: For any missing names, fetch all objects and filter
    miss_names = names - have_names
    all_items = list_func(fmc_ip, headers, domain_uuid)
    selected = [it for it in all_items if it.get("name") in miss_names]
```

The key insight is:
1. **Scan** → Discover what objects are referenced in configs
2. **Fetch by ID first** → Use `get_objects_by_type_and_ids()` for efficiency
3. **Fallback to name lookup** → For objects with name-only references
4. **Rescan after each level** → Discover nested dependencies (e.g., a RouteMap references an IPv4PrefixList)

---

## Final YAML Structure

```yaml
loopback_interfaces: [...]
physical_interfaces: [...]
etherchannel_interfaces: [...]
subinterfaces: [...]
vti_interfaces: [...]
inline_sets: [...]
bridge_group_interfaces: [...]
objects:
  interface:
    security_zones: [...]
  network:
    hosts: [...]
    groups: [...]
  prefix_lists:
    ipv4: [...]
  route_maps: [...]
  # ... only objects that are referenced
routing:
  bgp_general_settings: [...]
  bgp_policies: [...]
  ospfv2_policies: [...]
  # ... all routing configs
  vrf_specific:
    VRF-Name:
      bgp_policies: [...]
```

---

## Summary

| Phase | What | Dependency Behavior |
|-------|------|---------------------|
| 1 | Interfaces | Scan for referenced objects (SecurityZone, etc.) |
| 2 | Routing | Scan for referenced objects (RouteMaps, PrefixLists, etc.) |
| 3 | Objects | **Fetch ONLY what's referenced**, in reverse dependency order (L4→L1), rescanning after each level to catch nested refs |

---

## Key Files

- **Frontend**: `web_app/templates/fmc_configuration.html` (lines 922-1083)
- **Backend API**: `web_app/app.py` - `/api/fmc-config/config/get` endpoint
- **Core Logic**: `web_app/app.py` - `_export_config_sync()` function (lines 4441-5349)
- **FMC API Helpers**: `utils/fmc_api.py` - Individual GET functions for each config type
- **Dependency Resolver**: `utils/dependency_resolver.py` - Used during Push Config for resolving object IDs
