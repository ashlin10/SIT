import { useState } from 'react'
import { cn } from '@/lib/utils'
import {
  Plus, Trash2, ChevronDown, ChevronUp, Layers,
  Cable, GitBranch, Network, Radio, Columns, Shield,
  Router, Globe, MapPin, Route, Waypoints,
  Box, LayoutGrid,
} from 'lucide-react'

// ── Types ──

interface LoopIntf { loopId: string; ifname: string; ipv4: string; mask: string; ipv6: string; ipv6Pfx: string; secZone: string; mode: string }
interface PhyIntf { name: string; ifname: string; ipv4: string; mask: string; mtu: string; secZone: string; mode: string; enabled: boolean }
interface EcIntf { channelId: string; ifname: string; ipv4: string; mask: string; mtu: string; secZone: string; members: string; mode: string; lacpMode: string }
interface SubIntf { parent: string; vlanId: string; subId: string; ifname: string; ipv4: string; mask: string; ipv6: string; ipv6Pfx: string; secZone: string; mode: string }
interface VtiIntf { tunnelId: string; tunnelType: string; ifname: string; tunnelSource: string; ipsecMode: string; ipv4: string; mask: string; sgtProp: string; secZone: string }
interface InlineSet { name: string; pair1: string; pair2: string; bypass: boolean; standby: boolean }
interface BgiIntf { bviId: string; ifname: string; ipv4: string; mask: string; secZone: string; members: string }

// Range types
interface LoopRange { startId: string; ifname: string; mask: string; secZone: string; mode: string; count: string; startIpv4: string; incOctet: string; startIpv6: string; incHextet: string; ipv6Pfx: string }
interface SubRange { parent: string; startVlan: string; startSubId: string; ifname: string; mask: string; secZone: string; mode: string; count: string; startIpv4: string; incOctet: string; startIpv6: string; incHextet: string; ipv6Pfx: string }
interface VtiRange { startId: string; tunnelType: string; ipsecMode: string; sgtProp: string; ifname: string; count: string; startSrc: string; borrowIp: string; secZone: string; startIpv4: string; mask: string; incOctet: string; startIpv6: string; ipv6Pfx: string; incHextet: string }
interface BgiRange { startId: string; ifname: string; mask: string; secZone: string; count: string; startIpv4: string; incOctet: string; startIpv6: string; incHextet: string; startMembers: string[] }

// BGP
interface BgpSettings { asn: string; routerId: string; keepAlive: string; holdTime: string; logNbr: string; enFirstAs: string; fastFallover: string; maxAsLimit: string }
interface BgpNeighbor { addrFamily: string; address: string; remoteAs: string; bfd: string }
interface BgpNbrRange { remoteAs: string; bfd: string; count: string; startV4: string; incOctet: string; startV6: string; incHextet: string }

// OSPF
interface Ospfv2Policy { processId: string; areaId: string; areaType: string; networks: string }
interface Ospfv2If { ifname: string; cost: string; priority: string; hello: string; dead: string; bfd: string }
interface Ospfv2IfRange { startIntf: string; cost: string; priority: string; hello: string; dead: string; bfd: string; count: string }
interface Ospfv3Policy { processId: string; routerId: string; enabled: string }
interface Ospfv3If { ifname: string; processId: string; areaId: string; bfd: string; authType: string }
interface Ospfv3IfRange { startIntf: string; processId: string; areaId: string; bfd: string; authType: string; count: string }

// Other routing
interface EigrpPolicy { asn: string; networks: string; autoSummary: string }
interface PbrPolicy { ifname: string; routeMap: string }
interface StaticRoute { iface: string; network: string; gateway: string; metric: string }
interface EcmpZone { name: string; interfaces: string }
interface Vrf { name: string; description: string; interfaces: string }

// Objects
interface SecZone { name: string; mode: string }
interface SecZoneRange { startName: string; mode: string; count: string }
interface HostObj { name: string; value: string }
interface HostRange { startName: string; startIp: string; incOctet: string; count: string }
interface RangeObj { name: string; value: string }
interface RangeObjRange { startName: string; startIp: string; incOctet: string; endOffset: string; count: string }
interface NetworkObj { name: string; value: string }
interface NetworkObjRange { startName: string; startValue: string; incOctet: string; count: string }

// ── YAML Builder ──

function incrementIp(ip: string, amount: number, octet: number): string {
  const parts = ip.split('.')
  if (parts.length !== 4) return ip
  parts[octet - 1] = String(parseInt(parts[octet - 1]) + amount)
  return parts.join('.')
}

function incrementIpv6(ip: string, amount: number, hextet: number): string {
  const full = ip.split(':')
  if (full.length < 2) return ip
  // Simple increment on the specified hextet
  const expanded: string[] = []
  let emptyIdx = -1
  for (let i = 0; i < full.length; i++) {
    if (full[i] === '') { emptyIdx = i; expanded.push('0'); }
    else expanded.push(full[i])
  }
  while (expanded.length < 8) expanded.splice(emptyIdx >= 0 ? emptyIdx : expanded.length, 0, '0')
  const idx = hextet - 1
  if (idx >= 0 && idx < 8) expanded[idx] = (parseInt(expanded[idx], 16) + amount).toString(16)
  return expanded.join(':')
}

function deviceConfigToYaml(state: DeviceTemplateState): string {
  const lines: string[] = []
  const { loops, loopRanges, rangeMode, phys, ecs, subs, subRanges, vtis, vtiRanges, inlines, bgis, bgiRanges,
    bgp, bgpNbrs, bgpNbrRanges, ospfv2, ospfv2Ifs, ospfv2IfRanges, ospfv3, ospfv3Ifs, ospfv3IfRanges,
    eigrp, pbr, v4routes, v4routeRanges, v6routes, ecmpZones, vrfs,
    secZones, secZoneRanges, hosts, hostRanges, rangeObjs, rangeObjRanges, networkObjs, networkObjRanges,
    bfdPolicies } = state

  // === Interfaces ===

  // Loopbacks
  const allLoops: LoopIntf[] = [...loops]
  if (loopRanges.length) {
    for (const r of loopRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        allLoops.push({
          loopId: String(parseInt(r.startId) + i),
          ifname: `${r.ifname}${parseInt(r.startId) + i}`,
          ipv4: r.startIpv4 ? incrementIp(r.startIpv4, i, parseInt(r.incOctet)) : '',
          mask: r.mask, ipv6: r.startIpv6 ? incrementIpv6(r.startIpv6, i, parseInt(r.incHextet)) : '',
          ipv6Pfx: r.ipv6Pfx, secZone: r.secZone, mode: r.mode,
        })
      }
    }
  }

  if (allLoops.length) {
    lines.push('loopbackinterfaces:')
    for (const l of allLoops) {
      lines.push(`  - loopbackId: ${l.loopId}`)
      lines.push(`    name: "Loopback${l.loopId}"`)
      if (l.ifname) lines.push(`    ifname: "${l.ifname}"`)
      if (l.ipv4) lines.push(`    ipv4Address: "${l.ipv4}"`)
      if (l.mask) lines.push(`    ipv4Mask: "${l.mask}"`)
      if (l.ipv6) lines.push(`    ipv6Address: "${l.ipv6}"`)
      if (l.ipv6Pfx) lines.push(`    ipv6Prefix: ${l.ipv6Pfx}`)
      if (l.secZone) lines.push(`    securityZone: "${l.secZone}"`)
      if (l.mode && l.mode !== 'NONE') lines.push(`    mode: "${l.mode}"`)
    }
  }

  // Physical
  if (phys.length) {
    lines.push('physicalinterfaces:')
    for (const p of phys) {
      lines.push(`  - name: "${p.name}"`)
      if (p.ifname) lines.push(`    ifname: "${p.ifname}"`)
      if (p.ipv4) lines.push(`    ipv4Address: "${p.ipv4}"`)
      if (p.mask) lines.push(`    ipv4Mask: "${p.mask}"`)
      if (p.mtu) lines.push(`    MTU: ${p.mtu}`)
      if (p.secZone) lines.push(`    securityZone: "${p.secZone}"`)
      if (p.mode && p.mode !== 'NONE') lines.push(`    mode: "${p.mode}"`)
      lines.push(`    enabled: ${p.enabled}`)
    }
  }

  // EtherChannel
  if (ecs.length) {
    lines.push('etherchannelinterfaces:')
    for (const e of ecs) {
      lines.push(`  - channelId: ${e.channelId}`)
      lines.push(`    name: "Port-channel${e.channelId}"`)
      if (e.ifname) lines.push(`    ifname: "${e.ifname}"`)
      if (e.ipv4) lines.push(`    ipv4Address: "${e.ipv4}"`)
      if (e.mask) lines.push(`    ipv4Mask: "${e.mask}"`)
      if (e.mtu) lines.push(`    MTU: ${e.mtu}`)
      if (e.secZone) lines.push(`    securityZone: "${e.secZone}"`)
      if (e.members) lines.push(`    memberInterfaces: "${e.members}"`)
      if (e.mode && e.mode !== 'NONE') lines.push(`    mode: "${e.mode}"`)
      if (e.lacpMode) lines.push(`    lacpMode: "${e.lacpMode}"`)
    }
  }

  // Subinterfaces
  const allSubs: SubIntf[] = [...subs]
  if (subRanges.length) {
    for (const r of subRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        allSubs.push({
          parent: r.parent, vlanId: String(parseInt(r.startVlan) + i),
          subId: String(parseInt(r.startSubId) + i),
          ifname: `${r.ifname}${parseInt(r.startSubId) + i}`,
          ipv4: r.startIpv4 ? incrementIp(r.startIpv4, i, parseInt(r.incOctet)) : '',
          mask: r.mask, ipv6: r.startIpv6 ? incrementIpv6(r.startIpv6, i, parseInt(r.incHextet)) : '',
          ipv6Pfx: r.ipv6Pfx, secZone: r.secZone, mode: r.mode,
        })
      }
    }
  }

  if (allSubs.length) {
    lines.push('subinterfaces:')
    for (const s of allSubs) {
      lines.push(`  - parent: "${s.parent}"`)
      lines.push(`    vlanId: ${s.vlanId}`)
      lines.push(`    subinterfaceId: ${s.subId}`)
      if (s.ifname) lines.push(`    ifname: "${s.ifname}"`)
      if (s.ipv4) lines.push(`    ipv4Address: "${s.ipv4}"`)
      if (s.mask) lines.push(`    ipv4Mask: "${s.mask}"`)
      if (s.ipv6) lines.push(`    ipv6Address: "${s.ipv6}"`)
      if (s.ipv6Pfx) lines.push(`    ipv6Prefix: ${s.ipv6Pfx}`)
      if (s.secZone) lines.push(`    securityZone: "${s.secZone}"`)
      if (s.mode && s.mode !== 'NONE') lines.push(`    mode: "${s.mode}"`)
    }
  }

  // VTI
  const allVtis: VtiIntf[] = [...vtis]
  if (vtiRanges.length) {
    for (const r of vtiRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        allVtis.push({
          tunnelId: String(parseInt(r.startId) + i), tunnelType: r.tunnelType,
          ifname: `${r.ifname}${parseInt(r.startId) + i}`,
          tunnelSource: r.startSrc, ipsecMode: r.ipsecMode,
          ipv4: r.startIpv4 ? incrementIp(r.startIpv4, i, parseInt(r.incOctet)) : '',
          mask: r.mask, sgtProp: r.sgtProp, secZone: r.secZone,
        })
      }
    }
  }

  if (allVtis.length) {
    lines.push('vtis:')
    for (const v of allVtis) {
      lines.push(`  - tunnelId: ${v.tunnelId}`)
      lines.push(`    name: "VTI${v.tunnelId}"`)
      if (v.tunnelType) lines.push(`    tunnelType: "${v.tunnelType}"`)
      if (v.ifname) lines.push(`    ifname: "${v.ifname}"`)
      if (v.tunnelSource) lines.push(`    tunnelSource: "${v.tunnelSource}"`)
      if (v.ipsecMode) lines.push(`    ipsecMode: "${v.ipsecMode}"`)
      if (v.ipv4) lines.push(`    ipv4Address: "${v.ipv4}"`)
      if (v.mask) lines.push(`    ipv4Mask: "${v.mask}"`)
      if (v.sgtProp === 'true') lines.push(`    sgtPropagation: true`)
      if (v.secZone) lines.push(`    securityZone: "${v.secZone}"`)
    }
  }

  // Inline Sets
  if (inlines.length) {
    lines.push('inlinesets:')
    for (const il of inlines) {
      lines.push(`  - name: "${il.name}"`)
      if (il.pair1) lines.push(`    interfacePair1: "${il.pair1}"`)
      if (il.pair2) lines.push(`    interfacePair2: "${il.pair2}"`)
      lines.push(`    bypass: ${il.bypass}`)
      lines.push(`    standby: ${il.standby}`)
    }
  }

  // Bridge Groups
  const allBgis: BgiIntf[] = [...bgis]
  if (bgiRanges.length) {
    for (const r of bgiRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        allBgis.push({
          bviId: String(parseInt(r.startId) + i),
          ifname: `${r.ifname}${parseInt(r.startId) + i}`,
          ipv4: r.startIpv4 ? incrementIp(r.startIpv4, i, parseInt(r.incOctet)) : '',
          mask: r.mask, secZone: r.secZone, members: r.startMembers.join(','),
        })
      }
    }
  }

  if (allBgis.length) {
    lines.push('bridgegroupinterfaces:')
    for (const b of allBgis) {
      lines.push(`  - bviId: ${b.bviId}`)
      lines.push(`    name: "BVI${b.bviId}"`)
      if (b.ifname) lines.push(`    ifname: "${b.ifname}"`)
      if (b.ipv4) lines.push(`    ipv4Address: "${b.ipv4}"`)
      if (b.mask) lines.push(`    ipv4Mask: "${b.mask}"`)
      if (b.secZone) lines.push(`    securityZone: "${b.secZone}"`)
      if (b.members) lines.push(`    memberInterfaces: "${b.members}"`)
    }
  }

  // === Routing ===

  // BGP
  if (bgp.asn) {
    lines.push('bgp_general_settings:')
    lines.push(`  asNumber: "${bgp.asn}"`)
    if (bgp.routerId) lines.push(`  routerId: "${bgp.routerId}"`)
    lines.push(`  keepAlive: ${bgp.keepAlive}`)
    lines.push(`  holdTime: ${bgp.holdTime}`)
    lines.push(`  logNeighborChanges: ${bgp.logNbr}`)
    lines.push(`  enforceFirstAS: ${bgp.enFirstAs}`)
    lines.push(`  fastExternalFallover: ${bgp.fastFallover}`)
    if (bgp.maxAsLimit !== '0') lines.push(`  maxASLimit: ${bgp.maxAsLimit}`)
  }

  // BGP Neighbors
  const allBgpNbrs: BgpNeighbor[] = [...bgpNbrs]
  if (bgpNbrRanges.length) {
    for (const r of bgpNbrRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        if (r.startV4) allBgpNbrs.push({ addrFamily: 'ipv4', address: incrementIp(r.startV4, i, parseInt(r.incOctet)), remoteAs: r.remoteAs, bfd: r.bfd })
        if (r.startV6) allBgpNbrs.push({ addrFamily: 'ipv6', address: incrementIpv6(r.startV6, i, parseInt(r.incHextet)), remoteAs: r.remoteAs, bfd: r.bfd })
      }
    }
  }

  if (allBgpNbrs.length) {
    lines.push('bgp_neighbors:')
    for (const n of allBgpNbrs) {
      lines.push(`  - addressFamily: "${n.addrFamily}"`)
      lines.push(`    address: "${n.address}"`)
      lines.push(`    remoteAS: "${n.remoteAs}"`)
      if (n.bfd && n.bfd !== 'NONE') lines.push(`    bfd: "${n.bfd}"`)
    }
  }

  // BFD Policies
  if (bfdPolicies.length) {
    lines.push('bfd_policies:')
    for (const b of bfdPolicies) {
      lines.push(`  - interface: "${(b as Record<string, string>).iface}"`)
      lines.push(`    templateName: "${(b as Record<string, string>).templateName}"`)
      lines.push(`    hopType: "${(b as Record<string, string>).hopType}"`)
      lines.push(`    slowTimer: ${(b as Record<string, string>).slowTimer}`)
    }
  }

  // OSPFv2
  if (ospfv2.length) {
    lines.push('ospfv2_policies:')
    for (const o of ospfv2) {
      lines.push(`  - processId: ${o.processId}`)
      lines.push(`    areaId: "${o.areaId}"`)
      if (o.areaType) lines.push(`    areaType: "${o.areaType}"`)
      if (o.networks) lines.push(`    networks: "${o.networks}"`)
    }
  }

  // OSPFv2 Interfaces
  const allOspfv2Ifs: Ospfv2If[] = [...ospfv2Ifs]
  if (ospfv2IfRanges.length) {
    for (const r of ospfv2IfRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        allOspfv2Ifs.push({ ifname: `${r.startIntf}`, cost: r.cost, priority: r.priority, hello: r.hello, dead: r.dead, bfd: r.bfd })
      }
    }
  }

  if (allOspfv2Ifs.length) {
    lines.push('ospfv2_interfaces:')
    for (const o of allOspfv2Ifs) {
      lines.push(`  - interface: "${o.ifname}"`)
      lines.push(`    cost: ${o.cost}`)
      lines.push(`    priority: ${o.priority}`)
      lines.push(`    helloInterval: ${o.hello}`)
      lines.push(`    deadInterval: ${o.dead}`)
      if (o.bfd === 'true') lines.push(`    bfd: true`)
    }
  }

  // OSPFv3
  if (ospfv3.length) {
    lines.push('ospfv3_policies:')
    for (const o of ospfv3) {
      lines.push(`  - processId: ${o.processId}`)
      if (o.routerId) lines.push(`    routerId: "${o.routerId}"`)
      lines.push(`    enabled: ${o.enabled}`)
    }
  }

  // OSPFv3 Interfaces
  const allOspfv3Ifs: Ospfv3If[] = [...ospfv3Ifs]
  if (ospfv3IfRanges.length) {
    for (const r of ospfv3IfRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        allOspfv3Ifs.push({ ifname: r.startIntf, processId: r.processId, areaId: r.areaId, bfd: r.bfd, authType: r.authType })
      }
    }
  }

  if (allOspfv3Ifs.length) {
    lines.push('ospfv3_interfaces:')
    for (const o of allOspfv3Ifs) {
      lines.push(`  - interface: "${o.ifname}"`)
      lines.push(`    processId: ${o.processId}`)
      lines.push(`    areaId: "${o.areaId}"`)
      if (o.bfd === 'true') lines.push(`    bfd: true`)
      if (o.authType) lines.push(`    authType: "${o.authType}"`)
    }
  }

  // EIGRP
  if (eigrp.length) {
    lines.push('eigrp_policies:')
    for (const e of eigrp) {
      lines.push(`  - asNumber: "${e.asn}"`)
      if (e.networks) lines.push(`    networks: "${e.networks}"`)
      lines.push(`    autoSummary: ${e.autoSummary}`)
    }
  }

  // PBR
  if (pbr.length) {
    lines.push('pbr_policies:')
    for (const p of pbr) {
      lines.push(`  - interface: "${p.ifname}"`)
      lines.push(`    routeMap: "${p.routeMap}"`)
    }
  }

  // IPv4 Static Routes
  const allV4Routes: StaticRoute[] = [...v4routes]
  if (v4routeRanges.length) {
    for (const r of v4routeRanges) {
      const cnt = parseInt((r as { count: string }).count) || 0
      for (let i = 0; i < cnt; i++) {
        allV4Routes.push({
          iface: (r as { startIntf: string }).startIntf,
          network: incrementIp((r as { startNet: string }).startNet, i, parseInt((r as { incOctet: string }).incOctet)),
          gateway: (r as { gateway: string }).gateway,
          metric: (r as { metric: string }).metric,
        })
      }
    }
  }

  if (allV4Routes.length) {
    lines.push('ipv4_static_routes:')
    for (const r of allV4Routes) {
      lines.push(`  - interface: "${r.iface}"`)
      lines.push(`    network: "${r.network}"`)
      lines.push(`    gateway: "${r.gateway}"`)
      lines.push(`    metric: ${r.metric}`)
    }
  }

  // IPv6 Static Routes
  if (v6routes.length) {
    lines.push('ipv6_static_routes:')
    for (const r of v6routes) {
      lines.push(`  - interface: "${r.iface}"`)
      lines.push(`    network: "${r.network}"`)
      lines.push(`    gateway: "${r.gateway}"`)
      lines.push(`    metric: ${r.metric}`)
    }
  }

  // ECMP Zones
  if (ecmpZones.length) {
    lines.push('ecmp_zones:')
    for (const z of ecmpZones) {
      lines.push(`  - name: "${z.name}"`)
      lines.push(`    interfaces: "${z.interfaces}"`)
    }
  }

  // VRFs
  if (vrfs.length) {
    lines.push('vrfs:')
    for (const v of vrfs) {
      lines.push(`  - name: "${v.name}"`)
      if (v.description) lines.push(`    description: "${v.description}"`)
      lines.push(`    interfaces: "${v.interfaces}"`)
    }
  }

  // === Objects ===

  // Security Zones
  const allSzs: SecZone[] = [...secZones]
  if (secZoneRanges.length) {
    for (const r of secZoneRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) allSzs.push({ name: `${r.startName}${i + 1}`, mode: r.mode })
    }
  }

  if (allSzs.length) {
    lines.push('securityzones:')
    for (const z of allSzs) {
      lines.push(`  - name: "${z.name}"`)
      lines.push(`    interfaceMode: "${z.mode}"`)
    }
  }

  // Hosts
  const allHosts: HostObj[] = [...hosts]
  if (hostRanges.length) {
    for (const r of hostRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) allHosts.push({ name: `${r.startName}${i + 1}`, value: incrementIp(r.startIp, i, parseInt(r.incOctet)) })
    }
  }

  if (allHosts.length) {
    lines.push('host_objects:')
    for (const h of allHosts) {
      lines.push(`  - name: "${h.name}"`)
      lines.push(`    value: "${h.value}"`)
    }
  }

  // Range Objects
  const allRangeObjs: RangeObj[] = [...rangeObjs]
  if (rangeObjRanges.length) {
    for (const r of rangeObjRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) {
        const start = incrementIp(r.startIp, i, parseInt(r.incOctet))
        const endParts = start.split('.')
        endParts[3] = String(parseInt(endParts[3]) + parseInt(r.endOffset))
        allRangeObjs.push({ name: `${r.startName}${i + 1}`, value: `${start}-${endParts.join('.')}` })
      }
    }
  }

  if (allRangeObjs.length) {
    lines.push('range_objects:')
    for (const r of allRangeObjs) {
      lines.push(`  - name: "${r.name}"`)
      lines.push(`    value: "${r.value}"`)
    }
  }

  // Network Objects
  const allNetObjs: NetworkObj[] = [...networkObjs]
  if (networkObjRanges.length) {
    for (const r of networkObjRanges) {
      const cnt = parseInt(r.count) || 0
      for (let i = 0; i < cnt; i++) allNetObjs.push({ name: `${r.startName}${i + 1}`, value: incrementIp(r.startValue, i, parseInt(r.incOctet)) })
    }
  }

  if (allNetObjs.length) {
    lines.push('network_objects:')
    for (const n of allNetObjs) {
      lines.push(`  - name: "${n.name}"`)
      lines.push(`    value: "${n.value}"`)
    }
  }

  return lines.join('\n') + '\n'
}

// ── State type ──

interface DeviceTemplateState {
  loops: LoopIntf[]; loopRanges: LoopRange[]
  phys: PhyIntf[]; ecs: EcIntf[]
  subs: SubIntf[]; subRanges: SubRange[]
  vtis: VtiIntf[]; vtiRanges: VtiRange[]
  inlines: InlineSet[]
  bgis: BgiIntf[]; bgiRanges: BgiRange[]
  bgp: BgpSettings; bgpNbrs: BgpNeighbor[]; bgpNbrRanges: BgpNbrRange[]
  bfdPolicies: Record<string, string>[]
  ospfv2: Ospfv2Policy[]; ospfv2Ifs: Ospfv2If[]; ospfv2IfRanges: Ospfv2IfRange[]
  ospfv3: Ospfv3Policy[]; ospfv3Ifs: Ospfv3If[]; ospfv3IfRanges: Ospfv3IfRange[]
  eigrp: EigrpPolicy[]; pbr: PbrPolicy[]
  v4routes: StaticRoute[]; v4routeRanges: Record<string, string>[]; v6routes: StaticRoute[]
  ecmpZones: EcmpZone[]; vrfs: Vrf[]
  secZones: SecZone[]; secZoneRanges: SecZoneRange[]
  hosts: HostObj[]; hostRanges: HostRange[]
  rangeObjs: RangeObj[]; rangeObjRanges: RangeObjRange[]
  networkObjs: NetworkObj[]; networkObjRanges: NetworkObjRange[]
  rangeMode: Record<string, boolean>
}

// ── Component ──

interface Props {
  inputCls: string
  selectCls: string
  labelCls: string
  sectionHeaderCls: string
  onYaml: (yaml: string) => void
}

export default function DeviceTemplateContent({ inputCls, selectCls, labelCls, sectionHeaderCls, onYaml }: Props) {
  // All state
  const [loops, setLoops] = useState<LoopIntf[]>([])
  const [loopRanges, setLoopRanges] = useState<LoopRange[]>([])
  const [phys, setPhys] = useState<PhyIntf[]>([])
  const [ecs, setEcs] = useState<EcIntf[]>([])
  const [subs, setSubs] = useState<SubIntf[]>([])
  const [subRanges, setSubRanges] = useState<SubRange[]>([])
  const [vtis, setVtis] = useState<VtiIntf[]>([])
  const [vtiRanges, setVtiRanges] = useState<VtiRange[]>([])
  const [inlines, setInlines] = useState<InlineSet[]>([])
  const [bgis, setBgis] = useState<BgiIntf[]>([])
  const [bgiRanges, setBgiRanges] = useState<BgiRange[]>([])

  const [bgp, setBgp] = useState<BgpSettings>({ asn: '', routerId: 'AUTOMATIC', keepAlive: '60', holdTime: '180', logNbr: 'true', enFirstAs: 'true', fastFallover: 'true', maxAsLimit: '0' })
  const [bgpNbrs, setBgpNbrs] = useState<BgpNeighbor[]>([])
  const [bgpNbrRanges, setBgpNbrRanges] = useState<BgpNbrRange[]>([])
  const [bfdPolicies, setBfdPolicies] = useState<Record<string, string>[]>([])
  const [ospfv2, setOspfv2] = useState<Ospfv2Policy[]>([])
  const [ospfv2Ifs, setOspfv2Ifs] = useState<Ospfv2If[]>([])
  const [ospfv2IfRanges, setOspfv2IfRanges] = useState<Ospfv2IfRange[]>([])
  const [ospfv3, setOspfv3] = useState<Ospfv3Policy[]>([])
  const [ospfv3Ifs, setOspfv3Ifs] = useState<Ospfv3If[]>([])
  const [ospfv3IfRanges, setOspfv3IfRanges] = useState<Ospfv3IfRange[]>([])
  const [eigrp, setEigrp] = useState<EigrpPolicy[]>([])
  const [pbr, setPbr] = useState<PbrPolicy[]>([])
  const [v4routes, setV4routes] = useState<StaticRoute[]>([])
  const [v4routeRanges, setV4routeRanges] = useState<Record<string, string>[]>([])
  const [v6routes, setV6routes] = useState<StaticRoute[]>([])
  const [ecmpZones, setEcmpZones] = useState<EcmpZone[]>([])
  const [vrfs, setVrfs] = useState<Vrf[]>([])

  const [secZones, setSecZones] = useState<SecZone[]>([])
  const [secZoneRanges, setSecZoneRanges] = useState<SecZoneRange[]>([])
  const [hosts, setHosts] = useState<HostObj[]>([])
  const [hostRanges, setHostRanges] = useState<HostRange[]>([])
  const [rangeObjs, setRangeObjs] = useState<RangeObj[]>([])
  const [rangeObjRanges, setRangeObjRanges] = useState<RangeObjRange[]>([])
  const [networkObjs, setNetworkObjs] = useState<NetworkObj[]>([])
  const [networkObjRanges, setNetworkObjRanges] = useState<NetworkObjRange[]>([])

  const [rangeMode, setRangeMode] = useState<Record<string, boolean>>({})
  const toggleRange = (key: string) => setRangeMode(r => ({ ...r, [key]: !r[key] }))

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({
    loop: true, phy: true, ec: true, sub: true, vti: true, inline: true, bgi: true,
    bgpGen: true, bgpNbr: true, bfd: true, ospfv2: true, ospfv2If: true, ospfv3: true, ospfv3If: true,
    eigrp: true, pbr: true, v4route: true, v6route: true, ecmp: true, vrf: true,
    sz: true, host: true, rangeObj: true, nw: true, networkObj: true,
  })
  const toggle = (id: string) => setCollapsed(c => ({ ...c, [id]: !c[id] }))

  // Expose YAML generation to parent
  const buildYaml = () => {
    const state: DeviceTemplateState = {
      loops, loopRanges, phys, ecs, subs, subRanges, vtis, vtiRanges, inlines, bgis, bgiRanges,
      bgp, bgpNbrs, bgpNbrRanges, bfdPolicies, ospfv2, ospfv2Ifs, ospfv2IfRanges,
      ospfv3, ospfv3Ifs, ospfv3IfRanges, eigrp, pbr, v4routes, v4routeRanges, v6routes,
      ecmpZones, vrfs, secZones, secZoneRanges, hosts, hostRanges, rangeObjs, rangeObjRanges,
      networkObjs, networkObjRanges, rangeMode,
    }
    return deviceConfigToYaml(state)
  }

  // Notify parent on each render for preview
  const handlePreview = () => onYaml(buildYaml())

  // Helpers
  const badge = (n: number) => <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">{n}</span>
  const delBtn = (onClick: () => void) => <button onClick={onClick} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-3 h-3" /></button>
  const addBtn = (label: string, onClick: () => void) => (
    <button onClick={onClick} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5 mt-1"><Plus className="w-3 h-3" /> {label}</button>
  )
  const rangeToggle = (key: string) => (
    <button onClick={(e) => { e.stopPropagation(); toggleRange(key) }} className={cn('text-[9px] px-1.5 py-0.5 rounded font-medium flex items-center gap-0.5 transition-colors', rangeMode[key] ? 'bg-accent-violet/20 text-accent-violet' : 'bg-surface-100 dark:bg-surface-800 text-surface-500 hover:text-surface-700')}>
      <Layers className="w-3 h-3" /> Range
    </button>
  )
  const SH = ({ id, label, count, extra, icon }: { id: string; label: string; count?: number; extra?: React.ReactNode; icon?: React.ReactNode }) => (
    <div className={sectionHeaderCls} onClick={() => toggle(id)}>
      <div className="flex items-center gap-2">
        {collapsed[id] ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
        {icon}
        <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">{label}</span>
        {count !== undefined && badge(count)}
        {extra}
      </div>
    </div>
  )

  const modeOpts = <><option value="NONE">NONE</option><option value="ROUTED">ROUTED</option><option value="SWITCHED">SWITCHED</option></>
  const octOpts = <><option value="1">1st</option><option value="2">2nd</option><option value="3">3rd</option><option value="4">4th</option></>
  const hexOpts = <><option value="1">1st</option><option value="2">2nd</option><option value="3">3rd</option><option value="4">4th</option><option value="5">5th</option><option value="6">6th</option><option value="7">7th</option><option value="8">8th</option></>

  return (
    <div className="space-y-4">
      {/* ═══ INTERFACES ═══ */}
      <div className="flex items-center gap-2 text-xs font-semibold text-surface-700 dark:text-surface-300 border-b border-surface-200 dark:border-surface-700 pb-1"><Cable className="w-3.5 h-3.5 text-accent-violet" /> Interfaces</div>

      {/* Loopback */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="loop" label="Loopback Interfaces" count={loops.length + loopRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('loop')} icon={<Radio className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.loop && (
          <div className="p-3 space-y-2">
            {/* Individual items - always shown */}
            <div className="grid grid-cols-[60px_1fr_1fr_1fr_1fr_1fr_50px_1fr_60px_auto] gap-1 text-[9px] font-medium text-surface-400 px-1">
              <span>ID</span><span>Name</span><span>Logical</span><span>IPv4</span><span>Mask</span><span>IPv6</span><span>Pfx</span><span>Zone</span><span>Mode</span><span></span>
            </div>
            {loops.map((l, i) => (
              <div key={i} className="grid grid-cols-[60px_1fr_1fr_1fr_1fr_1fr_50px_1fr_60px_auto] gap-1 items-center">
                <input value={l.loopId} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, loopId: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <span className="text-[9px] text-surface-400 truncate">Loopback{l.loopId}</span>
                <input value={l.ifname} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={l.ipv4} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, ipv4: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={l.mask} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={l.ipv6} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, ipv6: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={l.ipv6Pfx} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, ipv6Pfx: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={l.secZone} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <select value={l.mode} onChange={e => setLoops(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-full')}>{modeOpts}</select>
                {delBtn(() => setLoops(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Loopback', () => setLoops(a => [...a, { loopId: String(a.length + 1), ifname: '', ipv4: '', mask: '255.255.255.255', ipv6: '', ipv6Pfx: '128', secZone: '', mode: 'NONE' }]))}
            {/* Range items - shown when range mode active */}
            {rangeMode.loop && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {loopRanges.map((r, i) => (
                  <div key={i} className="rounded border border-surface-150 dark:border-surface-700/50 p-2 space-y-1 text-[10px] mb-1">
                    <div className="flex items-center justify-between">{delBtn(() => setLoopRanges(a => a.filter((_, j) => j !== i)))}</div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start ID</label><input value={r.startId} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, startId: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                      <label className={labelCls}>Logical Name</label><input value={r.ifname} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-24')} />
                      <label className={labelCls}>Mask</label><input value={r.mask} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Zone</label><input value={r.secZone} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                      <label className={labelCls}>Mode</label><select value={r.mode} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-20')}>{modeOpts}</select>
                      <label className={labelCls}>Count</label><input type="number" value={r.count} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start IPv4</label><input value={r.startIpv4} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, startIpv4: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Inc Octet</label><select value={r.incOctet} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, incOctet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{octOpts}</select>
                      <label className={labelCls}>Start IPv6</label><input value={r.startIpv6} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, startIpv6: e.target.value } : x))} className={cn(inputCls, 'w-32')} />
                      <label className={labelCls}>Inc Hextet</label><select value={r.incHextet} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, incHextet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{hexOpts}</select>
                      <label className={labelCls}>IPv6 Pfx</label><input value={r.ipv6Pfx} onChange={e => setLoopRanges(a => a.map((x, j) => j === i ? { ...x, ipv6Pfx: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    </div>
                  </div>
                ))}
                {addBtn('Add Loopback Range', () => setLoopRanges(a => [...a, { startId: '1', ifname: 'loopback', mask: '255.255.255.255', secZone: '', mode: 'NONE', count: '1', startIpv4: '', incOctet: '4', startIpv6: '', incHextet: '8', ipv6Pfx: '128' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Physical */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="phy" label="Physical Interfaces" count={phys.length} icon={<Cable className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.phy && (
          <div className="p-3 space-y-1">
            <div className="grid grid-cols-[100px_1fr_1fr_1fr_50px_1fr_60px_50px_auto] gap-1 text-[9px] font-medium text-surface-400 px-1">
              <span>Name</span><span>Logical</span><span>IPv4</span><span>Mask</span><span>MTU</span><span>Zone</span><span>Mode</span><span>On</span><span></span>
            </div>
            {phys.map((p, i) => (
              <div key={i} className="grid grid-cols-[100px_1fr_1fr_1fr_50px_1fr_60px_50px_auto] gap-1 items-center">
                <input value={p.name} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, name: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={p.ifname} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={p.ipv4} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, ipv4: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={p.mask} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={p.mtu} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, mtu: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={p.secZone} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <select value={p.mode} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-full')}>{modeOpts}</select>
                <input type="checkbox" checked={p.enabled} onChange={e => setPhys(a => a.map((x, j) => j === i ? { ...x, enabled: e.target.checked } : x))} className="rounded border-surface-300 text-vyper-600" />
                {delBtn(() => setPhys(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Physical', () => setPhys(a => [...a, { name: `Ethernet1/${a.length + 1}`, ifname: '', ipv4: '', mask: '', mtu: '1500', secZone: '', mode: 'NONE', enabled: true }]))}
          </div>
        )}
      </div>

      {/* EtherChannel */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="ec" label="EtherChannel Interfaces" count={ecs.length} icon={<GitBranch className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.ec && (
          <div className="p-3 space-y-1">
            <div className="grid grid-cols-[60px_1fr_1fr_1fr_50px_1fr_1fr_60px_60px_auto] gap-1 text-[9px] font-medium text-surface-400 px-1">
              <span>Ch ID</span><span>Name</span><span>Logical</span><span>IPv4</span><span>MTU</span><span>Zone</span><span>Members</span><span>Mode</span><span>LACP</span><span></span>
            </div>
            {ecs.map((e, i) => (
              <div key={i} className="grid grid-cols-[60px_1fr_1fr_1fr_50px_1fr_1fr_60px_60px_auto] gap-1 items-center">
                <input value={e.channelId} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, channelId: ev.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <span className="text-[9px] text-surface-400 truncate">PC{e.channelId}</span>
                <input value={e.ifname} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, ifname: ev.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={e.ipv4} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, ipv4: ev.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={e.mtu} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, mtu: ev.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={e.secZone} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, secZone: ev.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={e.members} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, members: ev.target.value } : x))} className={cn(inputCls, 'w-full')} placeholder="Eth1/7,Eth1/8" />
                <select value={e.mode} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, mode: ev.target.value } : x))} className={cn(selectCls, 'w-full')}>{modeOpts}</select>
                <select value={e.lacpMode} onChange={ev => setEcs(a => a.map((x, j) => j === i ? { ...x, lacpMode: ev.target.value } : x))} className={cn(selectCls, 'w-full')}>
                  <option value="active">Active</option><option value="passive">Passive</option><option value="on">On</option>
                </select>
                {delBtn(() => setEcs(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add EtherChannel', () => setEcs(a => [...a, { channelId: String(a.length + 1), ifname: '', ipv4: '', mask: '', mtu: '1500', secZone: '', members: '', mode: 'NONE', lacpMode: 'active' }]))}
          </div>
        )}
      </div>

      {/* Subinterfaces */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="sub" label="Subinterfaces" count={subs.length + subRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('sub')} icon={<Network className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.sub && (
          <div className="p-3 space-y-2">
            <div className="grid grid-cols-[100px_50px_50px_1fr_1fr_1fr_1fr_50px_1fr_60px_auto] gap-1 text-[9px] font-medium text-surface-400 px-1">
              <span>Parent</span><span>VLAN</span><span>Sub</span><span>Logical</span><span>IPv4</span><span>Mask</span><span>IPv6</span><span>Pfx</span><span>Zone</span><span>Mode</span><span></span>
            </div>
            {subs.map((s, i) => (
              <div key={i} className="grid grid-cols-[100px_50px_50px_1fr_1fr_1fr_1fr_50px_1fr_60px_auto] gap-1 items-center">
                <input value={s.parent} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, parent: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.vlanId} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, vlanId: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.subId} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, subId: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.ifname} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.ipv4} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, ipv4: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.mask} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.ipv6} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, ipv6: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.ipv6Pfx} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, ipv6Pfx: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <input value={s.secZone} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-full')} />
                <select value={s.mode} onChange={e => setSubs(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-full')}>{modeOpts}</select>
                {delBtn(() => setSubs(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Subinterface', () => setSubs(a => [...a, { parent: '', vlanId: '100', subId: '100', ifname: '', ipv4: '', mask: '255.255.255.0', ipv6: '', ipv6Pfx: '64', secZone: '', mode: 'NONE' }]))}
            {rangeMode.sub && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {subRanges.map((r, i) => (
                  <div key={i} className="rounded border border-surface-150 dark:border-surface-700/50 p-2 space-y-1 text-[10px] mb-1">
                    <div className="flex justify-end">{delBtn(() => setSubRanges(a => a.filter((_, j) => j !== i)))}</div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Parent</label><input value={r.parent} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, parent: e.target.value } : x))} className={cn(inputCls, 'w-24')} />
                      <label className={labelCls}>Start VLAN</label><input value={r.startVlan} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, startVlan: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                      <label className={labelCls}>Start Sub ID</label><input value={r.startSubId} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, startSubId: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                      <label className={labelCls}>Logical</label><input value={r.ifname} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                      <label className={labelCls}>Mask</label><input value={r.mask} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Zone</label><input value={r.secZone} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                      <label className={labelCls}>Mode</label><select value={r.mode} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-20')}>{modeOpts}</select>
                      <label className={labelCls}>Count</label><input type="number" value={r.count} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start IPv4</label><input value={r.startIpv4} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, startIpv4: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Inc Octet</label><select value={r.incOctet} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, incOctet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{octOpts}</select>
                      <label className={labelCls}>Start IPv6</label><input value={r.startIpv6} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, startIpv6: e.target.value } : x))} className={cn(inputCls, 'w-32')} />
                      <label className={labelCls}>Inc Hextet</label><select value={r.incHextet} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, incHextet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{hexOpts}</select>
                      <label className={labelCls}>IPv6 Pfx</label><input value={r.ipv6Pfx} onChange={e => setSubRanges(a => a.map((x, j) => j === i ? { ...x, ipv6Pfx: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    </div>
                  </div>
                ))}
                {addBtn('Add Sub Range', () => setSubRanges(a => [...a, { parent: '', startVlan: '100', startSubId: '100', ifname: 'sub', mask: '255.255.255.0', secZone: '', mode: 'NONE', count: '1', startIpv4: '', incOctet: '4', startIpv6: '', incHextet: '8', ipv6Pfx: '64' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* VTI */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="vti" label="Virtual Tunnel Interfaces" count={vtis.length + vtiRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('vti')} icon={<Shield className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.vti && (
          <div className="p-3 space-y-2">
            {vtis.map((v, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={v.tunnelId} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, tunnelId: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="ID" />
                <select value={v.tunnelType} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, tunnelType: e.target.value } : x))} className={cn(selectCls, 'w-20')}><option value="STATIC">STATIC</option><option value="DYNAMIC">DYNAMIC</option></select>
                <input value={v.ifname} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-20')} placeholder="Logical" />
                <input value={v.tunnelSource} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, tunnelSource: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Source" />
                <input value={v.ipv4} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, ipv4: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="IPv4" />
                <input value={v.mask} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Mask" />
                <input value={v.secZone} onChange={e => setVtis(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-20')} placeholder="Zone" />
                {delBtn(() => setVtis(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add VTI', () => setVtis(a => [...a, { tunnelId: String(a.length + 1), tunnelType: 'STATIC', ifname: '', tunnelSource: '', ipsecMode: 'ipv4', ipv4: '', mask: '255.255.255.252', sgtProp: 'false', secZone: '' }]))}
            {rangeMode.vti && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {vtiRanges.map((r, i) => (
                  <div key={i} className="rounded border border-surface-150 dark:border-surface-700/50 p-2 space-y-1 text-[10px] mb-1">
                    <div className="flex justify-end">{delBtn(() => setVtiRanges(a => a.filter((_, j) => j !== i)))}</div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start ID</label><input value={r.startId} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, startId: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                      <label className={labelCls}>Type</label><select value={r.tunnelType} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, tunnelType: e.target.value } : x))} className={cn(selectCls, 'w-20')}><option value="STATIC">STATIC</option><option value="DYNAMIC">DYNAMIC</option></select>
                      <label className={labelCls}>IPsec</label><select value={r.ipsecMode} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, ipsecMode: e.target.value } : x))} className={cn(selectCls, 'w-16')}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="both">Both</option></select>
                      <label className={labelCls}>SGT</label><select value={r.sgtProp} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, sgtProp: e.target.value } : x))} className={cn(selectCls, 'w-14')}><option value="false">No</option><option value="true">Yes</option></select>
                      <label className={labelCls}>Logical</label><input value={r.ifname} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                      <label className={labelCls}>Count</label><input type="number" value={r.count} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Source</label><input value={r.startSrc} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, startSrc: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>BorrowIP</label><input value={r.borrowIp} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, borrowIp: e.target.value } : x))} className={cn(inputCls, 'w-24')} />
                      <label className={labelCls}>Zone</label><input value={r.secZone} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start IPv4</label><input value={r.startIpv4} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, startIpv4: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Mask</label><input value={r.mask} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Inc Octet</label><select value={r.incOctet} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, incOctet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{octOpts}</select>
                      <label className={labelCls}>Start IPv6</label><input value={r.startIpv6} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, startIpv6: e.target.value } : x))} className={cn(inputCls, 'w-32')} />
                      <label className={labelCls}>Pfx</label><input value={r.ipv6Pfx} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, ipv6Pfx: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                      <label className={labelCls}>Inc Hex</label><select value={r.incHextet} onChange={e => setVtiRanges(a => a.map((x, j) => j === i ? { ...x, incHextet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{hexOpts}</select>
                    </div>
                  </div>
                ))}
                {addBtn('Add VTI Range', () => setVtiRanges(a => [...a, { startId: '1', tunnelType: 'STATIC', ipsecMode: 'ipv4', sgtProp: 'false', ifname: 'vti', count: '1', startSrc: '', borrowIp: '', secZone: '', startIpv4: '', mask: '255.255.255.252', incOctet: '4', startIpv6: '', ipv6Pfx: '64', incHextet: '8' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Inline Sets */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="inline" label="Inline Sets" count={inlines.length} icon={<Columns className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.inline && (
          <div className="p-3 space-y-1">
            {inlines.map((il, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={il.name} onChange={e => setInlines(a => a.map((x, j) => j === i ? { ...x, name: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Name" />
                <input value={il.pair1} onChange={e => setInlines(a => a.map((x, j) => j === i ? { ...x, pair1: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Pair 1" />
                <input value={il.pair2} onChange={e => setInlines(a => a.map((x, j) => j === i ? { ...x, pair2: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Pair 2" />
                <label className="flex items-center gap-1"><input type="checkbox" checked={il.bypass} onChange={e => setInlines(a => a.map((x, j) => j === i ? { ...x, bypass: e.target.checked } : x))} className="rounded border-surface-300 text-vyper-600" /><span className="text-[9px] text-surface-500">Bypass</span></label>
                <label className="flex items-center gap-1"><input type="checkbox" checked={il.standby} onChange={e => setInlines(a => a.map((x, j) => j === i ? { ...x, standby: e.target.checked } : x))} className="rounded border-surface-300 text-vyper-600" /><span className="text-[9px] text-surface-500">Standby</span></label>
                {delBtn(() => setInlines(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Inline Set', () => setInlines(a => [...a, { name: '', pair1: '', pair2: '', bypass: false, standby: false }]))}
          </div>
        )}
      </div>

      {/* Bridge Groups */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="bgi" label="Bridge Group Interfaces" count={bgis.length + bgiRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('bgi')} icon={<LayoutGrid className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.bgi && (
          <div className="p-3 space-y-2">
            {bgis.map((b, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={b.bviId} onChange={e => setBgis(a => a.map((x, j) => j === i ? { ...x, bviId: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="BVI ID" />
                <input value={b.ifname} onChange={e => setBgis(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-20')} placeholder="Logical" />
                <input value={b.ipv4} onChange={e => setBgis(a => a.map((x, j) => j === i ? { ...x, ipv4: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="IPv4" />
                <input value={b.mask} onChange={e => setBgis(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Mask" />
                <input value={b.secZone} onChange={e => setBgis(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-20')} placeholder="Zone" />
                <input value={b.members} onChange={e => setBgis(a => a.map((x, j) => j === i ? { ...x, members: e.target.value } : x))} className={cn(inputCls, 'w-40')} placeholder="Members" />
                {delBtn(() => setBgis(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Bridge Group', () => setBgis(a => [...a, { bviId: String(a.length + 1), ifname: '', ipv4: '', mask: '255.255.255.0', secZone: '', members: '' }]))}
            {rangeMode.bgi && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {bgiRanges.map((r, i) => (
                  <div key={i} className="rounded border border-surface-150 dark:border-surface-700/50 p-2 space-y-1 text-[10px] mb-1">
                    <div className="flex justify-end">{delBtn(() => setBgiRanges(a => a.filter((_, j) => j !== i)))}</div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start BVI</label><input value={r.startId} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, startId: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                      <label className={labelCls}>Logical</label><input value={r.ifname} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                      <label className={labelCls}>Mask</label><input value={r.mask} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, mask: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Zone</label><input value={r.secZone} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, secZone: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                      <label className={labelCls}>Count</label><input type="number" value={r.count} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <label className={labelCls}>Start IPv4</label><input value={r.startIpv4} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, startIpv4: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                      <label className={labelCls}>Inc Octet</label><select value={r.incOctet} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, incOctet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{octOpts}</select>
                      <label className={labelCls}>Members</label><input value={r.startMembers.join(',')} onChange={e => setBgiRanges(a => a.map((x, j) => j === i ? { ...x, startMembers: e.target.value.split(',') } : x))} className={cn(inputCls, 'w-40')} placeholder="Eth1/1,Eth1/2" />
                    </div>
                  </div>
                ))}
                {addBtn('Add BGI Range', () => setBgiRanges(a => [...a, { startId: '1', ifname: 'bvi', mask: '255.255.255.0', secZone: '', count: '1', startIpv4: '', incOctet: '4', startIpv6: '', incHextet: '8', startMembers: [''] }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ═══ ROUTING ═══ */}
      <div className="flex items-center gap-2 text-xs font-semibold text-surface-700 dark:text-surface-300 border-b border-surface-200 dark:border-surface-700 pb-1 mt-4"><Router className="w-3.5 h-3.5 text-accent-violet" /> Routing</div>

      {/* BGP General */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="bgpGen" label="BGP General Settings" icon={<Globe className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.bgpGen && (
          <div className="p-3 grid grid-cols-4 gap-2">
            <div><label className={labelCls}>AS Number</label><input value={bgp.asn} onChange={e => setBgp(s => ({ ...s, asn: e.target.value }))} className={cn(inputCls, 'w-full mt-0.5')} /></div>
            <div><label className={labelCls}>Router ID</label><select value={bgp.routerId} onChange={e => setBgp(s => ({ ...s, routerId: e.target.value }))} className={cn(selectCls, 'w-full mt-0.5')}><option value="AUTOMATIC">AUTOMATIC</option><option value="MANUAL">MANUAL</option></select></div>
            <div><label className={labelCls}>Keep Alive</label><input type="number" value={bgp.keepAlive} onChange={e => setBgp(s => ({ ...s, keepAlive: e.target.value }))} className={cn(inputCls, 'w-full mt-0.5')} /></div>
            <div><label className={labelCls}>Hold Time</label><input type="number" value={bgp.holdTime} onChange={e => setBgp(s => ({ ...s, holdTime: e.target.value }))} className={cn(inputCls, 'w-full mt-0.5')} /></div>
            <div><label className={labelCls}>Log Neighbor</label><select value={bgp.logNbr} onChange={e => setBgp(s => ({ ...s, logNbr: e.target.value }))} className={cn(selectCls, 'w-full mt-0.5')}><option value="true">Yes</option><option value="false">No</option></select></div>
            <div><label className={labelCls}>Enforce First AS</label><select value={bgp.enFirstAs} onChange={e => setBgp(s => ({ ...s, enFirstAs: e.target.value }))} className={cn(selectCls, 'w-full mt-0.5')}><option value="true">Yes</option><option value="false">No</option></select></div>
            <div><label className={labelCls}>Fast Fallover</label><select value={bgp.fastFallover} onChange={e => setBgp(s => ({ ...s, fastFallover: e.target.value }))} className={cn(selectCls, 'w-full mt-0.5')}><option value="true">Yes</option><option value="false">No</option></select></div>
            <div><label className={labelCls}>Max AS Limit</label><input type="number" value={bgp.maxAsLimit} onChange={e => setBgp(s => ({ ...s, maxAsLimit: e.target.value }))} className={cn(inputCls, 'w-full mt-0.5')} /></div>
          </div>
        )}
      </div>

      {/* BGP Neighbors */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="bgpNbr" label="BGP Neighbors" count={bgpNbrs.length + bgpNbrRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('bgpNbr')} icon={<Globe className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.bgpNbr && (
          <div className="p-3 space-y-1">
            {bgpNbrs.map((n, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <select value={n.addrFamily} onChange={e => setBgpNbrs(a => a.map((x, j) => j === i ? { ...x, addrFamily: e.target.value } : x))} className={cn(selectCls, 'w-16')}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select>
                <input value={n.address} onChange={e => setBgpNbrs(a => a.map((x, j) => j === i ? { ...x, address: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Address" />
                <input value={n.remoteAs} onChange={e => setBgpNbrs(a => a.map((x, j) => j === i ? { ...x, remoteAs: e.target.value } : x))} className={cn(inputCls, 'w-20')} placeholder="Remote AS" />
                <select value={n.bfd} onChange={e => setBgpNbrs(a => a.map((x, j) => j === i ? { ...x, bfd: e.target.value } : x))} className={cn(selectCls, 'w-24')}><option value="NONE">NONE</option><option value="SINGLE_HOP">SINGLE_HOP</option><option value="MULTI_HOP">MULTI_HOP</option></select>
                {delBtn(() => setBgpNbrs(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Neighbor', () => setBgpNbrs(a => [...a, { addrFamily: 'ipv4', address: '', remoteAs: '', bfd: 'NONE' }]))}
            {rangeMode.bgpNbr && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {bgpNbrRanges.map((r, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                    <label className={labelCls}>Remote AS</label><input value={r.remoteAs} onChange={e => setBgpNbrRanges(a => a.map((x, j) => j === i ? { ...x, remoteAs: e.target.value } : x))} className={cn(inputCls, 'w-20')} />
                    <label className={labelCls}>BFD</label><select value={r.bfd} onChange={e => setBgpNbrRanges(a => a.map((x, j) => j === i ? { ...x, bfd: e.target.value } : x))} className={cn(selectCls, 'w-24')}><option value="NONE">NONE</option><option value="SINGLE_HOP">SINGLE_HOP</option><option value="MULTI_HOP">MULTI_HOP</option></select>
                    <label className={labelCls}>Count</label><input type="number" value={r.count} onChange={e => setBgpNbrRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    <label className={labelCls}>Start v4</label><input value={r.startV4} onChange={e => setBgpNbrRanges(a => a.map((x, j) => j === i ? { ...x, startV4: e.target.value } : x))} className={cn(inputCls, 'w-28')} />
                    <label className={labelCls}>Oct</label><select value={r.incOctet} onChange={e => setBgpNbrRanges(a => a.map((x, j) => j === i ? { ...x, incOctet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{octOpts}</select>
                    {delBtn(() => setBgpNbrRanges(a => a.filter((_, j) => j !== i)))}
                  </div>
                ))}
                {addBtn('Add Range', () => setBgpNbrRanges(a => [...a, { remoteAs: '65000', bfd: 'NONE', count: '1', startV4: '', incOctet: '4', startV6: '', incHextet: '8' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Compact: BFD, OSPF, EIGRP, PBR, Routes, ECMP, VRF sections */}
      {/* BFD Policies */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="bfd" label="BFD Policies" count={bfdPolicies.length} icon={<Waypoints className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.bfd && (
          <div className="p-3 space-y-1">
            {bfdPolicies.map((b, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={b.iface} onChange={e => setBfdPolicies(a => a.map((x, j) => j === i ? { ...x, iface: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Interface" />
                <input value={b.templateName} onChange={e => setBfdPolicies(a => a.map((x, j) => j === i ? { ...x, templateName: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Template" />
                <select value={b.hopType} onChange={e => setBfdPolicies(a => a.map((x, j) => j === i ? { ...x, hopType: e.target.value } : x))} className={cn(selectCls, 'w-24')}><option value="SINGLE_HOP">SINGLE_HOP</option><option value="MULTI_HOP">MULTI_HOP</option></select>
                <input value={b.slowTimer} onChange={e => setBfdPolicies(a => a.map((x, j) => j === i ? { ...x, slowTimer: e.target.value } : x))} className={cn(inputCls, 'w-16')} placeholder="Slow" />
                {delBtn(() => setBfdPolicies(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add BFD', () => setBfdPolicies(a => [...a, { iface: '', templateName: '', hopType: 'SINGLE_HOP', slowTimer: '2000' }]))}
          </div>
        )}
      </div>

      {/* OSPFv2 Policies */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="ospfv2" label="OSPFv2 Policies" count={ospfv2.length} icon={<Route className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.ospfv2 && (
          <div className="p-3 space-y-1">
            {ospfv2.map((o, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={o.processId} onChange={e => setOspfv2(a => a.map((x, j) => j === i ? { ...x, processId: e.target.value } : x))} className={cn(inputCls, 'w-16')} placeholder="PID" />
                <input value={o.areaId} onChange={e => setOspfv2(a => a.map((x, j) => j === i ? { ...x, areaId: e.target.value } : x))} className={cn(inputCls, 'w-16')} placeholder="Area" />
                <select value={o.areaType} onChange={e => setOspfv2(a => a.map((x, j) => j === i ? { ...x, areaType: e.target.value } : x))} className={cn(selectCls, 'w-20')}><option value="">Normal</option><option value="stub">Stub</option><option value="nssa">NSSA</option></select>
                <input value={o.networks} onChange={e => setOspfv2(a => a.map((x, j) => j === i ? { ...x, networks: e.target.value } : x))} className={cn(inputCls, 'flex-1')} placeholder="Networks" />
                {delBtn(() => setOspfv2(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add OSPFv2', () => setOspfv2(a => [...a, { processId: '1', areaId: '0', areaType: '', networks: '' }]))}
          </div>
        )}
      </div>

      {/* OSPFv2 Interfaces */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="ospfv2If" label="OSPFv2 Interfaces" count={ospfv2Ifs.length + ospfv2IfRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('ospfv2If')} icon={<Route className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.ospfv2If && (
          <div className="p-3 space-y-1">
            {ospfv2Ifs.map((o, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={o.ifname} onChange={e => setOspfv2Ifs(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Interface" />
                <input value={o.cost} onChange={e => setOspfv2Ifs(a => a.map((x, j) => j === i ? { ...x, cost: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                <input value={o.priority} onChange={e => setOspfv2Ifs(a => a.map((x, j) => j === i ? { ...x, priority: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                <input value={o.hello} onChange={e => setOspfv2Ifs(a => a.map((x, j) => j === i ? { ...x, hello: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                <input value={o.dead} onChange={e => setOspfv2Ifs(a => a.map((x, j) => j === i ? { ...x, dead: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                <select value={o.bfd} onChange={e => setOspfv2Ifs(a => a.map((x, j) => j === i ? { ...x, bfd: e.target.value } : x))} className={cn(selectCls, 'w-14')}><option value="false">No</option><option value="true">Yes</option></select>
                {delBtn(() => setOspfv2Ifs(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Interface', () => setOspfv2Ifs(a => [...a, { ifname: '', cost: '10', priority: '1', hello: '10', dead: '40', bfd: 'false' }]))}
            {rangeMode.ospfv2If && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {ospfv2IfRanges.map((r, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                    <input value={r.startIntf} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, startIntf: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Start Intf" />
                    <input value={r.cost} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, cost: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Cost" />
                    <input value={r.priority} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, priority: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Pri" />
                    <input value={r.hello} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, hello: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Hello" />
                    <input value={r.dead} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, dead: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Dead" />
                    <select value={r.bfd} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, bfd: e.target.value } : x))} className={cn(selectCls, 'w-14')}><option value="false">No</option><option value="true">Yes</option></select>
                    <input type="number" value={r.count} onChange={e => setOspfv2IfRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    {delBtn(() => setOspfv2IfRanges(a => a.filter((_, j) => j !== i)))}
                  </div>
                ))}
                {addBtn('Add Range', () => setOspfv2IfRanges(a => [...a, { startIntf: '', cost: '10', priority: '1', hello: '10', dead: '40', bfd: 'false', count: '1' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* OSPFv3 Interfaces */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="ospfv3If" label="OSPFv3 Interfaces" count={ospfv3Ifs.length + ospfv3IfRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('ospfv3If')} icon={<Route className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.ospfv3If && (
          <div className="p-3 space-y-1">
            {ospfv3Ifs.map((o, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={o.ifname} onChange={e => setOspfv3Ifs(a => a.map((x, j) => j === i ? { ...x, ifname: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Interface" />
                <input value={o.processId} onChange={e => setOspfv3Ifs(a => a.map((x, j) => j === i ? { ...x, processId: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="PID" />
                <input value={o.areaId} onChange={e => setOspfv3Ifs(a => a.map((x, j) => j === i ? { ...x, areaId: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Area" />
                <select value={o.bfd} onChange={e => setOspfv3Ifs(a => a.map((x, j) => j === i ? { ...x, bfd: e.target.value } : x))} className={cn(selectCls, 'w-14')}><option value="false">No</option><option value="true">Yes</option></select>
                <select value={o.authType} onChange={e => setOspfv3Ifs(a => a.map((x, j) => j === i ? { ...x, authType: e.target.value } : x))} className={cn(selectCls, 'w-20')}><option value="AREA">AREA</option><option value="INTERFACE">INTF</option><option value="NONE">NONE</option></select>
                {delBtn(() => setOspfv3Ifs(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Interface', () => setOspfv3Ifs(a => [...a, { ifname: '', processId: '1', areaId: '0', bfd: 'false', authType: 'AREA' }]))}
            {rangeMode.ospfv3If && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {ospfv3IfRanges.map((r, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                    <input value={r.startIntf} onChange={e => setOspfv3IfRanges(a => a.map((x, j) => j === i ? { ...x, startIntf: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Start Intf" />
                    <input value={r.processId} onChange={e => setOspfv3IfRanges(a => a.map((x, j) => j === i ? { ...x, processId: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="PID" />
                    <input value={r.areaId} onChange={e => setOspfv3IfRanges(a => a.map((x, j) => j === i ? { ...x, areaId: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Area" />
                    <select value={r.bfd} onChange={e => setOspfv3IfRanges(a => a.map((x, j) => j === i ? { ...x, bfd: e.target.value } : x))} className={cn(selectCls, 'w-14')}><option value="false">No</option><option value="true">Yes</option></select>
                    <select value={r.authType} onChange={e => setOspfv3IfRanges(a => a.map((x, j) => j === i ? { ...x, authType: e.target.value } : x))} className={cn(selectCls, 'w-20')}><option value="AREA">AREA</option><option value="INTERFACE">INTF</option><option value="NONE">NONE</option></select>
                    <input type="number" value={r.count} onChange={e => setOspfv3IfRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    {delBtn(() => setOspfv3IfRanges(a => a.filter((_, j) => j !== i)))}
                  </div>
                ))}
                {addBtn('Add Range', () => setOspfv3IfRanges(a => [...a, { startIntf: '', processId: '1', areaId: '0', bfd: 'false', authType: 'AREA', count: '1' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* IPv4 Static Routes (with range mode) */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="v4route" label="IPv4 Static Routes" count={v4routes.length + v4routeRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('v4route')} icon={<MapPin className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.v4route && (
          <div className="p-3 space-y-1">
            {v4routes.map((r, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                <input value={r.iface} onChange={e => setV4routes(a => a.map((x, j) => j === i ? { ...x, iface: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Interface" />
                <input value={r.network} onChange={e => setV4routes(a => a.map((x, j) => j === i ? { ...x, network: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Network" />
                <input value={r.gateway} onChange={e => setV4routes(a => a.map((x, j) => j === i ? { ...x, gateway: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Gateway" />
                <input value={r.metric} onChange={e => setV4routes(a => a.map((x, j) => j === i ? { ...x, metric: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Metric" />
                {delBtn(() => setV4routes(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Route', () => setV4routes(a => [...a, { iface: '', network: '', gateway: '', metric: '1' }]))}
            {rangeMode.v4route && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {v4routeRanges.map((r, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                    <input value={r.startIntf || ''} onChange={e => setV4routeRanges(a => a.map((x, j) => j === i ? { ...x, startIntf: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Start Intf" />
                    <input value={r.startNet || ''} onChange={e => setV4routeRanges(a => a.map((x, j) => j === i ? { ...x, startNet: e.target.value } : x))} className={cn(inputCls, 'w-28')} placeholder="Start Net" />
                    <label className={labelCls}>Oct</label><select value={r.incOctet || '3'} onChange={e => setV4routeRanges(a => a.map((x, j) => j === i ? { ...x, incOctet: e.target.value } : x))} className={cn(selectCls, 'w-14')}>{octOpts}</select>
                    <input value={r.gateway || ''} onChange={e => setV4routeRanges(a => a.map((x, j) => j === i ? { ...x, gateway: e.target.value } : x))} className={cn(inputCls, 'w-24')} placeholder="Gateway" />
                    <input value={r.metric || '1'} onChange={e => setV4routeRanges(a => a.map((x, j) => j === i ? { ...x, metric: e.target.value } : x))} className={cn(inputCls, 'w-14')} placeholder="Metric" />
                    <input type="number" value={r.count || '1'} onChange={e => setV4routeRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    {delBtn(() => setV4routeRanges(a => a.filter((_, j) => j !== i)))}
                  </div>
                ))}
                {addBtn('Add Range', () => setV4routeRanges(a => [...a, { startIntf: '', startNet: '10.0.0.0/8', incOctet: '3', gateway: '', metric: '1', count: '1' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Remaining compact sections */}
      {[
        { id: 'ospfv3', label: 'OSPFv3 Policies', items: ospfv3, set: setOspfv3, fields: ['processId:PID:w-16', 'routerId:Router ID:w-20', 'enabled:Enabled:w-14'], def: { processId: '1', routerId: '', enabled: 'true' } },
        { id: 'eigrp', label: 'EIGRP Policies', items: eigrp, set: setEigrp, fields: ['asn:AS:w-16', 'networks:Networks:flex-1', 'autoSummary:AutoSum:w-14'], def: { asn: '', networks: '', autoSummary: 'false' } },
        { id: 'pbr', label: 'PBR Policies', items: pbr, set: setPbr, fields: ['ifname:Interface:w-32', 'routeMap:Route Map:w-32'], def: { ifname: '', routeMap: '' } },
        { id: 'v6route', label: 'IPv6 Static Routes', items: v6routes, set: setV6routes, fields: ['iface:Interface:w-28', 'network:Network:w-28', 'gateway:Gateway:w-28', 'metric:Metric:w-14'], def: { iface: '', network: '', gateway: '', metric: '1' } },
        { id: 'ecmp', label: 'ECMP Zones', items: ecmpZones, set: setEcmpZones, fields: ['name:Name:w-28', 'interfaces:Interfaces:flex-1'], def: { name: '', interfaces: '' } },
        { id: 'vrf', label: 'VRFs', items: vrfs, set: setVrfs, fields: ['name:Name:w-28', 'description:Desc:w-28', 'interfaces:Interfaces:flex-1'], def: { name: '', description: '', interfaces: '' } },
      ].map(({ id, label, items, set, fields, def }) => (
        <div key={id} className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
          <SH id={id} label={label} count={(items as unknown[]).length} />
          {!collapsed[id] && (
            <div className="p-3 space-y-1">
              {(items as any[]).map((item: any, i: number) => (
                <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                  {fields.map(f => { const [k, ph, w] = f.split(':'); return (
                    <input key={k} value={item[k]} onChange={e => (set as any)((a: any[]) => a.map((x: any, j: number) => j === i ? { ...x, [k]: e.target.value } : x))} className={cn(inputCls, w)} placeholder={ph} />
                  )})}
                  {delBtn(() => (set as any)((a: any[]) => a.filter((_: any, j: number) => j !== i)))}
                </div>
              ))}
              {addBtn(`Add`, () => (set as any)((a: any[]) => [...a, { ...def }]))}
            </div>
          )}
        </div>
      ))}

      {/* ═══ OBJECTS ═══ */}
      <div className="flex items-center gap-2 text-xs font-semibold text-surface-700 dark:text-surface-300 border-b border-surface-200 dark:border-surface-700 pb-1 mt-4"><Box className="w-3.5 h-3.5 text-accent-violet" /> Objects</div>

      {/* Security Zones */}
      <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
        <SH id="sz" label="Security Zones" count={secZones.length + secZoneRanges.reduce((s, r) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle('sz')} icon={<Shield className="w-3.5 h-3.5 text-surface-500" />} />
        {!collapsed.sz && (
          <div className="p-3 space-y-1">
            {secZones.map((z, i) => (
              <div key={i} className="flex items-center gap-2 text-[10px]">
                <input value={z.name} onChange={e => setSecZones(a => a.map((x, j) => j === i ? { ...x, name: e.target.value } : x))} className={cn(inputCls, 'w-32')} placeholder="Name" />
                <select value={z.mode} onChange={e => setSecZones(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-24')}><option value="ROUTED">ROUTED</option><option value="SWITCHED">SWITCHED</option><option value="ASA">ASA</option></select>
                {delBtn(() => setSecZones(a => a.filter((_, j) => j !== i)))}
              </div>
            ))}
            {addBtn('Add Zone', () => setSecZones(a => [...a, { name: '', mode: 'ROUTED' }]))}
            {rangeMode.sz && (
              <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                {secZoneRanges.map((r, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                    <label className={labelCls}>Start Name</label><input value={r.startName} onChange={e => setSecZoneRanges(a => a.map((x, j) => j === i ? { ...x, startName: e.target.value } : x))} className={cn(inputCls, 'w-24')} />
                    <label className={labelCls}>Mode</label><select value={r.mode} onChange={e => setSecZoneRanges(a => a.map((x, j) => j === i ? { ...x, mode: e.target.value } : x))} className={cn(selectCls, 'w-20')}><option value="ROUTED">ROUTED</option><option value="SWITCHED">SWITCHED</option><option value="ASA">ASA</option></select>
                    <label className={labelCls}>Count</label><input type="number" value={r.count} onChange={e => setSecZoneRanges(a => a.map((x, j) => j === i ? { ...x, count: e.target.value } : x))} className={cn(inputCls, 'w-14')} />
                    {delBtn(() => setSecZoneRanges(a => a.filter((_, j) => j !== i)))}
                  </div>
                ))}
                {addBtn('Add Range', () => setSecZoneRanges(a => [...a, { startName: 'zone', mode: 'ROUTED', count: '1' }]))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Host / Range / Network Objects - compact with range modes */}
      {[
        { id: 'host', label: 'Host Objects', items: hosts, set: setHosts, ranges: hostRanges, setRanges: setHostRanges, f1: 'name:Name:w-24', f2: 'value:IP:w-28', rFields: ['startName:Name:w-20', 'startIp:Start IP:w-28', 'incOctet:Oct:w-14', 'count:Count:w-14'], rDef: { startName: 'host', startIp: '10.0.0.1', incOctet: '4', count: '1' } },
        { id: 'rangeObj', label: 'Range Objects', items: rangeObjs, set: setRangeObjs, ranges: rangeObjRanges, setRanges: setRangeObjRanges, f1: 'name:Name:w-24', f2: 'value:Value:w-32', rFields: ['startName:Name:w-20', 'startIp:Start IP:w-28', 'incOctet:Oct:w-14', 'endOffset:End Off:w-14', 'count:Count:w-14'], rDef: { startName: 'range', startIp: '10.0.0.1', incOctet: '4', endOffset: '253', count: '1' } },
        { id: 'networkObj', label: 'Network Objects', items: networkObjs, set: setNetworkObjs, ranges: networkObjRanges, setRanges: setNetworkObjRanges, f1: 'name:Name:w-24', f2: 'value:CIDR:w-32', rFields: ['startName:Name:w-20', 'startValue:Start:w-28', 'incOctet:Oct:w-14', 'count:Count:w-14'], rDef: { startName: 'net', startValue: '10.0.0.0/24', incOctet: '3', count: '1' } },
      ].map(({ id, label, items, set, ranges, setRanges, f1, f2, rFields, rDef }) => (
        <div key={id} className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
          <SH id={id} label={label} count={(items as unknown[]).length + (ranges as any[]).reduce((s: number, r: any) => s + (parseInt(r.count) || 0), 0)} extra={rangeToggle(id)} />
          {!collapsed[id] && (
            <div className="p-3 space-y-1">
              {(items as any[]).map((item: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-[10px]">
                  {[f1, f2].map(f => { const [k, ph, w] = f.split(':'); return (
                    <input key={k} value={item[k]} onChange={e => (set as any)((a: any[]) => a.map((x: any, j: number) => j === i ? { ...x, [k]: e.target.value } : x))} className={cn(inputCls, w)} placeholder={ph} />
                  )})}
                  {delBtn(() => (set as any)((a: any[]) => a.filter((_: any, j: number) => j !== i)))}
                </div>
              ))}
              {addBtn('Add', () => (set as any)((a: any[]) => [...a, { name: '', value: '' }]))}
              {rangeMode[id] && (
                <div className="mt-2 pt-2 border-t border-dashed border-surface-200 dark:border-surface-700">
                  <div className="text-[9px] font-medium text-accent-violet mb-1">Range Generator</div>
                  {(ranges as any[]).map((r: any, i: number) => (
                    <div key={i} className="flex flex-wrap items-center gap-2 text-[10px]">
                      {rFields.map(f => { const [k, ph, w] = f.split(':'); return (
                        k === 'incOctet' ? <select key={k} value={r[k]} onChange={e => (setRanges as any)((a: any[]) => a.map((x: any, j: number) => j === i ? { ...x, [k]: e.target.value } : x))} className={cn(selectCls, w)}>{octOpts}</select>
                        : <input key={k} value={r[k]} onChange={e => (setRanges as any)((a: any[]) => a.map((x: any, j: number) => j === i ? { ...x, [k]: e.target.value } : x))} className={cn(inputCls, w)} placeholder={ph} />
                      )})}
                      {delBtn(() => (setRanges as any)((a: any[]) => a.filter((_: any, j: number) => j !== i)))}
                    </div>
                  ))}
                  {addBtn('Add Range', () => (setRanges as any)((a: any[]) => [...a, { ...rDef }]))}
                </div>
              )}
            </div>
          )}
        </div>
      ))}

      {/* Preview trigger */}
      <div className="pt-2">
        <button onClick={handlePreview} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
          Preview YAML
        </button>
      </div>
    </div>
  )
}

export { deviceConfigToYaml }
export type { DeviceTemplateState }
