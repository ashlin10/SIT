import { useState, useEffect, useRef } from 'react'
import { cn, selectCls } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { fetchTemplateLookups, uploadChassisConfig, uploadConfig } from './api'
import {
  X, Plus, Trash2, Layers, Eye, Zap,
  ChevronDown, ChevronUp,
  Cpu, Network, GitBranch, Server,
  Settings, IdCard, Cable,
} from 'lucide-react'
import DeviceTemplateContent from './DeviceTemplateContent'

// ── Types ──

interface PhyIntf { name: string; portType: string; enabled: boolean; speed: string; duplex: string; fecMode: string }
interface EcIntf { channelId: string; members: string[]; portType: string; enabled: boolean; lacpMode: string; speed: string }
interface SubIntf { parent: string; vlanStart: string; vlanEnd: string; portType: string }
interface PortRow { type: string; interfaceName: string; portType: string }
interface RangeRow { parent: string; vlanStart: string; vlanEnd: string; portType: string }
interface IndividualLdPorts { ldName: string; ports: PortRow[]; ranges: RangeRow[] }
interface LogicalDevice {
  name: string
  allPorts: PortRow[]
  allRanges: RangeRow[]
  individualLds: IndividualLdPorts[]
  mgmtIpv4Start: string; mgmtIpv4Gw: string; mgmtIpv4Mask: string
  mgmtIpv6Start: string; mgmtIpv6Gw: string; mgmtIpv6Prefix: string
  fqdnDomain: string; searchDomain: string; dnsServers: string
  fwMode: string; expertMode: string; adminPwd: string
  accessPolicy: string; deviceGroup: string; platformSettings: string; resourceProfile: string
  licenses: { carrier: boolean; malware: boolean; threat: boolean; urlFilter: boolean }
  adminState: string
}

interface TemplateModalProps {
  open: boolean
  onClose: () => void
  mode: 'chassis' | 'device'
}

// ── Helper: YAML builder ──

// ── IP helpers ──

function incrementIpv4(ip: string, offset: number): string {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4) return ip
  let val = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3] + offset
  return [(val >>> 24) & 0xff, (val >>> 16) & 0xff, (val >>> 8) & 0xff, val & 0xff].join('.')
}

function incrementIpv6Last(ip: string, offset: number): string {
  // Expand :: notation
  const halves = ip.split('::')
  let groups: string[]
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : []
    const right = halves[1] ? halves[1].split(':') : []
    const fill = 8 - left.length - right.length
    groups = [...left, ...Array(fill).fill('0'), ...right]
  } else {
    groups = ip.split(':')
  }
  while (groups.length < 8) groups.push('0')
  // Increment last group
  groups[7] = (parseInt(groups[7], 16) + offset).toString(16)
  // Compress back
  const full = groups.map(g => g.replace(/^0+/, '') || '0')
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
  for (let i = 0; i < 8; i++) {
    if (full[i] === '0') {
      if (curStart === -1) curStart = i
      curLen++
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen }
    } else { curStart = -1; curLen = 0 }
  }
  if (bestLen >= 2) {
    const before = full.slice(0, bestStart).join(':')
    const after = full.slice(bestStart + bestLen).join(':')
    return `${before}::${after}`
  }
  return full.join(':')
}

// ── YAML builder: FMC API-compatible format ──

function chassisConfigToYaml(
  phyInterfaces: PhyIntf[],
  ecInterfaces: EcIntf[],
  subInterfaces: SubIntf[],
  ldState: LogicalDevice,
  ldCount: number,
  baseName: string,
  ftdVersion: string,
  lookups: Record<string, { id: string; name: string }[]>,
): string {
  const lines: string[] = []
  const q = (s: string) => `'${s}'`  // single-quote wrapper
  const hasIntf = phyInterfaces.length || ecInterfaces.length || subInterfaces.length
  if (hasIntf) lines.push('chassis_interfaces:')

  // --- Physical Interfaces ---
  if (phyInterfaces.length) {
    lines.push('  physicalinterfaces:')
    for (const p of phyInterfaces) {
      lines.push(`    - type: PhysicalInterface`)
      lines.push(`      name: ${p.name}`)
      lines.push(`      portType: ${p.portType}`)
      lines.push(`      adminState: ${p.enabled ? 'ENABLED' : 'DISABLED'}`)
      lines.push(`      hardware:`)
      lines.push(`        speed: ${p.speed || 'ONE_GBPS'}`)
      lines.push(`        duplex: ${p.duplex || 'FULL'}`)
      lines.push(`        fecMode: ${p.fecMode || 'AUTO'}`)
      lines.push(`        autoNegState: true`)
    }
  }

  // --- EtherChannel Interfaces ---
  if (ecInterfaces.length) {
    lines.push('  etherchannelinterfaces:')
    for (const e of ecInterfaces) {
      const ecName = `Port-channel${e.channelId}`
      lines.push(`    - type: EtherChannelInterface`)
      lines.push(`      name: ${q(ecName)}`)
      lines.push(`      portType: ${e.portType}`)
      lines.push(`      etherChannelId: ${e.channelId}`)
      if (e.members.length) {
        lines.push(`      selectedInterfaces:`)
        for (const m of e.members) {
          lines.push(`        - type: PhysicalInterface`)
          lines.push(`          name: ${m}`)
        }
      }
      lines.push(`      lacpMode: ${e.lacpMode ? e.lacpMode.toUpperCase() : 'ACTIVE'}`)
      lines.push(`      lacpRate: DEFAULT`)
      lines.push(`      adminState: ${e.enabled ? 'ENABLED' : 'DISABLED'}`)
      lines.push(`      hardware:`)
      lines.push(`        speed: ${e.speed || 'DETECT_SFP'}`)
      lines.push(`        duplex: FULL`)
      lines.push(`        autoNegState: true`)
    }
  }

  // --- Subinterfaces (expand VLAN ranges) ---
  if (subInterfaces.length) {
    lines.push('  subinterfaces:')
    for (const s of subInterfaces) {
      const vs = parseInt(s.vlanStart) || 0
      const ve = parseInt(s.vlanEnd) || vs
      // Determine parent type
      const parentIsEc = ecInterfaces.some(e => `Port-channel${e.channelId}` === s.parent)
      const parentType = parentIsEc ? 'EtherChannelInterface' : 'PhysicalInterface'
      for (let v = vs; v <= ve; v++) {
        lines.push(`    - type: SubInterface`)
        lines.push(`      name: ${q(s.parent + '.' + v)}`)
        lines.push(`      portType: ${s.portType}`)
        lines.push(`      subIntfId: ${v}`)
        lines.push(`      parentInterface:`)
        lines.push(`        type: ${parentType}`)
        lines.push(`        name: ${q(s.parent)}`)
        lines.push(`      vlanId: ${v}`)
      }
    }
  }

  // --- Lookup helpers to resolve id/type from name ---
  const findLookup = (key: string, name: string) => {
    const items = (lookups[key] || []) as { id: string; name: string; type?: string }[]
    return items.find(i => i.name === name)
  }

  // --- Helper: map port type to FMC external port link format ---
  const portTypeLower = (pt: string) => {
    if (pt === 'DATA_SHARING') return 'data-sharing'
    return pt.toLowerCase()
  }

  // --- Helper: resolve interface type string for externalPortLink ---
  const resolveIntfType = (row: PortRow) => {
    if (row.type === 'EtherChannel') return 'EtherChannelInterface'
    if (row.type === 'Subinterface') return 'SubInterface'
    return 'PhysicalInterface'
  }

  // --- Logical Devices ---
  lines.push('logical_devices:')
  for (let i = 0; i < ldCount; i++) {
    const ldName = `${baseName}${i + 1}`
    lines.push(`  - ftdApplicationVersion: ${ftdVersion}`)

    // externalPortLink: collect from allPorts, allRanges, and individualLd
    const extPorts: string[] = []

    // Ports assigned to all LDs
    for (const p of ldState.allPorts) {
      extPorts.push(`      - name: ${q(p.interfaceName)}`)
      extPorts.push(`        type: ${resolveIntfType(p)}`)
      extPorts.push(`        portType: ${q(portTypeLower(p.portType))}`)
    }

    // Ranges assigned to all LDs: assign VLANs incrementally
    for (const r of ldState.allRanges) {
      const vs = parseInt(r.vlanStart) || 0
      const ve = parseInt(r.vlanEnd) || vs
      const totalVlans = ve - vs + 1
      const vlansPerLd = Math.max(1, Math.floor(totalVlans / ldCount))
      const startVlan = vs + i * vlansPerLd
      const endVlan = (i === ldCount - 1) ? ve : Math.min(startVlan + vlansPerLd - 1, ve)
      for (let v = startVlan; v <= endVlan; v++) {
        const subName = `${r.parent}.${v}`
        extPorts.push(`      - name: ${q(subName)}`)
        extPorts.push(`        type: SubInterface`)
        extPorts.push(`        portType: ${portTypeLower(r.portType)}`)
      }
    }

    // Individual LD ports/ranges
    const indiv = ldState.individualLds.find(x => x.ldName === ldName)
    if (indiv) {
      for (const p of indiv.ports) {
        extPorts.push(`      - name: ${q(p.interfaceName)}`)
        extPorts.push(`        type: ${resolveIntfType(p)}`)
        extPorts.push(`        portType: ${q(portTypeLower(p.portType))}`)
      }
      for (const r of indiv.ranges) {
        const vs = parseInt(r.vlanStart) || 0
        const ve = parseInt(r.vlanEnd) || vs
        for (let v = vs; v <= ve; v++) {
          const subName = `${r.parent}.${v}`
          extPorts.push(`      - name: ${q(subName)}`)
          extPorts.push(`        type: SubInterface`)
          extPorts.push(`        portType: ${portTypeLower(r.portType)}`)
        }
      }
    }

    if (extPorts.length) {
      lines.push('    externalPortLink:')
      lines.push(...extPorts)
    }

    // managementBootstrap
    lines.push('    managementBootstrap:')
    const ipv4 = incrementIpv4(ldState.mgmtIpv4Start, i)
    lines.push(`      ipv4:`)
    lines.push(`        gateway: ${ldState.mgmtIpv4Gw}`)
    lines.push(`        mask: ${ldState.mgmtIpv4Mask}`)
    lines.push(`        ip: ${ipv4}`)
    if (ldState.mgmtIpv6Start) {
      const ipv6 = incrementIpv6Last(ldState.mgmtIpv6Start, i)
      lines.push(`      ipv6:`)
      lines.push(`        gateway: ${q(ldState.mgmtIpv6Gw)}`)
      lines.push(`        ip: ${q(ipv6)}`)
      lines.push(`        prefixLength: ${ldState.mgmtIpv6Prefix || '64'}`)
    }
    lines.push(`      permitExpertMode: ${q(ldState.expertMode)}`)
    lines.push(`      searchDomain: ${ldState.searchDomain}`)
    lines.push(`      firewallMode: ${ldState.fwMode}`)
    lines.push(`      dnsServers: ${q(ldState.dnsServers)}`)
    lines.push(`      adminPassword: ${q(ldState.adminPwd)}`)
    const fqdn = `${ldName}.${ldState.fqdnDomain}`
    lines.push(`      fqdn: ${q(fqdn)}`)

    // deviceRegistration
    const lics = Object.entries(ldState.licenses).filter(([, v]) => v).map(([k]) => k === 'urlFilter' ? 'URLFilter' : k.toUpperCase())
    lines.push('    deviceRegistration:')
    if (lics.length) {
      lines.push('      licenseCaps:')
      for (const l of lics) lines.push(`        - ${l}`)
    }
    if (ldState.accessPolicy) {
      const ap = findLookup('accessPolicies', ldState.accessPolicy)
      lines.push('      accessPolicy:')
      lines.push(`        name: ${ldState.accessPolicy}`)
      if (ap) lines.push(`        id: ${q(ap.id)}`)
      lines.push(`        type: AccessPolicy`)
    }
    if (ldState.deviceGroup) {
      const dg = findLookup('deviceGroups', ldState.deviceGroup)
      lines.push('      deviceGroup:')
      lines.push(`        name: ${ldState.deviceGroup}`)
      if (dg) lines.push(`        id: ${q(dg.id)}`)
      lines.push(`        type: DeviceGroupId`)
    }
    if (ldState.platformSettings) {
      const ps = findLookup('platformSettings', ldState.platformSettings)
      lines.push('      platformSettings:')
      lines.push(`        name: ${q(ldState.platformSettings)}`)
      if (ps) lines.push(`        id: ${q(ps.id)}`)
      lines.push(`        type: PG.PLATFORM.NgfwPFSettings`)
    }
    // resourceProfile
    if (ldState.resourceProfile) {
      const rp = findLookup('resourceProfiles', ldState.resourceProfile)
      lines.push('    resourceProfile:')
      lines.push(`      name: ${q(ldState.resourceProfile)}`)
      if (rp) lines.push(`      id: ${q(rp.id)}`)
      lines.push(`      type: ResourceProfile`)
    }
    lines.push(`    adminState: ${ldState.adminState}`)
    lines.push(`    name: ${q(ldName)}`)
    lines.push(`    type: LogicalDevice`)
  }

  return lines.join('\n') + '\n'
}

// ── Default logical device state ──

const defaultLd = (): LogicalDevice => ({
  name: '',
  allPorts: [], allRanges: [], individualLds: [],
  mgmtIpv4Start: '192.168.2.231', mgmtIpv4Gw: '192.168.2.1', mgmtIpv4Mask: '255.255.255.0',
  mgmtIpv6Start: '2000:2::231', mgmtIpv6Gw: '2000:2::1', mgmtIpv6Prefix: '64',
  fqdnDomain: 'blr.sit.com', searchDomain: 'blr.sit.com', dnsServers: '10.196.156.154,72.163.128.140,64.104.128.236',
  fwMode: 'routed', expertMode: 'yes', adminPwd: 'Cisco@12',
  accessPolicy: '', deviceGroup: '', platformSettings: '', resourceProfile: '',
  licenses: { carrier: true, malware: true, threat: true, urlFilter: true },
  adminState: 'enabled',
})

// ── Component ──

export default function TemplateModal({ open, onClose, mode }: TemplateModalProps) {
  const { connected } = useFmcConfigStore()

  const [lookups, setLookups] = useState<Record<string, { id: string; name: string }[]>>({})
  const [loadingLookups, setLoadingLookups] = useState(false)

  const [baseName, setBaseName] = useState('tpk-3-')
  const [ldCount, setLdCount] = useState(3)
  const [ftdVersion, setFtdVersion] = useState('10.5.0.0.1344')
  const [phyInterfaces, setPhyInterfaces] = useState<PhyIntf[]>(() =>
    Array.from({ length: 16 }, (_, i) => ({
      name: `Ethernet1/${i + 1}`, portType: 'DATA',
      enabled: true, speed: '', duplex: '', fecMode: '',
    }))
  )
  const [ecInterfaces, setEcInterfaces] = useState<EcIntf[]>([
    { channelId: '10', members: ['Ethernet1/1', 'Ethernet1/2'], portType: 'DATA_SHARING', enabled: true, lacpMode: 'active', speed: '' },
    { channelId: '20', members: ['Ethernet1/3', 'Ethernet1/4'], portType: 'DATA_SHARING', enabled: true, lacpMode: 'active', speed: '' },
    { channelId: '30', members: ['Ethernet1/5', 'Ethernet1/6'], portType: 'DATA_SHARING', enabled: true, lacpMode: 'active', speed: '' },
  ])
  const [subInterfaces, setSubInterfaces] = useState<SubIntf[]>([])
  const [ldState, setLdState] = useState<LogicalDevice>(defaultLd)

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ phy: false, ec: true, sub: true, ld: false, dp: true, mgmt: false, reg: false })
  const toggle = (id: string) => setCollapsed((c) => ({ ...c, [id]: !c[id] }))

  const [preview, setPreview] = useState('')
  const deviceBuildYamlRef = useRef<(() => string) | null>(null)

  useEffect(() => {
    if (!open || !connected) return
    setLoadingLookups(true)
    fetchTemplateLookups().then((data) => {
      if (data.success) setLookups(data)
    }).finally(() => setLoadingLookups(false))
  }, [open, connected])

  const allParentNames = [
    ...phyInterfaces.map(p => p.name),
    ...ecInterfaces.map(e => `Port-channel${e.channelId}`),
  ]

  // Expand subinterface VLAN ranges into individual names
  const subInterfaceNames = subInterfaces.flatMap(s => {
    const vs = parseInt(s.vlanStart) || 0
    const ve = parseInt(s.vlanEnd) || vs
    const names: string[] = []
    for (let v = vs; v <= ve; v++) names.push(`${s.parent}.${v}`)
    return names
  })

  // Return interface names filtered by selected type
  const getNamesByType = (type: string): string[] => {
    if (type === 'Physical') return phyInterfaces.map(p => p.name)
    if (type === 'EtherChannel') return ecInterfaces.map(e => `Port-channel${e.channelId}`)
    if (type === 'Subinterface') return subInterfaceNames
    return [...phyInterfaces.map(p => p.name), ...ecInterfaces.map(e => `Port-channel${e.channelId}`), ...subInterfaceNames]
  }

  // DATA_SHARING-only names filtered by type (for "Assigned to all LDs")
  const getDataSharingNamesByType = (type: string): string[] => {
    if (type === 'Physical') return phyInterfaces.filter(p => p.portType === 'DATA_SHARING').map(p => p.name)
    if (type === 'EtherChannel') return ecInterfaces.filter(e => e.portType === 'DATA_SHARING').map(e => `Port-channel${e.channelId}`)
    if (type === 'Subinterface') return subInterfaceNames  // subinterfaces inherit parent port type, show all
    return [
      ...phyInterfaces.filter(p => p.portType === 'DATA_SHARING').map(p => p.name),
      ...ecInterfaces.filter(e => e.portType === 'DATA_SHARING').map(e => `Port-channel${e.channelId}`),
    ]
  }

  const handlePreview = () => {
    if (mode === 'device' && deviceBuildYamlRef.current) {
      setPreview(deviceBuildYamlRef.current())
    } else {
      setPreview(chassisConfigToYaml(phyInterfaces, ecInterfaces, subInterfaces, ldState, ldCount, baseName, ftdVersion, lookups))
    }
  }

  const handleGenerate = async () => {
    let yaml: string
    let filename: string
    if (mode === 'chassis') {
      if (!baseName.trim()) { alert('Base Name is required'); return }
      yaml = chassisConfigToYaml(phyInterfaces, ecInterfaces, subInterfaces, ldState, ldCount, baseName, ftdVersion, lookups)
      filename = `chassis_template_${baseName}${ldCount}.yaml`
    } else {
      yaml = deviceBuildYamlRef.current ? deviceBuildYamlRef.current() : preview
      if (!yaml.trim()) { alert('Nothing to generate. Add some configuration first.'); return }
      filename = `device_template_${Date.now()}.yaml`
    }
    const blob = new Blob([yaml], { type: 'application/x-yaml' })
    const file = new File([blob], filename, { type: 'application/x-yaml' })
    if (mode === 'chassis') {
      const result = await uploadChassisConfig(file, yaml)
      if (result.success) onClose(); else alert(result.message || 'Failed')
    } else {
      const result = await uploadConfig(file, yaml)
      if (result.success) onClose(); else alert(result.message || 'Failed')
    }
  }

  if (!open) return null

  const inputCls = cn(
    'rounded-lg border px-2 py-1 text-xs',
    'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50',
    'text-surface-800 dark:text-surface-200',
    'hover:border-vyper-400 dark:hover:border-vyper-500',
    'focus:outline-none focus:ring-2 focus:ring-vyper-500/20 focus:border-vyper-500',
    'transition-colors'
  )
  const labelCls = 'text-[10px] font-medium text-surface-500'
  const sectionHeaderCls = 'flex items-center justify-between px-3 py-2 bg-surface-50 dark:bg-surface-800/50 cursor-pointer'
  const subSectionCls = 'rounded border border-surface-150 dark:border-surface-700/50 p-3 mt-2'

  const updatePhy = (idx: number, field: keyof PhyIntf, value: string | boolean) => {
    setPhyInterfaces((p) => p.map((item, i) => i === idx ? { ...item, [field]: value } : item))
  }
  const addPhy = () => {
    const last = phyInterfaces[phyInterfaces.length - 1]
    const match = last?.name.match(/Ethernet(\d+)\/(\d+)/)
    const slot = match ? parseInt(match[1]) : 1
    const port = match ? parseInt(match[2]) + 1 : phyInterfaces.length + 1
    const newPort = port > 16 ? `Ethernet${slot + 1}/${port - 16}` : `Ethernet${slot}/${port}`
    setPhyInterfaces((p) => [...p, { name: newPort, portType: 'DATA', enabled: true, speed: '', duplex: '', fecMode: '' }])
  }

  const updateLd = (field: string, value: unknown) => setLdState(s => ({ ...s, [field]: value }))
  const updateLdLicense = (lic: string, v: boolean) => setLdState(s => ({ ...s, licenses: { ...s.licenses, [lic]: v } }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className={cn(
        'relative w-[90vw] max-w-5xl max-h-[85vh] flex flex-col',
        'bg-white dark:bg-surface-900 rounded-xl border border-surface-200 dark:border-surface-800',
        'shadow-2xl overflow-hidden'
      )}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-200 dark:border-surface-800/50 shrink-0">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-accent-violet" />
            <h3 className="text-sm font-medium text-surface-800 dark:text-surface-200">
              {mode === 'chassis' ? 'Chassis' : 'Device'} Template Generator
            </h3>
            {loadingLookups && <span className="text-[10px] text-surface-400 animate-pulse">Loading FMC lookups…</span>}
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">

          {mode === 'chassis' && (
            <>
              {/* ═══ SECTION 1: CHASSIS INTERFACES ═══ */}
              <div className="flex items-center gap-2 text-xs font-semibold text-surface-700 dark:text-surface-300 border-b border-surface-200 dark:border-surface-700 pb-1"><Cpu className="w-3.5 h-3.5 text-accent-violet" /> Chassis Interfaces</div>

              {/* Physical Interfaces */}
              <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                <div className={sectionHeaderCls} onClick={() => toggle('phy')}>
                  <div className="flex items-center gap-2">
                    {collapsed.phy ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
                    <Cable className="w-3.5 h-3.5 text-surface-500" />
                    <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Physical Interfaces</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">{phyInterfaces.length}</span>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); addPhy() }} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5">
                    <Plus className="w-3 h-3" /> Add
                  </button>
                </div>
                {!collapsed.phy && (
                  <div className="p-3 space-y-1">
                    <div className="grid grid-cols-[120px_1fr_1fr_1fr_1fr_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                      <span>Name</span><span>Port Type</span><span>Admin State</span><span>Speed</span><span>Duplex</span><span>FEC Mode</span><span></span>
                    </div>
                    {phyInterfaces.map((p, i) => (
                      <div key={i} className="grid grid-cols-[120px_1fr_1fr_1fr_1fr_1fr_auto] gap-2 items-center">
                        <input value={p.name} onChange={(e) => updatePhy(i, 'name', e.target.value)} className={cn(inputCls, 'w-full')} />
                        <select value={p.portType} onChange={(e) => updatePhy(i, 'portType', e.target.value)} className={cn(selectCls, 'w-full')}>
                          <option value="DATA">DATA</option>
                          <option value="DATA_SHARING">DATA_SHARING</option>
                          <option value="MGMT">MGMT</option>
                          <option value="FIREPOWER_EVENTING">FIREPOWER_EVENTING</option>
                          <option value="CLUSTER">CLUSTER</option>
                        </select>
                        <select value={p.enabled ? 'enabled' : 'disabled'} onChange={(e) => updatePhy(i, 'enabled', e.target.value === 'enabled')} className={cn(selectCls, 'w-full')}>
                          <option value="enabled">Enabled</option>
                          <option value="disabled">Disabled</option>
                        </select>
                        <select value={p.speed} onChange={(e) => updatePhy(i, 'speed', e.target.value)} className={cn(selectCls, 'w-full')}>
                          <option value="">ONE_GBPS</option>
                          <option value="ONE_GBPS">ONE_GBPS</option>
                          <option value="DETECT_SFP">DETECT_SFP</option>
                          <option value="TEN_GBPS">TEN_GBPS</option>
                          <option value="TWENTY_FIVE_GBPS">TWENTY_FIVE_GBPS</option>
                          <option value="FORTY_GBPS">FORTY_GBPS</option>
                          <option value="HUNDRED_GBPS">HUNDRED_GBPS</option>
                        </select>
                        <select value={p.duplex} onChange={(e) => updatePhy(i, 'duplex', e.target.value)} className={cn(selectCls, 'w-full')}>
                          <option value="">FULL</option>
                          <option value="FULL">FULL</option>
                          <option value="HALF">HALF</option>
                          <option value="AUTO">AUTO</option>
                        </select>
                        <select value={p.fecMode} onChange={(e) => updatePhy(i, 'fecMode', e.target.value)} className={cn(selectCls, 'w-full')}>
                          <option value="">AUTO</option>
                          <option value="AUTO">AUTO</option>
                          <option value="CL74">CL74</option>
                          <option value="CL91">CL91</option>
                          <option value="OFF">OFF</option>
                        </select>
                        <button onClick={() => setPhyInterfaces((a) => a.filter((_, j) => j !== i))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose">
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* EtherChannel Interfaces */}
              <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                <div className={sectionHeaderCls} onClick={() => toggle('ec')}>
                  <div className="flex items-center gap-2">
                    {collapsed.ec ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
                    <GitBranch className="w-3.5 h-3.5 text-surface-500" />
                    <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">EtherChannel Interfaces</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">{ecInterfaces.length}</span>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); setEcInterfaces(a => [...a, { channelId: String((a.length + 1) * 10), members: [], portType: 'DATA_SHARING', enabled: true, lacpMode: 'active', speed: '' }]) }} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5">
                    <Plus className="w-3 h-3" /> Add
                  </button>
                </div>
                {!collapsed.ec && (
                  <div className="p-3 space-y-1">
                    <div className="grid grid-cols-[70px_1fr_1fr_1fr_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                      <span>Channel ID</span><span>Port Type</span><span>LACP Mode</span><span>Admin State</span><span>Speed</span><span></span>
                    </div>
                    {ecInterfaces.map((e, i) => (
                      <div key={i} className="space-y-1">
                        <div className="grid grid-cols-[70px_1fr_1fr_1fr_1fr_auto] gap-2 items-center">
                          <input value={e.channelId} onChange={(ev) => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, channelId: ev.target.value } : item))} className={cn(inputCls, 'w-full')} />
                          <select value={e.portType} onChange={(ev) => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, portType: ev.target.value } : item))} className={cn(selectCls, 'w-full')}>
                            <option value="DATA">DATA</option>
                            <option value="DATA_SHARING">DATA_SHARING</option>
                            <option value="CLUSTER">CLUSTER</option>
                          </select>
                          <select value={e.lacpMode} onChange={(ev) => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, lacpMode: ev.target.value } : item))} className={cn(selectCls, 'w-full')}>
                            <option value="active">Active</option>
                            <option value="passive">Passive</option>
                            <option value="on">On</option>
                          </select>
                          <select value={e.enabled ? 'enabled' : 'disabled'} onChange={(ev) => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, enabled: ev.target.value === 'enabled' } : item))} className={cn(selectCls, 'w-full')}>
                            <option value="enabled">Enabled</option>
                            <option value="disabled">Disabled</option>
                          </select>
                          <select value={e.speed} onChange={(ev) => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, speed: ev.target.value } : item))} className={cn(selectCls, 'w-full')}>
                            <option value="">DETECT_SFP</option>
                            <option value="DETECT_SFP">DETECT_SFP</option>
                            <option value="ONE_GBPS">ONE_GBPS</option>
                            <option value="TEN_GBPS">TEN_GBPS</option>
                            <option value="TWENTY_FIVE_GBPS">TWENTY_FIVE_GBPS</option>
                            <option value="FORTY_GBPS">FORTY_GBPS</option>
                          </select>
                          <button onClick={() => setEcInterfaces(a => a.filter((_, j) => j !== i))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose">
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                        <div className="pl-[70px]">
                          <label className={labelCls}>Member Interfaces ({e.members.length}/8)</label>
                          <div className="flex flex-wrap items-center gap-1 mt-0.5">
                            {e.members.map((m, mi) => (
                              <div key={mi} className="flex items-center gap-0.5">
                                <select value={m} onChange={(ev) => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, members: item.members.map((mm, mj) => mj === mi ? ev.target.value : mm) } : item))} className={cn(selectCls, 'text-[10px] py-0.5 px-1')}>
                                  {phyInterfaces.map(p => <option key={p.name} value={p.name}>{p.name}</option>)}
                                </select>
                                <button onClick={() => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, members: item.members.filter((_, mj) => mj !== mi) } : item))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-2.5 h-2.5" /></button>
                              </div>
                            ))}
                            {e.members.length < 8 && (
                              <button onClick={() => setEcInterfaces(a => a.map((item, j) => j === i ? { ...item, members: [...item.members, phyInterfaces[0]?.name || ''] } : item))} className="text-[9px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5 px-1.5 py-0.5 rounded border border-dashed border-surface-300 dark:border-surface-600">
                                <Plus className="w-2.5 h-2.5" /> Member
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                    {ecInterfaces.length === 0 && <p className="text-[10px] text-surface-400 text-center py-2">No EtherChannel interfaces</p>}
                  </div>
                )}
              </div>

              {/* Subinterfaces */}
              <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                <div className={sectionHeaderCls} onClick={() => toggle('sub')}>
                  <div className="flex items-center gap-2">
                    {collapsed.sub ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
                    <Network className="w-3.5 h-3.5 text-surface-500" />
                    <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Subinterfaces</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">{subInterfaces.length}</span>
                  </div>
                  <button onClick={(e) => { e.stopPropagation(); setSubInterfaces(a => [...a, { parent: allParentNames[0] || '', vlanStart: '100', vlanEnd: '100', portType: 'DATA_SHARING' }]) }} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5">
                    <Plus className="w-3 h-3" /> Add
                  </button>
                </div>
                {!collapsed.sub && (
                  <div className="p-3 space-y-1">
                    <div className="grid grid-cols-[1fr_80px_80px_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                      <span>Parent Interface</span><span>VLAN Start</span><span>VLAN End</span><span>Port Type</span><span></span>
                    </div>
                    {subInterfaces.map((s, i) => (
                      <div key={i} className="grid grid-cols-[1fr_80px_80px_1fr_auto] gap-2 items-center">
                        <select value={s.parent} onChange={(ev) => setSubInterfaces(a => a.map((item, j) => j === i ? { ...item, parent: ev.target.value } : item))} className={cn(selectCls, 'w-full')}>
                          {allParentNames.map(n => <option key={n} value={n}>{n}</option>)}
                        </select>
                        <input value={s.vlanStart} onChange={(ev) => setSubInterfaces(a => a.map((item, j) => j === i ? { ...item, vlanStart: ev.target.value } : item))} className={cn(inputCls, 'w-full')} />
                        <input value={s.vlanEnd} onChange={(ev) => setSubInterfaces(a => a.map((item, j) => j === i ? { ...item, vlanEnd: ev.target.value } : item))} className={cn(inputCls, 'w-full')} />
                        <select value={s.portType} onChange={(ev) => setSubInterfaces(a => a.map((item, j) => j === i ? { ...item, portType: ev.target.value } : item))} className={cn(selectCls, 'w-full')}>
                          <option value="DATA">DATA</option>
                          <option value="DATA_SHARING">DATA_SHARING</option>
                        </select>
                        <button onClick={() => setSubInterfaces(a => a.filter((_, j) => j !== i))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose">
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                    {subInterfaces.length === 0 && <p className="text-[10px] text-surface-400 text-center py-2">No subinterfaces</p>}
                  </div>
                )}
              </div>

              {/* ═══ SECTION 2: LOGICAL DEVICES ═══ */}
              <div className="flex items-center gap-2 text-xs font-semibold text-surface-700 dark:text-surface-300 border-b border-surface-200 dark:border-surface-700 pb-1 mt-4"><Server className="w-3.5 h-3.5 text-accent-violet" /> Logical Devices</div>

              {/* Basic info */}
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className={labelCls}>Base Name</label>
                  <input value={baseName} onChange={(e) => setBaseName(e.target.value)} className={cn(inputCls, 'w-full mt-1')} placeholder="tpk-3-" />
                  <div className="text-[9px] text-surface-400 mt-0.5">Suffix 1…N appended</div>
                </div>
                <div>
                  <label className={labelCls}>Number of Logical Devices</label>
                  <input type="number" min={1} max={50} value={ldCount} onChange={(e) => setLdCount(Math.max(1, parseInt(e.target.value) || 1))} className={cn(inputCls, 'w-full mt-1')} />
                </div>
                <div>
                  <label className={labelCls}>FTD Application Version</label>
                  <input value={ftdVersion} onChange={(e) => setFtdVersion(e.target.value)} className={cn(inputCls, 'w-full mt-1')} />
                </div>
              </div>

              {/* Data Port Assignments */}
              <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                <div className={sectionHeaderCls} onClick={() => toggle('dp')}>
                  <div className="flex items-center gap-2">
                    {collapsed.dp ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
                    <Network className="w-3.5 h-3.5 text-surface-500" />
                    <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Data Port Assignments</span>
                  </div>
                </div>
                {!collapsed.dp && (
                  <div className="p-3 space-y-3">
                    {/* Assigned to ALL LDs */}
                    <div className={subSectionCls}>
                      <div className="text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-2">Assigned to all logical devices</div>
                      {/* Ports */}
                      <div className="text-[10px] font-medium text-surface-500 mb-1">Ports</div>
                      <div className="text-[9px] text-surface-400 mb-1">Only DATA_SHARING interfaces listed.</div>
                      <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                        <span>Type</span><span>Interface Name</span><span>Port Type</span><span></span>
                      </div>
                      {ldState.allPorts.map((p, i) => (
                        <div key={i} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-center mb-1">
                          <select value={p.type} onChange={(e) => { const newType = e.target.value; const names = getDataSharingNamesByType(newType); const np = [...ldState.allPorts]; np[i] = { ...np[i], type: newType, interfaceName: names[0] || '' }; updateLd('allPorts', np) }} className={cn(selectCls, 'w-full')}>
                            <option value="Physical">Physical</option>
                            <option value="EtherChannel">EtherChannel</option>
                            <option value="Subinterface">Subinterface</option>
                          </select>
                          <select value={p.interfaceName} onChange={(e) => { const np = [...ldState.allPorts]; np[i] = { ...np[i], interfaceName: e.target.value }; updateLd('allPorts', np) }} className={cn(selectCls, 'w-full')}>
                            {getDataSharingNamesByType(p.type).map(n => <option key={n} value={n}>{n}</option>)}
                          </select>
                          <span className="text-[9px] text-surface-500">{p.portType || 'DATA_SHARING'}</span>
                          <button onClick={() => updateLd('allPorts', ldState.allPorts.filter((_, j) => j !== i))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-3 h-3" /></button>
                        </div>
                      ))}
                      <button onClick={() => { const names = getDataSharingNamesByType('Physical'); updateLd('allPorts', [...ldState.allPorts, { type: 'Physical', interfaceName: names[0] || '', portType: 'DATA_SHARING' }]) }} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5 mt-1">
                        <Plus className="w-3 h-3" /> Add Port
                      </button>

                      {/* Ranges */}
                      <div className="text-[10px] font-medium text-surface-500 mt-3 mb-1">Ranges</div>
                      <div className="text-[9px] text-surface-400 mb-1">Subinterfaces assigned in incrementing order, one per LD.</div>
                      <div className="grid grid-cols-[1fr_80px_80px_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                        <span>Parent Interface</span><span>VLAN Start</span><span>VLAN End</span><span>Port Type</span><span></span>
                      </div>
                      {ldState.allRanges.map((r, i) => (
                        <div key={i} className="grid grid-cols-[1fr_80px_80px_1fr_auto] gap-2 items-center mb-1">
                          <select value={r.parent} onChange={(e) => { const nr = [...ldState.allRanges]; nr[i] = { ...nr[i], parent: e.target.value }; updateLd('allRanges', nr) }} className={cn(selectCls, 'w-full')}>
                            {allParentNames.map(n => <option key={n} value={n}>{n}</option>)}
                          </select>
                          <input value={r.vlanStart} onChange={(e) => { const nr = [...ldState.allRanges]; nr[i] = { ...nr[i], vlanStart: e.target.value }; updateLd('allRanges', nr) }} className={cn(inputCls, 'w-full')} />
                          <input value={r.vlanEnd} onChange={(e) => { const nr = [...ldState.allRanges]; nr[i] = { ...nr[i], vlanEnd: e.target.value }; updateLd('allRanges', nr) }} className={cn(inputCls, 'w-full')} />
                          <select value={r.portType} onChange={(e) => { const nr = [...ldState.allRanges]; nr[i] = { ...nr[i], portType: e.target.value }; updateLd('allRanges', nr) }} className={cn(selectCls, 'w-full')}>
                            <option value="DATA">DATA</option>
                            <option value="DATA_SHARING">DATA_SHARING</option>
                          </select>
                          <button onClick={() => updateLd('allRanges', ldState.allRanges.filter((_, j) => j !== i))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-3 h-3" /></button>
                        </div>
                      ))}
                      <button onClick={() => updateLd('allRanges', [...ldState.allRanges, { parent: allParentNames[0] || '', vlanStart: '100', vlanEnd: '100', portType: 'DATA_SHARING' }])} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5 mt-1">
                        <Plus className="w-3 h-3" /> Add Range
                      </button>
                    </div>

                    {/* Assigned to individual LDs */}
                    <div className={subSectionCls}>
                      <div className="text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-2">Assigned to individual logical devices</div>
                      {ldState.individualLds.map((ind, idx) => {
                        const updateIndiv = (field: string, value: unknown) => {
                          const updated = [...ldState.individualLds]
                          updated[idx] = { ...updated[idx], [field]: value }
                          updateLd('individualLds', updated)
                        }
                        return (
                          <div key={idx} className="rounded border border-surface-100 dark:border-surface-700/50 p-2 mb-2 space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <label className={labelCls}>LD Name</label>
                                <input value={ind.ldName} onChange={e => updateIndiv('ldName', e.target.value)} className={cn(inputCls, 'w-44 py-0.5 text-[10px]')} placeholder="Logical device name" />
                              </div>
                              <button onClick={() => updateLd('individualLds', ldState.individualLds.filter((_, j) => j !== idx))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-3 h-3" /></button>
                            </div>
                            {/* Ports */}
                            <div>
                              <div className="text-[10px] font-medium text-surface-500 mb-1">Ports</div>
                              <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                                <span>Type</span><span>Interface Name</span><span>Port Type</span><span></span>
                              </div>
                              {ind.ports.map((p, pi) => (
                                <div key={pi} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-center mb-1">
                                  <select value={p.type} onChange={e => { const newType = e.target.value; const names = getNamesByType(newType); const np = [...ind.ports]; np[pi] = { ...np[pi], type: newType, interfaceName: names[0] || '' }; updateIndiv('ports', np) }} className={cn(selectCls, 'w-full text-[10px] py-0.5')}>
                                    <option value="Physical">Physical</option><option value="EtherChannel">EtherChannel</option><option value="Subinterface">Subinterface</option>
                                  </select>
                                  <select value={p.interfaceName} onChange={e => { const np = [...ind.ports]; np[pi] = { ...np[pi], interfaceName: e.target.value }; updateIndiv('ports', np) }} className={cn(selectCls, 'w-full text-[10px] py-0.5')}>
                                    {getNamesByType(p.type).map(n => <option key={n} value={n}>{n}</option>)}
                                  </select>
                                  <select value={p.portType} onChange={e => { const np = [...ind.ports]; np[pi] = { ...np[pi], portType: e.target.value }; updateIndiv('ports', np) }} className={cn(selectCls, 'w-full text-[10px] py-0.5')}>
                                    <option value="DATA">DATA</option><option value="DATA_SHARING">DATA_SHARING</option>
                                  </select>
                                  <button onClick={() => updateIndiv('ports', ind.ports.filter((_, j) => j !== pi))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-2.5 h-2.5" /></button>
                                </div>
                              ))}
                              <button onClick={() => { const names = getNamesByType('Physical'); updateIndiv('ports', [...ind.ports, { type: 'Physical', interfaceName: names[0] || '', portType: 'DATA' }]) }} className="text-[9px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5 mt-0.5">
                                <Plus className="w-2.5 h-2.5" /> Add Port
                              </button>
                            </div>
                            {/* Ranges */}
                            <div>
                              <div className="text-[10px] font-medium text-surface-500 mb-1">Ranges</div>
                              <div className="grid grid-cols-[1fr_80px_80px_1fr_auto] gap-2 text-[9px] font-medium text-surface-400 px-1 mb-1">
                                <span>Parent Interface</span><span>VLAN Start</span><span>VLAN End</span><span>Port Type</span><span></span>
                              </div>
                              {ind.ranges.map((r, ri) => (
                                <div key={ri} className="grid grid-cols-[1fr_80px_80px_1fr_auto] gap-2 items-center mb-1">
                                  <select value={r.parent} onChange={e => { const nr = [...ind.ranges]; nr[ri] = { ...nr[ri], parent: e.target.value }; updateIndiv('ranges', nr) }} className={cn(selectCls, 'w-full text-[10px] py-0.5')}>
                                    {allParentNames.map(n => <option key={n} value={n}>{n}</option>)}
                                  </select>
                                  <input value={r.vlanStart} onChange={e => { const nr = [...ind.ranges]; nr[ri] = { ...nr[ri], vlanStart: e.target.value }; updateIndiv('ranges', nr) }} className={cn(inputCls, 'w-full text-[10px] py-0.5')} />
                                  <input value={r.vlanEnd} onChange={e => { const nr = [...ind.ranges]; nr[ri] = { ...nr[ri], vlanEnd: e.target.value }; updateIndiv('ranges', nr) }} className={cn(inputCls, 'w-full text-[10px] py-0.5')} />
                                  <select value={r.portType} onChange={e => { const nr = [...ind.ranges]; nr[ri] = { ...nr[ri], portType: e.target.value }; updateIndiv('ranges', nr) }} className={cn(selectCls, 'w-full text-[10px] py-0.5')}>
                                    <option value="DATA">DATA</option><option value="DATA_SHARING">DATA_SHARING</option>
                                  </select>
                                  <button onClick={() => updateIndiv('ranges', ind.ranges.filter((_, j) => j !== ri))} className="p-0.5 text-accent-rose/60 hover:text-accent-rose"><Trash2 className="w-2.5 h-2.5" /></button>
                                </div>
                              ))}
                              <button onClick={() => updateIndiv('ranges', [...ind.ranges, { parent: allParentNames[0] || '', vlanStart: '100', vlanEnd: '100', portType: 'DATA_SHARING' }])} className="text-[9px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5 mt-0.5">
                                <Plus className="w-2.5 h-2.5" /> Add Range
                              </button>
                            </div>
                          </div>
                        )
                      })}
                      <button onClick={() => updateLd('individualLds', [...ldState.individualLds, { ldName: '', ports: [], ranges: [] }])} className="text-[10px] text-vyper-600 hover:text-vyper-700 font-medium flex items-center gap-0.5">
                        <Plus className="w-3 h-3" /> Add
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Management Bootstrap & Device Registration side by side */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Management Bootstrap */}
                <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                  <div className={sectionHeaderCls} onClick={() => toggle('mgmt')}>
                    <div className="flex items-center gap-2">
                      {collapsed.mgmt ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
                      <Settings className="w-3.5 h-3.5 text-surface-500" />
                      <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Management Bootstrap</span>
                    </div>
                  </div>
                  {!collapsed.mgmt && (
                    <div className="p-3 space-y-2">
                      <div className="grid grid-cols-3 gap-2">
                        <div><label className={labelCls}>IPv4 Start</label><input value={ldState.mgmtIpv4Start} onChange={e => updateLd('mgmtIpv4Start', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /><div className="text-[8px] text-surface-400">Increments per LD</div></div>
                        <div><label className={labelCls}>IPv4 Gateway</label><input value={ldState.mgmtIpv4Gw} onChange={e => updateLd('mgmtIpv4Gw', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                        <div><label className={labelCls}>IPv4 Mask</label><input value={ldState.mgmtIpv4Mask} onChange={e => updateLd('mgmtIpv4Mask', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                      </div>
                      <div className="grid grid-cols-3 gap-2">
                        <div><label className={labelCls}>IPv6 Start</label><input value={ldState.mgmtIpv6Start} onChange={e => updateLd('mgmtIpv6Start', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /><div className="text-[8px] text-surface-400">Increments per LD</div></div>
                        <div><label className={labelCls}>IPv6 Gateway</label><input value={ldState.mgmtIpv6Gw} onChange={e => updateLd('mgmtIpv6Gw', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                        <div><label className={labelCls}>IPv6 Prefix Length</label><input value={ldState.mgmtIpv6Prefix} onChange={e => updateLd('mgmtIpv6Prefix', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                      </div>
                      <div className="grid grid-cols-3 gap-2">
                        <div><label className={labelCls}>FQDN Domain</label><input value={ldState.fqdnDomain} onChange={e => updateLd('fqdnDomain', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /><div className="text-[8px] text-surface-400">FQDN = name.domain</div></div>
                        <div><label className={labelCls}>Search Domain</label><input value={ldState.searchDomain} onChange={e => updateLd('searchDomain', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                        <div><label className={labelCls}>DNS Servers</label><input value={ldState.dnsServers} onChange={e => updateLd('dnsServers', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                      </div>
                      <div className="grid grid-cols-3 gap-2">
                        <div><label className={labelCls}>Firewall Mode</label>
                          <select value={ldState.fwMode} onChange={e => updateLd('fwMode', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}><option value="routed">Routed</option><option value="transparent">Transparent</option></select>
                        </div>
                        <div><label className={labelCls}>Permit Expert Mode</label>
                          <select value={ldState.expertMode} onChange={e => updateLd('expertMode', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}><option value="yes">Yes</option><option value="no">No</option></select>
                        </div>
                        <div><label className={labelCls}>Admin Password</label><input value={ldState.adminPwd} onChange={e => updateLd('adminPwd', e.target.value)} className={cn(inputCls, 'w-full mt-0.5')} /></div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Device Registration */}
                <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                  <div className={sectionHeaderCls} onClick={() => toggle('reg')}>
                    <div className="flex items-center gap-2">
                      {collapsed.reg ? <ChevronDown className="w-3.5 h-3.5 text-surface-400" /> : <ChevronUp className="w-3.5 h-3.5 text-surface-400" />}
                      <IdCard className="w-3.5 h-3.5 text-surface-500" />
                      <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Device Registration</span>
                    </div>
                  </div>
                  {!collapsed.reg && (
                    <div className="p-3 space-y-2">
                      <div><label className={labelCls}>Access Policy</label>
                        <select value={ldState.accessPolicy} onChange={e => updateLd('accessPolicy', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}>
                          <option value="">-- Select --</option>
                          {(lookups.accessPolicies || []).map(p => <option key={p.id} value={p.name}>{p.name}</option>)}
                        </select>
                      </div>
                      <div><label className={labelCls}>Device Group</label>
                        <select value={ldState.deviceGroup} onChange={e => updateLd('deviceGroup', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}>
                          <option value="">-- Select --</option>
                          {(lookups.deviceGroups || []).map(g => <option key={g.id} value={g.name}>{g.name}</option>)}
                        </select>
                      </div>
                      <div><label className={labelCls}>Platform Settings</label>
                        <select value={ldState.platformSettings} onChange={e => updateLd('platformSettings', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}>
                          <option value="">-- Select --</option>
                          {(lookups.platformSettings || []).map(p => <option key={p.id} value={p.name}>{p.name}</option>)}
                        </select>
                      </div>
                      <div><label className={labelCls}>Resource Profile</label>
                        <select value={ldState.resourceProfile} onChange={e => updateLd('resourceProfile', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}>
                          <option value="">-- Select --</option>
                          {(lookups.resourceProfiles || []).map(p => <option key={p.id} value={p.name}>{p.name}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className={labelCls}>License Capabilities</label>
                        <div className="flex items-center gap-3 mt-1">
                          {(['carrier', 'malware', 'threat', 'urlFilter'] as const).map(lic => (
                            <label key={lic} className="flex items-center gap-1 text-[10px] text-surface-600 dark:text-surface-400">
                              <input type="checkbox" checked={ldState.licenses[lic]} onChange={e => updateLdLicense(lic, e.target.checked)} className="rounded border-surface-300 text-vyper-600" />
                              {lic === 'urlFilter' ? 'URLFilter' : lic.toUpperCase()}
                            </label>
                          ))}
                        </div>
                      </div>
                      <div><label className={labelCls}>Admin State</label>
                        <select value={ldState.adminState} onChange={e => updateLd('adminState', e.target.value)} className={cn(selectCls, 'w-full mt-0.5')}>
                          <option value="enabled">Enabled</option>
                          <option value="disabled">Disabled</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {mode === 'device' && (
            <DeviceTemplateContent
              inputCls={inputCls}
              selectCls={selectCls}
              labelCls={labelCls}
              sectionHeaderCls={sectionHeaderCls}
              onYaml={(yaml) => setPreview(yaml)}
              buildYamlRef={deviceBuildYamlRef}
            />
          )}

          {/* Preview */}
          {preview && (
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
              <div className="px-3 py-2 bg-surface-50 dark:bg-surface-800/50 flex items-center gap-2">
                <Eye className="w-3.5 h-3.5 text-surface-500" />
                <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Preview</span>
              </div>
              <pre className="px-4 py-3 bg-surface-950 text-surface-300 font-mono text-[10px] leading-relaxed overflow-auto max-h-60 whitespace-pre-wrap">
                {preview}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-surface-200 dark:border-surface-800/50 shrink-0">
          <button
            onClick={handlePreview}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
              'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
            )}
          >
            <Eye className="w-3.5 h-3.5" /> Preview
          </button>
          <div className="flex items-center gap-2">
            <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[11px] font-medium border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
              Cancel
            </button>
            <button
              onClick={handleGenerate}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-accent-violet hover:bg-accent-violet/90 text-white transition-colors',
              )}
            >
              <Zap className="w-3.5 h-3.5" /> Generate & Load
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
