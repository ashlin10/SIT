import { useRef, useState, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { uploadConfig, getConfigFromFmc, applyConfig, deleteConfig, deleteObjects } from './api'
import {
  Upload, Download, FileCode, Send, Trash2, ChevronDown, ChevronUp,
  Settings2, Layers,
} from 'lucide-react'

// ── Config type groups ──

interface ConfigItem { key: string; label: string; dataPath?: string }
interface ConfigGroup {
  id: string
  label: string
  items: ConfigItem[]
  subsections?: ConfigGroup[]
}

const CONFIG_GROUPS: ConfigGroup[] = [
  {
    id: 'interfaces',
    label: 'Interfaces',
    items: [
      { key: 'loopback_interfaces', label: 'Loopback Interfaces', dataPath: 'loopback_interfaces' },
      { key: 'physical_interfaces', label: 'Physical Interfaces', dataPath: 'physical_interfaces' },
      { key: 'etherchannel_interfaces', label: 'EtherChannel Interfaces', dataPath: 'etherchannel_interfaces' },
      { key: 'subinterfaces', label: 'Subinterfaces', dataPath: 'subinterfaces' },
      { key: 'vti_interfaces', label: 'Virtual Tunnel Interfaces', dataPath: 'vti_interfaces' },
      { key: 'inline_sets', label: 'Inline Sets', dataPath: 'inline_sets' },
      { key: 'bridge_group_interfaces', label: 'Bridge Group Interfaces', dataPath: 'bridge_group_interfaces' },
    ],
  },
  {
    id: 'routing',
    label: 'Routing',
    items: [
      { key: 'routing_bgp_general_settings', label: 'BGP General Settings', dataPath: 'routing.bgp_general_settings' },
      { key: 'routing_bgp_policies', label: 'BGP Policies', dataPath: 'routing.bgp_policies' },
      { key: 'routing_bfd_policies', label: 'BFD Policies', dataPath: 'routing.bfd_policies' },
      { key: 'routing_ospfv2_policies', label: 'OSPFv2 Policies', dataPath: 'routing.ospfv2_policies' },
      { key: 'routing_ospfv2_interfaces', label: 'OSPFv2 Interfaces', dataPath: 'routing.ospfv2_interfaces' },
      { key: 'routing_ospfv3_policies', label: 'OSPFv3 Policies', dataPath: 'routing.ospfv3_policies' },
      { key: 'routing_ospfv3_interfaces', label: 'OSPFv3 Interfaces', dataPath: 'routing.ospfv3_interfaces' },
      { key: 'routing_eigrp_policies', label: 'EIGRP Policies', dataPath: 'routing.eigrp_policies' },
      { key: 'routing_pbr_policies', label: 'PBR Policies', dataPath: 'routing.pbr_policies' },
      { key: 'routing_ipv4_static_routes', label: 'IPv4 Static Routes', dataPath: 'routing.ipv4_static_routes' },
      { key: 'routing_ipv6_static_routes', label: 'IPv6 Static Routes', dataPath: 'routing.ipv6_static_routes' },
      { key: 'routing_ecmp_zones', label: 'ECMP Zones', dataPath: 'routing.ecmp_zones' },
      { key: 'routing_vrfs', label: 'VRFs', dataPath: 'routing.vrfs' },
    ],
  },
  {
    id: 'objects',
    label: 'Objects',
    items: [],
    subsections: [
      {
        id: 'obj-interface',
        label: 'Interface',
        items: [
          { key: 'objects_interface_security_zones', label: 'Security Zones', dataPath: 'objects.interface.security_zones' },
        ],
      },
      {
        id: 'obj-network',
        label: 'Network',
        items: [
          { key: 'objects_network_hosts', label: 'Host', dataPath: 'objects.network.hosts' },
          { key: 'objects_network_ranges', label: 'Range', dataPath: 'objects.network.ranges' },
          { key: 'objects_network_networks', label: 'Network', dataPath: 'objects.network.networks' },
          { key: 'objects_network_fqdns', label: 'FQDN', dataPath: 'objects.network.fqdns' },
          { key: 'objects_network_groups', label: 'Group', dataPath: 'objects.network.groups' },
        ],
      },
      {
        id: 'obj-port',
        label: 'Port',
        items: [
          { key: 'objects_port_objects', label: 'Port Objects', dataPath: 'objects.port.objects' },
        ],
      },
      {
        id: 'obj-routing',
        label: 'Routing Templates & Lists',
        items: [
          { key: 'objects_bfd_templates', label: 'BFD Template', dataPath: 'objects.bfd_templates' },
          { key: 'objects_as_path_lists', label: 'AS Path', dataPath: 'objects.as_path_lists' },
          { key: 'objects_key_chains', label: 'Key Chain', dataPath: 'objects.key_chains' },
          { key: 'objects_sla_monitors', label: 'SLA Monitor', dataPath: 'objects.sla_monitors' },
          { key: 'objects_community_lists_community', label: 'Community List (Community)', dataPath: 'objects.community_lists.community' },
          { key: 'objects_community_lists_extended', label: 'Community List (Extended)', dataPath: 'objects.community_lists.extended' },
          { key: 'objects_prefix_lists_ipv4', label: 'IPv4 Prefix List', dataPath: 'objects.prefix_lists.ipv4' },
          { key: 'objects_prefix_lists_ipv6', label: 'IPv6 Prefix List', dataPath: 'objects.prefix_lists.ipv6' },
          { key: 'objects_access_lists_extended', label: 'Access List (Extended)', dataPath: 'objects.access_lists.extended' },
          { key: 'objects_access_lists_standard', label: 'Access List (Standard)', dataPath: 'objects.access_lists.standard' },
          { key: 'objects_route_maps', label: 'Route Map', dataPath: 'objects.route_maps' },
        ],
      },
      {
        id: 'obj-addrpool',
        label: 'Address Pools',
        items: [
          { key: 'objects_address_pools_ipv4', label: 'IPv4 Pools', dataPath: 'objects.address_pools.ipv4' },
          { key: 'objects_address_pools_ipv6', label: 'IPv6 Pools', dataPath: 'objects.address_pools.ipv6' },
          { key: 'objects_address_pools_mac', label: 'MAC Address Pool', dataPath: 'objects.address_pools.mac' },
        ],
      },
    ],
  },
]

// ── Hover card helpers ──

function tryGet(obj: unknown, path: string): unknown {
  try {
    const segs = path.split('.')
    let cur: unknown = obj
    for (const s of segs) { if (cur == null || typeof cur !== 'object') return undefined; cur = (cur as Record<string, unknown>)[s] }
    return cur
  } catch { return undefined }
}

function getNameFromItem(it: unknown, pathKey: string): string {
  if (typeof it === 'string') return it
  if (!it || typeof it !== 'object') return ''
  const o = it as Record<string, unknown>
  const generic = (o.name || o.ifname || o.ifName || o.interfaceName || o.id) as string | undefined
  if (pathKey === 'subinterfaces') {
    const name = (o.name || o.ifname || o.ifName || '') as string
    const sid = o.subIntfId ?? o.subinterfaceId ?? o.subInterfaceId ?? o.vlanId
    const parent = (o.parentName || o.parent || o.parentInterfaceName || '') as string
    if (sid != null) {
      if (parent) return `${parent}.${sid}`
      if (name) return String(name).includes('.') ? name : `${name}.${sid}`
    }
    return String(name || generic || '')
  }
  if (/^(loopback_interfaces|physical_interfaces|etherchannel_interfaces|vti_interfaces|inline_sets|bridge_group_interfaces)$/.test(pathKey))
    return String(generic || (tryGet(it, 'deviceInterface.name') as string) || (tryGet(it, 'securityZone.name') as string) || '')
  if (pathKey === 'routing.ospfv2_interfaces' || pathKey === 'routing.ospfv3_interfaces')
    return String((tryGet(it, 'deviceInterface.name') as string) || generic || '')
  if (pathKey === 'routing.ospfv2_policies' || pathKey === 'routing.ospfv3_policies') {
    const pid = o.processId || o.processID || o.id; return pid ? `Process ${pid}` : String(generic || '')
  }
  if (pathKey === 'routing.bgp_general_settings') {
    const asn = o.asNumber || o.localAS || o.bgpAS; return asn ? `AS ${asn}` : String(generic || 'General Settings')
  }
  if (pathKey === 'routing.eigrp_policies') { const asn = o.asNumber || o.autonomousSystem; if (asn) return `AS ${asn}` }
  if (pathKey === 'routing.bfd_policies') { const tn = tryGet(it, 'template.name') as string; if (tn) return tn }
  if (/^routing\./.test(pathKey)) return String(generic || '')
  if (pathKey === 'routing.ipv4_static_routes' || pathKey === 'routing.ipv6_static_routes') {
    const iface = (o.interfaceName || o.interface || '') as string
    const gw = (tryGet(it, 'gateway.literal.value') || o.gateway || o.nextHop || o.nextHopIp || '') as string
    if (iface && gw) return `${iface} via ${gw}`
    return String(iface || 'Static route')
  }
  if (pathKey.startsWith('objects.')) return String(generic || o.poolName || o.listName || o.value || o.fqdn || o.ipAddress || o.address || '')
  for (const [, v] of Object.entries(o)) { if (typeof v === 'string' && v) return v }
  return ''
}

function namesFromConfig(config: Record<string, unknown> | null, dataPath: string): string[] {
  if (!config) return []
  const val = tryGet(config, dataPath)
  const list = Array.isArray(val) ? val : []
  let names = list.map((it) => getNameFromItem(it, dataPath)).filter(Boolean)
  if (names.length === 0 && list.length > 0) names = list.slice(0, 50).map((_, i) => `Item ${i + 1}`)
  return names.slice(0, 50)
}

// ── Auth override fields ──

const AUTH_FIELDS = [
  { key: 'ospf_md5_key', label: 'OSPF MD5 Key' },
  { key: 'ospf_auth_key', label: 'OSPF Password (authKey)' },
  { key: 'ospfv3_auth_key', label: 'OSPFv3 Auth Key' },
  { key: 'ospfv3_encryption_key', label: 'OSPFv3 Encryption Key' },
  { key: 'bfd_auth_key', label: 'BFD Auth Key' },
  { key: 'bgp_secret', label: 'BGP Neighbor Secret' },
  { key: 'eigrp_password', label: 'EIGRP Password' },
]

export default function DeviceConfigSection({ onTemplate }: { onTemplate?: () => void }) {
  const {
    uploadedConfig, uploadedConfigFilename, uploadedConfigYaml, uploadedCounts, configCheckboxes,
    selectedDeviceIds, isOperationRunning, bulkEnabled, batchSize, authOverrides,
    setConfigCheckbox, setAllConfigCheckboxes,
    setBulkEnabled, setBatchSize, setAuthOverride, openViewer, setUploadedConfigYaml,
  } = useFmcConfigStore()

  const fileRef = useRef<HTMLInputElement>(null)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [authOpen, setAuthOpen] = useState(false)

  const toggle = (id: string) => setCollapsed((c) => ({ ...c, [id]: !c[id] }))

  const handleUpload = async (file: File) => {
    const result = await uploadConfig(file)
    if (!result.success) alert(result.message || 'Upload failed')
  }

  const handleGetConfig = async () => {
    const ids = Array.from(selectedDeviceIds)
    if (ids.length !== 1) { alert('Select exactly one device for Get Config'); return }
    const result = await getConfigFromFmc(ids)
    if (!result.success) alert(result.message || 'Get Config failed')
  }

  const handleApply = async () => {
    const ids = Array.from(selectedDeviceIds)
    if (ids.length === 0) { alert('Select at least one device'); return }
    if (!uploadedConfig) { alert('Upload a config first'); return }
    const result = await applyConfig(ids, configCheckboxes)
    if (!result.success) alert(result.message || 'Apply failed')
  }

  const handleDelete = async () => {
    const ids = Array.from(selectedDeviceIds)
    if (ids.length === 0) { alert('Select at least one device'); return }
    if (!confirm('Delete selected configuration types?')) return
    const result = await deleteConfig(ids, configCheckboxes)
    if (!result.success) alert(result.message || 'Delete failed')
  }

  const handleDeleteObjects = async () => {
    if (!confirm('Delete objects from FMC? This does not require device selection.')) return
    const result = await deleteObjects(configCheckboxes)
    if (!result.success) alert(result.message || 'Delete Objects failed')
  }

  const handleDownload = () => {
    if (!uploadedConfigYaml && !uploadedConfig) return
    const content = uploadedConfigYaml || JSON.stringify(uploadedConfig, null, 2)
    const blob = new Blob([content], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = uploadedConfigFilename || 'config.yaml'
    a.click()
    URL.revokeObjectURL(url)
  }

  const hasConfig = !!uploadedConfig && Object.keys(uploadedCounts).length > 0

  const inputCls = cn(
    'rounded-lg border px-3 py-2 text-sm',
    'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50',
    'text-surface-800 dark:text-surface-200 placeholder:text-surface-400',
    'hover:border-vyper-400 dark:hover:border-vyper-500',
    'focus:outline-none focus:ring-2 focus:ring-vyper-500/20 focus:border-vyper-500',
    'transition-colors'
  )

  const btnCls = (variant: 'primary' | 'secondary' | 'danger' | 'warning' = 'secondary') =>
    cn(
      'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
      variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
      variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
      variant === 'danger' && 'border border-accent-rose/30 text-accent-rose/70 hover:bg-accent-rose/10 hover:text-accent-rose',
      variant === 'warning' && 'border border-accent-amber/30 text-accent-amber hover:bg-accent-amber/10',
    )

  // Gather all items from groups for select-all
  const getAllKeys = () => {
    const keys: string[] = []
    CONFIG_GROUPS.forEach((g) => {
      g.items.forEach((i) => keys.push(i.key))
      g.subsections?.forEach((sub) => sub.items.forEach((i) => keys.push(i.key)))
    })
    return keys
  }

  const allChecked = getAllKeys().every((k) => configCheckboxes[k] !== false)

  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Device Configuration</h2>
          {uploadedConfigFilename && (
            <button
              onClick={() => openViewer(`Config — ${uploadedConfigFilename}`, uploadedConfigYaml, setUploadedConfigYaml)}
              className="text-[10px] font-medium text-accent-violet bg-accent-violet/10 border border-accent-violet/20 rounded-full px-2.5 py-0.5 hover:bg-accent-violet/20 transition-colors cursor-pointer"
            >
              <FileCode className="w-3 h-3 inline mr-1" />
              {uploadedConfigFilename}
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => onTemplate?.()} className={btnCls()}>
            <Layers className="w-3.5 h-3.5" /> Template
          </button>
          <button onClick={handleGetConfig} disabled={isOperationRunning} className={cn(btnCls(), isOperationRunning && 'opacity-40 pointer-events-none')}>
            <Download className="w-3.5 h-3.5" /> Get Config
          </button>
          <button onClick={() => fileRef.current?.click()} className={btnCls()}>
            <Upload className="w-3.5 h-3.5" /> Upload
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".yaml,.yml"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) handleUpload(f)
              e.target.value = ''
            }}
          />
          <button onClick={handleDownload} disabled={!hasConfig} className={cn(btnCls(), !hasConfig && 'opacity-40 pointer-events-none')}>
            <Download className="w-3.5 h-3.5" /> Download
          </button>
        </div>
      </div>

      <div className="px-5 py-4 space-y-4">
        <p className="text-[11px] text-surface-400">
          Upload a YAML to preview configuration types and counts. Then choose which types to apply and click Push Config.
        </p>

        {/* Options */}
        <CollapsibleGroup
          title="Options"
          icon={<Settings2 className="w-3.5 h-3.5 text-surface-500" />}
          isOpen={!collapsed['options']}
          onToggle={() => toggle('options')}
        >
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 text-[11px] text-surface-600 dark:text-surface-400">
              <input
                type="checkbox"
                checked={bulkEnabled}
                onChange={(e) => setBulkEnabled(e.target.checked)}
                className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
              />
              Bulk
            </label>
            <label className="flex items-center gap-2 text-[11px] text-surface-600 dark:text-surface-400">
              Batch size
              <input
                type="number"
                value={batchSize}
                onChange={(e) => setBatchSize(parseInt(e.target.value) || 50)}
                className={cn(inputCls, 'w-20 py-1 text-xs')}
                min={1}
              />
            </label>
          </div>
        </CollapsibleGroup>

        {/* Select All + Collapse All */}
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-[11px] font-medium text-surface-600 dark:text-surface-400">
            <input
              type="checkbox"
              checked={allChecked}
              onChange={(e) => setAllConfigCheckboxes(e.target.checked)}
              className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
            />
            Select All
          </label>
        </div>

        {/* Auth Overrides */}
        <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
          <button
            onClick={() => setAuthOpen(!authOpen)}
            className="flex items-center justify-between w-full px-3 py-2 text-[11px] font-medium text-surface-600 dark:text-surface-400 hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors"
          >
            <span>Advanced: Authentication overrides (optional)</span>
            {authOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          {authOpen && (
            <div className="px-3 pb-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {AUTH_FIELDS.map((f) => (
                <div key={f.key}>
                  <label className="block text-[10px] font-medium text-surface-500 mb-1">{f.label}</label>
                  <input
                    type="text"
                    value={authOverrides[f.key] || ''}
                    onChange={(e) => setAuthOverride(f.key, e.target.value)}
                    className={cn(inputCls, 'w-full py-1 text-xs')}
                  />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Config checkbox groups */}
        {hasConfig && (
          <div className="space-y-3">
            {CONFIG_GROUPS.map((group) => (
              <ConfigGroupPanel
                key={group.id}
                group={group}
                counts={uploadedCounts}
                checkboxes={configCheckboxes}
                onCheckbox={setConfigCheckbox}
                isOpen={!collapsed[group.id]}
                onToggle={() => toggle(group.id)}
                config={uploadedConfig}
              />
            ))}

            {/* Action buttons */}
            <div className="flex items-center gap-2 pt-2">
              <button onClick={handleApply} disabled={isOperationRunning} className={cn(btnCls('primary'), isOperationRunning && 'opacity-40 pointer-events-none')}>
                <Send className="w-3.5 h-3.5" /> Push Config
              </button>
              <button onClick={handleDelete} disabled={isOperationRunning} className={cn(btnCls('danger'), isOperationRunning && 'opacity-40 pointer-events-none')}>
                <Trash2 className="w-3.5 h-3.5" /> Delete
              </button>
              <button onClick={handleDeleteObjects} disabled={isOperationRunning} className={cn(btnCls('warning'), isOperationRunning && 'opacity-40 pointer-events-none')}>
                <Trash2 className="w-3.5 h-3.5" /> Delete Objects
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Collapsible group wrapper ──

function CollapsibleGroup({
  title, icon, isOpen, onToggle, children, actions,
}: {
  title: string
  icon?: React.ReactNode
  isOpen: boolean
  onToggle: () => void
  children: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-surface-50 dark:bg-surface-800/50">
        <div className="flex items-center gap-2">
          <button onClick={onToggle} className="p-0.5 text-surface-400 hover:text-surface-600 transition-colors">
            {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          {icon}
          <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">{title}</span>
        </div>
        {actions}
      </div>
      {isOpen && <div className="p-3">{children}</div>}
    </div>
  )
}

// ── Config group with checkboxes ──

function ConfigGroupPanel({
  group, counts, checkboxes, onCheckbox, isOpen, onToggle, config,
}: {
  group: ConfigGroup
  counts: Record<string, number>
  checkboxes: Record<string, boolean>
  onCheckbox: (key: string, value: boolean) => void
  isOpen: boolean
  onToggle: () => void
  config: Record<string, unknown> | null
}) {
  const allItems = [...group.items]
  group.subsections?.forEach((sub) => allItems.push(...sub.items))

  const groupAllChecked = allItems.length > 0 && allItems.every((i) => checkboxes[i.key] !== false)

  const toggleGroupAll = (v: boolean) => {
    allItems.forEach((i) => onCheckbox(i.key, v))
  }

  return (
    <CollapsibleGroup
      title={group.label}
      isOpen={isOpen}
      onToggle={onToggle}
      actions={
        allItems.length > 0 ? (
          <label className="flex items-center gap-1.5 text-[10px] text-surface-500">
            <input
              type="checkbox"
              checked={groupAllChecked}
              onChange={(e) => toggleGroupAll(e.target.checked)}
              className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
            />
            Select All
          </label>
        ) : undefined
      }
    >
      {/* Direct items */}
      {group.items.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {group.items.map((item) => (
            <ConfigCheckboxItem
              key={item.key}
              item={item}
              count={counts[item.key]}
              checked={checkboxes[item.key] !== false}
              onChange={(v) => onCheckbox(item.key, v)}
              config={config}
            />
          ))}
        </div>
      )}

      {/* Subsections */}
      {group.subsections?.map((sub) => (
        <SubsectionPanel
          key={sub.id}
          subsection={sub}
          counts={counts}
          checkboxes={checkboxes}
          onCheckbox={onCheckbox}
          config={config}
        />
      ))}
    </CollapsibleGroup>
  )
}

function SubsectionPanel({
  subsection, counts, checkboxes, onCheckbox, config,
}: {
  subsection: ConfigGroup
  counts: Record<string, number>
  checkboxes: Record<string, boolean>
  onCheckbox: (key: string, value: boolean) => void
  config: Record<string, unknown> | null
}) {
  const [open, setOpen] = useState(true)
  const subAllChecked = subsection.items.every((i) => checkboxes[i.key] !== false)

  return (
    <div className="mt-2 rounded-lg border border-surface-150 dark:border-surface-700/50 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-surface-25 dark:bg-surface-800/30">
        <div className="flex items-center gap-2">
          <button onClick={() => setOpen(!open)} className="p-0.5 text-surface-400">
            {open ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
          <span className="text-[10px] font-medium text-surface-600 dark:text-surface-400">{subsection.label}</span>
        </div>
        <label className="flex items-center gap-1.5 text-[10px] text-surface-500">
          <input
            type="checkbox"
            checked={subAllChecked}
            onChange={(e) => subsection.items.forEach((i) => onCheckbox(i.key, e.target.checked))}
            className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
          />
          Select All
        </label>
      </div>
      {open && (
        <div className="p-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {subsection.items.map((item) => (
            <ConfigCheckboxItem
              key={item.key}
              item={item}
              count={counts[item.key]}
              checked={checkboxes[item.key] !== false}
              onChange={(v) => onCheckbox(item.key, v)}
              config={config}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function ConfigCheckboxItem({
  item, count, checked, onChange, config,
}: {
  item: ConfigItem
  count?: number
  checked: boolean
  onChange: (v: boolean) => void
  config: Record<string, unknown> | null
}) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const names = item.dataPath && config && pos ? namesFromConfig(config, item.dataPath) : []

  const show = useCallback((e: React.MouseEvent) => {
    if (!item.dataPath) return
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null }
    setPos({ x: e.clientX + 12, y: e.clientY + 12 })
  }, [item.dataPath])
  const scheduleHide = useCallback(() => {
    hideTimer.current = setTimeout(() => setPos(null), 250)
  }, [])
  const cancelHide = useCallback(() => {
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null }
  }, [])

  return (
    <label className="flex items-center gap-2 text-[11px] text-surface-600 dark:text-surface-400 cursor-pointer hover:text-surface-800 dark:hover:text-surface-200 transition-colors">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
      />
      <span
        className={item.dataPath ? 'underline decoration-dotted underline-offset-2 cursor-default' : ''}
        onMouseEnter={show}
        onMouseLeave={scheduleHide}
      >
        {item.label}
      </span>
      {count !== undefined && count > 0 && (
        <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">
          {count}
        </span>
      )}
      {pos && (
        <div
          className="fixed min-w-44 max-w-80 bg-gray-900 text-gray-50 rounded-lg shadow-xl px-3 py-2 text-[11px]"
          style={{ zIndex: 9999, left: Math.min(pos.x, window.innerWidth - 320), top: Math.min(pos.y, window.innerHeight - 220) }}
          onMouseEnter={cancelHide}
          onMouseLeave={scheduleHide}
        >
          <div className="text-xs font-semibold text-blue-300 mb-1">{item.label}</div>
          <ul className="list-none m-0 p-0 max-h-48 overflow-y-auto">
            {names.length === 0
              ? <li className="text-gray-400 italic">No items loaded</li>
              : names.map((n, i) => (
                <li key={i} className="py-0.5 border-b border-white/5 last:border-0">{n}</li>
              ))
            }
          </ul>
        </div>
      )}
    </label>
  )
}
