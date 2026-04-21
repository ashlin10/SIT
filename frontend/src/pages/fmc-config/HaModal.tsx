import { useState, useEffect, useMemo } from 'react'
import { cn, selectCls } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { createHaPairs } from './api'
import { X, Plus, Trash2, Shield, Eye, EyeOff } from 'lucide-react'

interface HaPair {
  primary: string   // device name
  secondary: string // device name
}

interface HaModalProps {
  open: boolean
  onClose: () => void
}

// ---- Auto-pair logic (matches old implementation) ----
// Groups devices by trailing numeric suffix and pairs consecutive prefixes within each group.
// e.g. tpk-3-1 & tpk-4-1 pair together (same suffix "1", consecutive bases "tpk-3-" and "tpk-4-")
function autoMatchPairs(names: string[]): HaPair[] {
  const parsed = names.map((name) => {
    const match = name.match(/^(.+[-_])(\d+)$/)
    if (match) {
      return { name, prefix: match[1], suffix: parseInt(match[2], 10) }
    }
    return { name, prefix: name, suffix: -1 }
  })

  const bySuffix: Record<string, typeof parsed> = {}
  parsed.forEach((p) => {
    const key = p.suffix >= 0 ? String(p.suffix) : p.name
    if (!bySuffix[key]) bySuffix[key] = []
    bySuffix[key].push(p)
  })

  const pairs: HaPair[] = []
  Object.keys(bySuffix)
    .sort((a, b) => {
      const na = parseInt(a, 10), nb = parseInt(b, 10)
      if (!isNaN(na) && !isNaN(nb)) return na - nb
      return a.localeCompare(b)
    })
    .forEach((key) => {
      const items = bySuffix[key].sort((a, b) =>
        a.prefix.localeCompare(b.prefix, undefined, { numeric: true, sensitivity: 'base' })
      )
      for (let i = 0; i + 1 < items.length; i += 2) {
        pairs.push({ primary: items[i].name, secondary: items[i + 1].name })
      }
    })
  return pairs
}

export default function HaModal({ open, onClose }: HaModalProps) {
  const { devices, selectedDeviceIds, isOperationRunning } = useFmcConfigStore()

  // Failover link settings
  const [failoverIntfMode, setFailoverIntfMode] = useState<'single' | 'range'>('single')
  const [failoverIntfName, setFailoverIntfName] = useState('Ethernet1/6')
  const [failoverRangePrefix, setFailoverRangePrefix] = useState('Ethernet1/')
  const [failoverRangeStart, setFailoverRangeStart] = useState(6)
  const [failoverIpVer, setFailoverIpVer] = useState<'ipv4' | 'ipv6'>('ipv4')
  const [failoverPrimaryIp, setFailoverPrimaryIp] = useState('10.100.1.1')
  const [failoverSecondaryIp, setFailoverSecondaryIp] = useState('10.100.1.2')
  const [failoverSubnet, setFailoverSubnet] = useState('255.255.255.252')
  const [failoverIncOctet, setFailoverIncOctet] = useState(3)

  // Stateful link settings
  const [statefulMode, setStatefulMode] = useState<'same' | 'single' | 'range'>('same')
  const [statefulIntfName, setStatefulIntfName] = useState('Ethernet1/7')
  const [statefulRangePrefix, setStatefulRangePrefix] = useState('Ethernet1/')
  const [statefulRangeStart, setStatefulRangeStart] = useState(7)
  const [statefulIpVer, setStatefulIpVer] = useState<'ipv4' | 'ipv6'>('ipv4')
  const [statefulPrimaryIp, setStatefulPrimaryIp] = useState('10.100.101.1')
  const [statefulSecondaryIp, setStatefulSecondaryIp] = useState('10.100.101.2')
  const [statefulSubnet, setStatefulSubnet] = useState('255.255.255.252')
  const [statefulIncOctet, setStatefulIncOctet] = useState(3)

  // Encryption
  const [encEnabled, setEncEnabled] = useState(false)
  const [encKeyType, setEncKeyType] = useState<'auto' | 'custom'>('auto')
  const [encKey, setEncKey] = useState('')

  // HA pairs (use device names, not UUIDs)
  const [pairs, setPairs] = useState<HaPair[]>([])

  // Preview
  const [showPreview, setShowPreview] = useState(false)

  // Selected devices sorted alphanumerically by name
  const selectedDevices = useMemo(
    () =>
      devices
        .filter((d) => selectedDeviceIds.has(d.id))
        .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' })),
    [devices, selectedDeviceIds]
  )

  // All device names (sorted) for dropdown options
  const allDeviceNames = useMemo(
    () => selectedDevices.map((d) => d.name).filter(Boolean),
    [selectedDevices]
  )

  // Auto-populate pairs from selected devices using the old autoMatchPairs algorithm
  useEffect(() => {
    if (!open) return
    const matched = autoMatchPairs(allDeviceNames)
    if (matched.length > 0) {
      setPairs(matched)
    } else if (allDeviceNames.length >= 2) {
      // Fallback: pair consecutive
      const fallback: HaPair[] = []
      for (let i = 0; i + 1 < allDeviceNames.length; i += 2) {
        fallback.push({ primary: allDeviceNames[i], secondary: allDeviceNames[i + 1] })
      }
      setPairs(fallback.length > 0 ? fallback : [{ primary: '', secondary: '' }])
    } else {
      setPairs([{ primary: '', secondary: '' }])
    }
    setShowPreview(false)
  }, [open, allDeviceNames.join(',')])

  if (!open) return null

  // Unmatched devices (not in any pair)
  const matchedNames = new Set<string>()
  pairs.forEach((p) => { if (p.primary) matchedNames.add(p.primary); if (p.secondary) matchedNames.add(p.secondary) })
  const unmatchedDevices = allDeviceNames.filter((n) => !matchedNames.has(n))

  const addPair = () => setPairs((p) => [...p, { primary: '', secondary: '' }])
  const removePair = (idx: number) => setPairs((p) => p.filter((_, i) => i !== idx))
  const updatePair = (idx: number, field: 'primary' | 'secondary', value: string) => {
    setPairs((p) => p.map((pair, i) => (i === idx ? { ...pair, [field]: value } : pair)))
  }

  const incrementIp = (ip: string, octet: number, amount: number): string => {
    const parts = ip.split('.')
    if (parts.length !== 4) return ip
    parts[octet - 1] = String(parseInt(parts[octet - 1]) + amount)
    return parts.join('.')
  }

  // Compute resolved interface name for a given pair index
  const getFailoverIntf = (idx: number): string => {
    if (failoverIntfMode === 'range') {
      const sep = failoverRangePrefix.endsWith('/') ? '' : '.'
      return `${failoverRangePrefix}${sep}${failoverRangeStart + idx}`
    }
    return failoverIntfName
  }

  const getStatefulIntf = (idx: number): string => {
    if (statefulMode === 'same') return getFailoverIntf(idx)
    if (statefulMode === 'range') {
      const sep = statefulRangePrefix.endsWith('/') ? '' : '.'
      return `${statefulRangePrefix}${sep}${statefulRangeStart + idx}`
    }
    return statefulIntfName
  }

  const getFailoverIPs = (idx: number) => ({
    active: failoverIpVer === 'ipv4' ? incrementIp(failoverPrimaryIp, failoverIncOctet, idx) : failoverPrimaryIp,
    standby: failoverIpVer === 'ipv4' ? incrementIp(failoverSecondaryIp, failoverIncOctet, idx) : failoverSecondaryIp,
    mask: failoverSubnet,
  })

  const getStatefulIPs = (idx: number) => {
    if (statefulMode === 'same') return getFailoverIPs(idx)
    return {
      active: statefulIpVer === 'ipv4' ? incrementIp(statefulPrimaryIp, statefulIncOctet, idx) : statefulPrimaryIp,
      standby: statefulIpVer === 'ipv4' ? incrementIp(statefulSecondaryIp, statefulIncOctet, idx) : statefulSecondaryIp,
      mask: statefulSubnet,
    }
  }

  // Build FMC-API-matching payload (same format as old UI: primary.id = device name)
  const buildPayload = () => {
    const validPairs = pairs.filter((p) => p.primary && p.secondary && p.primary !== p.secondary)
    if (validPairs.length === 0) return null

    return validPairs.map((pair, idx) => {
      const foIntf = getFailoverIntf(idx)
      const stIntf = getStatefulIntf(idx)
      const foIPs = getFailoverIPs(idx)
      const stIPs = getStatefulIPs(idx)
      const useSameLink = foIntf === stIntf

      const lanFailover: Record<string, unknown> = {
        interfaceObject: { name: foIntf },
        logicalName: 'failover-link',
        activeIP: foIPs.active,
        standbyIP: foIPs.standby,
        useIPv6Address: failoverIpVer === 'ipv6',
      }
      if (failoverIpVer === 'ipv4') {
        lanFailover.subnetMask = foIPs.mask
      }

      const statefulFailover: Record<string, unknown> = {
        interfaceObject: { name: stIntf },
        logicalName: useSameLink ? 'failover-link' : 'stateful-link',
        activeIP: stIPs.active,
        standbyIP: stIPs.standby,
        useIPv6Address: (statefulMode === 'same' ? failoverIpVer : statefulIpVer) === 'ipv6',
      }
      if ((statefulMode === 'same' ? failoverIpVer : statefulIpVer) === 'ipv4') {
        statefulFailover.subnetMask = stIPs.mask
      }

      const ftdHABootstrap: Record<string, unknown> = {
        isEncryptionEnabled: encEnabled,
        lanFailover,
        statefulFailover,
        useSameLinkForFailovers: useSameLink,
      }

      if (encEnabled) {
        if (encKeyType === 'custom' && encKey) {
          ftdHABootstrap.encKeyGenerationScheme = 'CUSTOM'
          ftdHABootstrap.sharedKey = encKey
        } else {
          ftdHABootstrap.encKeyGenerationScheme = 'AUTO'
        }
      }

      return {
        name: `${pair.primary}_${pair.secondary}_HA`,
        type: 'DeviceHAPair',
        primary: { id: pair.primary },
        secondary: { id: pair.secondary },
        ftdHABootstrap,
      }
    })
  }

  // Generate YAML preview string
  const buildPreviewYaml = (): string => {
    const payload = buildPayload()
    if (!payload) return '# No valid pairs configured'
    const lines: string[] = ['ftd_ha_pairs:']
    payload.forEach((p) => {
      lines.push(`  - name: ${p.name}`)
      lines.push(`    type: ${p.type}`)
      lines.push(`    primary:`)
      lines.push(`      id: ${(p.primary as Record<string, string>).id}`)
      lines.push(`    secondary:`)
      lines.push(`      id: ${(p.secondary as Record<string, string>).id}`)
      lines.push(`    ftdHABootstrap:`)
      const b = p.ftdHABootstrap as Record<string, unknown>
      lines.push(`      isEncryptionEnabled: ${b.isEncryptionEnabled}`)
      if (b.encKeyGenerationScheme) lines.push(`      encKeyGenerationScheme: ${b.encKeyGenerationScheme}`)
      if (b.sharedKey) lines.push(`      sharedKey: ${b.sharedKey}`)
      lines.push(`      useSameLinkForFailovers: ${b.useSameLinkForFailovers}`)
      const lan = b.lanFailover as Record<string, unknown>
      lines.push(`      lanFailover:`)
      lines.push(`        interfaceObject:`)
      lines.push(`          name: ${(lan.interfaceObject as Record<string, string>).name}`)
      lines.push(`        logicalName: ${lan.logicalName}`)
      lines.push(`        activeIP: ${lan.activeIP}`)
      lines.push(`        standbyIP: ${lan.standbyIP}`)
      if (lan.subnetMask) lines.push(`        subnetMask: ${lan.subnetMask}`)
      lines.push(`        useIPv6Address: ${lan.useIPv6Address}`)
      const sf = b.statefulFailover as Record<string, unknown>
      lines.push(`      statefulFailover:`)
      lines.push(`        interfaceObject:`)
      lines.push(`          name: ${(sf.interfaceObject as Record<string, string>).name}`)
      lines.push(`        logicalName: ${sf.logicalName}`)
      lines.push(`        activeIP: ${sf.activeIP}`)
      lines.push(`        standbyIP: ${sf.standbyIP}`)
      if (sf.subnetMask) lines.push(`        subnetMask: ${sf.subnetMask}`)
      lines.push(`        useIPv6Address: ${sf.useIPv6Address}`)
    })
    return lines.join('\n')
  }

  const handleCreate = async () => {
    const payload = buildPayload()
    if (!payload || payload.length === 0) {
      alert('Configure at least one complete HA pair (primary ≠ secondary)')
      return
    }

    const result = await createHaPairs(payload)
    if (result.success) {
      onClose()
    } else {
      alert(result.message || 'HA creation failed')
    }
  }

  const inputCls = cn(
    'rounded-lg border px-2.5 py-1.5 text-xs',
    'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50',
    'text-surface-800 dark:text-surface-200 placeholder:text-surface-400',
    'hover:border-vyper-400 dark:hover:border-vyper-500',
    'focus:outline-none focus:ring-2 focus:ring-vyper-500/20 focus:border-vyper-500',
    'transition-colors'
  )

  const labelCls = 'block text-[10px] font-medium text-surface-500 mb-1'

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
            <Shield className="w-4 h-4 text-accent-violet" />
            <h3 className="text-sm font-medium text-surface-800 dark:text-surface-200">FTD HA Pair Creator</h3>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Settings Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Failover Link */}
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3 space-y-2">
              <h4 className="text-[11px] font-semibold text-accent-violet uppercase tracking-wider">Failover Link</h4>

              <div>
                <label className={labelCls}>Interface Mode</label>
                <select value={failoverIntfMode} onChange={(e) => setFailoverIntfMode(e.target.value as 'single' | 'range')} className={cn(selectCls, 'w-full')}>
                  <option value="single">Same interface for all pairs</option>
                  <option value="range">Range (incremental per pair)</option>
                </select>
              </div>

              {failoverIntfMode === 'single' ? (
                <div>
                  <label className={labelCls}>Interface Name</label>
                  <input value={failoverIntfName} onChange={(e) => setFailoverIntfName(e.target.value)} className={cn(inputCls, 'w-full')} placeholder="e.g. Ethernet1/6" />
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className={labelCls}>Prefix</label>
                    <input value={failoverRangePrefix} onChange={(e) => setFailoverRangePrefix(e.target.value)} className={cn(inputCls, 'w-full')} />
                  </div>
                  <div>
                    <label className={labelCls}>Start Index</label>
                    <input type="number" value={failoverRangeStart} onChange={(e) => setFailoverRangeStart(+e.target.value)} className={cn(inputCls, 'w-full')} />
                  </div>
                </div>
              )}

              <div>
                <label className={labelCls}>IP Version</label>
                <select value={failoverIpVer} onChange={(e) => setFailoverIpVer(e.target.value as 'ipv4' | 'ipv6')} className={cn(selectCls, 'w-full')}>
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className={labelCls}>Primary IP</label>
                  <input value={failoverPrimaryIp} onChange={(e) => setFailoverPrimaryIp(e.target.value)} className={cn(inputCls, 'w-full')} />
                </div>
                <div>
                  <label className={labelCls}>Secondary IP</label>
                  <input value={failoverSecondaryIp} onChange={(e) => setFailoverSecondaryIp(e.target.value)} className={cn(inputCls, 'w-full')} />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className={labelCls}>Subnet Mask</label>
                  <input value={failoverSubnet} onChange={(e) => setFailoverSubnet(e.target.value)} className={cn(inputCls, 'w-full')} />
                </div>
                <div>
                  <label className={labelCls}>Increment Octet</label>
                  <select value={failoverIncOctet} onChange={(e) => setFailoverIncOctet(+e.target.value)} className={cn(selectCls, 'w-full')}>
                    <option value={1}>1st octet</option>
                    <option value={2}>2nd octet</option>
                    <option value={3}>3rd octet</option>
                    <option value={4}>4th octet</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Stateful Link + Encryption */}
            <div className="space-y-4">
              <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3 space-y-2">
                <h4 className="text-[11px] font-semibold text-accent-violet uppercase tracking-wider">Stateful Failover Link</h4>
                <div>
                  <label className={labelCls}>Interface Mode</label>
                  <select value={statefulMode} onChange={(e) => setStatefulMode(e.target.value as 'same' | 'single' | 'range')} className={cn(selectCls, 'w-full')}>
                    <option value="same">Same as failover link</option>
                    <option value="single">Different single interface</option>
                    <option value="range">Range (incremental per pair)</option>
                  </select>
                </div>

                {statefulMode === 'single' && (
                  <div>
                    <label className={labelCls}>Interface Name</label>
                    <input value={statefulIntfName} onChange={(e) => setStatefulIntfName(e.target.value)} className={cn(inputCls, 'w-full')} placeholder="e.g. Ethernet1/7" />
                  </div>
                )}
                {statefulMode === 'range' && (
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className={labelCls}>Prefix</label>
                      <input value={statefulRangePrefix} onChange={(e) => setStatefulRangePrefix(e.target.value)} className={cn(inputCls, 'w-full')} />
                    </div>
                    <div>
                      <label className={labelCls}>Start Index</label>
                      <input type="number" value={statefulRangeStart} onChange={(e) => setStatefulRangeStart(+e.target.value)} className={cn(inputCls, 'w-full')} />
                    </div>
                  </div>
                )}

                {statefulMode !== 'same' && (
                  <>
                    <div>
                      <label className={labelCls}>IP Version</label>
                      <select value={statefulIpVer} onChange={(e) => setStatefulIpVer(e.target.value as 'ipv4' | 'ipv6')} className={cn(selectCls, 'w-full')}>
                        <option value="ipv4">IPv4</option>
                        <option value="ipv6">IPv6</option>
                      </select>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className={labelCls}>Primary IP</label>
                        <input value={statefulPrimaryIp} onChange={(e) => setStatefulPrimaryIp(e.target.value)} className={cn(inputCls, 'w-full')} />
                      </div>
                      <div>
                        <label className={labelCls}>Secondary IP</label>
                        <input value={statefulSecondaryIp} onChange={(e) => setStatefulSecondaryIp(e.target.value)} className={cn(inputCls, 'w-full')} />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className={labelCls}>Subnet Mask</label>
                        <input value={statefulSubnet} onChange={(e) => setStatefulSubnet(e.target.value)} className={cn(inputCls, 'w-full')} />
                      </div>
                      <div>
                        <label className={labelCls}>Increment Octet</label>
                        <select value={statefulIncOctet} onChange={(e) => setStatefulIncOctet(+e.target.value)} className={cn(selectCls, 'w-full')}>
                          <option value={1}>1st octet</option>
                          <option value={2}>2nd octet</option>
                          <option value={3}>3rd octet</option>
                          <option value={4}>4th octet</option>
                        </select>
                      </div>
                    </div>
                  </>
                )}
              </div>

              <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3 space-y-2">
                <h4 className="text-[11px] font-semibold text-accent-violet uppercase tracking-wider">Encryption</h4>
                <div>
                  <label className={labelCls}>Encryption</label>
                  <select value={encEnabled ? 'true' : 'false'} onChange={(e) => setEncEnabled(e.target.value === 'true')} className={cn(selectCls, 'w-full')}>
                    <option value="false">Disabled</option>
                    <option value="true">Enabled</option>
                  </select>
                </div>
                {encEnabled && (
                  <>
                    <div>
                      <label className={labelCls}>Key Type</label>
                      <select value={encKeyType} onChange={(e) => setEncKeyType(e.target.value as 'auto' | 'custom')} className={cn(selectCls, 'w-full')}>
                        <option value="auto">Auto (generated)</option>
                        <option value="custom">Custom Key</option>
                      </select>
                    </div>
                    {encKeyType === 'custom' && (
                      <div>
                        <label className={labelCls}>Shared Key</label>
                        <input value={encKey} onChange={(e) => setEncKey(e.target.value)} className={cn(inputCls, 'w-full')} placeholder="Enter shared secret key" />
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Device Pairs Table */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-semibold text-surface-700 dark:text-surface-300">Device Pairs</h4>
                {unmatchedDevices.length > 0 && (
                  <span className="text-[10px] text-accent-rose">
                    {unmatchedDevices.length} unmatched: {unmatchedDevices.join(', ')}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowPreview((v) => !v)}
                  className="flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium bg-accent-violet/10 text-accent-violet hover:bg-accent-violet/20 transition-colors"
                >
                  {showPreview ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                  {showPreview ? 'Hide Preview' : 'Preview'}
                </button>
                <button onClick={addPair} className="flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium bg-vyper-500/10 text-vyper-600 hover:bg-vyper-500/20 transition-colors">
                  <Plus className="w-3 h-3" /> Add Pair
                </button>
              </div>
            </div>
            <div className="overflow-auto max-h-60 rounded-lg border border-surface-200 dark:border-surface-700">
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 z-10">
                  <tr className="bg-surface-50 dark:bg-surface-800/80">
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500 w-8">#</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500">Primary Device</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500">Secondary Device</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500">Failover Link</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500">Stateful Link</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500 w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {pairs.map((pair, idx) => {
                    const foIntf = getFailoverIntf(idx)
                    const stIntf = getStatefulIntf(idx)
                    const foIPs = getFailoverIPs(idx)
                    const stIPs = getStatefulIPs(idx)
                    return (
                      <tr key={idx} className="border-b border-surface-100 dark:border-surface-800/50 last:border-b-0">
                        <td className="px-3 py-1.5 text-surface-400 font-semibold">{idx + 1}</td>
                        <td className="px-3 py-1.5">
                          <select value={pair.primary} onChange={(e) => updatePair(idx, 'primary', e.target.value)} className={cn(selectCls, 'w-full py-1')}>
                            <option value="">— Select Primary —</option>
                            {allDeviceNames.map((n) => (
                              <option key={n} value={n}>{n}</option>
                            ))}
                          </select>
                        </td>
                        <td className="px-3 py-1.5">
                          <select value={pair.secondary} onChange={(e) => updatePair(idx, 'secondary', e.target.value)} className={cn(selectCls, 'w-full py-1')}>
                            <option value="">— Select Secondary —</option>
                            {allDeviceNames.map((n) => (
                              <option key={n} value={n}>{n}</option>
                            ))}
                          </select>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-[10px] text-surface-500">
                          <div>{foIntf}</div>
                          <div className="text-[9px] text-surface-400">{foIPs.active} / {foIPs.standby}</div>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-[10px] text-surface-500">
                          <div>{stIntf}</div>
                          <div className="text-[9px] text-surface-400">{stIPs.active} / {stIPs.standby}</div>
                        </td>
                        <td className="px-3 py-1.5">
                          {pairs.length > 1 && (
                            <button onClick={() => removePair(idx)} className="p-1 text-accent-rose/60 hover:text-accent-rose transition-colors">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Preview */}
          {showPreview && (
            <div>
              <h4 className="text-xs font-semibold text-surface-700 dark:text-surface-300 mb-2">
                HA Config Preview
                <span className="ml-2 text-[10px] font-normal text-surface-400">
                  — {pairs.filter((p) => p.primary && p.secondary && p.primary !== p.secondary).length} pair(s)
                </span>
              </h4>
              <pre className={cn(
                'rounded-lg border border-surface-200 dark:border-surface-700 p-3',
                'bg-surface-50 dark:bg-surface-800/50 text-[10px] font-mono leading-relaxed',
                'text-surface-700 dark:text-surface-300 max-h-64 overflow-auto whitespace-pre'
              )}>
                {buildPreviewYaml()}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-surface-200 dark:border-surface-800/50 shrink-0">
          <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[11px] font-medium border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
            Cancel
          </button>
          <button
            onClick={handleCreate}
            disabled={isOperationRunning}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-vyper-600 hover:bg-vyper-700 text-white transition-colors',
              isOperationRunning && 'opacity-40 pointer-events-none'
            )}
          >
            <Plus className="w-3.5 h-3.5" /> Create HA Pairs
          </button>
        </div>
      </div>
    </div>
  )
}
