import { useState, useEffect } from 'react'
import { cn, selectCls } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { createHaPairs } from './api'
import { X, Plus, Trash2, Shield } from 'lucide-react'

interface HaPair {
  primary: string
  secondary: string
}

interface HaModalProps {
  open: boolean
  onClose: () => void
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

  // HA pairs
  const [pairs, setPairs] = useState<HaPair[]>([])

  // Auto-populate pairs from selected devices
  useEffect(() => {
    if (!open) return
    const ids = Array.from(selectedDeviceIds)
    const newPairs: HaPair[] = []
    for (let i = 0; i < ids.length - 1; i += 2) {
      newPairs.push({ primary: ids[i], secondary: ids[i + 1] })
    }
    if (ids.length % 2 !== 0) {
      newPairs.push({ primary: ids[ids.length - 1], secondary: '' })
    }
    if (newPairs.length === 0) newPairs.push({ primary: '', secondary: '' })
    setPairs(newPairs)
  }, [open, selectedDeviceIds])

  if (!open) return null

  const selectedDevices = devices.filter((d) => selectedDeviceIds.has(d.id))

  const addPair = () => setPairs((p) => [...p, { primary: '', secondary: '' }])
  const removePair = (idx: number) => setPairs((p) => p.filter((_, i) => i !== idx))
  const updatePair = (idx: number, field: 'primary' | 'secondary', value: string) => {
    setPairs((p) => p.map((pair, i) => i === idx ? { ...pair, [field]: value } : pair))
  }

  const incrementIp = (ip: string, octet: number, amount: number): string => {
    const parts = ip.split('.')
    if (parts.length !== 4) return ip
    parts[octet - 1] = String(parseInt(parts[octet - 1]) + amount)
    return parts.join('.')
  }

  const handleCreate = async () => {
    const validPairs = pairs.filter((p) => p.primary && p.secondary)
    if (validPairs.length === 0) { alert('Configure at least one complete HA pair'); return }

    const pairsPayload = validPairs.map((pair, idx) => {
      // Failover interface
      const foIntf = failoverIntfMode === 'range'
        ? `${failoverRangePrefix}${failoverRangeStart + idx}`
        : failoverIntfName

      const foPrimaryIp = failoverIpVer === 'ipv4' ? incrementIp(failoverPrimaryIp, failoverIncOctet, idx) : failoverPrimaryIp
      const foSecondaryIp = failoverIpVer === 'ipv4' ? incrementIp(failoverSecondaryIp, failoverIncOctet, idx) : failoverSecondaryIp

      // Stateful interface
      let sfIntf = foIntf
      let sfPrimaryIp = foPrimaryIp
      let sfSecondaryIp = foSecondaryIp
      let sfSubnet = failoverSubnet

      if (statefulMode === 'single') {
        sfIntf = statefulIntfName
        sfPrimaryIp = statefulIpVer === 'ipv4' ? incrementIp(statefulPrimaryIp, statefulIncOctet, idx) : statefulPrimaryIp
        sfSecondaryIp = statefulIpVer === 'ipv4' ? incrementIp(statefulSecondaryIp, statefulIncOctet, idx) : statefulSecondaryIp
        sfSubnet = statefulSubnet
      } else if (statefulMode === 'range') {
        sfIntf = `${statefulRangePrefix}${statefulRangeStart + idx}`
        sfPrimaryIp = statefulIpVer === 'ipv4' ? incrementIp(statefulPrimaryIp, statefulIncOctet, idx) : statefulPrimaryIp
        sfSecondaryIp = statefulIpVer === 'ipv4' ? incrementIp(statefulSecondaryIp, statefulIncOctet, idx) : statefulSecondaryIp
        sfSubnet = statefulSubnet
      }

      const primaryDev = devices.find((d) => d.id === pair.primary)
      const secondaryDev = devices.find((d) => d.id === pair.secondary)

      return {
        name: `${primaryDev?.name || 'device'}-HA`,
        primary_device: { id: pair.primary, name: primaryDev?.name },
        secondary_device: { id: pair.secondary, name: secondaryDev?.name },
        failover_link: {
          interface_name: foIntf,
          primary_ip: foPrimaryIp,
          secondary_ip: foSecondaryIp,
          subnet_mask: failoverIpVer === 'ipv4' ? failoverSubnet : undefined,
          ip_version: failoverIpVer,
        },
        stateful_failover_link: {
          use_same: statefulMode === 'same',
          interface_name: sfIntf,
          primary_ip: sfPrimaryIp,
          secondary_ip: sfSecondaryIp,
          subnet_mask: sfSubnet,
        },
        encryption: {
          enabled: encEnabled,
          key_type: encKeyType,
          shared_key: encKeyType === 'custom' ? encKey : undefined,
        },
      }
    })

    const result = await createHaPairs(pairsPayload)
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
              <h4 className="text-xs font-semibold text-surface-700 dark:text-surface-300">Device Pairs</h4>
              <button onClick={addPair} className="flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium bg-vyper-500/10 text-vyper-600 hover:bg-vyper-500/20 transition-colors">
                <Plus className="w-3 h-3" /> Add Pair
              </button>
            </div>
            <div className="overflow-auto max-h-60 rounded-lg border border-surface-200 dark:border-surface-700">
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 z-10">
                  <tr className="bg-surface-50 dark:bg-surface-800/80">
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500 w-8">#</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500">Primary Device</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500">Secondary Device</th>
                    <th className="px-3 py-1.5 text-left font-medium text-surface-500 w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {pairs.map((pair, idx) => (
                    <tr key={idx} className="border-b border-surface-100 dark:border-surface-800/50 last:border-b-0">
                      <td className="px-3 py-1.5 text-surface-400">{idx + 1}</td>
                      <td className="px-3 py-1.5">
                        <select value={pair.primary} onChange={(e) => updatePair(idx, 'primary', e.target.value)} className={cn(selectCls, 'w-full py-1')}>
                          <option value="">— Select Primary —</option>
                          {selectedDevices.map((d) => (
                            <option key={d.id} value={d.id}>{d.name}{d.hostname ? ` (${d.hostname})` : ''}</option>
                          ))}
                        </select>
                      </td>
                      <td className="px-3 py-1.5">
                        <select value={pair.secondary} onChange={(e) => updatePair(idx, 'secondary', e.target.value)} className={cn(selectCls, 'w-full py-1')}>
                          <option value="">— Select Secondary —</option>
                          {selectedDevices.map((d) => (
                            <option key={d.id} value={d.id}>{d.name}{d.hostname ? ` (${d.hostname})` : ''}</option>
                          ))}
                        </select>
                      </td>
                      <td className="px-3 py-1.5">
                        {pairs.length > 1 && (
                          <button onClick={() => removePair(idx)} className="p-1 text-accent-rose/60 hover:text-accent-rose transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
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
