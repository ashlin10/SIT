import { useEffect, useMemo, useState } from 'react'
import { cn, selectCls } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { convertToMultiInstance, fetchTemplateLookups, type MultiInstanceForm } from './api'
import { Layers, X, Wand2, Info } from 'lucide-react'

interface Props {
  open: boolean
  onClose: () => void
  sourceConfig: Record<string, unknown> | null
  sourceName: string
}

interface InstanceRow {
  vrf: string
  name: string
  fqdn: string
  mgmt_ip: string
  mgmt_ipv6: string
}

const vrfCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })

type Lookup = { id: string; name: string }
type Licenses = { CARRIER: boolean; MALWARE: boolean; THREAT: boolean; URLFilter: boolean }

const LICENSE_KEYS: Array<keyof Licenses> = ['CARRIER', 'MALWARE', 'THREAT', 'URLFilter']

const inputCls =
  'w-full px-2.5 py-1 text-xs rounded-md border border-surface-200 dark:border-surface-700 ' +
  'bg-white dark:bg-surface-800 text-surface-800 dark:text-surface-200 ' +
  'focus:outline-none focus:ring-2 focus:ring-vyper-500/40'
const labelCls = 'text-[11px] font-medium text-surface-500 dark:text-surface-400'
const panelCls = 'rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden'
const panelHeadCls = 'px-3 py-2 bg-surface-50 dark:bg-surface-800/50 flex items-center gap-2 text-[11px] font-medium text-surface-700 dark:text-surface-300'

/** Increment the last octet of an IPv4 address by n; returns '' on parse failure. */
function incrementIp(ip: string, n: number): string {
  const parts = (ip || '').trim().split('.')
  if (parts.length !== 4) return ''
  const nums = parts.map((p) => parseInt(p, 10))
  if (nums.some((x) => Number.isNaN(x) || x < 0 || x > 255)) return ''
  const val = ((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3] + n
  const a = (val >>> 24) & 255
  const b = (val >>> 16) & 255
  const c = (val >>> 8) & 255
  const d = val & 255
  return `${a}.${b}.${c}.${d}`
}

/** Increment the last hextet of an IPv6 address by offset (mirrors chassis template). */
function incrementIpv6Last(ip: string, offset: number): string {
  if (!ip) return ''
  const halves = ip.split('::')
  let groups: string[]
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : []
    const right = halves[1] ? halves[1].split(':') : []
    const fill = 8 - left.length - right.length
    groups = [...left, ...Array(Math.max(fill, 0)).fill('0'), ...right]
  } else {
    groups = ip.split(':')
  }
  while (groups.length < 8) groups.push('0')
  groups[7] = (parseInt(groups[7] || '0', 16) + offset).toString(16)
  const full = groups.map((g) => g.replace(/^0+/, '') || '0')
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

export default function MultiInstanceDialog({ open, onClose, sourceConfig, sourceName }: Props) {
  // Detect VRFs (Global first, then source order).
  const detectedVrfs = useMemo(() => {
    const routing = (sourceConfig?.routing || {}) as Record<string, unknown>
    const vrfs = (routing.vrfs || []) as Array<Record<string, unknown>>
    const names = vrfs.map((v) => String(v.name || '').trim()).filter(Boolean)
    // Global first, then all other VRFs sorted alphanumerically (natural order).
    const global = names.filter((n) => n.toLowerCase() === 'global').sort(vrfCollator.compare)
    const others = names.filter((n) => n.toLowerCase() !== 'global').sort(vrfCollator.compare)
    return [...global, ...others]
  }, [sourceConfig])

  const { connected } = useFmcConfigStore()

  // FMC lookups for registration dropdowns.
  const [lookups, setLookups] = useState<Record<string, Lookup[]>>({})
  const [loadingLookups, setLoadingLookups] = useState(false)
  const findLookup = (key: string, name: string): Lookup | undefined =>
    (lookups[key] || []).find((x) => x.name === name)

  // Shared Management Bootstrap
  const [mgmtGateway, setMgmtGateway] = useState('192.168.2.1')
  const [mgmtMask, setMgmtMask] = useState('255.255.255.0')
  const [mgmtIpv6Gw, setMgmtIpv6Gw] = useState('')
  const [mgmtIpv6Prefix, setMgmtIpv6Prefix] = useState('64')
  const [dnsServers, setDnsServers] = useState('72.163.128.140,64.104.128.236')
  const [searchDomain, setSearchDomain] = useState('cisco.com')
  const [adminPassword, setAdminPassword] = useState('C15c01@3')
  const [firewallMode, setFirewallMode] = useState('routed')
  const [permitExpertMode, setPermitExpertMode] = useState('yes')
  const [ftdVersion, setFtdVersion] = useState('')

  // Shared Device Registration (dropdowns selected by name; ids resolved from lookups)
  const [resourceProfile, setResourceProfile] = useState('')
  const [accessPolicy, setAccessPolicy] = useState('')
  const [deviceGroup, setDeviceGroup] = useState('')
  const [platformSettings, setPlatformSettings] = useState('')
  const [licenses, setLicenses] = useState<Licenses>({ CARRIER: false, MALWARE: true, THREAT: true, URLFilter: true })
  const [adminState, setAdminState] = useState('enabled')

  // Per-instance rows (initialised from detected VRFs).
  const [rows, setRows] = useState<InstanceRow[]>([])
  const [busy, setBusy] = useState(false)

  const effectiveDomain = searchDomain.trim() || 'cisco.com'

  // (Re)initialise rows whenever the detected VRF set changes. Name is derived
  // from the source FTD name (metadata.source_ftd.name) as `<name>-app-<N>`,
  // and FQDN is pre-filled as `<name>.<searchDomain>`.
  useEffect(() => {
    setRows(detectedVrfs.map((vrf, i) => {
      const name = `${sourceName}-app-${i + 1}`
      return { vrf, name, fqdn: `${name}.${effectiveDomain}`, mgmt_ip: '', mgmt_ipv6: '' }
    }))
    // effectiveDomain intentionally omitted so user edits to FQDN/domain persist.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detectedVrfs, sourceName])

  // Fetch FMC lookups when the dialog opens (only if connected).
  useEffect(() => {
    if (!open || !connected) return
    setLoadingLookups(true)
    fetchTemplateLookups().then((data) => {
      if (data.success) setLookups(data)
    }).finally(() => setLoadingLookups(false))
  }, [open, connected])

  if (!open) return null

  const setRow = (idx: number, patch: Partial<InstanceRow>) =>
    setRows((rs) => rs.map((r, i) => (i === idx ? { ...r, ...patch } : r)))

  const toggleLicense = (k: keyof Licenses) => setLicenses((l) => ({ ...l, [k]: !l[k] }))

  // Auto-fill: take the first row's IPv4/IPv6 values as the base and increment
  // each subsequent row by one. IPv4 and IPv6 are independent and optional.
  const autoFillIps = () => {
    setRows((rs) => {
      const baseV4 = rs[0]?.mgmt_ip?.trim() || ''
      const baseV6 = rs[0]?.mgmt_ipv6?.trim() || ''
      return rs.map((r, i) => {
        const v4 = baseV4 ? incrementIp(baseV4, i) : r.mgmt_ip
        const v6 = baseV6 ? incrementIpv6Last(baseV6, i) : r.mgmt_ipv6
        return { ...r, mgmt_ip: v4 || r.mgmt_ip, mgmt_ipv6: v6 || r.mgmt_ipv6 }
      })
    })
  }

  const handleConvert = async () => {
    if (detectedVrfs.length === 0) {
      alert('The source config has no routing.vrfs to split into instances.')
      return
    }
    setBusy(true)
    try {
      const licenseCaps = LICENSE_KEYS.filter((k) => licenses[k]).join(',')
      const form: MultiInstanceForm = {
        mgmt_gateway: mgmtGateway,
        mgmt_mask: mgmtMask,
        mgmt_ipv6_gateway: mgmtIpv6Gw,
        mgmt_ipv6_prefix: mgmtIpv6Prefix ? parseInt(mgmtIpv6Prefix, 10) : undefined,
        dns_servers: dnsServers,
        search_domain: searchDomain,
        admin_password: adminPassword,
        firewall_mode: firewallMode,
        permit_expert_mode: permitExpertMode,
        admin_state: adminState,
        ftd_version: ftdVersion,
        resource_profile_name: resourceProfile,
        resource_profile_id: findLookup('resourceProfiles', resourceProfile)?.id || '',
        access_policy_name: accessPolicy,
        access_policy_id: findLookup('accessPolicies', accessPolicy)?.id || '',
        device_group_name: deviceGroup,
        device_group_id: findLookup('deviceGroups', deviceGroup)?.id || '',
        platform_settings_name: platformSettings,
        platform_settings_id: findLookup('platformSettings', platformSettings)?.id || '',
        license_caps: licenseCaps,
        instances: rows.map((r) => ({
          vrf: r.vrf,
          name: r.name,
          fqdn: r.fqdn.trim() || `${r.name}.${effectiveDomain}`,
          mgmt_ip: r.mgmt_ip.trim(),
          mgmt_ipv6: r.mgmt_ipv6.trim(),
        })),
      }
      const res = await convertToMultiInstance(sourceConfig || {}, form)
      if (!res.success) {
        alert(res.message || 'Conversion failed')
        return
      }
      const warns = Array.isArray(res.warnings) ? res.warnings : []
      const count = Array.isArray(res.instances) ? res.instances.length : rows.length
      alert(
        `Generated ${count} instance config(s) + chassis config.\n` +
        `Both files were loaded into the Device/Chassis panes and downloaded.` +
        (warns.length ? `\n\nWarnings:\n- ${warns.slice(0, 10).join('\n- ')}` : '')
      )
      onClose()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />

      <div className={cn(
        'relative w-[92vw] max-w-3xl max-h-[88vh] flex flex-col',
        'bg-white dark:bg-surface-900 rounded-xl border border-surface-200 dark:border-surface-800',
        'shadow-2xl overflow-hidden'
      )}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-200 dark:border-surface-800/50 shrink-0">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-vyper-500" />
            <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">
              Convert to Multi-Instance — {sourceName}
            </h3>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* VRF preview */}
          <div className="rounded-lg border border-vyper-300/40 dark:border-vyper-500/30 bg-vyper-50/40 dark:bg-vyper-500/5 p-3">
            <div className="text-[11px] font-semibold text-vyper-700 dark:text-vyper-300 mb-1">
              Detected VRFs → Instances
            </div>
            {detectedVrfs.length === 0 ? (
              <p className="text-[11px] text-accent-rose">No routing.vrfs found in this config — nothing to split.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {detectedVrfs.map((v, i) => (
                  <span key={v} className="text-[10px] font-medium text-surface-700 dark:text-surface-200 bg-white dark:bg-surface-800 border border-surface-200 dark:border-surface-600 rounded-full px-2 py-0.5">
                    {v} <span className="text-vyper-600 dark:text-vyper-400">→</span> instance {i + 1}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Management Bootstrap & Device Registration */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Management Bootstrap */}
            <div className={panelCls}>
              <div className={panelHeadCls}><Layers className="w-3.5 h-3.5 text-surface-500" /> Management Bootstrap</div>
              <div className="p-3 space-y-2">
                <div className="grid grid-cols-2 gap-2">
                  <div><label className={labelCls}>IPv4 Gateway</label><input className={cn(inputCls, 'mt-0.5')} value={mgmtGateway} onChange={(e) => setMgmtGateway(e.target.value)} placeholder="192.168.2.1" /></div>
                  <div><label className={labelCls}>IPv4 Mask</label><input className={cn(inputCls, 'mt-0.5')} value={mgmtMask} onChange={(e) => setMgmtMask(e.target.value)} placeholder="255.255.255.0" /></div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div><label className={labelCls}>IPv6 Gateway</label><input className={cn(inputCls, 'mt-0.5')} value={mgmtIpv6Gw} onChange={(e) => setMgmtIpv6Gw(e.target.value)} placeholder="2000:2::1" /></div>
                  <div><label className={labelCls}>IPv6 Prefix</label><input className={cn(inputCls, 'mt-0.5')} value={mgmtIpv6Prefix} onChange={(e) => setMgmtIpv6Prefix(e.target.value)} placeholder="64" /></div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div><label className={labelCls}>Search Domain</label><input className={cn(inputCls, 'mt-0.5')} value={searchDomain} onChange={(e) => setSearchDomain(e.target.value)} placeholder="cisco.com" /></div>
                  <div><label className={labelCls}>DNS Servers</label><input className={cn(inputCls, 'mt-0.5')} value={dnsServers} onChange={(e) => setDnsServers(e.target.value)} placeholder="72.163.128.140,64.104.128.236" /></div>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div><label className={labelCls}>Firewall Mode</label>
                    <select className={cn(selectCls, 'w-full mt-0.5')} value={firewallMode} onChange={(e) => setFirewallMode(e.target.value)}>
                      <option value="routed">Routed</option>
                      <option value="transparent">Transparent</option>
                    </select>
                  </div>
                  <div><label className={labelCls}>Permit Expert Mode</label>
                    <select className={cn(selectCls, 'w-full mt-0.5')} value={permitExpertMode} onChange={(e) => setPermitExpertMode(e.target.value)}>
                      <option value="yes">Yes</option>
                      <option value="no">No</option>
                    </select>
                  </div>
                  <div><label className={labelCls}>Admin Password</label><input type="text" className={cn(inputCls, 'mt-0.5')} value={adminPassword} onChange={(e) => setAdminPassword(e.target.value)} /></div>
                </div>
                <div><label className={labelCls}>FTD App Version</label><input className={cn(inputCls, 'mt-0.5')} value={ftdVersion} onChange={(e) => setFtdVersion(e.target.value)} placeholder="10.1.0.136" /></div>
              </div>
            </div>

            {/* Device Registration */}
            <div className={panelCls}>
              <div className={panelHeadCls}><Layers className="w-3.5 h-3.5 text-surface-500" /> Device Registration</div>
              <div className="p-3 space-y-2">
                {!connected && (
                  <div className="flex items-start gap-1.5 rounded-md bg-amber-500/10 border border-amber-500/30 px-2.5 py-1.5 text-[10px] text-amber-700 dark:text-amber-400">
                    <Info className="w-3.5 h-3.5 shrink-0 mt-px" />
                    Connect to FMC to load Access Policy, Device Group, Platform Settings and Resource Profile options.
                  </div>
                )}
                {connected && loadingLookups && (
                  <div className="text-[10px] text-surface-400">Loading options from FMC…</div>
                )}
                <div><label className={labelCls}>Access Policy</label>
                  <select className={cn(selectCls, 'w-full mt-0.5')} value={accessPolicy} onChange={(e) => setAccessPolicy(e.target.value)} disabled={!connected}>
                    <option value="">-- Select --</option>
                    {(lookups.accessPolicies || []).map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
                  </select>
                </div>
                <div><label className={labelCls}>Device Group</label>
                  <select className={cn(selectCls, 'w-full mt-0.5')} value={deviceGroup} onChange={(e) => setDeviceGroup(e.target.value)} disabled={!connected}>
                    <option value="">-- Select --</option>
                    {(lookups.deviceGroups || []).map((g) => <option key={g.id} value={g.name}>{g.name}</option>)}
                  </select>
                </div>
                <div><label className={labelCls}>Platform Settings</label>
                  <select className={cn(selectCls, 'w-full mt-0.5')} value={platformSettings} onChange={(e) => setPlatformSettings(e.target.value)} disabled={!connected}>
                    <option value="">-- Select --</option>
                    {(lookups.platformSettings || []).map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
                  </select>
                </div>
                <div><label className={labelCls}>Resource Profile</label>
                  <select className={cn(selectCls, 'w-full mt-0.5')} value={resourceProfile} onChange={(e) => setResourceProfile(e.target.value)} disabled={!connected}>
                    <option value="">-- Select --</option>
                    {(lookups.resourceProfiles || []).map((p) => <option key={p.id} value={p.name}>{p.name}</option>)}
                  </select>
                </div>
                <div>
                  <label className={labelCls}>License Capabilities</label>
                  <div className="flex flex-wrap items-center gap-3 mt-1">
                    {LICENSE_KEYS.map((lic) => (
                      <label key={lic} className="flex items-center gap-1 text-[10px] text-surface-600 dark:text-surface-400">
                        <input type="checkbox" checked={licenses[lic]} onChange={() => toggleLicense(lic)} className="rounded border-surface-300 dark:border-surface-600 text-vyper-600" />
                        {lic}
                      </label>
                    ))}
                  </div>
                </div>
                <div><label className={labelCls}>Admin State</label>
                  <select className={cn(selectCls, 'w-full mt-0.5')} value={adminState} onChange={(e) => setAdminState(e.target.value)}>
                    <option value="enabled">Enabled</option>
                    <option value="disabled">Disabled</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Per-instance */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-semibold text-surface-700 dark:text-surface-300">Per-Instance Settings</div>
              <button onClick={autoFillIps} title="Increment IPv4/IPv6 from the first row down each instance" className="flex items-center gap-1 text-[10px] font-medium text-vyper-600 dark:text-vyper-400 bg-vyper-500/10 border border-vyper-500/20 rounded-md px-2 py-1 hover:bg-vyper-500/20 transition-colors">
                <Wand2 className="w-3 h-3" /> Auto-fill IPs
              </button>
            </div>
            <div className="space-y-2">
              {rows.length > 0 && (
                <div className="grid grid-cols-[70px_1.2fr_1.6fr_1fr_1.2fr] gap-2 text-[10px] text-surface-400 px-1">
                  <span>VRF</span><span>Name</span><span>FQDN</span><span>Mgmt IPv4</span><span>Mgmt IPv6</span>
                </div>
              )}
              {rows.map((r, i) => (
                <div key={r.vrf} className="grid grid-cols-[70px_1.2fr_1.6fr_1fr_1.2fr] gap-2 items-center">
                  <span className="text-[11px] font-medium text-surface-600 dark:text-surface-400 truncate" title={r.vrf}>{r.vrf}</span>
                  <input className={inputCls} value={r.name} onChange={(e) => setRow(i, { name: e.target.value })} placeholder={`${sourceName}-app-${i + 1}`} />
                  <input className={inputCls} value={r.fqdn} onChange={(e) => setRow(i, { fqdn: e.target.value })} placeholder={`${r.name || `${sourceName}-app-${i + 1}`}.${effectiveDomain}`} />
                  <input className={inputCls} value={r.mgmt_ip} onChange={(e) => setRow(i, { mgmt_ip: e.target.value })} />
                  <input className={inputCls} value={r.mgmt_ipv6} onChange={(e) => setRow(i, { mgmt_ipv6: e.target.value })} />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-surface-200 dark:border-surface-800/50 shrink-0">
          <button onClick={onClose} className="text-xs font-medium text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 px-3 py-1.5">
            Cancel
          </button>
          <button
            onClick={handleConvert}
            disabled={busy || detectedVrfs.length === 0}
            className={cn(
              'flex items-center gap-1.5 text-xs font-medium text-white bg-vyper-600 hover:bg-vyper-700 rounded-md px-3.5 py-1.5 transition-colors',
              (busy || detectedVrfs.length === 0) && 'opacity-40 pointer-events-none'
            )}
          >
            <Layers className="w-3.5 h-3.5" /> {busy ? 'Converting…' : 'Convert & Load'}
          </button>
        </div>
      </div>
    </div>
  )
}
