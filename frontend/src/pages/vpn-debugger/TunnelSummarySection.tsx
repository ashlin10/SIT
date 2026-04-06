import { useState, useMemo, useCallback } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import type { TunnelData, ParamFilters } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, inputCls } from '@/lib/utils'
import CustomSelect from '@/components/CustomSelect'
import {
  Search, RefreshCw, ChevronDown, ChevronRight, XCircle,
  Plug, CircleDot, Shield, Loader2,
} from 'lucide-react'
import { refreshTunnels, fetchTunnelDetail, applyFilters, tunnelStatusCategory, parseCryptoParams, connectToServer } from './api'
import SectionCard from './SectionCard'
import ConnectPopup from './ConnectPopup'
import Toggle from '@/components/Toggle'

// ── Pie Chart (pure CSS/SVG) ──

function PieChart({ active, inactive, nodata }: { active: number; inactive: number; nodata: number }) {
  const total = active + inactive + nodata
  if (total === 0) {
    return (
      <div className="w-32 h-32 rounded-full border-[10px] border-surface-200 dark:border-surface-700 flex items-center justify-center">
        <span className="text-xs text-surface-400">No data</span>
      </div>
    )
  }

  const pct = (n: number) => Math.round((n / total) * 100)
  const activeP = pct(active)
  const inactiveP = pct(inactive)
  const nodataP = 100 - activeP - inactiveP

  const a1 = (activeP / 100) * 360
  const a2 = a1 + (inactiveP / 100) * 360

  return (
    <div className="flex flex-col items-center gap-3">
      <div
        className="w-32 h-32 rounded-full"
        style={{
          background: `conic-gradient(
            #84cc16 0deg ${a1}deg,
            #ef4444 ${a1}deg ${a2}deg,
            #9ca3af ${a2}deg 360deg
          )`,
        }}
      />
      <div className="space-y-1">
        <LegendItem color="#84cc16" label="Active" pct={activeP} count={active} />
        <LegendItem color="#ef4444" label="Inactive" pct={inactiveP} count={inactive} />
        <LegendItem color="#9ca3af" label="No Active Data" pct={nodataP} count={nodata} />
      </div>
    </div>
  )
}

function LegendItem({ color, label, pct, count }: { color: string; label: string; pct: number; count: number }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
      <span className="text-surface-600 dark:text-surface-400 min-w-[40px]">{pct}%</span>
      <span className="text-surface-700 dark:text-surface-300 font-medium">{label}</span>
      <span className="text-surface-400 ml-auto">{count}</span>
    </div>
  )
}

// ── Status helpers ──

function ikeColorClass(state: string) {
  const s = state.toUpperCase()
  if (s === 'ESTABLISHED') return 'text-lime-500'
  if (['CONNECTING', 'REKEYING', 'REAUTHENTICATING'].includes(s)) return 'text-yellow-500'
  if (['DESTROYING', 'DELETING', 'FAILED'].includes(s)) return 'text-red-500'
  if (s === 'PASSIVE') return 'text-surface-900 dark:text-surface-100'
  return 'text-surface-400'
}

function ipsecColorClass(state: string) {
  const s = state.toUpperCase()
  if (s === 'INSTALLED') return 'text-lime-500'
  if (['REKEYING', 'ROUTED', 'CREATED', 'INSTALLING', 'UPDATING'].includes(s)) return 'text-yellow-500'
  if (['DELETING', 'DESTROYING', 'FAILED'].includes(s)) return 'text-red-500'
  return 'text-surface-400'
}

function ikeDotColor(state: string) {
  const s = state.toUpperCase()
  if (s === 'ESTABLISHED') return 'bg-lime-500'
  if (['CONNECTING', 'REKEYING', 'REAUTHENTICATING'].includes(s)) return 'bg-yellow-500'
  if (['DESTROYING', 'DELETING', 'FAILED'].includes(s)) return 'bg-red-500'
  return 'bg-surface-400'
}

function ipsecDotColor(state: string) {
  const s = state.toUpperCase()
  if (s === 'INSTALLED') return 'bg-lime-500'
  if (['REKEYING', 'ROUTED', 'CREATED', 'INSTALLING', 'UPDATING'].includes(s)) return 'bg-yellow-500'
  if (['DELETING', 'DESTROYING', 'FAILED'].includes(s)) return 'bg-red-500'
  return 'bg-surface-400'
}

// ── Crypto Param Tag (clickable to add as filter) ──

function CryptoTag({ label, value, filterKey }: { label: string; value: string; filterKey?: keyof ParamFilters }) {
  const { paramFilters, setParamFilters } = useVpnDebuggerStore()
  const addFilter = () => {
    if (!filterKey || !value || value === 'NONE') return
    const current = paramFilters[filterKey]
    if (!current.includes(value)) {
      setParamFilters({ ...paramFilters, [filterKey]: [...current, value] })
      applyFilters()
    }
  }
  const isClickable = filterKey && value && value !== 'NONE'
  return (
    <div className="flex items-center gap-1 text-[10px]">
      <span className="text-surface-400 font-medium">{label}</span>
      <span
        className={cn(
          'font-mono px-1 py-px rounded',
          value === 'NONE' ? 'text-surface-400' : 'text-surface-700 dark:text-surface-300 bg-surface-100 dark:bg-surface-800',
          isClickable && 'cursor-pointer hover:bg-vyper-100 dark:hover:bg-vyper-900/30 hover:text-vyper-600 dark:hover:text-vyper-400 transition-colors',
        )}
        onClick={isClickable ? addFilter : undefined}
        title={isClickable ? `Click to filter by ${label}: ${value}` : undefined}
      >
        {value}
      </span>
    </div>
  )
}

// ── Expandable Row ──

function TunnelRow({ tunnel }: { tunnel: TunnelData }) {
  const [expanded, setExpanded] = useState(false)
  const [detail, setDetail] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const toggleExpand = async () => {
    if (!expanded && detail === null) {
      setLoading(true)
      const d = await fetchTunnelDetail(tunnel.name)
      setDetail(d)
      setLoading(false)
    }
    setExpanded(!expanded)
  }

  const ikeState = tunnel.ike_state || (tunnel.is_inactive ? 'INACTIVE' : '-')
  const ipsecState = tunnel.ipsec_state || (tunnel.is_inactive ? 'INACTIVE' : '-')
  const ikeParams = parseCryptoParams(tunnel.ike_crypto, true)
  const ipsecParams = parseCryptoParams(tunnel.ipsec_crypto, false)
  const localIpDisplay = tunnel.local_addr ? `(VPN IP: ${tunnel.local_addr}${tunnel.local_port ? '[' + tunnel.local_port + ']' : ''})` : ''
  const remoteIpDisplay = tunnel.remote_addr ? `(VPN IP: ${tunnel.remote_addr}${tunnel.remote_port ? '[' + tunnel.remote_port + ']' : ''})` : ''

  return (
    <>
      <tr className="hover:bg-surface-50 dark:hover:bg-surface-800/40 transition-colors cursor-pointer" onClick={toggleExpand}>
        <td className="px-2 py-2">
          <button className="p-0.5 rounded hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
            {loading ? (
              <Loader2 className="w-3.5 h-3.5 text-surface-400 animate-spin" />
            ) : expanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-surface-400" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-surface-400" />
            )}
          </button>
        </td>
        <td className="px-2 py-2 text-xs text-surface-700 dark:text-surface-300">
          <div className="font-medium truncate max-w-[140px]">{tunnel.local_name || tunnel.name || '-'}</div>
          <div className="text-[10px] text-surface-400 font-mono truncate">{localIpDisplay}</div>
        </td>
        <td className="px-2 py-2 text-xs text-surface-700 dark:text-surface-300">
          <div className="font-medium truncate max-w-[140px]">{tunnel.remote_name || 'remote'}</div>
          <div className="text-[10px] text-surface-400 font-mono truncate">{remoteIpDisplay}</div>
        </td>
        <td className="px-2 py-2">
          <div className="space-y-0.5">
            <div className="flex items-center gap-1.5">
              <span className="text-[9px] text-surface-400 w-[42px]">IKE SA:</span>
              <span className={cn('w-2 h-2 rounded-full inline-block', ikeDotColor(ikeState))} />
              <span className={cn('text-[10px] font-medium', ikeColorClass(ikeState))}>{ikeState}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[9px] text-surface-400 w-[42px]">IPsec:</span>
              <span className={cn('w-2 h-2 rounded-full inline-block', ipsecDotColor(ipsecState))} />
              <span className={cn('text-[10px] font-medium', ipsecColorClass(ipsecState))}>{ipsecState}</span>
            </div>
          </div>
        </td>
        <td className="px-2 py-2">
          {ikeParams ? (
            <div className="space-y-0.5">
              <CryptoTag label="Enc:" value={ikeParams.encryption} filterKey="encryption" />
              <CryptoTag label="Int:" value={ikeParams.integrity} filterKey="integrity" />
              <CryptoTag label="PRF:" value={ikeParams.prf} filterKey="prf" />
              <CryptoTag label="DH:" value={ikeParams.dh_group} filterKey="dh_group" />
              {ikeParams.akes.map(ake => (
                <CryptoTag key={`ike-ake-${ake.num}`} label={`AKE${ake.num}:`} value={ake.alg} filterKey="ake" />
              ))}
            </div>
          ) : <span className="text-[10px] text-surface-400">-</span>}
        </td>
        <td className="px-2 py-2">
          {ipsecParams ? (
            <div className="space-y-0.5">
              <CryptoTag label="Enc:" value={ipsecParams.encryption} filterKey="encryption" />
              <CryptoTag label="Int:" value={ipsecParams.integrity} filterKey="integrity" />
              <CryptoTag label="DH:" value={ipsecParams.dh_group} filterKey="dh_group" />
              {ipsecParams.akes.map(ake => (
                <CryptoTag key={`esp-ake-${ake.num}`} label={`AKE${ake.num}:`} value={ake.alg} filterKey="ake" />
              ))}
            </div>
          ) : <span className="text-[10px] text-surface-400">-</span>}
        </td>
        <td className="px-2 py-2 text-[10px] text-surface-500 font-mono">
          {tunnel.is_inactive || !tunnel.traffic_in ? (
            <span className="text-surface-400">-</span>
          ) : (
            <div className="space-y-0.5">
              <div>In: {tunnel.traffic_in_bytes || '0'} bytes, {tunnel.traffic_in_packets || '0'} pkts</div>
              <div>Out: {tunnel.traffic_out_bytes || '0'} bytes, {tunnel.traffic_out_packets || '0'} pkts</div>
            </div>
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="p-0">
            <div className="bg-surface-950 border-y border-surface-800 px-4 py-3">
              <pre className="text-[11px] font-mono text-accent-emerald leading-relaxed whitespace-pre-wrap break-all max-h-[300px] overflow-auto">
                {detail || 'No detail available'}
              </pre>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Param Filter Tags ──

function ParamFilterBar() {
  const { paramFilters, setParamFilters } = useVpnDebuggerStore()
  const [selectedParam, setSelectedParam] = useState('')
  const [paramValue, setParamValue] = useState('')

  const addTag = () => {
    if (!selectedParam || !paramValue.trim()) return
    const key = selectedParam as keyof ParamFilters
    const current = paramFilters[key]
    if (!current.includes(paramValue.trim())) {
      setParamFilters({ ...paramFilters, [key]: [...current, paramValue.trim()] })
    }
    setParamValue('')
    applyFilters()
  }

  const removeTag = (key: keyof ParamFilters, val: string) => {
    setParamFilters({ ...paramFilters, [key]: paramFilters[key].filter((v) => v !== val) })
    applyFilters()
  }

  const allTags = Object.entries(paramFilters).flatMap(([k, vals]: [string, string[]]) =>
    vals.map((v: string) => ({ key: k as keyof ParamFilters, val: v }))
  )

  const clearAll = () => {
    setParamFilters({ encryption: [], integrity: [], prf: [], dh_group: [], ake: [] })
    setSelectedParam('')
    setParamValue('')
    applyFilters()
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <CustomSelect
        value={selectedParam}
        onChange={setSelectedParam}
        placeholder="Filter by param..."
        minWidth="155px"
        options={[
          { value: 'encryption', label: 'Encryption' },
          { value: 'integrity', label: 'Integrity' },
          { value: 'prf', label: 'PRF' },
          { value: 'dh_group', label: 'DH Group' },
          { value: 'ake', label: 'AKE Algorithm' },
        ]}
      />
      {allTags.length > 0 && (
        <button onClick={clearAll} className="p-1 rounded-md text-surface-400 hover:text-accent-rose hover:bg-accent-rose/10 transition-colors" title="Clear all filters">
          <XCircle className="w-3.5 h-3.5" />
        </button>
      )}
      {selectedParam && (
        <input
          value={paramValue}
          onChange={(e) => setParamValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addTag()}
          placeholder="Enter value..."
          className={cn(inputCls, 'w-28')}
        />
      )}
      {allTags.map((t) => (
        <span key={`${t.key}-${t.val}`} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-vyper-50 dark:bg-vyper-900/20 text-[10px] font-medium text-vyper-600 dark:text-vyper-400">
          {t.key}: {t.val}
          <button onClick={() => removeTag(t.key, t.val)} className="hover:text-red-500 transition-colors">
            <XCircle className="w-3 h-3" />
          </button>
        </span>
      ))}
    </div>
  )
}

// ── Main ──

export default function TunnelSummarySection() {
  const store = useVpnDebuggerStore()
  const {
    localConnected, tunnels, filteredTunnels,
    searchQuery, setSearchQuery, statusFilter, setStatusFilter,
    currentPage, setCurrentPage, pageSize,
    refreshInterval, setRefreshInterval, lastUpdated, refreshing,
    summaryConnPopupOpen, summaryConn, openSummaryConnPopup, closeSummaryConnPopup, setSummaryConn,
    localNodeType,
  } = store

  const isCsc = localNodeType === 'csc'
  const [sameAsLocal, setSameAsLocal] = useState(true)
  const [summaryConnected, setSummaryConnected] = useState(false)

  const connected = sameAsLocal ? localConnected : summaryConnected

  const stats = useMemo(() => {
    let active = 0, inactive = 0, nodata = 0
    for (const t of tunnels) {
      const c = tunnelStatusCategory(t)
      if (c === 'active') active++
      else if (c === 'inactive') inactive++
      else nodata++
    }
    return { active, inactive, nodata }
  }, [tunnels])

  const totalPages = Math.max(1, Math.ceil(filteredTunnels.length / pageSize))
  const page = Math.min(currentPage, totalPages)
  const paged = filteredTunnels.slice((page - 1) * pageSize, page * pageSize)
  const showStart = filteredTunnels.length > 0 ? (page - 1) * pageSize + 1 : 0
  const showEnd = Math.min(page * pageSize, filteredTunnels.length)

  const handleRefresh = useCallback(() => { refreshTunnels() }, [])

  const clearAllFilters = () => {
    setSearchQuery('')
    setStatusFilter(null)
    useVpnDebuggerStore.getState().setParamFilters({ encryption: [], integrity: [], prf: [], dh_group: [], ake: [] })
    applyFilters()
  }

  const hasFilters = searchQuery || statusFilter || Object.values(useVpnDebuggerStore.getState().paramFilters).some((v: string[]) => v.length > 0)

  const handleSummaryConnect = async () => {
    await connectToServer(summaryConn)
    setSummaryConnected(true)
    closeSummaryConnPopup()
  }

  return (
    <>
      <SectionCard
        title="Tunnel Summary"
        headerRight={
          <div className="flex items-center gap-2">
            <Toggle checked={sameAsLocal} onChange={setSameAsLocal} label="Same as Local Node" />
            {!sameAsLocal && (
              <button onClick={openSummaryConnPopup} className="p-1 text-blue-500 hover:text-blue-600 transition-colors" title="Connect">
                <Plug className="w-3.5 h-3.5" />
              </button>
            )}
            <span className={cn(
              'inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full',
              connected ? 'bg-accent-emerald/10 text-accent-emerald' : 'bg-surface-100 dark:bg-surface-800 text-surface-500'
            )}>
              <CircleDot className="w-2.5 h-2.5" />
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        }
      >
        {isCsc ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <Shield className="w-10 h-10 text-surface-300 dark:text-surface-600 mb-3" />
            <div className="text-sm font-medium text-surface-500 dark:text-surface-400">Tunnel Summary unavailable</div>
            <div className="text-xs text-surface-400 mt-1">This feature is only available in strongSwan mode</div>
          </div>
        ) : (
        <>
        {/* Controls bar */}
        <div className="flex items-center gap-2 flex-wrap mb-3">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-surface-400" />
            <input
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); applyFilters() }}
              placeholder="Search..."
              className={cn(inputCls, 'pl-6 w-48')}
            />
          </div>
          <ParamFilterBar />
          {hasFilters && (
            <button onClick={clearAllFilters} className={cn(btnCls(), 'text-red-500 hover:bg-red-500/10')}>
              <XCircle className="w-3.5 h-3.5" /> Clear All
            </button>
          )}
          <div className="flex items-center gap-1.5 ml-auto">
            <button onClick={handleRefresh} disabled={!connected || refreshing} className={btnCls()}>
              <RefreshCw className={cn('w-3.5 h-3.5', refreshing && 'animate-spin')} /> Refresh
            </button>
            <span className="text-[10px] text-surface-400">every</span>
            <CustomSelect
              value={String(refreshInterval)}
              onChange={(v) => setRefreshInterval(parseInt(v))}
              options={[
                { value: '0', label: 'Manual' },
                { value: '5', label: '5 sec' },
                { value: '10', label: '10 sec' },
                { value: '30', label: '30 sec' },
                { value: '60', label: '1 min' },
                { value: '300', label: '5 min' },
              ]}
            />
          </div>
        </div>

        {lastUpdated && (
          <div className="text-[10px] text-surface-400 mb-3">Last Updated: {lastUpdated}</div>
        )}

        {tunnels.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-10 h-10 text-surface-300 dark:text-surface-700 mx-auto mb-3" />
            <p className="text-sm text-surface-400">No tunnel data available. Connect to a strongSwan server to view tunnels.</p>
          </div>
        ) : (
          <div className="flex gap-5">
            <div className="shrink-0">
              <h3 className="text-xs font-semibold text-surface-600 dark:text-surface-400 mb-3">Tunnel Summary</h3>
              <PieChart {...stats} />
            </div>

            <div className="flex-1 min-w-0">
              <div className="overflow-x-auto rounded-lg border border-surface-200 dark:border-surface-800">
                <table className="w-full">
                  <thead>
                    <tr className="bg-surface-50 dark:bg-surface-800/50">
                      <th className="w-8 px-2 py-2" />
                      <th className="px-2 py-2 text-left text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Local Node</th>
                      <th className="px-2 py-2 text-left text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Remote Node</th>
                      <th className="px-2 py-2 text-left text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Status</th>
                      <th className="px-2 py-2 text-left text-[10px] font-semibold text-surface-500 uppercase tracking-wider">IKE Params</th>
                      <th className="px-2 py-2 text-left text-[10px] font-semibold text-surface-500 uppercase tracking-wider">IPsec Params</th>
                      <th className="px-2 py-2 text-left text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Traffic</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-100 dark:divide-surface-800">
                    {paged.map((t) => (
                      <TunnelRow key={t.name} tunnel={t} />
                    ))}
                    {paged.length === 0 && (
                      <tr>
                        <td colSpan={7} className="px-4 py-6 text-center text-xs text-surface-400">
                          No tunnels match your filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between mt-2.5">
                <span className="text-[10px] text-surface-400">
                  Viewing {showStart}-{showEnd} of {filteredTunnels.length}
                </span>
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
                    <button
                      key={p}
                      onClick={() => setCurrentPage(p)}
                      className={cn(
                        'w-6 h-6 rounded text-[10px] font-medium transition-colors',
                        p === page
                          ? 'bg-vyper-600 text-white'
                          : 'text-surface-500 hover:bg-surface-100 dark:hover:bg-surface-800',
                      )}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
        </>
        )}
      </SectionCard>

      {summaryConnPopupOpen && (
        <ConnectPopup
          title="Connect to Tunnel Summary Server"
          conn={summaryConn}
          setConn={setSummaryConn}
          onConnect={handleSummaryConnect}
          onClose={closeSummaryConnPopup}
        />
      )}
    </>
  )
}
