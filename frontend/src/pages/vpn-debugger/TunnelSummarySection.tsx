import { useState, useMemo, useCallback, useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import type { TunnelData, ParamFilters } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, inputCls } from '@/lib/utils'
import CustomSelect from '@/components/CustomSelect'
import {
  Search, RefreshCw, ChevronDown, ChevronRight, XCircle,
  Plug, CircleDot, Shield, Loader2,
} from 'lucide-react'
import { refreshTunnels, fetchTunnelDetail, applyFilters, tunnelStatusCategory, parseCryptoParams, connectToServer, fetchCscVpnSessions } from './api'
import SectionCard from './SectionCard'
import ConnectPopup from './ConnectPopup'
import Toggle from '@/components/Toggle'

// ── Donut Chart (SVG with hover + animation) ──

interface Segment { label: string; value: number; color: string; hoverColor: string }

function DonutChart({ active, inactive, nodata }: { active: number; inactive: number; nodata: number }) {
  const total = active + inactive + nodata
  const [hovered, setHovered] = useState<number | null>(null)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 50)
    return () => clearTimeout(t)
  }, [])

  if (total === 0) {
    return (
      <div className="flex flex-col items-center gap-3">
        <div className="relative w-36 h-36">
          <svg viewBox="0 0 120 120" className="w-full h-full">
            <circle cx="60" cy="60" r="45" fill="none" strokeWidth="18" className="stroke-surface-200 dark:stroke-surface-700" />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xs text-surface-400">No data</span>
          </div>
        </div>
      </div>
    )
  }

  const segments: Segment[] = [
    { label: 'Active', value: active, color: '#84cc16', hoverColor: '#a3e635' },
    { label: 'Inactive', value: inactive, color: '#ef4444', hoverColor: '#f87171' },
    { label: 'No Data', value: nodata, color: '#6b7280', hoverColor: '#9ca3af' },
  ].filter(s => s.value > 0)

  const radius = 45
  const circumference = 2 * Math.PI * radius
  let cumulativeOffset = 0

  const hoveredSeg = hovered !== null ? segments[hovered] : null
  const hoveredPct = hoveredSeg ? Math.round((hoveredSeg.value / total) * 100) : null

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36 group">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          {/* Background ring */}
          <circle cx="60" cy="60" r={radius} fill="none" strokeWidth="18" className="stroke-surface-100 dark:stroke-surface-800/60" />
          {/* Segments */}
          {segments.map((seg, i) => {
            const pct = seg.value / total
            const segLen = circumference * pct
            const gap = segments.length > 1 ? 2 : 0
            const dashLen = Math.max(0, segLen - gap)
            const offset = cumulativeOffset
            cumulativeOffset += segLen
            const isHovered = hovered === i
            return (
              <circle
                key={seg.label}
                cx="60" cy="60"
                r={radius}
                fill="none"
                stroke={isHovered ? seg.hoverColor : seg.color}
                strokeWidth={isHovered ? 22 : 18}
                strokeDasharray={`${dashLen} ${circumference - dashLen}`}
                strokeDashoffset={mounted ? -offset : -offset}
                strokeLinecap="butt"
                className="transition-all duration-300 ease-out cursor-pointer"
                style={{
                  opacity: mounted ? 1 : 0,
                  filter: isHovered ? 'drop-shadow(0 0 6px rgba(0,0,0,0.25))' : 'none',
                  transformOrigin: 'center',
                }}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}
              />
            )
          })}
        </svg>
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          {hoveredSeg ? (
            <>
              <span className="text-lg font-bold tabular-nums" style={{ color: hoveredSeg.color }}>
                {hoveredSeg.value}
              </span>
              <span className="text-[9px] font-semibold uppercase tracking-wider text-surface-400">
                {hoveredSeg.label} ({hoveredPct}%)
              </span>
            </>
          ) : (
            <>
              <span className="text-lg font-bold text-surface-700 dark:text-surface-200 tabular-nums">{total}</span>
              <span className="text-[9px] font-semibold uppercase tracking-wider text-surface-400">Tunnels</span>
            </>
          )}
        </div>
      </div>
      {/* Legend */}
      <div className="space-y-1 w-full">
        {[
          { label: 'Active', color: '#84cc16', count: active },
          { label: 'Inactive', color: '#ef4444', count: inactive },
          { label: 'No Data', color: '#6b7280', count: nodata },
        ].map(item => {
          const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
          return (
            <div key={item.label} className="flex items-center gap-2 text-[11px]">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
              <span className="text-surface-700 dark:text-surface-300 font-medium flex-1">{item.label}</span>
              <span className="text-surface-500 tabular-nums">{item.count}</span>
              <span className="text-surface-400 tabular-nums w-8 text-right">{pct}%</span>
            </div>
          )
        })}
      </div>
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
    if (!expanded) {
      // Always fetch fresh data on expand
      setExpanded(true)
      setLoading(true)
      const d = await fetchTunnelDetail(tunnel.name)
      setDetail(d)
      setLoading(false)
    } else {
      setExpanded(false)
    }
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
          <div className="flex items-center gap-1.5">
            <span className="font-medium truncate max-w-[120px]">{tunnel.local_name || tunnel.name || '-'}</span>
            {tunnel.vpn_type && (
              <span className={cn(
                'shrink-0 text-[7px] font-bold uppercase tracking-wider px-1 py-px rounded-full',
                tunnel.vpn_type === 'route' ? 'bg-accent-amber/15 text-accent-amber' : tunnel.vpn_type === 'ravpn' ? 'bg-blue-500/15 text-blue-500' : 'bg-vyper-500/10 text-vyper-500',
              )}>
                {tunnel.vpn_type === 'route' ? 'R' : tunnel.vpn_type === 'ravpn' ? 'RA' : 'P'}
              </span>
            )}
          </div>
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
  } = store

  const [sameAsLocal, setSameAsLocal] = useState(true)
  const [summaryConnected, setSummaryConnected] = useState(false)

  // Top-level toggle: 's2s' (Site-to-Site) or 'ravpn' (Remote Access)
  const [summaryMode, setSummaryMode] = useState<'s2s' | 'ravpn'>('s2s')

  // Sub-filter for S2S only: 'all', 'policy', 'route'
  const [s2sSubFilter, setS2sSubFilter] = useState<'all' | 'policy' | 'route'>('all')

  // RA VPN data (loaded only when summaryMode === 'ravpn')
  const [ravpnTunnels, setRavpnTunnels] = useState<TunnelData[]>([])
  const [ravpnLoading, setRavpnLoading] = useState(false)
  const [ravpnLastUpdated, setRavpnLastUpdated] = useState('')
  const [ravpnPage, setRavpnPage] = useState(1)

  const connected = sameAsLocal ? localConnected : summaryConnected

  // Fetch RA VPN data only when switching to ravpn mode
  const fetchRavpnData = useCallback(async () => {
    setRavpnLoading(true)
    try {
      const data = await fetchCscVpnSessions()
      if (data.success && data.tunnels) {
        setRavpnTunnels(data.tunnels as TunnelData[])
      }
      setRavpnLastUpdated(new Date().toLocaleString())
    } catch { /* ignore */ }
    setRavpnLoading(false)
  }, [])

  useEffect(() => {
    if (summaryMode === 'ravpn' && connected) {
      fetchRavpnData()
    }
  }, [summaryMode, connected, fetchRavpnData])

  // ── S2S computed values ──
  const s2sFilteredTunnels = useMemo(() => {
    if (s2sSubFilter === 'all') return filteredTunnels
    return filteredTunnels.filter(t => (t.vpn_type || 'policy') === s2sSubFilter)
  }, [filteredTunnels, s2sSubFilter])

  const s2sStats = useMemo(() => {
    const src = s2sSubFilter === 'all' ? tunnels : tunnels.filter(t => (t.vpn_type || 'policy') === s2sSubFilter)
    let active = 0, inactive = 0, nodata = 0
    for (const t of src) {
      const c = tunnelStatusCategory(t)
      if (c === 'active') active++
      else if (c === 'inactive') inactive++
      else nodata++
    }
    return { active, inactive, nodata }
  }, [tunnels, s2sSubFilter])

  const s2sCounts = useMemo(() => {
    let policy = 0, route = 0
    for (const t of tunnels) {
      if (t.vpn_type === 'route') route++
      else policy++
    }
    return { policy, route }
  }, [tunnels])

  // ── RA VPN computed values ──
  const ravpnStats = useMemo(() => {
    let active = 0, inactive = 0, nodata = 0
    for (const t of ravpnTunnels) {
      const c = tunnelStatusCategory(t)
      if (c === 'active') active++
      else if (c === 'inactive') inactive++
      else nodata++
    }
    return { active, inactive, nodata }
  }, [ravpnTunnels])

  // ── Pagination (mode-specific) ──
  const activeTunnels = summaryMode === 's2s' ? s2sFilteredTunnels : ravpnTunnels
  const activePage = summaryMode === 's2s' ? currentPage : ravpnPage
  const setActivePage = summaryMode === 's2s' ? setCurrentPage : setRavpnPage
  const totalPages = Math.max(1, Math.ceil(activeTunnels.length / pageSize))
  const page = Math.min(activePage, totalPages)
  const paged = activeTunnels.slice((page - 1) * pageSize, page * pageSize)
  const showStart = activeTunnels.length > 0 ? (page - 1) * pageSize + 1 : 0
  const showEnd = Math.min(page * pageSize, activeTunnels.length)
  const activeStats = summaryMode === 's2s' ? s2sStats : ravpnStats
  const activeLastUpdated = summaryMode === 's2s' ? lastUpdated : ravpnLastUpdated
  const isRefreshing = summaryMode === 's2s' ? refreshing : ravpnLoading

  const clearAllFilters = () => {
    setSearchQuery('')
    setStatusFilter(null)
    setS2sSubFilter('all')
    useVpnDebuggerStore.getState().setParamFilters({ encryption: [], integrity: [], prf: [], dh_group: [], ake: [] })
    applyFilters()
  }

  const handleRefresh = useCallback(() => {
    if (summaryMode === 's2s') {
      refreshTunnels()
    } else {
      fetchRavpnData()
    }
  }, [summaryMode, fetchRavpnData])

  const hasFilters = summaryMode === 's2s' && (searchQuery || statusFilter || s2sSubFilter !== 'all' || Object.values(useVpnDebuggerStore.getState().paramFilters).some((v: string[]) => v.length > 0))

  const handleSummaryConnect = async () => {
    await connectToServer(summaryConn)
    setSummaryConnected(true)
    closeSummaryConnPopup()
  }

  const tabCls = (active: boolean) => cn(
    'px-3 py-1.5 text-[10px] font-semibold rounded-md transition-all',
    active
      ? 'bg-vyper-600 text-white shadow-sm'
      : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800',
  )

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
        <>
        {/* Top-level mode toggle */}
        <div className="flex items-center gap-1.5 mb-3 p-0.5 bg-surface-100 dark:bg-surface-800/50 rounded-lg w-fit">
          <button onClick={() => setSummaryMode('s2s')} className={tabCls(summaryMode === 's2s')}>
            Site-to-Site VPN ({tunnels.length})
          </button>
          <button onClick={() => setSummaryMode('ravpn')} className={tabCls(summaryMode === 'ravpn')}>
            Remote Access VPN ({ravpnTunnels.length})
          </button>
        </div>

        {/* Controls bar */}
        <div className="flex items-center gap-2 flex-wrap mb-3">
          {summaryMode === 's2s' && (
            <>
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-surface-400" />
                <input
                  value={searchQuery}
                  onChange={(e) => { setSearchQuery(e.target.value); applyFilters() }}
                  placeholder="Search..."
                  className={cn(inputCls, 'pl-6 w-48')}
                />
              </div>
              <CustomSelect
                value={s2sSubFilter}
                onChange={(v) => setS2sSubFilter(v as 'all' | 'policy' | 'route')}
                minWidth="170px"
                options={[
                  { value: 'all', label: `All Types (${s2sCounts.policy + s2sCounts.route})` },
                  { value: 'policy', label: `Policy-Based (${s2sCounts.policy})` },
                  { value: 'route', label: `Route-Based (${s2sCounts.route})` },
                ]}
              />
              <ParamFilterBar />
            </>
          )}
          {hasFilters && (
            <button onClick={clearAllFilters} className={cn(btnCls(), 'text-red-500 hover:bg-red-500/10')}>
              <XCircle className="w-3.5 h-3.5" /> Clear All
            </button>
          )}
          <div className="flex items-center gap-1.5 ml-auto">
            <button onClick={handleRefresh} disabled={!connected || isRefreshing} className={btnCls()}>
              <RefreshCw className={cn('w-3.5 h-3.5', isRefreshing && 'animate-spin')} /> Refresh
            </button>
            {summaryMode === 's2s' && (
              <>
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
              </>
            )}
          </div>
        </div>

        {activeLastUpdated && (
          <div className="text-[10px] text-surface-400 mb-3">Last Updated: {activeLastUpdated}</div>
        )}

        {activeTunnels.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-10 h-10 text-surface-300 dark:text-surface-700 mx-auto mb-3" />
            <p className="text-sm text-surface-400">
              {summaryMode === 's2s'
                ? 'No tunnel data available. Connect to a server and refresh to view tunnels.'
                : 'No RA VPN sessions found. Deploy CSC containers and connect to view sessions.'}
            </p>
          </div>
        ) : (
          <div className="flex gap-5">
            <div className="shrink-0">
              <h3 className="text-xs font-semibold text-surface-600 dark:text-surface-400 mb-3">
                {summaryMode === 's2s' ? 'Site-to-Site VPN' : 'Remote Access VPN'}
              </h3>
              <DonutChart {...activeStats} />
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
                  Viewing {showStart}-{showEnd} of {activeTunnels.length}
                </span>
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
                    <button
                      key={p}
                      onClick={() => setActivePage(p)}
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
