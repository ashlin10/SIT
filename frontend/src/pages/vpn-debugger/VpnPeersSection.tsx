import { useState, useCallback, useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import type { ConnectionInfo, Preset, ConfigFile, XfrmInterface } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls, inputCls } from '@/lib/utils'
import CustomSelect from '@/components/CustomSelect'
import {
  Plug, Save, List, Loader2, CircleDot,
  Settings, FileText, Network, Gauge, RefreshCw, Plus,
  Eye, EyeOff, Pencil, Trash2, Download, Upload, Play,
  Route, Terminal, Ban, RotateCcw, CheckCircle, AlertTriangle, Layers, X,
} from 'lucide-react'
import {
  connectToServer, connectRemoteServer, ensureCscConnected, ensureStrongswanConnected, savePreset, deletePreset, loadPresets,
  serviceAction, fetchConfigFiles, fetchRemoteConfigFiles,
  fetchFileContent, deleteFile, toggleFileVisibility,
  fetchNetplanFiles, fetchRemoteNetplanFiles, fetchNetplanContent,
  netplanApply, netplanRoutes, tcShow, tcApply, tcRemove,
  cscDeleteConfigFile,
  fetchXfrmInterfaces,
} from './api'
import SectionCard from './SectionCard'
import CscAdministrationSection from './CscAdministrationSection'
import CscContainerConfigSection from './CscContainerConfigSection'

// ── Connection Form ──

function ConnectionForm({
  conn,
  setConn,
  connected,
  connecting,
  onConnect,
  presets,
  onSavePreset,
  onDeletePreset,
  onLoadPreset,
}: {
  conn: ConnectionInfo
  setConn: (c: Partial<ConnectionInfo>) => void
  connected: boolean
  connecting: boolean
  onConnect: () => void
  presets: Preset[]
  onSavePreset: () => void
  onDeletePreset: (id: string) => void
  onLoadPreset: (p: Preset) => void
}) {
  const [showPresets, setShowPresets] = useState(false)

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h4 className="text-xs font-semibold text-surface-700 dark:text-surface-300">Server Connection</h4>
          <span className={cn(
            'inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full',
            connected
              ? 'bg-accent-emerald/10 text-accent-emerald'
              : 'bg-surface-100 dark:bg-surface-800 text-surface-500'
          )}>
            <CircleDot className="w-2.5 h-2.5" />
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={onSavePreset} className={btnCls('success')}>
            <Save className="w-3 h-3" /> Save
          </button>
          <div className="relative">
            <button onClick={() => { setShowPresets(!showPresets); if (!showPresets) loadPresets() }} className={btnCls()}>
              <List className="w-3 h-3" /> Presets
            </button>
            {showPresets && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setShowPresets(false)} />
                <div className="absolute right-0 mt-1.5 w-72 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 max-h-60 overflow-auto py-1">
                  {presets.length === 0 ? (
                    <div className="p-3 text-xs text-surface-400 text-center italic">No presets</div>
                  ) : presets.map((p) => (
                    <div key={p.id} className="flex items-center justify-between px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/70 cursor-pointer group transition-colors" onClick={() => { onLoadPreset(p); setShowPresets(false) }}>
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-surface-700 dark:text-surface-300 truncate">{p.name}</div>
                        <div className="text-[10px] text-surface-400 font-mono truncate">{p.ip}:{p.port}</div>
                      </div>
                      <button onClick={(e) => { e.stopPropagation(); onDeletePreset(p.id) }} className="p-1 rounded opacity-0 group-hover:opacity-100 text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
          <button onClick={onConnect} disabled={connecting || !conn.ip} className={btnCls('primary')}>
            {connecting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Plug className="w-3 h-3" />}
            Connect
          </button>
        </div>
      </div>
      <div className="grid grid-cols-4 gap-2.5">
        <div>
          <label className="block text-[10px] font-medium text-surface-500 mb-1">Host</label>
          <input value={conn.ip} onChange={(e) => setConn({ ip: e.target.value })} placeholder="10.0.0.10" className={cn(inputCls, 'w-full')} />
        </div>
        <div>
          <label className="block text-[10px] font-medium text-surface-500 mb-1">SSH Port</label>
          <input value={conn.port} onChange={(e) => setConn({ port: e.target.value })} type="number" className={cn(inputCls, 'w-full')} />
        </div>
        <div>
          <label className="block text-[10px] font-medium text-surface-500 mb-1">Username</label>
          <input value={conn.username} onChange={(e) => setConn({ username: e.target.value })} placeholder="root" className={cn(inputCls, 'w-full')} />
        </div>
        <div>
          <label className="block text-[10px] font-medium text-surface-500 mb-1">Password</label>
          <input value={conn.password} onChange={(e) => setConn({ password: e.target.value })} type="password" placeholder="password" className={cn(inputCls, 'w-full')} />
        </div>
      </div>
    </div>
  )
}

// ── Administration (strongSwan process) ──

function AdministrationSubsection({ nodeType }: { nodeType: string }) {
  if (nodeType === 'csc') return <CscAdministrationSection />
  return <StrongSwanAdministration />
}

function StrongSwanAdministration() {
  const { serviceStatus, localConnected } = useVpnDebuggerStore()
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  const doAction = async (action: 'enable' | 'disable' | 'restart') => {
    setActionLoading(action)
    await serviceAction(action)
    setActionLoading(null)
  }

  const statusStyles: Record<string, string> = {
    active: 'bg-accent-emerald/10 text-accent-emerald',
    inactive: 'bg-red-500/10 text-red-500',
    unknown: 'bg-surface-100 dark:bg-surface-800 text-surface-500',
  }

  return (
    <div className="space-y-2">
      <h5 className="flex items-center gap-1.5 text-[11px] font-semibold text-surface-600 dark:text-surface-400 border-b border-surface-100 dark:border-surface-800 pb-1.5">
        <Settings className="w-3.5 h-3.5 text-surface-400" /> Administration
      </h5>
      <div className="flex items-center gap-3 p-2 rounded-lg border border-surface-100 dark:border-surface-800 bg-surface-50/50 dark:bg-surface-800/30">
        <span className="text-xs font-medium text-surface-700 dark:text-surface-300 min-w-[80px]">strongSwan</span>
        <span className={cn('inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full', statusStyles[serviceStatus] || statusStyles.unknown)}>
          <CircleDot className="w-2.5 h-2.5" />
          {serviceStatus === 'active' ? 'Active' : serviceStatus === 'inactive' ? 'Inactive' : 'Unknown'}
        </span>
        <div className="flex items-center gap-1 ml-auto">
          <button onClick={() => doAction('enable')} disabled={!localConnected || actionLoading !== null} className={btnCls('success')}>
            {actionLoading === 'enable' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />} Enable
          </button>
          <button onClick={() => doAction('disable')} disabled={!localConnected || actionLoading !== null} className={btnCls('danger')}>
            {actionLoading === 'disable' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />} Disable
          </button>
          <button onClick={() => doAction('restart')} disabled={!localConnected || actionLoading !== null} className={btnCls('warning')}>
            {actionLoading === 'restart' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />} Restart
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Route-Based Config Popup (XFRM + Routing + Route Table) ──

function RouteBasedConfigPopup({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { localConnected, xfrmInterfaces, xfrmLoading } = useVpnDebuggerStore()
  const [tab, setTab] = useState<'xfrm' | 'routing' | 'routes'>('xfrm')
  const [routingConfig, setRoutingConfig] = useState('')
  const [routeTable, setRouteTable] = useState('')
  const [protocolInfo, setProtocolInfo] = useState<Record<string, string>>({})
  const [routeSections, setRouteSections] = useState<Record<string, string>>({})
  const [loadingRouting, setLoadingRouting] = useState(false)

  const loadRoutingInfo = useCallback(async () => {
    setLoadingRouting(true)
    try {
      const res = await fetch('/api/strongswan/overlay-routing/status', { credentials: 'include' })
      const d = await res.json()
      if (d.success) {
        setRoutingConfig(d.config || 'No overlay routing configured')
        setRouteTable(d.route_table || 'No routes found')
        setProtocolInfo(d.protocol_info || {})
        setRouteSections(d.route_sections || {})
      }
    } catch { /* ignore */ }
    setLoadingRouting(false)
  }, [])

  useEffect(() => {
    if (!open || !localConnected) return
    fetchXfrmInterfaces()
    loadRoutingInfo()
  }, [open, localConnected, loadRoutingInfo])

  if (!open) return null

  const tabCls = (t: string) => cn(
    'px-3 py-1.5 text-[10px] font-medium rounded-md transition-colors',
    tab === t ? 'bg-vyper-500/10 text-vyper-500' : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300',
  )

  const preCls = "text-[10px] font-mono text-surface-600 dark:text-surface-400 p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700 whitespace-pre-wrap max-h-48 overflow-auto"

  const protocolSections: { key: string; label: string }[] = [
    { key: 'bgp', label: 'BGP Summary' },
    { key: 'ospfv2_neighbors', label: 'OSPFv2 Neighbors' },
    { key: 'ospfv2_interfaces', label: 'OSPFv2 Interfaces' },
    { key: 'ospfv3_neighbors', label: 'OSPFv3 Neighbors' },
    { key: 'eigrp_neighbors', label: 'EIGRP Neighbors' },
    { key: 'eigrp_topology', label: 'EIGRP Topology' },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-[95%] max-w-[700px] max-h-[80vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200 flex items-center gap-2">
            <Route className="w-4 h-4 text-surface-400" /> Route-Based Configuration
          </h3>
          <div className="flex items-center gap-2">
            <button onClick={() => { fetchXfrmInterfaces(); loadRoutingInfo() }} disabled={xfrmLoading || loadingRouting} className={iconBtnCls()} title="Refresh">
              <RefreshCw className={cn('w-3.5 h-3.5', (xfrmLoading || loadingRouting) && 'animate-spin')} />
            </button>
            <button onClick={onClose} className="p-1 rounded-lg hover:bg-surface-200 dark:hover:bg-surface-700 transition-colors">
              <X className="w-4 h-4 text-surface-500" />
            </button>
          </div>
        </div>
        {/* Tabs */}
        <div className="flex items-center gap-1 px-4 pt-2 pb-1 border-b border-surface-200 dark:border-surface-800">
          <button onClick={() => setTab('xfrm')} className={tabCls('xfrm')}>XFRM Interfaces</button>
          <button onClick={() => setTab('routing')} className={tabCls('routing')}>Overlay Routing</button>
          <button onClick={() => setTab('routes')} className={tabCls('routes')}>Route Table</button>
        </div>
        <div className="flex-1 overflow-auto p-3">
          {/* XFRM Tab */}
          {tab === 'xfrm' && (
            xfrmInterfaces.length === 0 ? (
              <div className="text-xs text-surface-400 italic py-6 text-center">
                {xfrmLoading ? 'Loading...' : 'No XFRM interfaces found'}
              </div>
            ) : (
              <table className="w-full text-[11px]">
                <thead>
                  <tr className="border-b border-surface-200 dark:border-surface-700 text-surface-400">
                    <th className="py-1.5 px-2 text-left">Name</th>
                    <th className="py-1.5 px-2 text-left">IF ID</th>
                    <th className="py-1.5 px-2 text-left">Status</th>
                    <th className="py-1.5 px-2 text-left">IP Addresses</th>
                    <th className="py-1.5 px-2 text-left">MTU</th>
                  </tr>
                </thead>
                <tbody>
                  {xfrmInterfaces.map((intf: XfrmInterface) => (
                    <tr key={intf.name} className="border-b border-surface-100 dark:border-surface-800 hover:bg-surface-50 dark:hover:bg-surface-800/40 transition-colors">
                      <td className="py-1.5 px-2 font-mono font-medium text-surface-700 dark:text-surface-300">{intf.name}</td>
                      <td className="py-1.5 px-2 font-mono text-surface-500">{intf.ifId}</td>
                      <td className="py-1.5 px-2">
                        <span className={cn(
                          'inline-flex items-center gap-0.5 text-[9px] font-medium px-1.5 py-0.5 rounded-full',
                          intf.state === 'UP' ? 'bg-accent-emerald/10 text-accent-emerald' : 'bg-surface-100 dark:bg-surface-800 text-surface-500',
                        )}>
                          <CircleDot className="w-2 h-2" /> {intf.state}
                        </span>
                      </td>
                      <td className="py-1.5 px-2 font-mono text-surface-500">
                        {intf.addresses && intf.addresses.length > 0 ? intf.addresses.join(', ') : <span className="text-surface-400 italic">none</span>}
                      </td>
                      <td className="py-1.5 px-2 text-surface-400">{intf.mtu || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
          {/* Routing Config Tab */}
          {tab === 'routing' && (
            <div className="space-y-3">
              {loadingRouting ? (
                <div className="text-xs text-surface-400 italic py-6 text-center">Loading...</div>
              ) : (
                <>
                  <div>
                    <div className="text-[10px] font-semibold text-surface-500 mb-1">FRR Running Configuration</div>
                    <pre className={preCls}>{routingConfig}</pre>
                  </div>
                  {protocolSections.map(({ key, label }) =>
                    protocolInfo[key] ? (
                      <div key={key}>
                        <div className="text-[10px] font-semibold text-surface-500 mb-1">{label}</div>
                        <pre className={preCls}>{protocolInfo[key]}</pre>
                      </div>
                    ) : null
                  )}
                </>
              )}
            </div>
          )}
          {/* Route Table Tab */}
          {tab === 'routes' && (
            <div className="space-y-3">
              {loadingRouting ? (
                <div className="text-xs text-surface-400 italic py-6 text-center">Loading...</div>
              ) : (
                <>
                  {[
                    { key: 'static_v4', label: 'IPv4 Static Routes' },
                    { key: 'static_v6', label: 'IPv6 Static Routes' },
                    { key: 'bgp_v4', label: 'IPv4 BGP Routes' },
                    { key: 'bgp_v6', label: 'IPv6 BGP Routes' },
                    { key: 'ospf_v4', label: 'IPv4 OSPF Routes' },
                    { key: 'ospf_v6', label: 'IPv6 OSPFv3 Routes' },
                    { key: 'eigrp_v4', label: 'IPv4 EIGRP Routes' },
                    { key: 'eigrp_v6', label: 'IPv6 EIGRP Routes' },
                  ].map(({ key, label }) =>
                    routeSections[key] ? (
                      <div key={key}>
                        <div className="text-[10px] font-semibold text-surface-500 mb-1">{label}</div>
                        <pre className={preCls}>{routeSections[key]}</pre>
                      </div>
                    ) : null
                  )}
                  {Object.keys(routeSections).length === 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-surface-500 mb-1">XFRM Interface Routes</div>
                      <pre className={preCls}>{routeTable || 'No routes found'}</pre>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Config Files List ──

function ConfigFilesList({
  title,
  description,
  icon,
  files,
  connected,
  onRefresh,
  onView,
  onEdit,
  onDownload,
  onDelete,
  onToggleVisibility,
  onAdd,
  onUpload,
  extraButtons,
  externalRefreshing,
  cscMode,
}: {
  title: string
  description?: string
  icon: React.ReactNode
  files: ConfigFile[]
  connected: boolean
  onRefresh: () => void
  onView: (f: string) => void
  onEdit: (f: string) => void
  onDownload: (f: string) => void
  onDelete: (f: string) => void
  onToggleVisibility?: (f: string) => void
  onAdd?: () => void
  onUpload?: () => void
  extraButtons?: React.ReactNode
  externalRefreshing?: boolean
  cscMode?: boolean
}) {
  const [refreshing, setRefreshing] = useState(false)
  const isRefreshing = refreshing || !!externalRefreshing

  const doRefresh = async () => {
    setRefreshing(true)
    await onRefresh()
    setRefreshing(false)
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h5 className="flex items-center gap-1.5 text-[11px] font-semibold text-surface-600 dark:text-surface-400 border-b border-surface-100 dark:border-surface-800 pb-1.5 flex-1">
          {icon} {title}
        </h5>
        <div className="flex items-center gap-1">
          {extraButtons}
          {onAdd && (
            <button onClick={onAdd} disabled={!connected} className={iconBtnCls('primary')} title="Add file">
              <Plus className="w-3.5 h-3.5" />
            </button>
          )}
          {onUpload && (
            <button onClick={onUpload} disabled={!connected} className={iconBtnCls()} title="Upload">
              <Upload className="w-3.5 h-3.5" />
            </button>
          )}
          <button onClick={doRefresh} disabled={!connected} className={iconBtnCls()} title="Refresh">
            <RefreshCw className={cn('w-3.5 h-3.5', isRefreshing && 'animate-spin')} />
          </button>
        </div>
      </div>
      {description && (
        <div className="text-[10px] text-surface-400">
          Files in <code className="text-[10px] px-1 py-0.5 rounded bg-surface-100 dark:bg-surface-800">{description}</code>
        </div>
      )}
      {files.length === 0 ? (
        <div className="text-xs text-surface-400 italic py-2">
          {connected ? 'No files found' : 'Connect to server to view files'}
        </div>
      ) : (
        <div className="space-y-1">
          {files.map((f) => {
            const isHidden = f.name.startsWith('.')
            const isProtected = cscMode && /^(Dockerfile|entry\.sh)$/i.test(f.name)
            return (
              <div key={f.name} className={cn(
                'flex items-center justify-between px-2 py-1.5 rounded-md border border-surface-100 dark:border-surface-800 group hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors',
                isHidden && 'opacity-50',
              )}>
                {cscMode && !isProtected ? (
                  <span className="text-[11px] font-mono text-surface-500 dark:text-surface-500 truncate text-left flex-1 min-w-0">
                    {f.name}
                  </span>
                ) : (
                  <button onClick={() => onView(f.name)} className="text-[11px] font-mono text-surface-700 dark:text-surface-300 hover:text-vyper-600 dark:hover:text-vyper-400 truncate text-left flex-1 min-w-0 transition-colors">
                    {f.name}
                  </button>
                )}
                {f.vpnType && (
                  <span className={cn(
                    'shrink-0 text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full',
                    f.vpnType === 'route'
                      ? 'bg-accent-amber/15 text-accent-amber'
                      : 'bg-vyper-500/10 text-vyper-500',
                  )}>
                    {f.vpnType === 'route' ? 'Route-Based' : 'Policy-Based'}
                  </span>
                )}
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  {isProtected ? null : cscMode ? (
                    <button onClick={() => { if (confirm(`Delete ${f.name}?`)) onDelete(f.name) }} className={iconBtnCls('danger')} title="Delete">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  ) : (
                    <>
                      {onToggleVisibility && (
                        <button onClick={() => onToggleVisibility(f.name)} className={iconBtnCls()} title={isHidden ? 'Unhide' : 'Hide'}>
                          {isHidden ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
                        </button>
                      )}
                      <button onClick={() => onEdit(f.name)} className={iconBtnCls('primary')} title="Edit">
                        <Pencil className="w-3 h-3" />
                      </button>
                      <button onClick={() => onDownload(f.name)} className={iconBtnCls()} title="Download">
                        <Download className="w-3 h-3" />
                      </button>
                      <button onClick={() => { if (confirm(`Delete ${f.name}?`)) onDelete(f.name) }} className={iconBtnCls('danger')} title="Delete">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Route-Based Config Button ──

function RouteConfigButton({ disabled }: { disabled: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)} disabled={disabled} className={iconBtnCls()} title="View Route-Based Config">
        <Route className="w-3.5 h-3.5" />
      </button>
      <RouteBasedConfigPopup open={open} onClose={() => setOpen(false)} />
    </>
  )
}


// ── Traffic Control ──

function TrafficControlSubsection() {
  const store = useVpnDebuggerStore()
  const { localConnected } = store
  const [tcInput, setTcInput] = useState('')
  const [loading, setLoading] = useState(false)

  const doShow = async () => {
    store.openFileViewerLoading('Traffic Control Rules', 'tc-rules.txt', 'local', 'config')
    const out = await tcShow()
    store.setFileViewerLoaded(out || 'No TC rules found.')
  }

  const doApply = async () => {
    if (!tcInput.trim()) return
    setLoading(true)
    await tcApply(tcInput)
    setLoading(false)
  }

  const doRemove = async () => {
    if (!confirm('Remove all TC rules?')) return
    setLoading(true)
    await tcRemove()
    setLoading(false)
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h5 className="flex items-center gap-1.5 text-[11px] font-semibold text-surface-600 dark:text-surface-400 border-b border-surface-100 dark:border-surface-800 pb-1.5 flex-1">
          <Gauge className="w-3.5 h-3.5 text-surface-400" /> Traffic Control
        </h5>
        <div className="flex items-center gap-1">
          <button onClick={doShow} disabled={!localConnected} className={btnCls('success')}>
            <Eye className="w-3.5 h-3.5" /> View TC
          </button>
          <button onClick={doRemove} disabled={!localConnected || loading} className={btnCls('danger')}>
            <Trash2 className="w-3.5 h-3.5" /> Remove All
          </button>
        </div>
      </div>
      <div className="text-[10px] text-surface-400">Manage Linux traffic control (tc) rules on the connected server</div>
      <div className="flex gap-2 items-start">
        <textarea
          value={tcInput}
          onChange={(e) => setTcInput(e.target.value)}
          disabled={!localConnected}
          placeholder={'tc qdisc add dev eth0 root netem delay 100ms\ntc qdisc add dev eth1 root netem delay 50ms'}
          className={cn(inputCls, 'flex-1 font-mono min-h-[60px] resize-y')}
        />
        <button onClick={doApply} disabled={!localConnected || loading || !tcInput.trim()} className={btnCls('success')}>
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Terminal className="w-3.5 h-3.5" />} Apply
        </button>
      </div>
    </div>
  )
}

// ── Node Panel (full-width, used in tabs) ──

function NodePanel({
  side,
}: {
  side: 'local' | 'remote'
}) {
  const store = useVpnDebuggerStore()
  const isLocal = side === 'local'
  const conn = isLocal ? store.localConn : store.remoteConn
  const setConn = isLocal ? store.setLocalConn : store.setRemoteConn
  const connected = isLocal ? store.localConnected : store.remoteConnected
  const files = isLocal ? store.configFiles : store.remoteConfigFiles
  const netFiles = isLocal ? store.netplanFiles : store.remoteNetplanFiles
  const nodeType = isLocal ? store.localNodeType : store.remoteNodeType
  const configLoading = isLocal ? store.configFilesLoading : store.remoteConfigFilesLoading
  const netplanLoading = isLocal ? store.netplanFilesLoading : store.remoteNetplanFilesLoading

  // Auto-refresh data when node type changes + ensure backend connection exists
  useEffect(() => {
    if (!connected || !isLocal) return
    // When switching node types while already connected, ensure the target backend has a connection
    if (nodeType === 'csc') {
      ensureCscConnected(conn).then(() => {
        fetchConfigFiles()
        fetchNetplanFiles()
      })
    } else {
      ensureStrongswanConnected(conn).then(() => {
        fetchConfigFiles()
        fetchNetplanFiles()
      })
    }
  }, [nodeType, connected, isLocal, conn])

  const doConnect = useCallback(() => {
    if (isLocal) connectToServer(conn)
    else connectRemoteServer(conn)
  }, [isLocal, conn])

  const handleSavePreset = useCallback(() => {
    const name = prompt('Preset name:')
    if (name) savePreset(name, conn)
  }, [conn])

  const handleLoadPreset = useCallback((p: Preset) => {
    setConn({ ip: p.ip, port: p.port, username: p.username, password: p.password })
  }, [setConn])

  // File view/edit with loading indicator
  const handleViewFile = useCallback(async (filename: string) => {
    store.openFileViewerLoading(filename, filename, side, 'config')
    const content = await fetchFileContent(filename)
    store.setFileViewerLoaded(content, false)
  }, [store, side])

  const handleEditFile = useCallback(async (filename: string) => {
    store.openFileViewerLoading(`Edit: ${filename}`, filename, side, 'config')
    const content = await fetchFileContent(filename)
    store.setFileViewerLoaded(content, true)
  }, [store, side])

  const handleDownloadFile = useCallback(async (filename: string) => {
    const content = await fetchFileContent(filename)
    if (!content && content !== '') return
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }, [])

  const handleDeleteFile = useCallback(async (filename: string) => {
    await deleteFile(filename)
  }, [])

  const handleToggleVis = useCallback(async (filename: string) => {
    const isHidden = filename.startsWith('.')
    const newName = isHidden ? filename.slice(1) : `.${filename}`
    await toggleFileVisibility(filename, newName)
  }, [])

  const handleViewNetplan = useCallback(async (filename: string) => {
    store.openFileViewerLoading(filename, filename, side, 'netplan')
    const content = await fetchNetplanContent(filename)
    store.setFileViewerLoaded(content, false)
  }, [store, side])

  const handleEditNetplan = useCallback(async (filename: string) => {
    store.openFileViewerLoading(`Edit: ${filename}`, filename, side, 'netplan')
    const content = await fetchNetplanContent(filename)
    store.setFileViewerLoaded(content, true)
  }, [store, side])

  const handleDownloadNetplan = useCallback(async (filename: string) => {
    const content = await fetchNetplanContent(filename)
    if (!content && content !== '') return
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }, [])

  const [netplanApplying, setNetplanApplying] = useState(false)
  const handleNetplanApply = async () => {
    setNetplanApplying(true)
    try {
      await netplanApply()
    } finally {
      setNetplanApplying(false)
    }
  }

  const handleShowRoutes = async () => {
    store.openFileViewerLoading('Routes', '', side, 'netplan')
    const out = await netplanRoutes()
    store.setFileViewerLoaded(out, false)
  }

  // Config file paths based on node type
  const configPath = nodeType === 'csc' ? '/opt/cisco-secure-client-docker/' : '/etc/swanctl/conf.d'
  const netplanPath = '/etc/netplan'

  const isRemoteAsaFtd = !isLocal && nodeType === 'asa_ftd'

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2.5">
        <span className="text-[10px] font-medium text-surface-500">Node Type</span>
        {isLocal ? (
          <CustomSelect
            value={store.localNodeType}
            onChange={(v) => store.setLocalNodeType(v as 'strongswan' | 'csc')}
            minWidth="340px"
            options={[
              { value: 'strongswan', label: 'Site-to-Site VPN (strongSwan)' },
              { value: 'csc', label: 'Remote Access VPN (Cisco Secure Client)' },
            ]}
          />
        ) : (
          <CustomSelect
            value="asa_ftd"
            onChange={() => {}}
            disabled
            minWidth="170px"
            options={[{ value: 'asa_ftd', label: 'ASA / FTD' }]}
          />
        )}
      </div>

      {isRemoteAsaFtd ? (
        <div className="flex items-center gap-2 p-3 rounded-lg border border-accent-amber/30 bg-accent-amber/5">
          <AlertTriangle className="w-4 h-4 text-accent-amber shrink-0" />
          <div>
            <div className="text-xs font-medium text-surface-700 dark:text-surface-300">ASA / FTD Remote Node</div>
            <div className="text-[10px] text-surface-500">Remote node monitoring for ASA/FTD is not currently tracked. Use the Local Node to connect and manage VPN configurations.</div>
          </div>
        </div>
      ) : (
        <>
          <ConnectionForm
            conn={conn}
            setConn={setConn}
            connected={connected}
            connecting={store.connecting}
            onConnect={doConnect}
            presets={store.presets}
            onSavePreset={handleSavePreset}
            onDeletePreset={deletePreset}
            onLoadPreset={handleLoadPreset}
          />

          {isLocal && (
            <div className="rounded-xl border border-surface-200 dark:border-surface-800 p-3">
              <AdministrationSubsection nodeType={nodeType} />
            </div>
          )}

          <div className="rounded-xl border border-surface-200 dark:border-surface-800 p-3 space-y-3">
          <ConfigFilesList
            title="Configuration Files"
            description={configPath}
            icon={<FileText className="w-3.5 h-3.5 text-surface-400" />}
            files={files}
            connected={connected}
            onRefresh={isLocal ? fetchConfigFiles : fetchRemoteConfigFiles}
            onView={handleViewFile}
            onEdit={handleEditFile}
            onDownload={handleDownloadFile}
            onDelete={nodeType === 'csc' ? cscDeleteConfigFile : handleDeleteFile}
            onToggleVisibility={nodeType === 'csc' ? undefined : handleToggleVis}
            onAdd={nodeType === 'csc' ? undefined : () => {
              const name = prompt('New config filename (e.g. tunnel.conf):')
              if (name) store.openFileViewer(`New: ${name}`, '', true, name, side, 'config')
            }}
            onUpload={nodeType === 'csc' ? undefined : () => {
              const input = document.createElement('input')
              input.type = 'file'
              input.onchange = async (e) => {
                const file = (e.target as HTMLInputElement).files?.[0]
                if (!file) return
                const content = await file.text()
                store.openFileViewer(`Upload: ${file.name}`, content, true, file.name, side, 'config')
              }
              input.click()
            }}
            extraButtons={
              isLocal && nodeType === 'strongswan' ? (
                <>
                  <RouteConfigButton disabled={!connected} />
                  <button onClick={() => store.openTemplateBuilder()} disabled={!connected} className={btnCls()} title="SwanCtl Template Builder">
                    <Layers className="w-3.5 h-3.5" /> Template
                  </button>
                </>
              ) : undefined
            }
            externalRefreshing={configLoading}
            cscMode={nodeType === 'csc'}
          />

          {isLocal && nodeType === 'csc' && <CscContainerConfigSection />}
          </div>

          <div className="rounded-xl border border-surface-200 dark:border-surface-800 p-3">
          <ConfigFilesList
            title="Netplan"
            description={netplanPath}
            icon={<Network className="w-3.5 h-3.5 text-surface-400" />}
            files={netFiles}
            connected={connected}
            onRefresh={isLocal ? fetchNetplanFiles : fetchRemoteNetplanFiles}
            onView={handleViewNetplan}
            onEdit={handleEditNetplan}
            onDownload={handleDownloadNetplan}
            onDelete={handleDeleteFile}
            onAdd={() => {
              const name = prompt('New netplan filename (e.g. 99-custom.yaml):')
              if (name) store.openFileViewer(`New: ${name}`, '', true, name, side, 'netplan')
            }}
            extraButtons={isLocal ? (
              <>
                <button onClick={handleNetplanApply} disabled={!connected || netplanApplying} className={btnCls('success')}>
                  {netplanApplying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />} Apply
                </button>
                <button onClick={handleShowRoutes} disabled={!connected} className={btnCls()}>
                  <Route className="w-3.5 h-3.5" /> Routes
                </button>
              </>
            ) : undefined}
            externalRefreshing={netplanLoading}
          />
          </div>

          {isLocal && (
            <div className="rounded-xl border border-surface-200 dark:border-surface-800 p-3">
              <TrafficControlSubsection />
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ── Main Section ──

export default function VpnPeersSection() {
  const [activeTab, setActiveTab] = useState<'local' | 'remote'>('local')

  return (
    <SectionCard title="VPN Peers">
      {/* Animated tab switcher */}
      <div className="flex mb-4 p-0.5 rounded-lg bg-surface-100 dark:bg-surface-800/60">
        {(['local', 'remote'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              'flex-1 px-4 py-1.5 rounded-md text-xs font-medium transition-all duration-200',
              activeTab === tab
                ? 'bg-white dark:bg-surface-700 text-surface-800 dark:text-surface-200 shadow-sm'
                : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300'
            )}
          >
            {tab === 'local' ? 'Local Node' : 'Remote Node'}
          </button>
        ))}
      </div>
      {/* Tab content with slide animation */}
      <div className="relative overflow-hidden">
        <div
          className="flex transition-transform duration-300 ease-in-out"
          style={{ transform: activeTab === 'local' ? 'translateX(0)' : 'translateX(-100%)' }}
        >
          <div className="w-full shrink-0">
            <NodePanel side="local" />
          </div>
          <div className="w-full shrink-0">
            <NodePanel side="remote" />
          </div>
        </div>
      </div>
    </SectionCard>
  )
}
