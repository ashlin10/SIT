import { useState, useCallback, useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import type { ConnectionInfo, Preset, ConfigFile } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls, selectCls, inputCls } from '@/lib/utils'
import {
  Plug, Save, List, ChevronLeft, Loader2, CircleDot,
  Settings, FileText, Network, Gauge, RefreshCw, Plus,
  Eye, EyeOff, Pencil, Trash2, Download, Upload, Play,
  Route, Terminal, Ban, RotateCcw, CheckCircle, AlertTriangle, Layers,
} from 'lucide-react'
import {
  connectToServer, connectRemoteServer, savePreset, deletePreset, loadPresets,
  serviceAction, fetchConfigFiles, fetchRemoteConfigFiles,
  fetchFileContent, deleteFile, toggleFileVisibility,
  fetchNetplanFiles, fetchRemoteNetplanFiles, fetchNetplanContent,
  netplanApply, netplanRoutes, tcShow, tcApply, tcRemove,
  cscDeleteConfigFile,
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
              <List className="w-3 h-3" /> Saved
            </button>
            {showPresets && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setShowPresets(false)} />
                <div className="absolute right-0 mt-1.5 w-72 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 max-h-60 overflow-auto py-1">
                  {presets.length === 0 ? (
                    <div className="p-3 text-xs text-surface-400 text-center italic">No saved connections</div>
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
                <button onClick={() => onView(f.name)} className="text-[11px] font-mono text-surface-700 dark:text-surface-300 hover:text-vyper-600 dark:hover:text-vyper-400 truncate text-left flex-1 min-w-0 transition-colors">
                  {f.name}
                </button>
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

// ── Node Column ──

function NodeColumn({
  side,
  collapsed,
  onToggleCollapse,
}: {
  side: 'local' | 'remote'
  collapsed: boolean
  onToggleCollapse: () => void
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

  // Auto-refresh data when node type changes
  useEffect(() => {
    if (!connected || !isLocal) return
    fetchConfigFiles()
    fetchNetplanFiles()
  }, [nodeType, connected, isLocal])

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

  const handleNetplanApply = async () => {
    await netplanApply()
  }

  const handleShowRoutes = async () => {
    store.openFileViewerLoading('Routes', '', side, 'netplan')
    const out = await netplanRoutes()
    store.setFileViewerLoaded(out, false)
  }

  // Config file paths based on node type
  const configPath = nodeType === 'csc' ? '/opt/cisco-secure-client-docker/' : '/etc/swanctl/conf.d'
  const netplanPath = '/etc/netplan'

  if (collapsed) {
    return (
      <div className="flex flex-col items-center w-10 shrink-0">
        <button onClick={onToggleCollapse} className="p-1.5 rounded-md border border-surface-200 dark:border-surface-700 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors" title={`Expand ${isLocal ? 'Local' : 'Remote'} Node`}>
          <ChevronLeft className="w-3.5 h-3.5 text-surface-400 rotate-180" />
        </button>
      </div>
    )
  }

  const isRemoteAsaFtd = !isLocal && nodeType === 'asa_ftd'

  return (
    <div className="flex-1 min-w-0 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">
            {isLocal ? 'Local Node' : 'Remote Node'}
          </h3>
          {isLocal ? (
            <select
              value={store.localNodeType}
              onChange={(e) => store.setLocalNodeType(e.target.value as 'strongswan' | 'csc')}
              className={selectCls}
            >
              <option value="strongswan">strongSwan</option>
              <option value="csc">Cisco Secure Client</option>
            </select>
          ) : (
            <select
              value="asa_ftd"
              disabled
              className={selectCls}
            >
              <option value="asa_ftd">ASA / FTD</option>
            </select>
          )}
        </div>
        <button onClick={onToggleCollapse} className="p-1 rounded-md border border-surface-200 dark:border-surface-700 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors" title="Collapse">
          <ChevronLeft className="w-3.5 h-3.5 text-surface-400" />
        </button>
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
                <button onClick={() => store.openTemplateBuilder()} disabled={!connected} className={btnCls()} title="SwanCtl Template Builder">
                  <Layers className="w-3.5 h-3.5" /> Template
                </button>
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
                <button onClick={handleNetplanApply} disabled={!connected} className={btnCls('success')}>
                  <Play className="w-3.5 h-3.5" /> Apply
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
  const [localCollapsed, setLocalCollapsed] = useState(false)
  const [remoteCollapsed, setRemoteCollapsed] = useState(false)

  return (
    <SectionCard title="VPN Peers">
      <div className="flex gap-5">
        <NodeColumn side="local" collapsed={localCollapsed} onToggleCollapse={() => setLocalCollapsed(!localCollapsed)} />
        <div className="w-px bg-surface-200 dark:bg-surface-800 shrink-0" />
        <NodeColumn side="remote" collapsed={remoteCollapsed} onToggleCollapse={() => setRemoteCollapsed(!remoteCollapsed)} />
      </div>
    </SectionCard>
  )
}
