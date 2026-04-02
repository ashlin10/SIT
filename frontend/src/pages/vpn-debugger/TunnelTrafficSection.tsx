import { useState } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls, selectCls } from '@/lib/utils'
import {
  Server, Network, Plug, CircleDot, RefreshCw, Plus, Trash2, Eye, EyeOff,
  Pencil, Download, Upload, PlayCircle, StopCircle,
} from 'lucide-react'
import {
  fetchLocalTtFiles, fetchRemoteTtFiles, connectToServer, connectRemoteServer,
  fetchTtFileContent, deleteTtFile, toggleTtFileVisibility,
  executeTtScript, killTtScript,
} from './api'
import SectionCard from './SectionCard'
import ConnectPopup from './ConnectPopup'
import type { ConfigFile } from '@/stores/vpnDebuggerStore'

function TtFileList({
  label,
  icon,
  files,
  connected,
  onRefresh,
  onConnect,
  sameAsLocal,
  onSameAsLocalChange,
  showSameAsLocal,
  onAdd,
  externalRefreshing,
  side,
}: {
  label: string
  icon: React.ReactNode
  files: ConfigFile[]
  connected: boolean
  onRefresh: () => void
  onConnect?: () => void
  sameAsLocal?: boolean
  onSameAsLocalChange?: (v: boolean) => void
  showSameAsLocal?: boolean
  onAdd?: () => void
  externalRefreshing?: boolean
  side: 'local' | 'remote'
}) {
  const store = useVpnDebuggerStore()
  const [refreshing, setRefreshing] = useState(false)
  const isRefreshing = refreshing || !!externalRefreshing

  const doRefresh = async () => {
    setRefreshing(true)
    await onRefresh()
    setRefreshing(false)
  }

  const handleView = async (f: string) => {
    store.openFileViewerLoading(f, f, side, 'tunnel-traffic')
    const content = await fetchTtFileContent(side, f)
    store.setFileViewerLoaded(content, false)
  }

  const handleEdit = async (f: string) => {
    store.openFileViewerLoading(`Edit: ${f}`, f, side, 'tunnel-traffic')
    const content = await fetchTtFileContent(side, f)
    store.setFileViewerLoaded(content, true)
  }

  const handleDownload = async (f: string) => {
    const content = await fetchTtFileContent(side, f)
    if (!content && content !== '') return
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = f; a.click()
    URL.revokeObjectURL(url)
  }

  const handleUpload = (f: string) => {
    const input = document.createElement('input')
    input.type = 'file'
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file) return
      const content = await file.text()
      store.openFileViewer(`Upload: ${f}`, content, true, f, side, 'tunnel-traffic')
    }
    input.click()
  }

  return (
    <div className="flex-1 min-w-0 space-y-2.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h4 className="flex items-center gap-1.5 text-xs font-semibold text-surface-700 dark:text-surface-300">
            {icon}
            {label}
          </h4>
          {onConnect && (
            <button onClick={onConnect} className={iconBtnCls('primary')} title="Connect">
              <Plug className="w-3.5 h-3.5" />
            </button>
          )}
          <span className={cn(
            'inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full',
            connected ? 'bg-accent-emerald/10 text-accent-emerald' : 'bg-surface-100 dark:bg-surface-800 text-surface-500'
          )}>
            <CircleDot className="w-2 h-2" />
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <div className="flex items-center gap-1">
          {showSameAsLocal && onSameAsLocalChange && (
            <label className="flex items-center gap-1.5 text-[10px] text-surface-500 cursor-pointer mr-1">
              <input type="checkbox" checked={sameAsLocal} onChange={(e) => onSameAsLocalChange(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" />
              Same as Local
            </label>
          )}
          {onAdd && (
            <button onClick={onAdd} disabled={!connected} className={iconBtnCls()} title="Add file">
              <Plus className="w-3.5 h-3.5" />
            </button>
          )}
          <button onClick={doRefresh} disabled={!connected} className={iconBtnCls()} title="Refresh">
            <RefreshCw className={cn('w-3.5 h-3.5', isRefreshing && 'animate-spin')} />
          </button>
        </div>
      </div>
      <div className="text-[10px] text-surface-400">Files in <code className="text-[10px] px-1 py-0.5 rounded bg-surface-100 dark:bg-surface-800">/var/tmp/tunnel_traffic</code></div>
      {files.length === 0 ? (
        <div className="text-xs text-surface-400 italic py-3 text-center">
          {connected ? 'No files found' : 'Connect to server to view files'}
        </div>
      ) : (
        <div className="space-y-1">
          {files.map((f) => {
            const isHidden = f.name.startsWith('.')
            const isSh = f.name.endsWith('.sh')
            return (
              <div key={f.name} className={cn(
                'flex items-center justify-between px-2.5 py-1.5 rounded-lg border border-surface-100 dark:border-surface-800 group hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors',
                isHidden && 'opacity-50',
              )}>
                <button onClick={() => handleView(f.name)} className="text-[11px] font-mono text-surface-700 dark:text-surface-300 hover:text-vyper-600 dark:hover:text-vyper-400 truncate text-left flex-1 min-w-0 transition-colors">
                  {f.name}
                  {f.size !== undefined && <span className="text-[9px] text-surface-400 ml-2">{formatFileSize(f.size)}</span>}
                </button>
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  {isSh && (
                    <>
                      <button onClick={() => executeTtScript(side, f.name)} className={iconBtnCls('success')} title="Execute script">
                        <PlayCircle className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => killTtScript(side, f.name)} className={iconBtnCls('danger')} title="Kill task">
                        <StopCircle className="w-3.5 h-3.5" />
                      </button>
                    </>
                  )}
                  <button onClick={() => handleEdit(f.name)} className={iconBtnCls()} title="Edit">
                    <Pencil className="w-3 h-3" />
                  </button>
                  <button onClick={() => { if (confirm(`Delete ${f.name}?`)) deleteTtFile(side, f.name) }} className={iconBtnCls('danger')} title="Delete">
                    <Trash2 className="w-3 h-3" />
                  </button>
                  <button onClick={() => handleUpload(f.name)} className={iconBtnCls()} title="Upload/Replace">
                    <Upload className="w-3 h-3" />
                  </button>
                  <button onClick={() => handleDownload(f.name)} className={iconBtnCls()} title="Download">
                    <Download className="w-3 h-3" />
                  </button>
                  <button onClick={() => toggleTtFileVisibility(side, f.name)} className={iconBtnCls()} title={isHidden ? 'Unhide' : 'Hide'}>
                    {isHidden ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function formatFileSize(bytes?: number) {
  if (bytes === undefined || bytes === null) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function TunnelTrafficSection() {
  const store = useVpnDebuggerStore()
  const { localTtFiles, remoteTtFiles, localTtConnected, remoteTtConnected, localConnected,
    ttConnPopupOpen, ttConnPopupSide, ttConn, closeTtConnPopup, setTtConn, openTtConnPopup,
    localTtFilesLoading, remoteTtFilesLoading } = store
  const [localSameAsLocal, setLocalSameAsLocal] = useState(true)

  const localEffConnected = localSameAsLocal ? localConnected : localTtConnected

  const handleTtConnect = () => {
    const side = ttConnPopupSide
    if (side === 'local') {
      connectToServer(ttConn).then(() => { store.setLocalTtConnected(true); closeTtConnPopup() })
    } else {
      connectRemoteServer(ttConn).then(() => { store.setRemoteTtConnected(true); closeTtConnPopup() })
    }
  }

  const handleAddFile = (side: 'local' | 'remote') => {
    const name = prompt('New tunnel traffic filename:')
    if (name) {
      store.openFileViewer(`New: ${name}`, '', true, name, side, 'tunnel-traffic')
    }
  }

  return (
    <>
      <SectionCard title="Tunnel Traffic">
        <div className="flex gap-4">
          <TtFileList
            label="Local Network"
            icon={<Server className="w-3.5 h-3.5 text-accent-violet" />}
            files={localTtFiles}
            connected={localEffConnected}
            onRefresh={fetchLocalTtFiles}
            onConnect={localSameAsLocal ? undefined : () => openTtConnPopup('local')}
            showSameAsLocal
            sameAsLocal={localSameAsLocal}
            onSameAsLocalChange={setLocalSameAsLocal}
            onAdd={() => handleAddFile('local')}
            externalRefreshing={localTtFilesLoading}
            side="local"
          />
          <div className="w-px bg-surface-200 dark:bg-surface-800 shrink-0" />
          <TtFileList
            label="Remote Network"
            icon={<Network className="w-3.5 h-3.5 text-purple-500" />}
            files={remoteTtFiles}
            connected={remoteTtConnected}
            onRefresh={fetchRemoteTtFiles}
            onConnect={() => openTtConnPopup('remote')}
            onAdd={() => handleAddFile('remote')}
            externalRefreshing={remoteTtFilesLoading}
            side="remote"
          />
        </div>
      </SectionCard>

      {ttConnPopupOpen && (
        <ConnectPopup
          title={`Connect to ${ttConnPopupSide === 'local' ? 'Local' : 'Remote'} Network`}
          conn={ttConn}
          setConn={setTtConn}
          onConnect={handleTtConnect}
          onClose={closeTtConnPopup}
        />
      )}
    </>
  )
}
