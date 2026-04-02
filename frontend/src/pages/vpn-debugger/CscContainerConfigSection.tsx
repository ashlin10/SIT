import { useState, useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls, selectCls } from '@/lib/utils'
import { Eye, RefreshCw, Loader2, FileText, Trash2 } from 'lucide-react'
import { cscGetContainers, cscGetContainerConfig } from './api'

interface ContainerInfo {
  id: string
  name: string
  status: string
}

interface ContainerConfigFile {
  name: string
  content?: string
}

export default function CscContainerConfigSection() {
  const { localConnected } = useVpnDebuggerStore()
  const store = useVpnDebuggerStore()
  const [containers, setContainers] = useState<ContainerInfo[]>([])
  const [selectedContainer, setSelectedContainer] = useState('')
  const [configFiles, setConfigFiles] = useState<ContainerConfigFile[]>([])
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  const runningContainers = containers.filter(
    c => c.status?.toLowerCase().includes('running') || c.status?.toLowerCase() === 'up'
  )

  useEffect(() => {
    if (localConnected) fetchContainers()
  }, [localConnected])

  const fetchContainers = async () => {
    setRefreshing(true)
    const data = await cscGetContainers()
    if (data.success !== false) {
      setContainers(data.containers || [])
    }
    setRefreshing(false)
  }

  const handleViewConfig = async () => {
    if (!selectedContainer) return
    setLoading(true)
    setConfigFiles([])
    const data = await cscGetContainerConfig(selectedContainer)
    if (data.success !== false && data.files) {
      setConfigFiles(data.files)
    } else if (data.success !== false && data.content) {
      setConfigFiles([{ name: 'config', content: data.content }])
    }
    setLoading(false)
  }

  const handleViewFile = (file: ContainerConfigFile) => {
    store.openFileViewer(
      `Container: ${file.name}`,
      file.content || '(empty)',
      false,
      file.name,
      'local',
      'config'
    )
  }

  return (
    <div className="space-y-2 mt-2">
      <div className="text-[10px] text-surface-400">
        Container config (select a running container)
      </div>
      <div className="flex items-center gap-2">
        <select
          value={selectedContainer}
          onChange={e => setSelectedContainer(e.target.value)}
          disabled={!localConnected || runningContainers.length === 0}
          className={cn(selectCls, 'flex-1')}
        >
          <option value="">{runningContainers.length === 0 ? 'No containers' : 'Select container...'}</option>
          {runningContainers.map(c => (
            <option key={c.id} value={c.id}>{c.name || c.id.slice(0, 12)}</option>
          ))}
        </select>
        <button
          onClick={handleViewConfig}
          disabled={!selectedContainer || loading}
          className={btnCls('primary')}
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />} View Config
        </button>
        <button
          onClick={fetchContainers}
          disabled={!localConnected || refreshing}
          className={iconBtnCls()}
          title="Refresh containers"
        >
          <RefreshCw className={cn('w-3.5 h-3.5', refreshing && 'animate-spin')} />
        </button>
      </div>
      {configFiles.length > 0 && (
        <div className="space-y-1">
          {configFiles.map((f, i) => {
            const isClickable = /^(Dockerfile|entry\.sh)$/i.test(f.name)
            return (
              <div
                key={i}
                onClick={isClickable ? () => handleViewFile(f) : undefined}
                className={cn(
                  'flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-surface-100 dark:border-surface-800 group transition-colors',
                  isClickable
                    ? 'cursor-pointer hover:bg-surface-50 dark:hover:bg-surface-800/50'
                    : 'opacity-70',
                )}
              >
                <FileText className={cn('w-3 h-3 shrink-0', isClickable ? 'text-purple-500' : 'text-surface-400')} />
                <span className={cn(
                  'text-[11px] font-mono truncate flex-1',
                  isClickable
                    ? 'text-surface-700 dark:text-surface-300 group-hover:text-vyper-600 dark:group-hover:text-vyper-400'
                    : 'text-surface-500',
                )}>{f.name}</span>
                {isClickable ? (
                  <Eye className="w-3 h-3 ml-auto text-surface-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                ) : (
                  <button
                    onClick={(e) => { e.stopPropagation(); if (confirm(`Delete ${f.name}?`)) { /* TODO: wire csc file delete API */ } }}
                    className={cn(iconBtnCls('danger'), 'opacity-0 group-hover:opacity-100 ml-auto')}
                    title={`Delete ${f.name}`}
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
      {configFiles.length === 0 && selectedContainer && !loading && (
        <div className="text-xs text-surface-400 italic py-1">Select a container and click View Config</div>
      )}
    </div>
  )
}
