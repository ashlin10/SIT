import { useState, useEffect, useCallback } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls } from '@/lib/utils'
import CustomSelect from '@/components/CustomSelect'
import { Eye, RefreshCw, Loader2, FileText, X, Copy, Check } from 'lucide-react'
import { cscGetContainers, cscGetContainerConfig } from './api'

interface ContainerInfo {
  id: string
  name: string
  status: string
  state: string
}

interface ContainerConfigFile {
  path: string
  content: string
  description?: string
}

export default function CscContainerConfigSection() {
  const { localConnected } = useVpnDebuggerStore()
  const [containers, setContainers] = useState<ContainerInfo[]>([])
  const [selectedContainer, setSelectedContainer] = useState('')
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  // Popup state
  const [popupOpen, setPopupOpen] = useState(false)
  const [popupConfigs, setPopupConfigs] = useState<ContainerConfigFile[]>([])
  const [popupTitle, setPopupTitle] = useState('')
  const [expandedFile, setExpandedFile] = useState<number | null>(null)
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null)

  const runningContainers = containers.filter(
    c => (c.state || '').toLowerCase() === 'running'
  )

  const cscContainerRefreshKey = useVpnDebuggerStore(s => s.cscContainerRefreshKey)

  useEffect(() => {
    if (localConnected) fetchContainers()
  }, [localConnected, cscContainerRefreshKey])

  const fetchContainers = useCallback(async () => {
    setRefreshing(true)
    const data = await cscGetContainers()
    if (data.success !== false) {
      setContainers(data.containers || [])
    }
    setRefreshing(false)
  }, [])

  const handleViewConfig = async () => {
    if (!selectedContainer) return
    setLoading(true)
    const data = await cscGetContainerConfig(selectedContainer)
    if (data.success !== false && data.configs && data.configs.length > 0) {
      const containerName = runningContainers.find(c => c.id === selectedContainer)?.name || selectedContainer.slice(0, 12)
      setPopupTitle(`Config: ${containerName}`)
      setPopupConfigs(data.configs)
      setExpandedFile(null)
      setCopiedIdx(null)
      setPopupOpen(true)
    }
    setLoading(false)
  }

  const handleCopyContent = (idx: number) => {
    navigator.clipboard.writeText(popupConfigs[idx].content)
    setCopiedIdx(idx)
    setTimeout(() => setCopiedIdx(null), 2000)
  }

  return (
    <div className="space-y-2 mt-2">
      <div className="text-[10px] text-surface-400">
        Container config (select a running container)
      </div>
      <div className="flex items-center gap-2">
        <CustomSelect
          value={selectedContainer}
          onChange={v => setSelectedContainer(v)}
          disabled={!localConnected || runningContainers.length === 0}
          className="flex-1"
          placeholder={runningContainers.length === 0 ? 'No containers' : 'Select container...'}
          options={runningContainers.map(c => ({ value: c.id, label: c.name || c.id.slice(0, 12) }))}
        />
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

      {/* Config Popup */}
      {popupOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setPopupOpen(false)} />
          <div className="relative w-[680px] max-w-[90vw] max-h-[85vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
              <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">{popupTitle}</h3>
              <button onClick={() => setPopupOpen(false)} className="p-1 rounded-lg hover:bg-surface-200 dark:hover:bg-surface-700 transition-colors"><X className="w-4 h-4 text-surface-500" /></button>
            </div>
            <div className="flex-1 overflow-auto p-3 space-y-2">
              {popupConfigs.map((c, i) => (
                <div key={i} className="rounded-lg border border-surface-100 dark:border-surface-800 overflow-hidden">
                  <button
                    onClick={() => setExpandedFile(expandedFile === i ? null : i)}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors text-left"
                  >
                    <FileText className="w-3.5 h-3.5 text-purple-500 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-semibold text-surface-700 dark:text-surface-300 truncate">{c.path}</div>
                      {c.description && <div className="text-[9px] text-surface-400">{c.description}</div>}
                    </div>
                    <Eye className="w-3 h-3 text-surface-400 shrink-0" />
                  </button>
                  {expandedFile === i && (
                    <div className="border-t border-surface-100 dark:border-surface-800">
                      <div className="flex items-center justify-end px-3 py-1">
                        <button onClick={() => handleCopyContent(i)} className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-surface-100 dark:bg-surface-800 hover:bg-surface-200 dark:hover:bg-surface-700 text-surface-600 dark:text-surface-300 transition-colors">
                          {copiedIdx === i ? <><Check className="w-3 h-3 text-accent-emerald" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
                        </button>
                      </div>
                      <pre className="px-3 pb-3 max-h-[250px] overflow-auto text-[10px] font-mono text-surface-600 dark:text-surface-300 whitespace-pre-wrap break-all leading-relaxed bg-surface-50 dark:bg-surface-800/30">
                        {c.content}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
