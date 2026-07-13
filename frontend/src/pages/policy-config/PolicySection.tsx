import { useCallback, useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { usePolicyConfigStore, selectedAcpNames } from '@/stores/policyConfigStore'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import SourceConnectionPanel from './SourceConnectionPanel'
import AcpTable from './AcpTable'
import {
  listAcps, uploadPolicyYaml, downloadYaml, loadTargetPolicies, previewPush,
  listServerYamls, loadServerYamls,
  type ServerYamlFile,
} from './api'
import {
  RefreshCw, Upload, Download, Send, FileCode, ShieldCheck, Loader2,
  ChevronDown, HardDrive, Globe, X,
} from 'lucide-react'

type SchemaSource = 'oas' | 'ftl'

export default function PolicySection() {
  const acps = usePolicyConfigStore((s) => s.acps)
  const sourceConnected = usePolicyConfigStore((s) => s.sourceConnected)
  const targetMeta = usePolicyConfigStore((s) => s.targetMeta)
  const yaml = usePolicyConfigStore((s) => s.yaml)
  const filename = usePolicyConfigStore((s) => s.filename)
  const perRuleFallback = usePolicyConfigStore((s) => s.perRuleFallback)
  const setPerRuleFallback = usePolicyConfigStore((s) => s.setPerRuleFallback)
  const isOperationRunning = useFmcConfigStore((s) => s.isOperationRunning)
  const openViewer = useFmcConfigStore((s) => s.openViewer)
  const policyValidateEnabled = useFmcConfigStore((s) => s.policyValidateEnabled)
  const setPolicyValidateEnabled = useFmcConfigStore((s) => s.setPolicyValidateEnabled)
  const policySchemaSource = useFmcConfigStore((s) => s.policySchemaSource)
  const setPolicySchemaSource = useFmcConfigStore((s) => s.setPolicySchemaSource)

  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState<string | null>(null)

  // Upload dropdown state
  const [uploadOpen, setUploadOpen] = useState(false)
  const [serverOpen, setServerOpen] = useState(false)
  const [serverFiles, setServerFiles] = useState<ServerYamlFile[]>([])
  const [serverLoading, setServerLoading] = useState(false)
  const [serverError, setServerError] = useState('')
  const [serverSelected, setServerSelected] = useState<string | null>(null)
  const uploadRef = useRef<HTMLDivElement>(null)
  const serverRef = useRef<HTMLDivElement>(null)

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const t = e.target as Node
      const inUpload = uploadRef.current?.contains(t)
      const inServer = serverRef.current?.contains(t)
      if (!inUpload && !inServer) {
        setUploadOpen(false)
        setServerOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleOpenServer = useCallback(async () => {
    setServerOpen(true)
    setUploadOpen(false)
    if (serverFiles.length > 0) return
    setServerLoading(true)
    setServerError('')
    const r = await listServerYamls()
    setServerLoading(false)
    if (r.success && r.files) {
      setServerFiles(r.files)
    } else {
      setServerError(r.message || 'Failed to list files')
    }
  }, [serverFiles.length])

  const selectServerFile = (url: string) => {
    setServerSelected(prev => prev === url ? null : url)
  }

  const handleLoadSelected = async () => {
    if (!serverSelected) return
    setBusy('server')
    const r = await loadServerYamls([serverSelected])
    setBusy(null)
    if (r.success) {
      setServerOpen(false)
      setServerSelected(null)
    } else {
      alert(r.message || 'Failed to load server YAMLs')
    }
  }

  const selectedCount = acps.filter((a) => a.selected).length
  const anyFetched = acps.some((a) => a.fetched)
  const targetConnected = targetMeta.status === 'connected'

  const handleList = async () => {
    setBusy('list')
    const r = await listAcps()
    setBusy(null)
    if (!r.success) alert(r.message || 'Failed to list ACPs')
  }

  const handleUpload = async (file: File) => {
    const r = await uploadPolicyYaml(file)
    if (!r.success) alert([r.message, ...(r.errors || [])].filter(Boolean).join('\n') || 'Upload failed')
  }

  const handlePreview = async () => {
    if (selectedAcpNames().length === 0) { alert('Select an ACP to push'); return }
    setBusy('preview')
    // Scroll to the terminal so the user can follow progress.
    setTimeout(() => document.getElementById('terminal-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 200)
    // Load target policies for the assigned-policy mapping dropdowns first.
    if (targetConnected) { try { await loadTargetPolicies() } catch { /* non-fatal */ } }
    const r = await previewPush()
    setBusy(null)
    if (!r.success) alert(r.message || 'Preview failed')
  }

  const btnCls = (variant: 'primary' | 'secondary' = 'secondary') => cn(
    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
    variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
    variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
  )

  const hasLoadedPolicy = anyFetched || !!yaml
  const pushDisabled = selectedCount === 0 || !targetConnected || !hasLoadedPolicy || isOperationRunning

  return (
    <div className="space-y-4">
      <SourceConnectionPanel />

      <div id="acp-section" className="rounded-xl border border-surface-200 dark:border-surface-800/60 bg-white dark:bg-surface-900/50">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-surface-800 dark:text-surface-200">Access Control Policy</span>
            {filename && (
              <button
                onClick={() => openViewer(`Policy — ${filename}`, yaml)}
                className="text-[10px] font-medium text-accent-violet bg-accent-violet/10 border border-accent-violet/20 rounded-full px-2.5 py-0.5 hover:bg-accent-violet/20 transition-colors"
              >
                <FileCode className="w-3 h-3 inline mr-1" />{filename}
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleList} disabled={!sourceConnected || busy === 'list'}
              className={cn(btnCls(), (!sourceConnected || busy === 'list') && 'opacity-40 pointer-events-none')}>
              {busy === 'list' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />} List ACPs
            </button>
            <div className="relative" ref={uploadRef}>
              <button onClick={() => { setUploadOpen(!uploadOpen); setServerOpen(false) }} className={cn(btnCls(), 'pr-2')}>
                <Upload className="w-3.5 h-3.5" /> Upload YAML
                <ChevronDown className={cn('w-3 h-3 ml-0.5 transition-transform', uploadOpen && 'rotate-180')} />
              </button>
              {uploadOpen && (
                <div className="absolute right-0 top-full mt-1 w-44 bg-white dark:bg-surface-800 border border-surface-200 dark:border-surface-700 rounded-lg shadow-lg z-50 py-1 animate-in fade-in slide-in-from-top-1 duration-150">
                  <button
                    className="flex items-center gap-2 w-full px-3 py-2 text-[11px] font-medium text-surface-700 dark:text-surface-300 hover:bg-surface-50 dark:hover:bg-surface-700/60 transition-colors"
                    onClick={() => { setUploadOpen(false); fileRef.current?.click() }}
                  >
                    <HardDrive className="w-3.5 h-3.5 text-surface-400" /> Local File
                  </button>
                  <button
                    className="flex items-center gap-2 w-full px-3 py-2 text-[11px] font-medium text-surface-700 dark:text-surface-300 hover:bg-surface-50 dark:hover:bg-surface-700/60 transition-colors"
                    onClick={handleOpenServer}
                  >
                    <Globe className="w-3.5 h-3.5 text-surface-400" /> Server
                  </button>
                </div>
              )}
              {/* Server YAML Popover — anchored above the Upload YAML button */}
              {serverOpen && (
                <div ref={serverRef} className="absolute right-0 bottom-full mb-1 w-[480px] bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl z-50 animate-in fade-in slide-in-from-bottom-2 duration-200">
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-surface-100 dark:border-surface-800">
                    <span className="text-[11px] font-semibold text-surface-700 dark:text-surface-200 tracking-wide uppercase">Server Policies</span>
                    <div className="flex items-center gap-1.5">
                      {serverSelected && (
                        <button
                          onClick={handleLoadSelected}
                          disabled={busy === 'server'}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-semibold bg-vyper-600 text-white hover:bg-vyper-700 disabled:opacity-50 transition-colors"
                        >
                          {busy === 'server' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                          Load
                        </button>
                      )}
                      <button onClick={() => setServerOpen(false)} className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
                        <X className="w-3.5 h-3.5 text-surface-400 dark:text-surface-500" />
                      </button>
                    </div>
                  </div>
                  {/* Column header */}
                  <div className="flex items-center px-4 py-1.5 border-b border-surface-100 dark:border-surface-800 text-[10px] font-medium text-surface-400 dark:text-surface-500 uppercase tracking-wider">
                    <span className="w-7" />
                    <span className="flex-1">Policy</span>
                    <span className="w-36 text-right">Version</span>
                  </div>
                  <div className="max-h-[200px] overflow-y-auto">
                    {serverLoading && (
                      <div className="flex items-center justify-center py-6 gap-2 text-[11px] text-surface-400 dark:text-surface-500">
                        <Loader2 className="w-4 h-4 animate-spin" /> Loading...
                      </div>
                    )}
                    {serverError && (
                      <div className="px-4 py-3 text-[11px] text-accent-rose">{serverError}</div>
                    )}
                    {!serverLoading && !serverError && serverFiles.length === 0 && (
                      <div className="px-4 py-6 text-[11px] text-surface-400 dark:text-surface-500 text-center">No policy files found</div>
                    )}
                    {!serverLoading && serverFiles.map((f) => {
                      const selected = serverSelected === f.url
                      const displayName = f.name
                      return (
                        <button
                          key={f.url}
                          onClick={() => selectServerFile(f.url)}
                          className={cn(
                            'flex items-center w-full px-4 py-2 text-left transition-colors',
                            selected
                              ? 'bg-vyper-50 dark:bg-vyper-900/40'
                              : 'hover:bg-surface-50 dark:hover:bg-surface-800',
                          )}
                        >
                          <div className={cn(
                            'flex items-center justify-center w-4 h-4 rounded-full border mr-3 flex-shrink-0 transition-colors',
                            selected
                              ? 'border-vyper-600'
                              : 'border-surface-300 dark:border-surface-600',
                          )}>
                            {selected && <div className="w-2 h-2 rounded-full bg-vyper-600" />}
                          </div>
                          <span className="text-[11px] font-medium text-surface-700 dark:text-surface-200 truncate flex-1 mr-2">{displayName}</span>
                          {f.version && (
                            <span className="text-[10px] font-mono text-surface-500 dark:text-surface-400 w-36 text-right flex-shrink-0">{f.version}</span>
                          )}
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
            <input ref={fileRef} type="file" accept=".yaml,.yml" className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleUpload(f); e.target.value = '' }} />
            <button onClick={() => downloadYaml()} disabled={!yaml}
              className={cn(btnCls(), !yaml && 'opacity-40 pointer-events-none')}>
              <Download className="w-3.5 h-3.5" /> Download
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-3">
          <AcpTable />

          <div className="flex items-center gap-2 pt-1">
            <button onClick={handlePreview} disabled={pushDisabled || busy === 'preview'}
              className={cn(btnCls('primary'), (pushDisabled || busy === 'preview') && 'opacity-40 pointer-events-none')}>
              {busy === 'preview' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              Push Policy
            </button>
            <label className={cn('flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400 cursor-pointer',
              isOperationRunning && 'opacity-50 pointer-events-none')}
              title="If a bulk rule push fails, retry the failed batch rule-by-rule so valid rules still push.">
              <input type="checkbox" checked={perRuleFallback} disabled={isOperationRunning}
                onChange={(e) => setPerRuleFallback(e.target.checked)}
                className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
              Per-rule fallback
            </label>
            {!targetConnected && (
              <span className="inline-flex items-center gap-1 text-[10px] text-accent-amber">
                <ShieldCheck className="w-3 h-3" /> Connect a target FMC to push
              </span>
            )}
            {targetConnected && !hasLoadedPolicy && selectedCount > 0 && (
              <span className="text-[10px] text-surface-400">Fetch the selected ACP(s) before pushing</span>
            )}
            <div className="ml-auto flex items-center gap-2">
              <label
                className="flex items-center gap-1.5 cursor-pointer select-none"
                title="Validate the policy YAML (ACPs, dependent policies, objects) against the FMC OAS/FTL schema for the source and target versions before pushing. If unchecked, the validation phase is skipped."
              >
                <input
                  type="checkbox"
                  checked={policyValidateEnabled}
                  onChange={e => setPolicyValidateEnabled(e.target.checked)}
                  className="rounded border-surface-300 dark:border-surface-600 text-vyper-600 focus:ring-vyper-500/30 w-3.5 h-3.5"
                />
                <ShieldCheck className={cn('w-3.5 h-3.5 transition-colors', policyValidateEnabled ? 'text-vyper-600' : 'text-surface-400')} />
                <span className={cn('text-[11px] font-medium transition-colors', policyValidateEnabled ? 'text-vyper-600' : 'text-surface-500')}>Validate Config</span>
              </label>
              {policyValidateEnabled && (
                <select
                  value={policySchemaSource}
                  onChange={e => setPolicySchemaSource(e.target.value as SchemaSource)}
                  className="rounded border border-surface-300 dark:border-surface-600 bg-white dark:bg-surface-800 px-2 py-1 text-[11px] text-surface-700 dark:text-surface-300 focus:outline-none focus:ring-1 focus:ring-vyper-500"
                  title="Select which FMC schema to use for policy validation."
                >
                  <option value="oas">OAS Schemas</option>
                  <option value="ftl">FTL Schemas</option>
                </select>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
