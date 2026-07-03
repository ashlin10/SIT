import { useRef, useState } from 'react'
import { cn } from '@/lib/utils'
import { usePolicyConfigStore, selectedAcpNames } from '@/stores/policyConfigStore'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import SourceConnectionPanel from './SourceConnectionPanel'
import AcpTable from './AcpTable'
import {
  listAcps, uploadPolicyYaml, downloadYaml, loadTargetPolicies, previewPush,
} from './api'
import {
  RefreshCw, Upload, Download, Send, FileCode, ShieldCheck, Loader2,
} from 'lucide-react'

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

  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState<string | null>(null)

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
    if (selectedAcpNames().length === 0) { alert('Select at least one ACP'); return }
    setBusy('preview')
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

  const pushDisabled = selectedCount === 0 || !targetConnected || !anyFetched || isOperationRunning

  return (
    <div className="space-y-4">
      <SourceConnectionPanel />

      <div className="rounded-xl border border-surface-200 dark:border-surface-800/60 bg-white dark:bg-surface-900/50">
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
            <button onClick={() => fileRef.current?.click()} className={btnCls()}>
              <Upload className="w-3.5 h-3.5" /> Upload YAML
            </button>
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
              Push Policies ({selectedCount})
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
            {targetConnected && !anyFetched && selectedCount > 0 && (
              <span className="text-[10px] text-surface-400">Fetch the selected ACP(s) before pushing</span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
