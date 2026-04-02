import { useState } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { X, Copy, Check, Download } from 'lucide-react'
import { cn } from '@/lib/utils'

export default function ReportViewerModal() {
  const { reportViewerOpen, reportContent, closeReportViewer } = useVpnDebuggerStore()
  const [copied, setCopied] = useState(false)

  if (!reportViewerOpen) return null

  const handleCopy = () => {
    navigator.clipboard.writeText(reportContent)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    const blob = new Blob([reportContent], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vpn-monitoring-report-${new Date().toISOString().slice(0, 10)}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-[1000]" onClick={closeReportViewer} />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[1001] w-[800px] max-w-[90vw] max-h-[80vh] flex flex-col rounded-xl border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-2xl">
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-100 dark:border-surface-800">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">Monitoring Report</h3>
          <div className="flex items-center gap-2">
            <button onClick={handleCopy} className={cn(
              'flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors',
              copied ? 'text-accent-emerald bg-accent-emerald/10' : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300'
            )}>
              {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button onClick={handleDownload} className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-accent-emerald hover:bg-accent-emerald/10 transition-colors">
              <Download className="w-3 h-3" /> Download
            </button>
            <button onClick={closeReportViewer} className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
              <X className="w-4 h-4 text-surface-400" />
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-auto">
          <pre className="p-4 bg-surface-950 text-surface-300 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words min-h-[300px]">
            {reportContent || 'No report data available.'}
          </pre>
        </div>
      </div>
    </>
  )
}
