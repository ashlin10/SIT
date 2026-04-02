import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { Terminal, Trash2, Download, Square, ChevronDown, ChevronUp, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react'

export default function TerminalPanel() {
  const {
    terminalLog, terminalVisible, isOperationRunning,
    progressPercent, progressLabel,
    summaryTables, summaryVisible,
    clearLog, setTerminalVisible, setSummaryVisible,
  } = useFmcConfigStore()

  const logRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [terminalLog])

  // Don't render if terminal was never opened
  if (!terminalVisible && !terminalLog && !summaryTables && !isOperationRunning) return null

  const handleDownload = () => {
    const blob = new Blob([terminalLog], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `fmc-logs-${new Date().toISOString().slice(0, 19)}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-5 py-2.5 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-vyper-500" />
          <span className="text-sm font-medium text-surface-800 dark:text-surface-200">Terminal</span>
          {isOperationRunning && (
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent-emerald animate-pulse" />
          )}
          {/* Progress */}
          {isOperationRunning && progressPercent > 0 && (
            <div className="flex items-center gap-2 ml-2">
              <div className="w-24 h-1.5 rounded-full bg-surface-200 dark:bg-surface-700 overflow-hidden">
                <div
                  className="h-full rounded-full bg-vyper-500 transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
              <span className="text-[10px] font-mono text-surface-500">{progressPercent}%</span>
              {progressLabel && <span className="text-[10px] text-surface-400">{progressLabel}</span>}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={clearLog} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors" title="Clear">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button onClick={handleDownload} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors" title="Download">
            <Download className="w-3.5 h-3.5" />
          </button>
          {isOperationRunning && (
            <button className="p-1.5 rounded-md hover:bg-accent-rose/10 text-accent-rose transition-colors" title="Stop">
              <Square className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            onClick={() => setTerminalVisible(!terminalVisible)}
            className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors"
          >
            {terminalVisible ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Terminal Content */}
      {terminalVisible && (
        <pre
          ref={logRef}
          className="px-4 py-3 bg-surface-950 text-accent-emerald/80 font-mono text-[11px] leading-relaxed overflow-auto whitespace-pre-wrap"
          style={{ height: '22rem' }}
        >
          {terminalLog || 'Waiting for output…'}
        </pre>
      )}

      {/* Summary Section */}
      {summaryTables && (
        <>
          <div className="flex items-center justify-between px-5 py-2.5 border-t border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-vyper-500" />
              <span className="text-sm font-medium text-surface-800 dark:text-surface-200">Summary</span>
            </div>
            <button
              onClick={() => setSummaryVisible(!summaryVisible)}
              className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors"
            >
              {summaryVisible ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          </div>

          {summaryVisible && (
            <div className="px-5 py-4 space-y-4 border-t border-surface-100 dark:border-surface-800/50">
              {/* Applied */}
              {summaryTables.applied && summaryTables.applied.length > 0 && (
                <SummaryTable
                  title="Configurations Applied"
                  icon={<CheckCircle2 className="w-3.5 h-3.5 text-accent-emerald" />}
                  headers={['Type', 'Name', 'Count']}
                  rows={summaryTables.applied}
                  variant="success"
                />
              )}

              {/* Failed */}
              {summaryTables.failed && summaryTables.failed.length > 0 && (
                <SummaryTable
                  title="Configurations Failed"
                  icon={<XCircle className="w-3.5 h-3.5 text-accent-rose" />}
                  headers={['Type', 'Name', 'Error']}
                  rows={summaryTables.failed}
                  variant="error"
                />
              )}

              {/* Skipped */}
              {summaryTables.skipped && summaryTables.skipped.length > 0 && (
                <SummaryTable
                  title="Configurations Skipped"
                  icon={<AlertTriangle className="w-3.5 h-3.5 text-accent-amber" />}
                  headers={['Type', 'Name', 'Reason']}
                  rows={summaryTables.skipped}
                  variant="warning"
                />
              )}

              {(!summaryTables.applied?.length && !summaryTables.failed?.length && !summaryTables.skipped?.length) && (
                <p className="text-[11px] text-surface-400 text-center py-2">No summary data available.</p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function SummaryTable({
  title, icon, headers, rows, variant,
}: {
  title: string
  icon: React.ReactNode
  headers: string[]
  rows: (string | number)[][]
  variant: 'success' | 'error' | 'warning'
}) {
  const headerBg = {
    success: 'bg-accent-emerald/5',
    error: 'bg-accent-rose/5',
    warning: 'bg-accent-amber/5',
  }

  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2">
        {icon}
        <span className="text-xs font-medium text-surface-700 dark:text-surface-300">{title}</span>
      </div>
      <div className="overflow-auto max-h-60 rounded-lg border border-surface-200 dark:border-surface-700">
        <table className="w-full text-[11px]">
          <thead>
            <tr className={headerBg[variant]}>
              {headers.map((h, i) => (
                <th key={i} className="px-3 py-1.5 text-left font-medium text-surface-600 dark:text-surface-400 border-b border-surface-200 dark:border-surface-700">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className="border-b border-surface-100 dark:border-surface-800/50 last:border-b-0">
                {headers.map((_, j) => (
                  <td key={j} className="px-3 py-1.5 text-surface-700 dark:text-surface-300">
                    {String(row[j] || '').replace(/\n/g, ', ')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
