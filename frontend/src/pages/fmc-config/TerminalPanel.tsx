import { useEffect, useRef, useState, useMemo } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { stopOperation } from './api'
import { Terminal, Trash2, Download, Square, ChevronDown, ChevronUp, CheckCircle2, XCircle, AlertTriangle, Copy, Check } from 'lucide-react'

export default function TerminalPanel() {
  const {
    terminalLog, terminalVisible, isOperationRunning,
    progressPercent, progressLabel, progressDevice,
    summaryTables, deviceSummaries, summaryVisible,
    clearLog, setTerminalVisible, setSummaryVisible,
  } = useFmcConfigStore()

  const logRef = useRef<HTMLPreElement>(null)
  const [copied, setCopied] = useState(false)
  // Per-device summary panes are collapsed by default.
  const [openDeviceSummaries, setOpenDeviceSummaries] = useState<Record<string, boolean>>({})
  const toggleDeviceSummary = (name: string) => setOpenDeviceSummaries((o) => ({ ...o, [name]: !o[name] }))

  const renderedLog = useMemo(() => {
    if (!terminalLog) return null
    const parts = terminalLog.split(/(\*\*[^*]+\*\*)/g)
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <span key={i} className="font-bold text-accent-emerald">{part.slice(2, -2)}</span>
      }
      return part
    })
  }, [terminalLog])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [terminalLog])

  // Don't render if terminal was never opened
  if (!terminalVisible && !terminalLog && !summaryTables && !isOperationRunning) return null

  const handleCopy = async () => {
    const text = logRef.current?.innerText || terminalLog || ''
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch { /* clipboard not available */ }
  }

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
    <div id="terminal-panel" className={cn(
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
              {progressDevice && (
                <span className="text-[10px] font-semibold text-vyper-500 whitespace-nowrap">Device {progressDevice}</span>
              )}
              {progressLabel && <span className="text-[10px] text-surface-400">{progressLabel}</span>}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={handleCopy} className={cn('p-1.5 rounded-md transition-colors', copied ? 'text-accent-emerald' : 'hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400')} title={copied ? 'Copied!' : 'Copy visible logs'}>
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button onClick={clearLog} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors" title="Clear">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button onClick={handleDownload} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors" title="Download">
            <Download className="w-3.5 h-3.5" />
          </button>
          {isOperationRunning && (
            <button onClick={stopOperation} className="p-1.5 rounded-md hover:bg-accent-rose/10 text-accent-rose transition-colors" title="Stop operation">
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
          {renderedLog || 'Waiting for output…'}
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

          {summaryVisible && deviceSummaries.length > 0 && (
            <div className="px-5 py-4 space-y-3 border-t border-surface-100 dark:border-surface-800/50">
              {deviceSummaries.map((dev) => {
                const t = dev.tables
                const total = (t.applied?.length || 0) + (t.failed?.length || 0) + (t.skipped?.length || 0)
                const isOpen = !!openDeviceSummaries[dev.deviceName]
                return (
                  <div key={dev.deviceName} className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                    <button
                      onClick={() => toggleDeviceSummary(dev.deviceName)}
                      className="w-full flex items-center justify-between px-3 py-2 bg-surface-50 dark:bg-surface-800/40 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors"
                    >
                      <span className="flex items-center gap-2 text-xs font-medium text-surface-800 dark:text-surface-200">
                        <CheckCircle2 className="w-3.5 h-3.5 text-vyper-500" />
                        {dev.deviceName}
                        <span className="text-[10px] font-normal text-surface-400">
                          ({t.applied?.length || 0} applied, {t.failed?.length || 0} failed, {t.skipped?.length || 0} skipped)
                        </span>
                      </span>
                      {isOpen ? <ChevronUp className="w-3.5 h-3.5 text-surface-400" /> : <ChevronDown className="w-3.5 h-3.5 text-surface-400" />}
                    </button>
                    {isOpen && (
                      <div className="px-3 py-3 space-y-4">
                        {t.applied && t.applied.length > 0 && (
                          <SummaryTable title="Configurations Applied" icon={<CheckCircle2 className="w-3.5 h-3.5 text-accent-emerald" />} headers={['Type', 'Name', 'Count']} rows={t.applied} variant="success" />
                        )}
                        {t.failed && t.failed.length > 0 && (
                          <SummaryTable title="Configurations Failed" icon={<XCircle className="w-3.5 h-3.5 text-accent-rose" />} headers={['Type', 'Name', 'Error']} rows={t.failed} variant="error" />
                        )}
                        {t.skipped && t.skipped.length > 0 && (
                          <SummaryTable title="Configurations Skipped" icon={<AlertTriangle className="w-3.5 h-3.5 text-accent-amber" />} headers={['Type', 'Name', 'Reason']} rows={t.skipped} variant="warning" />
                        )}
                        {total === 0 && (
                          <p className="text-[11px] text-surface-400 text-center py-2">No summary data for this device.</p>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {summaryVisible && deviceSummaries.length === 0 && (
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
