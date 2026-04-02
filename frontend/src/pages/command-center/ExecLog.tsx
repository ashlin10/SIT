import { useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { useCommandCenterStore } from '@/stores/commandCenterStore'
import { Terminal, CheckCircle2, XCircle } from 'lucide-react'

export default function ExecLog() {
  const execLog = useCommandCenterStore((s) => s.execLog)
  const execStatus = useCommandCenterStore((s) => s.execStatus)
  const execResults = useCommandCenterStore((s) => s.execResults)
  const isExecuting = useCommandCenterStore((s) => s.isExecuting)
  const logRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [execLog])

  if (!execLog && !execStatus && execResults.length === 0) return null

  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-vyper-500" />
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Execution Log</h2>
          {isExecuting && (
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent-emerald animate-pulse" />
          )}
        </div>
        {execStatus && (
          <span className="text-[11px] font-mono text-surface-500">{execStatus}</span>
        )}
      </div>

      {/* Terminal log */}
      <pre
        ref={logRef}
        className="px-4 py-3 bg-surface-950 text-accent-emerald/80 font-mono text-[11px] leading-relaxed h-48 overflow-auto whitespace-pre-wrap"
      >
        {execLog || 'Waiting for output…'}
      </pre>

      {/* Results */}
      {execResults.length > 0 && (
        <div className="px-5 py-3 border-t border-surface-100 dark:border-surface-800/50">
          <div className="space-y-1">
            {execResults.map((r, i) => (
              <div key={i} className="flex items-center gap-2 text-[12px]">
                {r.success ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-accent-emerald shrink-0" />
                ) : (
                  <XCircle className="w-3.5 h-3.5 text-accent-rose shrink-0" />
                )}
                <span className={cn(
                  'font-mono',
                  r.success ? 'text-accent-emerald' : 'text-accent-rose'
                )}>
                  {r.type} {r.name} ({r.ip_address}{r.port ? ':' + r.port : ''})
                  {' → '}
                  {r.success ? 'Success' : `Fail${r.error ? ' — ' + r.error : ''}`}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
