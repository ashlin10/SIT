import { Fragment } from 'react'
import { cn } from '@/lib/utils'
import { usePolicyConfigStore } from '@/stores/policyConfigStore'
import { fetchAcp } from './api'
import AcpDetail from './AcpDetail'
import {
  Download, ChevronRight, Loader2, CheckCircle2, AlertCircle, RefreshCw,
} from 'lucide-react'

/** Access Control Policy table: select, fetch, expand/collapse, status. */
export default function AcpTable() {
  const acps = usePolicyConfigStore((s) => s.acps)
  const listing = usePolicyConfigStore((s) => s.listing)
  const listError = usePolicyConfigStore((s) => s.listError)
  const toggleSelected = usePolicyConfigStore((s) => s.toggleAcpSelected)
  const selectAll = usePolicyConfigStore((s) => s.selectAllAcps)
  const toggleExpanded = usePolicyConfigStore((s) => s.toggleAcpExpanded)

  const fetchedAcps = acps.filter((a) => a.fetched)
  const allSelected = fetchedAcps.length > 0 && fetchedAcps.every((a) => a.selected)

  if (listing) {
    return (
      <div className="flex items-center justify-center gap-2 py-8 text-[11px] text-surface-400">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading Access Control Policies…
      </div>
    )
  }
  if (listError) {
    return (
      <div className="flex items-center gap-2 py-6 px-4 text-[11px] text-accent-rose">
        <AlertCircle className="w-4 h-4" /> {listError}
      </div>
    )
  }
  if (acps.length === 0) {
    return (
      <p className="text-[11px] text-surface-400 text-center py-6">
        No Access Control Policies loaded. Connect a source FMC and list ACPs, or upload a policy YAML.
      </p>
    )
  }

  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2 text-[10px] text-surface-500">
        <input type="checkbox" checked={allSelected} onChange={(e) => selectAll(e.target.checked)}
          className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
        Select All ({acps.length})
      </label>

      <div className="overflow-hidden rounded-lg border border-surface-200 dark:border-surface-700">
        <div className="overflow-y-auto" style={{ maxHeight: 'calc(15 * 2.25rem + 2rem)' }}>
        <table className="w-full text-[11px] table-fixed">
          <colgroup>
            <col className="w-10" />
            <col className="w-10" />
            <col />
            <col className="w-24" />
            <col className="w-28" />
          </colgroup>
          <thead className="sticky top-0 z-10">
            <tr className="bg-surface-50 dark:bg-surface-800/80">
              <th className="px-3 py-1.5" />
              <th className="px-3 py-1.5" />
              <th className="px-3 py-1.5 text-left font-medium text-surface-500">Access Control Policy</th>
              <th className="px-3 py-1.5 text-left font-medium text-surface-500">Status</th>
              <th className="px-3 py-1.5 text-right font-medium text-surface-500">Action</th>
            </tr>
          </thead>
          <tbody>
            {acps.map((a) => (
              <Fragment key={a.id}>
                <tr className={cn(
                  'border-t border-surface-100 dark:border-surface-800/50 transition-colors',
                  a.selected ? 'bg-vyper-500/5' : 'hover:bg-surface-50 dark:hover:bg-surface-800/30',
                )}>
                  <td className="px-3 py-1.5">
                    <input type="checkbox" checked={a.selected} onChange={() => toggleSelected(a.id)}
                      disabled={!a.fetched && !a.fetching}
                      className={cn('rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30',
                        !a.fetched && !a.fetching && 'cursor-not-allowed')} />
                  </td>
                  <td className="px-3 py-1.5">
                    <button
                      onClick={() => toggleExpanded(a.id)}
                      disabled={!a.fetched}
                      title={a.fetched ? 'Expand/collapse' : 'Fetch this ACP to view details'}
                      className={cn('p-0.5 rounded transition-transform',
                        a.fetched ? 'text-surface-500 hover:text-surface-700' : 'text-surface-300 cursor-not-allowed',
                        a.expanded && 'rotate-90')}
                    >
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="font-medium text-surface-700 dark:text-surface-300 truncate">{a.name}</div>
                    {a.description && <div className="text-[10px] text-surface-400 truncate">{a.description}</div>}
                  </td>
                  <td className="px-3 py-1.5">
                    <StatusBadge row={a} />
                  </td>
                  <td className="px-3 py-1.5 text-right">
                    <button
                      onClick={() => fetchAcp(a.id)}
                      disabled={a.fetching}
                      className={cn(
                        'inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-medium transition-colors',
                        a.fetched
                          ? 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800'
                          : 'bg-vyper-600 hover:bg-vyper-700 text-white shadow-sm',
                        // Only reduce affordance while an active fetch is in
                        // flight (prevents duplicate requests); the label is
                        // never changed to "Fetching".
                        a.fetching && 'opacity-70 cursor-wait',
                      )}
                    >
                      {a.fetching ? <Loader2 className="w-3 h-3 animate-spin" />
                        : a.fetched ? <RefreshCw className="w-3 h-3" /> : <Download className="w-3 h-3" />}
                      {a.fetched ? 'Re-fetch' : 'Fetch'}
                    </button>
                  </td>
                </tr>
                {a.expanded && a.detail && (
                  <tr>
                    <td colSpan={5} className="p-0">
                      <AcpDetail detail={a.detail} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  )
}

function StatusBadge({ row }: { row: { fetching: boolean; fetched: boolean; error: string } }) {
  if (row.error) {
    return <span className="inline-flex items-center gap-1 text-[10px] text-accent-rose" title={row.error}>
      <AlertCircle className="w-3 h-3" /> Error
    </span>
  }
  if (row.fetching) {
    return <span className="inline-flex items-center gap-1 text-[10px] text-vyper-500">
      <Loader2 className="w-3 h-3 animate-spin" /> Fetching
    </span>
  }
  if (row.fetched) {
    return <span className="inline-flex items-center gap-1 text-[10px] text-accent-emerald">
      <CheckCircle2 className="w-3 h-3" /> Fetched
    </span>
  }
  return <span className="text-[10px] text-surface-400">Not fetched</span>
}
