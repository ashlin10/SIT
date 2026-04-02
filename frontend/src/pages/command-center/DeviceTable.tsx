import { cn } from '@/lib/utils'
import { useCommandCenterStore, type Device } from '@/stores/commandCenterStore'

interface Props {
  type: 'ftd' | 'fmc'
  label: string
}

export default function DeviceTable({ type, label }: Props) {
  const devices = useCommandCenterStore((s) => (type === 'ftd' ? s.ftdDevices : s.fmcDevices))
  const selectedIds = useCommandCenterStore((s) => s.selectedIds)
  const toggleDevice = useCommandCenterStore((s) => s.toggleDevice)
  const selectAll = useCommandCenterStore((s) => s.selectAll)

  const selectedCount = devices.filter((d) => selectedIds.has(d.id)).length
  const allSelected = devices.length > 0 && selectedCount === devices.length

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">{label}</h3>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">
            {devices.length}
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent-emerald/10 text-accent-emerald">
            {selectedCount} sel
          </span>
        </div>
        <label className="flex items-center gap-1.5 text-[11px] text-surface-500 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={allSelected}
            onChange={(e) => selectAll(type, e.target.checked)}
            className="rounded border-surface-300 dark:border-surface-600 text-vyper-500 focus:ring-vyper-500/30 w-3.5 h-3.5"
          />
          All
        </label>
      </div>

      <div className="border border-surface-200 dark:border-surface-800/60 rounded-lg overflow-hidden">
        <div className="max-h-[360px] overflow-y-auto">
          <table className="w-full text-[12px]">
            <thead className="sticky top-0 bg-surface-50 dark:bg-surface-900/80 border-b border-surface-200 dark:border-surface-800/60">
              <tr>
                <th className="w-8 px-2 py-2"></th>
                <th className="px-2 py-2 text-left font-medium text-surface-500">Name</th>
                <th className="px-2 py-2 text-left font-medium text-surface-500">SSH IP</th>
                <th className="px-2 py-2 text-left font-medium text-surface-500">Port</th>
                <th className="px-2 py-2 text-left font-medium text-surface-500">User</th>
                <th className="px-2 py-2 text-left font-medium text-surface-500">Pass</th>
              </tr>
            </thead>
            <tbody>
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-surface-400 dark:text-surface-600">
                    No {label} devices uploaded
                  </td>
                </tr>
              ) : (
                devices.map((d: Device) => {
                  const checked = selectedIds.has(d.id)
                  return (
                    <tr
                      key={d.id}
                      className={cn(
                        'border-b border-surface-100 dark:border-surface-800/40 transition-colors',
                        checked
                          ? 'bg-vyper-500/5 dark:bg-vyper-500/10'
                          : 'hover:bg-surface-50 dark:hover:bg-surface-800/30'
                      )}
                    >
                      <td className="px-2 py-1.5 text-center">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleDevice(d.id)}
                          className="rounded border-surface-300 dark:border-surface-600 text-vyper-500 focus:ring-vyper-500/30 w-3.5 h-3.5"
                        />
                      </td>
                      <td className="px-2 py-1.5 text-surface-800 dark:text-surface-200 font-medium">{d.name || '—'}</td>
                      <td className="px-2 py-1.5 text-surface-600 dark:text-surface-400 font-mono">{d.ip_address || '—'}</td>
                      <td className="px-2 py-1.5 text-surface-600 dark:text-surface-400 font-mono">{d.port_spec || d.port || '—'}</td>
                      <td className="px-2 py-1.5 text-surface-600 dark:text-surface-400">{d.username || '—'}</td>
                      <td className="px-2 py-1.5 text-surface-600 dark:text-surface-400">{'•'.repeat(Math.min((d.password || '').length, 8))}</td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
