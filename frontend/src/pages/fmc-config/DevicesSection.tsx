import { useState } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { refreshDevices, deleteDevicesFromFmc } from './api'
import { ChevronDown, ChevronUp, RefreshCw, Trash2, Shield } from 'lucide-react'

export default function DevicesSection({ onCreateHa }: { onCreateHa?: () => void }) {
  const {
    devices, selectedDeviceIds, devicesCollapsed, connected,
    toggleDevice, selectAllDevices, setDevicesCollapsed,
  } = useFmcConfigStore()

  const [refreshing, setRefreshing] = useState(false)

  const handleRefresh = async () => {
    setRefreshing(true)
    await refreshDevices()
    setRefreshing(false)
  }

  const handleDelete = async () => {
    const ids = Array.from(selectedDeviceIds)
    if (ids.length === 0) return
    if (!confirm(`Delete ${ids.length} device(s) from FMC?`)) return
    await deleteDevicesFromFmc(ids)
    await refreshDevices()
  }

  // Sort devices alphanumerically by name
  const sortedDevices = [...devices].sort((a, b) =>
    a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' })
  )

  const allSelected = devices.length > 0 && selectedDeviceIds.size === devices.length

  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Available Devices</h2>
          <button
            onClick={() => setDevicesCollapsed(!devicesCollapsed)}
            className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors"
          >
            {devicesCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
          {selectedDeviceIds.size > 0 && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-vyper-500/10 text-vyper-500">
              {selectedDeviceIds.size} selected
            </span>
          )}
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-surface-100 dark:bg-surface-800 text-surface-500">
            {devices.length} total
          </span>
        </div>

        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-[11px] text-surface-600 dark:text-surface-400 cursor-pointer">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={(e) => selectAllDevices(e.target.checked)}
              className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
            />
            Select All
          </label>
          <button
            onClick={handleRefresh}
            disabled={!connected || refreshing}
            className={cn(
              'flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
              'border border-accent-emerald/30 bg-accent-emerald/5 text-accent-emerald hover:bg-accent-emerald/10',
              (!connected || refreshing) && 'opacity-40 pointer-events-none'
            )}
          >
            <RefreshCw className={cn('w-3.5 h-3.5', refreshing && 'animate-spin')} /> Refresh
          </button>
          <button
            onClick={() => onCreateHa?.()}
            disabled={selectedDeviceIds.size < 2}
            className={cn(
              'flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
              'border border-accent-violet/30 bg-accent-violet/5 text-accent-violet hover:bg-accent-violet/10',
              selectedDeviceIds.size < 2 && 'opacity-40 pointer-events-none'
            )}
          >
            <Shield className="w-3.5 h-3.5" /> Create HA
          </button>
          <button
            onClick={handleDelete}
            disabled={selectedDeviceIds.size === 0}
            className={cn(
              'flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
              'border border-accent-rose/30 text-accent-rose/70 hover:bg-accent-rose/10 hover:text-accent-rose',
              selectedDeviceIds.size === 0 && 'opacity-40 pointer-events-none'
            )}
          >
            <Trash2 className="w-3.5 h-3.5" /> Delete FTD
          </button>
        </div>
      </div>

      {/* Table */}
      {!devicesCollapsed && (
        <div className="px-5 py-4">
          {devices.length === 0 ? (
            <p className="text-[11px] text-surface-400 text-center py-4">
              Click Connect to fetch devices from FMC and list them here.
            </p>
          ) : (
            <div className="overflow-auto max-h-96 rounded-lg border border-surface-200 dark:border-surface-700">
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 z-10">
                  <tr className="bg-surface-50 dark:bg-surface-800/80">
                    <th className="px-3 py-2 text-left font-medium text-surface-500 w-10"></th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Status</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Name</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Hostname</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Type</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Version</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Mode</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500 font-mono">UUID</th>
                    <th className="px-3 py-2 text-left font-medium text-surface-500">Model</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedDevices.map((d) => {
                    const selected = selectedDeviceIds.has(d.id)
                    return (
                      <tr
                        key={d.id}
                        onClick={() => toggleDevice(d.id)}
                        className={cn(
                          'border-b border-surface-100 dark:border-surface-800/50 last:border-b-0 cursor-pointer transition-colors',
                          selected ? 'bg-vyper-500/5' : 'hover:bg-surface-50 dark:hover:bg-surface-800/30'
                        )}
                      >
                        <td className="px-3 py-2">
                          <input
                            type="checkbox"
                            checked={selected}
                            onChange={() => toggleDevice(d.id)}
                            onClick={(e) => e.stopPropagation()}
                            className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
                          />
                        </td>
                        <td className="px-3 py-2">
                          <StatusDot connected={d.isConnected} />
                        </td>
                        <td className="px-3 py-2 font-medium text-surface-700 dark:text-surface-300">{d.name}</td>
                        <td className="px-3 py-2 text-surface-500 font-mono">{d.hostname}</td>
                        <td className="px-3 py-2 text-surface-500">{d.type}</td>
                        <td className="px-3 py-2 text-surface-500 font-mono">{d.sw_version}</td>
                        <td className="px-3 py-2 text-surface-500">{d.ftdMode}</td>
                        <td className="px-3 py-2 text-surface-400 font-mono text-[10px]">{d.id}</td>
                        <td className="px-3 py-2 text-surface-500 whitespace-nowrap">{d.model}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatusDot({ connected }: { connected: boolean }) {
  return (
    <span
      className={cn('inline-block w-2 h-2 rounded-full', connected ? 'bg-accent-emerald' : 'bg-accent-rose')}
      title={connected ? 'Connected' : 'Disconnected'}
    />
  )
}
