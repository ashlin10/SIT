import { useEffect, useRef } from 'react'
import { useCommandCenterStore } from '@/stores/commandCenterStore'
import { cn } from '@/lib/utils'
import DeviceTable from './command-center/DeviceTable'
import ExecLog from './command-center/ExecLog'
import HttpProxySection from './command-center/HttpProxySection'
import StaticRoutesSection from './command-center/StaticRoutesSection'
import CopyDevCertSection from './command-center/CopyDevCertSection'
import RestoreBackupSection from './command-center/RestoreBackupSection'
import DownloadUpgradeSection from './command-center/DownloadUpgradeSection'
import { Upload, Trash2, Download, ChevronDown, ChevronUp } from 'lucide-react'

export default function CommandCenterPage() {
  const {
    setDevices,
    selectedIds,
    devicesCollapsed,
    setDevicesCollapsed,
    ftdDevices,
    fmcDevices,
  } = useCommandCenterStore()

  const fileRef = useRef<HTMLInputElement>(null)

  // Load devices on mount
  useEffect(() => {
    loadDevices()
  }, [])

  const loadDevices = async () => {
    try {
      const res = await fetch('/api/command-center/devices', { credentials: 'include' })
      const data = await res.json()
      if (data.success) {
        setDevices(data.ftd || [], data.fmc || [])
      }
    } catch { /* ignore */ }
  }

  const uploadDevices = async (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await fetch('/api/command-center/upload-devices', { method: 'POST', body: fd, credentials: 'include' })
      const data = await res.json()
      if (!data.success) throw new Error(data.message || 'Upload failed')
      setDevices(data.ftd || [], data.fmc || [])
    } catch (err) {
      alert('Upload error: ' + (err instanceof Error ? err.message : err))
    }
  }

  const deleteDevices = async () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) { alert('Select devices to delete'); return }
    if (!confirm(`Delete ${ids.length} device(s)?`)) return
    try {
      const res = await fetch('/api/command-center/delete-devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ device_ids: ids }),
      })
      const data = await res.json()
      if (!data.success) throw new Error(data.message || 'Delete failed')
      setDevices(data.ftd || [], data.fmc || [])
    } catch (err) {
      alert('Delete error: ' + (err instanceof Error ? err.message : err))
    }
  }

  const selectedCount = [...ftdDevices, ...fmcDevices].filter((d) => selectedIds.has(d.id)).length

  return (
    <div className="space-y-5 animate-in fade-in duration-300">
      <div>
        <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">
          Command Center
        </h1>
        <p className="text-[13px] text-surface-500 mt-0.5">
          Manage devices and execute operations across your fleet
        </p>
      </div>

      {/* ── Select Devices ── */}
      <div className={cn(
        'rounded-xl border border-surface-200 dark:border-surface-800/60',
        'bg-white dark:bg-surface-900/50 overflow-hidden'
      )}>
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Select Devices</h2>
            {selectedCount > 0 && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full bg-vyper-500/10 text-vyper-500">
                {selectedCount} selected
              </span>
            )}
            <button
              onClick={() => setDevicesCollapsed(!devicesCollapsed)}
              className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors"
            >
              {devicesCollapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <a
              href="/api/command-center/sample-devices?format=csv"
              download
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> CSV
            </a>
            <a
              href="/api/command-center/sample-devices?format=txt"
              download
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> TXT
            </a>
            <button
              onClick={() => fileRef.current?.click()}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border border-accent-emerald/30 bg-accent-emerald/5 text-accent-emerald hover:bg-accent-emerald/10 transition-colors"
            >
              <Upload className="w-3.5 h-3.5" /> Upload
            </button>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,.txt"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) uploadDevices(f)
                e.target.value = ''
              }}
            />
            <button
              onClick={deleteDevices}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border border-accent-rose/30 text-accent-rose/70 hover:bg-accent-rose/10 hover:text-accent-rose transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" /> Delete
            </button>
          </div>
        </div>

        {!devicesCollapsed && (
          <div className="px-5 py-4">
            <p className="text-[11px] text-surface-400 mb-3">
              Upload a CSV/TXT with columns: type, name, ip_address, username, password, port (optional). Types: FTD or FMC.
            </p>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <DeviceTable type="ftd" label="FTD" />
              <DeviceTable type="fmc" label="FMC" />
            </div>
          </div>
        )}
      </div>

      {/* ── Execution Log (always visible when populated) ── */}
      <ExecLog />

      {/* ── Operation Sections ── */}
      <HttpProxySection />
      <StaticRoutesSection />
      <CopyDevCertSection />
      <RestoreBackupSection />
      <DownloadUpgradeSection />
    </div>
  )
}
