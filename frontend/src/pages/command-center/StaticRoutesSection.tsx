import { useState, useEffect, useCallback } from 'react'
import { useCommandCenterStore, type StaticRoute, type StaticPreset } from '@/stores/commandCenterStore'
import { runStream } from './useStream'
import SectionCard from './SectionCard'
import { InputField, ActionBtn } from './HttpProxySection'
import { Play, Save, List, Trash2, Plus, X } from 'lucide-react'
import CustomSelect from '@/components/CustomSelect'

const EMPTY_ROUTE: StaticRoute = { ip_version: 'ipv4', interface: 'management0', ip_address: '', netmask_or_prefix: '', gateway: '' }

export default function StaticRoutesSection() {
  const selectedIds = useCommandCenterStore((s) => s.selectedIds)
  const isExecuting = useCommandCenterStore((s) => s.isExecuting)

  const [routes, setRoutes] = useState<StaticRoute[]>([{ ...EMPTY_ROUTE }])
  const [presets, setPresets] = useState<StaticPreset[]>([])
  const [showPresets, setShowPresets] = useState(false)

  const loadPresets = useCallback(async () => {
    try {
      const res = await fetch('/api/command-center/static-presets', { credentials: 'include' })
      const data = await res.json()
      if (data.success) setPresets(data.presets || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { loadPresets() }, [loadPresets])

  const updateRoute = (idx: number, field: keyof StaticRoute, value: string) => {
    setRoutes((prev) => prev.map((r, i) => (i === idx ? { ...r, [field]: value } : r)))
  }

  const removeRoute = (idx: number) => {
    setRoutes((prev) => prev.filter((_, i) => i !== idx))
  }

  const addRoute = () => {
    setRoutes((prev) => [...prev, { ...EMPTY_ROUTE }])
  }

  const collectValid = (): StaticRoute[] =>
    routes.filter((r) => r.ip_address && r.netmask_or_prefix && r.gateway)

  const savePreset = async () => {
    const valid = collectValid()
    if (valid.length === 0) { alert('Add at least one static route to save'); return }
    const name = prompt('Preset name (optional):') || ''
    try {
      const res = await fetch('/api/command-center/static-presets/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name, routes: valid }),
      })
      const data = await res.json()
      if (!data.success) throw new Error(data.message || 'Failed')
      await loadPresets()
    } catch (e) { alert('Save failed: ' + (e instanceof Error ? e.message : e)) }
  }

  const deletePreset = async (id: string) => {
    await fetch(`/api/command-center/static-presets/${id}`, { method: 'DELETE', credentials: 'include' })
    await loadPresets()
  }

  const applyPreset = (p: StaticPreset) => {
    setRoutes((p.routes || []).map((r) => ({ ...EMPTY_ROUTE, ...r })))
    setShowPresets(false)
  }

  const execute = async () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) { alert('Select at least one device'); return }
    const valid = collectValid()
    if (valid.length === 0) { alert('Add at least one static route'); return }
    await runStream('/api/command-center/execute-static-routes/stream', { device_ids: ids, routes: valid })
  }

  return (
    <SectionCard
      title="Configure Static Routes"
      badge="FTD Only"
      badgeColor="green"
      actions={
        <>
          <ActionBtn icon={<Save className="w-3.5 h-3.5" />} label="Save" onClick={savePreset} />
          <div className="relative">
            <ActionBtn icon={<List className="w-3.5 h-3.5" />} label="Presets" onClick={() => setShowPresets(!showPresets)} />
            {showPresets && (
              <div className="absolute right-0 mt-1 w-72 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-800 rounded-lg shadow-lg z-20 overflow-hidden">
                {presets.length === 0 ? (
                  <div className="px-3 py-3 text-[12px] text-surface-400">No presets</div>
                ) : (
                  presets.map((p) => (
                    <div key={p.id} className="flex items-center justify-between px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/40 border-b border-surface-100 dark:border-surface-800/40 last:border-b-0">
                      <button className="text-[12px] text-surface-700 dark:text-surface-300 hover:text-vyper-500 text-left truncate flex-1" onClick={() => applyPreset(p)}>
                        {p.name || 'Preset'}
                      </button>
                      <button onClick={() => deletePreset(p.id)} className="text-accent-rose/60 hover:text-accent-rose ml-2 shrink-0">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
          <ActionBtn icon={<Play className="w-3.5 h-3.5" />} label="Execute" onClick={execute} primary disabled={isExecuting} />
        </>
      }
    >
      <p className="text-[12px] text-surface-500 mb-3">Add one or more static routes to push to selected FTD devices.</p>
      <div className="space-y-2">
        {routes.map((r, idx) => (
          <div key={idx} className="grid grid-cols-2 md:grid-cols-6 gap-2 items-end p-2.5 rounded-lg border border-surface-100 dark:border-surface-800/40 bg-surface-50/50 dark:bg-surface-800/20">
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">IP Version</label>
              <CustomSelect
                value={r.ip_version}
                onChange={(v) => updateRoute(idx, 'ip_version', v)}
                options={[
                  { value: 'ipv4', label: 'ipv4' },
                  { value: 'ipv6', label: 'ipv6' },
                ]}
              />
            </div>
            <InputField label="Interface" value={r.interface} onChange={(v) => updateRoute(idx, 'interface', v)} placeholder="management0" />
            <InputField label="IP Address" value={r.ip_address} onChange={(v) => updateRoute(idx, 'ip_address', v)} placeholder="10.0.0.0" />
            <InputField label="Netmask/Prefix" value={r.netmask_or_prefix} onChange={(v) => updateRoute(idx, 'netmask_or_prefix', v)} placeholder="255.255.255.0" />
            <InputField label="Gateway" value={r.gateway} onChange={(v) => updateRoute(idx, 'gateway', v)} placeholder="192.168.2.1" />
            <div className="flex items-end pb-0.5">
              <button
                onClick={() => removeRoute(idx)}
                className="p-1.5 rounded-lg text-accent-rose/60 hover:text-accent-rose hover:bg-accent-rose/10 transition-colors"
                title="Remove route"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>
      <button
        onClick={addRoute}
        className="mt-2 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium border border-accent-emerald/30 bg-accent-emerald/5 text-accent-emerald hover:bg-accent-emerald/10 transition-colors"
      >
        <Plus className="w-3.5 h-3.5" /> Add Route
      </button>
    </SectionCard>
  )
}
