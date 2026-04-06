import { useState, useEffect, useCallback } from 'react'
import { useCommandCenterStore, type ProxyPreset } from '@/stores/commandCenterStore'
import { runStream } from './useStream'
import SectionCard from './SectionCard'
import { Play, Save, List, Trash2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import Toggle from '@/components/Toggle'

export default function HttpProxySection() {
  const selectedIds = useCommandCenterStore((s) => s.selectedIds)
  const isExecuting = useCommandCenterStore((s) => s.isExecuting)

  const [address, setAddress] = useState('')
  const [port, setPort] = useState('')
  const [auth, setAuth] = useState(false)
  const [proxyUser, setProxyUser] = useState('')
  const [proxyPass, setProxyPass] = useState('')
  const [presets, setPresets] = useState<ProxyPreset[]>([])
  const [showPresets, setShowPresets] = useState(false)

  const loadPresets = useCallback(async () => {
    try {
      const res = await fetch('/api/command-center/proxy-presets', { credentials: 'include' })
      const data = await res.json()
      if (data.success) setPresets(data.presets || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { loadPresets() }, [loadPresets])

  const savePreset = async () => {
    const name = prompt('Preset name (optional):') || ''
    try {
      const res = await fetch('/api/command-center/proxy-presets/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name,
          proxy_address: address,
          proxy_port: parseInt(port, 10) || 0,
          proxy_auth: auth,
          proxy_username: proxyUser,
          proxy_password: proxyPass,
        }),
      })
      const data = await res.json()
      if (!data.success) throw new Error(data.message || 'Failed')
      await loadPresets()
    } catch (e) { alert('Save failed: ' + (e instanceof Error ? e.message : e)) }
  }

  const deletePreset = async (id: string) => {
    await fetch(`/api/command-center/proxy-presets/${id}`, { method: 'DELETE', credentials: 'include' })
    await loadPresets()
  }

  const applyPreset = (p: ProxyPreset) => {
    setAddress(p.proxy_address || '')
    setPort(String(p.proxy_port || ''))
    setAuth(!!p.proxy_auth)
    setProxyUser(p.proxy_username || '')
    setProxyPass(p.proxy_password || '')
    setShowPresets(false)
  }

  const execute = async () => {
    if (!address || !port) { alert('Enter proxy address and port'); return }
    const ids = Array.from(selectedIds)
    if (ids.length === 0) { alert('Select at least one device'); return }
    await runStream('/api/command-center/execute-http-proxy/stream', {
      proxy_address: address,
      proxy_port: parseInt(port, 10),
      proxy_auth: auth,
      proxy_username: proxyUser,
      proxy_password: proxyPass,
      device_ids: ids,
    })
  }

  return (
    <SectionCard
      title="Configure HTTP Proxy"
      badge="FTD Only"
      badgeColor="green"
      actions={
        <>
          <ActionBtn icon={<Save className="w-3.5 h-3.5" />} label="Save" onClick={savePreset} />
          <div className="relative">
            <ActionBtn icon={<List className="w-3.5 h-3.5" />} label="Presets" onClick={() => setShowPresets(!showPresets)} />
            {showPresets && (
              <div className="absolute right-0 mt-1 w-64 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-800 rounded-lg shadow-lg z-20 overflow-hidden">
                {presets.length === 0 ? (
                  <div className="px-3 py-3 text-[12px] text-surface-400">No presets</div>
                ) : (
                  presets.map((p) => (
                    <div key={p.id} className="flex items-center justify-between px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/40 border-b border-surface-100 dark:border-surface-800/40 last:border-b-0">
                      <button className="text-[12px] text-surface-700 dark:text-surface-300 hover:text-vyper-500 text-left truncate flex-1" onClick={() => applyPreset(p)}>
                        {p.name || `${p.proxy_address}:${p.proxy_port}`}
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
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <InputField label="Proxy Address" value={address} onChange={setAddress} placeholder="173.39.92.229" />
        <InputField label="Proxy Port" value={port} onChange={setPort} placeholder="80" type="number" />
        <div className="flex items-end">
          <Toggle checked={auth} onChange={setAuth} label="Authentication required" />
        </div>
      </div>
      {auth && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
          <InputField label="Proxy Username" value={proxyUser} onChange={setProxyUser} placeholder="username" />
          <InputField label="Proxy Password" value={proxyPass} onChange={setProxyPass} placeholder="password" type="password" />
        </div>
      )}
    </SectionCard>
  )
}

function InputField({ label, value, onChange, placeholder, type = 'text' }: {
  label: string; value: string; onChange: (v: string) => void; placeholder: string; type?: string
}) {
  return (
    <div>
      <label className="block text-[11px] font-medium text-surface-500 dark:text-surface-500 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50 rounded-lg px-3 py-1.5 text-[13px] text-surface-800 dark:text-surface-200 placeholder:text-surface-400 hover:border-vyper-400 dark:hover:border-vyper-500 focus:outline-none focus:ring-2 focus:ring-vyper-500/20 focus:border-vyper-500 transition-colors"
      />
    </div>
  )
}

function ActionBtn({ icon, label, onClick, primary, disabled }: {
  icon: React.ReactNode; label: string; onClick: () => void; primary?: boolean; disabled?: boolean
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
        'border disabled:opacity-50 disabled:cursor-not-allowed',
        primary
          ? 'border-accent-emerald/30 bg-accent-emerald/10 text-accent-emerald hover:bg-accent-emerald/20'
          : 'border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800'
      )}
    >
      {icon} {label}
    </button>
  )
}

export { InputField, ActionBtn }
