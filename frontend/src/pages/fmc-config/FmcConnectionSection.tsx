import { useState, useRef, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { connectToFmc, loadPresets, savePreset, deletePreset } from './api'
import { Plug, Save, List, Trash2, Loader2 } from 'lucide-react'

export default function FmcConnectionSection() {
  const {
    fmcIp, fmcPort, fmcUsername, fmcPassword,
    connected, connecting,
    domains, domainUuid,
    presets,
    setConnection, setDomainUuid,
  } = useFmcConfigStore()

  const [presetsOpen, setPresetsOpen] = useState(false)
  const [notification, setNotification] = useState<{ msg: string; type: 'success' | 'error' | 'info' } | null>(null)
  const presetsRef = useRef<HTMLDivElement>(null)

  useEffect(() => { loadPresets() }, [])

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (presetsRef.current && !presetsRef.current.contains(e.target as Node)) setPresetsOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    if (notification) {
      const t = setTimeout(() => setNotification(null), 4000)
      return () => clearTimeout(t)
    }
  }, [notification])

  const handleConnect = async () => {
    if (!fmcIp.trim() || !fmcUsername.trim() || !fmcPassword) {
      setNotification({ msg: 'Enter FMC IP, username and password', type: 'error' })
      return
    }
    const result = await connectToFmc()
    if (result.success) {
      setNotification({ msg: 'Connected to FMC successfully', type: 'success' })
    } else {
      setNotification({ msg: result.message || 'Connection failed', type: 'error' })
    }
  }

  const handleSavePreset = async () => {
    const name = prompt('Preset name:')
    if (!name) return
    const result = await savePreset(name)
    if (result.success) setNotification({ msg: 'Preset saved', type: 'success' })
    else setNotification({ msg: result.message || 'Save failed', type: 'error' })
  }

  const handleLoadPreset = (p: typeof presets[0]) => {
    setConnection({
      fmcIp: p.fmc_ip,
      fmcPort: String(p.fmc_port || 443),
      fmcUsername: p.username,
      fmcPassword: p.password,
    })
    setPresetsOpen(false)
    setNotification({ msg: `Loaded preset "${p.name}"`, type: 'info' })
  }

  const inputCls = cn(
    'w-full rounded-lg border px-3 py-2 text-sm',
    'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50',
    'text-surface-800 dark:text-surface-200 placeholder:text-surface-400',
    'focus:outline-none focus:ring-2 focus:ring-vyper-500/30 focus:border-vyper-500',
    'transition-colors'
  )

  const btnCls = (variant: 'primary' | 'secondary' | 'ghost' = 'secondary') =>
    cn(
      'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
      variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
      variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
      variant === 'ghost' && 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300',
    )

  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      {/* Notification */}
      {notification && (
        <div className={cn(
          'px-4 py-2 text-xs font-medium border-b',
          notification.type === 'success' && 'bg-accent-emerald/10 text-accent-emerald border-accent-emerald/20',
          notification.type === 'error' && 'bg-accent-rose/10 text-accent-rose border-accent-rose/20',
          notification.type === 'info' && 'bg-vyper-500/10 text-vyper-500 border-vyper-500/20',
        )}>
          {notification.msg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">FMC Connection</h2>
        <div className="flex items-center gap-2">
          <button onClick={handleSavePreset} className={btnCls()}>
            <Save className="w-3.5 h-3.5" /> Save
          </button>
          <div className="relative" ref={presetsRef}>
            <button onClick={() => setPresetsOpen(!presetsOpen)} className={btnCls()}>
              <List className="w-3.5 h-3.5" /> Saved Configs
            </button>
            {presetsOpen && presets.length > 0 && (
              <div className="absolute right-0 mt-1.5 w-80 rounded-xl border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 max-h-64 overflow-auto py-1">
                {presets.map((p) => (
                  <div key={p.id} className="flex items-center justify-between px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/70 transition-colors">
                    <button
                      onClick={() => handleLoadPreset(p)}
                      className="text-left flex-1 min-w-0"
                    >
                      <div className="text-xs font-medium text-surface-700 dark:text-surface-300 truncate">{p.name}</div>
                      <div className="text-[10px] text-surface-400 truncate font-mono">{p.fmc_ip}:{p.fmc_port} — {p.username}</div>
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); deletePreset(p.id) }}
                      className="ml-2 p-1 text-accent-rose/60 hover:text-accent-rose transition-colors"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
            {presetsOpen && presets.length === 0 && (
              <div className="absolute right-0 mt-1.5 w-48 rounded-xl border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 p-3">
                <p className="text-[11px] text-surface-400 italic">No saved configs</p>
              </div>
            )}
          </div>
          <button
            onClick={handleConnect}
            disabled={connecting}
            className={cn(btnCls('primary'), connecting && 'opacity-60 pointer-events-none')}
          >
            {connecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plug className="w-3.5 h-3.5" />}
            {connecting ? 'Connecting…' : 'Connect'}
          </button>
        </div>
      </div>

      {/* Form */}
      <div className="px-5 py-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-[11px] font-medium text-surface-500 dark:text-surface-400 mb-1">FMC IP / Hostname</label>
            <input
              type="text"
              value={fmcIp}
              onChange={(e) => setConnection({ fmcIp: e.target.value })}
              placeholder="e.g. 10.0.0.10 or fmc.example.com"
              className={inputCls}
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-surface-500 dark:text-surface-400 mb-1">Port</label>
            <input
              type="number"
              value={fmcPort}
              onChange={(e) => setConnection({ fmcPort: e.target.value })}
              placeholder="443"
              className={inputCls}
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-surface-500 dark:text-surface-400 mb-1">Username</label>
            <input
              type="text"
              value={fmcUsername}
              onChange={(e) => setConnection({ fmcUsername: e.target.value })}
              placeholder="admin"
              className={inputCls}
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-surface-500 dark:text-surface-400 mb-1">Password</label>
            <input
              type="password"
              value={fmcPassword}
              onChange={(e) => setConnection({ fmcPassword: e.target.value })}
              placeholder="password"
              className={inputCls}
            />
          </div>
        </div>
        <p className="text-[10px] text-surface-400 mt-2">
          If protocol is not specified, HTTPS will be used by default. Example: https://&lt;ip&gt;:&lt;port&gt;
        </p>

        {/* Domain selector */}
        {connected && domains.length > 0 && (
          <div className="mt-4 max-w-sm">
            <label className="block text-[11px] font-medium text-surface-500 dark:text-surface-400 mb-1">Domain</label>
            <select
              value={domainUuid}
              onChange={(e) => setDomainUuid(e.target.value)}
              className={inputCls}
            >
              {domains.map((d) => (
                <option key={d.uuid} value={d.uuid}>{d.name}</option>
              ))}
            </select>
            <p className="text-[10px] text-surface-400 mt-1">Defaults to Global if available.</p>
          </div>
        )}

        {/* Connection status */}
        {connected && (
          <div className="mt-3 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-accent-emerald animate-pulse" />
            <span className="text-[11px] font-medium text-accent-emerald">Connected</span>
          </div>
        )}
      </div>
    </div>
  )
}
