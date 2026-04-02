import { useState } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import type { ConnectionInfo, Preset } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, inputCls } from '@/lib/utils'
import { X, Plug, Loader2, List, Trash2, Save } from 'lucide-react'
import { loadPresets, deletePreset, savePreset } from './api'

export default function ConnectPopup({
  title,
  conn,
  setConn,
  onConnect,
  onClose,
  connecting,
}: {
  title: string
  conn: ConnectionInfo
  setConn: (c: Partial<ConnectionInfo>) => void
  onConnect: () => void
  onClose: () => void
  connecting?: boolean
}) {
  const { presets } = useVpnDebuggerStore()
  const [showPresets, setShowPresets] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveName, setSaveName] = useState('')
  const [showSaveInput, setShowSaveInput] = useState(false)

  const handleLoadPreset = (p: Preset) => {
    setConn({ ip: p.ip, port: p.port, username: p.username, password: p.password })
    setShowPresets(false)
  }

  const handleSave = async () => {
    if (!saveName.trim()) return
    setSaving(true)
    await savePreset(saveName.trim(), conn)
    setSaving(false)
    setShowSaveInput(false)
    setSaveName('')
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-[1000]" onClick={onClose} />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[1001] w-[420px] max-w-[90vw] rounded-xl border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-2xl">
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-100 dark:border-surface-800">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">{title}</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
            <X className="w-4 h-4 text-surface-400" />
          </button>
        </div>
        <div className="px-4 py-4 space-y-3">
          <div className="grid grid-cols-2 gap-2.5">
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Host</label>
              <input value={conn.ip} onChange={(e) => setConn({ ip: e.target.value })} placeholder="10.0.0.10" className={cn(inputCls, 'w-full')} />
            </div>
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">SSH Port</label>
              <input value={conn.port} onChange={(e) => setConn({ port: e.target.value })} type="number" className={cn(inputCls, 'w-full')} />
            </div>
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Username</label>
              <input value={conn.username} onChange={(e) => setConn({ username: e.target.value })} placeholder="root" className={cn(inputCls, 'w-full')} />
            </div>
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Password</label>
              <input value={conn.password} onChange={(e) => setConn({ password: e.target.value })} type="password" placeholder="password" className={cn(inputCls, 'w-full')} />
            </div>
          </div>
          {showSaveInput && (
            <div className="flex items-center gap-2">
              <input
                value={saveName}
                onChange={(e) => setSaveName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && saveName.trim() && handleSave()}
                placeholder="Connection name..."
                className={cn(inputCls, 'flex-1')}
                autoFocus
              />
              <button onClick={handleSave} disabled={saving || !saveName.trim()} className={btnCls('success')}>
                {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
              </button>
              <button onClick={() => setShowSaveInput(false)} className={btnCls()}>
                Cancel
              </button>
            </div>
          )}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <div className="relative">
                <button onClick={() => { setShowPresets(!showPresets); if (!showPresets) loadPresets() }} className={btnCls()}>
                  <List className="w-3.5 h-3.5" /> Saved Connections
                </button>
                {showPresets && (
                  <>
                    <div className="fixed inset-0 z-10" onClick={() => setShowPresets(false)} />
                    <div className="absolute left-0 bottom-full mb-1.5 w-72 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 max-h-48 overflow-auto py-1">
                      {presets.length === 0 ? (
                        <div className="p-3 text-xs text-surface-400 text-center italic">No saved connections</div>
                      ) : presets.map((p) => (
                        <div key={p.id} className="flex items-center justify-between px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/70 cursor-pointer group transition-colors" onClick={() => handleLoadPreset(p)}>
                          <div className="min-w-0">
                            <div className="text-xs font-medium text-surface-700 dark:text-surface-300 truncate">{p.name}</div>
                            <div className="text-[10px] text-surface-400 font-mono truncate">{p.ip}:{p.port}</div>
                          </div>
                          <button onClick={(e) => { e.stopPropagation(); deletePreset(p.id) }} className="p-1 rounded opacity-0 group-hover:opacity-100 text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all">
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
              <button onClick={() => { setShowSaveInput(true); setSaveName(conn.ip ? `${conn.ip}:${conn.port}` : '') }} disabled={!conn.ip} className={btnCls('success')}>
                <Save className="w-3.5 h-3.5" /> Save
              </button>
            </div>
            <button onClick={onConnect} disabled={connecting || !conn.ip} className={btnCls('primary')}>
              {connecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plug className="w-3.5 h-3.5" />}
              Connect
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
