import { useState, useRef, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { usePolicyConfigStore, type FmcMeta } from '@/stores/policyConfigStore'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { loadPresets } from '../fmc-config/api'
import { connectSource, listAcps, saveSourcePreset } from './api'
import { Plug, List, Loader2, Server, CheckCircle2, XCircle, Plus, Save, X } from 'lucide-react'

export default function SourceConnectionPanel() {
  const {
    srcIp, srcPort, srcUsername, srcPassword,
    connecting, sourceConnected, sourceMeta, targetMeta,
    setSrc,
  } = usePolicyConfigStore()
  const presets = useFmcConfigStore((s) => s.presets)

  const [presetsOpen, setPresetsOpen] = useState(false)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [note, setNote] = useState<{ msg: string; type: 'success' | 'error' | 'info' } | null>(null)
  const presetsRef = useRef<HTMLDivElement>(null)

  // Manual-entry dialog form state
  const [dlgName, setDlgName] = useState('')
  const [dlgIp, setDlgIp] = useState('')
  const [dlgPort, setDlgPort] = useState('443')
  const [dlgUser, setDlgUser] = useState('')
  const [dlgPass, setDlgPass] = useState('')
  const [dlgError, setDlgError] = useState('')
  const [dlgSaving, setDlgSaving] = useState(false)

  useEffect(() => { loadPresets() }, [])
  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (presetsRef.current && !presetsRef.current.contains(e.target as Node)) setPresetsOpen(false)
    }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])
  useEffect(() => {
    if (note) { const t = setTimeout(() => setNote(null), 5000); return () => clearTimeout(t) }
  }, [note])

  const handleConnect = async () => {
    if (!srcIp.trim() || !srcUsername.trim() || !srcPassword) {
      setNote({ msg: 'Enter source FMC host, username and password', type: 'error' }); return
    }
    const r = await connectSource()
    if (r.success) {
      setNote({ msg: r.warning || 'Connected to source FMC', type: r.warning ? 'info' : 'success' })
      // Automatically list ACPs after a successful connection.
      listAcps().catch(() => { /* surfaced via listError */ })
    } else {
      setNote({ msg: r.message || 'Connection failed', type: 'error' })
    }
  }

  const openDialog = () => {
    setDlgName(''); setDlgIp(''); setDlgPort('443'); setDlgUser(''); setDlgPass(''); setDlgError('')
    setDialogOpen(true)
  }

  const validateDialog = (): string => {
    if (!dlgIp.trim()) return 'FMC host is required'
    if (!dlgUser.trim()) return 'Username is required'
    if (!dlgPass) return 'Password is required'
    const port = parseInt(dlgPort)
    if (dlgPort && (isNaN(port) || port < 1 || port > 65535)) return 'Port must be 1–65535'
    return ''
  }

  const handleDialogUse = () => {
    const err = validateDialog()
    if (err) { setDlgError(err); return }
    setSrc({ srcIp: dlgIp.trim(), srcPort: dlgPort || '443', srcUsername: dlgUser.trim(), srcPassword: dlgPass })
    setDialogOpen(false)
    setNote({ msg: 'Connection details applied', type: 'info' })
  }

  const handleDialogSave = async () => {
    const err = validateDialog()
    if (err) { setDlgError(err); return }
    const name = dlgName.trim()
    if (!name) { setDlgError('Enter a preset name to save'); return }
    if (presets.some((p) => p.name.toLowerCase() === name.toLowerCase())) {
      setDlgError(`Preset "${name}" already exists`); return
    }
    setDlgSaving(true)
    const r = await saveSourcePreset(name, dlgIp, dlgPort || '443', dlgUser, dlgPass)
    setDlgSaving(false)
    if (!r.success) { setDlgError(r.message || 'Save failed'); return }
    setSrc({ srcIp: dlgIp.trim(), srcPort: dlgPort || '443', srcUsername: dlgUser.trim(), srcPassword: dlgPass })
    setDialogOpen(false)
    setNote({ msg: `Preset "${name}" saved and applied`, type: 'success' })
  }

  const inputCls = cn(
    'w-full rounded-lg border px-3 py-2 text-sm',
    'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50',
    'text-surface-800 dark:text-surface-200 placeholder:text-surface-400',
    'focus:outline-none focus:ring-2 focus:ring-vyper-500/20 focus:border-vyper-500 transition-colors',
  )
  const btnCls = (variant: 'primary' | 'secondary' = 'secondary') => cn(
    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
    variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
    variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
  )

  return (
    <div className="rounded-xl border border-surface-200 dark:border-surface-800/60 bg-white dark:bg-surface-900/50">
      {note && (
        <div className={cn(
          'px-4 py-2 text-xs font-medium border-b',
          note.type === 'success' && 'bg-accent-emerald/10 text-accent-emerald border-accent-emerald/20',
          note.type === 'error' && 'bg-accent-rose/10 text-accent-rose border-accent-rose/20',
          note.type === 'info' && 'bg-vyper-500/10 text-vyper-500 border-vyper-500/20',
        )}>{note.msg}</div>
      )}

      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Source FMC Connection</h2>
        <div className="flex items-center gap-2">
          <button onClick={openDialog} className={btnCls()}>
            <Plus className="w-3.5 h-3.5" /> New Connection
          </button>
          <div className="relative" ref={presetsRef}>
            <button onClick={() => setPresetsOpen(!presetsOpen)} className={btnCls()}>
              <List className="w-3.5 h-3.5" /> Presets
            </button>
            {presetsOpen && (
              <div className="absolute right-0 mt-1.5 w-80 rounded-xl border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-xl z-20 max-h-64 overflow-auto py-1">
                {presets.length === 0 && <p className="px-3 py-2 text-[11px] text-surface-400 italic">No presets</p>}
                {presets.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => {
                      setSrc({ srcIp: p.fmc_ip, srcPort: String(p.fmc_port || 443), srcUsername: p.username, srcPassword: p.password })
                      setPresetsOpen(false)
                      setNote({ msg: `Loaded preset "${p.name}"`, type: 'info' })
                    }}
                    className="block w-full text-left px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/70"
                  >
                    <div className="text-xs font-medium text-surface-700 dark:text-surface-300 truncate">{p.name}</div>
                    <div className="text-[10px] text-surface-400 truncate font-mono">{p.fmc_ip}:{p.fmc_port} — {p.username}</div>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={handleConnect} disabled={connecting} className={cn(btnCls('primary'), connecting && 'opacity-60 pointer-events-none')}>
            {connecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plug className="w-3.5 h-3.5" />}
            {connecting ? 'Connecting…' : 'Connect Source'}
          </button>
        </div>
      </div>

      {/* Manual entry dialog */}
      {dialogOpen && (
        <div className="px-5 py-4 border-b border-surface-100 dark:border-surface-800/50 bg-surface-50/50 dark:bg-surface-800/20">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-surface-700 dark:text-surface-300">New Source FMC Connection</h3>
            <button onClick={() => setDialogOpen(false)} className="p-1 text-surface-400 hover:text-surface-600 transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          {dlgError && (
            <div className="mb-3 px-3 py-1.5 text-[10px] font-medium text-accent-rose bg-accent-rose/10 border border-accent-rose/20 rounded-lg">{dlgError}</div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-surface-500 mb-1">Preset Name (optional)</label>
              <input type="text" value={dlgName} onChange={(e) => { setDlgName(e.target.value); setDlgError('') }} placeholder="My Source FMC" className={inputCls} />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-surface-500 mb-1">FMC IP / Hostname *</label>
              <input type="text" value={dlgIp} onChange={(e) => { setDlgIp(e.target.value); setDlgError('') }} placeholder="10.0.0.20" className={inputCls} />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-surface-500 mb-1">Port</label>
              <input type="number" value={dlgPort} onChange={(e) => { setDlgPort(e.target.value); setDlgError('') }} placeholder="443" className={inputCls} />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-surface-500 mb-1">Username *</label>
              <input type="text" value={dlgUser} onChange={(e) => { setDlgUser(e.target.value); setDlgError('') }} placeholder="admin" className={inputCls} />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-surface-500 mb-1">Password *</label>
              <input type="password" value={dlgPass} onChange={(e) => { setDlgPass(e.target.value); setDlgError('') }} placeholder="password" className={inputCls} />
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <button onClick={handleDialogUse} className={btnCls('primary')}>
              <Plug className="w-3.5 h-3.5" /> Use
            </button>
            <button onClick={handleDialogSave} disabled={dlgSaving} className={cn(btnCls(), dlgSaving && 'opacity-50 pointer-events-none')}>
              {dlgSaving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
              Save & Use
            </button>
            <button onClick={() => setDialogOpen(false)} className={btnCls()}>Cancel</button>
          </div>
        </div>
      )}

      <div className="px-5 py-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-[11px] font-medium text-surface-500 mb-1">Source FMC IP / Hostname</label>
            <input type="text" value={srcIp} onChange={(e) => setSrc({ srcIp: e.target.value })} placeholder="10.0.0.20 or src-fmc.example.com" className={inputCls} />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-surface-500 mb-1">Port</label>
            <input type="number" value={srcPort} onChange={(e) => setSrc({ srcPort: e.target.value })} placeholder="443" className={inputCls} />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-surface-500 mb-1">Username</label>
            <input type="text" value={srcUsername} onChange={(e) => setSrc({ srcUsername: e.target.value })} placeholder="admin" className={inputCls} />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-surface-500 mb-1">Password</label>
            <input type="password" value={srcPassword} onChange={(e) => setSrc({ srcPassword: e.target.value })} placeholder="password" className={inputCls} />
          </div>
        </div>
        <p className="text-[10px] text-surface-400 mt-2">
          The <strong>target</strong> FMC is the one connected in the main FMC Connection section above. Credentials are never logged or persisted.
        </p>

        {/* Metadata cards */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <MetaCard title="Source FMC" meta={sourceMeta} connected={sourceConnected} />
          <MetaCard title="Target FMC" meta={targetMeta} connected={targetMeta.status === 'connected'} />
        </div>
      </div>
    </div>
  )
}

function MetaCard({ title, meta, connected }: { title: string; meta: FmcMeta; connected: boolean }) {
  return (
    <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold text-surface-700 dark:text-surface-300">
          <Server className="w-3.5 h-3.5" /> {title}
        </div>
        <span className={cn('flex items-center gap-1 text-[10px] font-medium',
          connected ? 'text-accent-emerald' : meta.status === 'error' ? 'text-accent-rose' : 'text-surface-400')}>
          {connected ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
          {connected ? 'Connected' : meta.status === 'error' ? 'Error' : 'Not connected'}
        </span>
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-[10px]">
        <MetaRow label="Host" value={meta.host} />
        <MetaRow label="Version" value={meta.version} />
        <MetaRow label="Build" value={meta.build} />
        <MetaRow label="Model" value={meta.model} />
      </dl>
    </div>
  )
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-surface-400">{label}</dt>
      <dd className="text-surface-700 dark:text-surface-300 font-mono truncate" title={value}>{value || '—'}</dd>
    </>
  )
}
