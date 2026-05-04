import { useState, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { useThemeStore } from '@/stores/themeStore'
import { useAuthStore } from '@/stores/authStore'
import { Sun, Moon, Check, Info, ShieldCheck, RefreshCw, AlertTriangle } from 'lucide-react'

interface CertStatus {
  things_configured: boolean
  cert_exists: boolean
  subject?: string
  issuer?: string
  not_before?: string
  not_after?: string
  thumbprint?: string
  self_signed?: boolean
  parse_error?: string
}

const THEMES = [
  {
    id: 'light' as const,
    label: 'Light',
    description: 'Clean and bright interface',
    icon: <Sun className="w-5 h-5" />,
    preview: 'bg-white border-surface-200',
    dot: 'bg-surface-100 border-surface-300',
  },
  {
    id: 'dark' as const,
    label: 'Dark',
    description: 'Reduced eye strain in low light',
    icon: <Moon className="w-5 h-5" />,
    preview: 'bg-surface-900 border-surface-700',
    dot: 'bg-surface-800 border-surface-600',
  },
]

export default function SettingsPage() {
  const { theme, setTheme } = useThemeStore()
  const isAdmin = useAuthStore((s) => s.isAdmin)
  const [certStatus, setCertStatus] = useState<CertStatus | null>(null)
  const [certLoading, setCertLoading] = useState(false)
  const [certRefreshing, setCertRefreshing] = useState(false)
  const [certMessage, setCertMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const fetchCertStatus = useCallback(async () => {
    if (!isAdmin) return
    setCertLoading(true)
    try {
      const res = await fetch('/api/admin/things-cert/status', { credentials: 'include' })
      if (res.ok) setCertStatus(await res.json())
    } catch { /* ignore */ }
    setCertLoading(false)
  }, [isAdmin])

  useEffect(() => { fetchCertStatus() }, [fetchCertStatus])

  const handleCertRefresh = async () => {
    setCertRefreshing(true)
    setCertMessage(null)
    try {
      const res = await fetch('/api/admin/things-cert/refresh', { method: 'POST', credentials: 'include' })
      const data = await res.json()
      if (res.ok && data.success) {
        setCertMessage({ type: 'success', text: data.message || 'Certificate refreshed successfully.' })
        fetchCertStatus()
      } else {
        setCertMessage({ type: 'error', text: data.error || 'Failed to refresh certificate.' })
      }
    } catch {
      setCertMessage({ type: 'error', text: 'Network error. Could not reach the server.' })
    }
    setCertRefreshing(false)
  }

  const formatDate = (iso?: string) => {
    if (!iso) return '—'
    try { return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) }
    catch { return iso }
  }

  return (
    <div className="space-y-6 max-w-2xl animate-[fadeIn_0.3s_ease-out]">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-surface-500 mt-0.5">
          Customize your VYPER experience
        </p>
      </div>

      {/* Theme section */}
      <div className={cn(
        'rounded-xl border border-surface-200 dark:border-surface-800/60',
        'bg-white dark:bg-surface-900/50 overflow-hidden'
      )}>
        <div className="px-5 py-3.5 border-b border-surface-100 dark:border-surface-800/50">
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">
            Appearance
          </h2>
        </div>
        <div className="p-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {THEMES.map((t) => {
              const isActive = theme === t.id
              return (
                <button
                  key={t.id}
                  onClick={() => setTheme(t.id)}
                  className={cn(
                    'relative flex items-center gap-4 p-4 rounded-xl border-2 text-left transition-all duration-200',
                    isActive
                      ? 'border-vyper-500 bg-vyper-500/5 dark:bg-vyper-500/10'
                      : 'border-surface-200 dark:border-surface-800 hover:border-surface-300 dark:hover:border-surface-700'
                  )}
                  aria-label={`Select ${t.label} theme`}
                  aria-pressed={isActive}
                >
                  <div className={cn(
                    'w-10 h-10 rounded-lg border flex items-center justify-center shrink-0',
                    t.dot,
                    isActive ? 'text-vyper-500' : 'text-surface-400 dark:text-surface-500'
                  )}>
                    {t.icon}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className={cn(
                      'text-sm font-medium',
                      isActive
                        ? 'text-vyper-600 dark:text-vyper-400'
                        : 'text-surface-800 dark:text-surface-200'
                    )}>
                      {t.label}
                    </p>
                    <p className="text-[12px] text-surface-500 dark:text-surface-500">
                      {t.description}
                    </p>
                  </div>
                  {isActive && (
                    <div className="absolute top-3 right-3">
                      <Check className="w-4 h-4 text-vyper-500" />
                    </div>
                  )}
                </button>
              )
            })}
          </div>

          {/* Info callout */}
          <div className="mt-5 flex items-start gap-3 rounded-lg bg-vyper-500/5 dark:bg-vyper-500/10 border border-vyper-500/10 dark:border-vyper-500/20 px-4 py-3">
            <Info className="w-4 h-4 text-vyper-500 mt-0.5 shrink-0" />
            <p className="text-[12px] text-surface-600 dark:text-surface-400 leading-relaxed">
              Your theme preference is saved to this browser and will be applied automatically on future visits.
            </p>
          </div>
        </div>
      </div>

      {/* HTTPS Certificate section — admin only */}
      {isAdmin && <div className={cn(
        'rounded-xl border border-surface-200 dark:border-surface-800/60',
        'bg-white dark:bg-surface-900/50 overflow-hidden'
      )}>
        <div className="px-5 py-3.5 border-b border-surface-100 dark:border-surface-800/50 flex items-center justify-between">
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">
            HTTPS Certificate
          </h2>
          {certStatus?.self_signed && (
            <span className="flex items-center gap-1.5 text-[11px] text-amber-500 font-medium">
              <AlertTriangle className="w-3.5 h-3.5" />
              Self-signed
            </span>
          )}
          {certStatus && !certStatus.self_signed && certStatus.cert_exists && (
            <span className="flex items-center gap-1.5 text-[11px] text-accent-emerald font-medium">
              <ShieldCheck className="w-3.5 h-3.5" />
              CA-signed
            </span>
          )}
        </div>
        <div className="p-5 space-y-4">
          {certLoading && !certStatus && (
            <div className="flex items-center gap-2 text-sm text-surface-500">
              <span className="inline-block w-4 h-4 border-2 border-vyper-500/30 border-t-vyper-500 rounded-full animate-spin" />
              Loading certificate info&hellip;
            </div>
          )}

          {certStatus && (
            <div className="space-y-3">
              <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-[13px]">
                <span className="text-surface-500 dark:text-surface-500">Subject</span>
                <span className="text-surface-800 dark:text-surface-200 font-mono text-[12px]">{certStatus.subject || '—'}</span>

                <span className="text-surface-500 dark:text-surface-500">Issuer</span>
                <span className="text-surface-800 dark:text-surface-200 font-mono text-[12px]">{certStatus.issuer || '—'}</span>

                <span className="text-surface-500 dark:text-surface-500">Valid from</span>
                <span className="text-surface-800 dark:text-surface-200">{formatDate(certStatus.not_before)}</span>

                <span className="text-surface-500 dark:text-surface-500">Expires</span>
                <span className="text-surface-800 dark:text-surface-200">{formatDate(certStatus.not_after)}</span>

                <span className="text-surface-500 dark:text-surface-500">Thumbprint</span>
                <span className="text-surface-800 dark:text-surface-200 font-mono text-[11px] break-all">{certStatus.thumbprint || '—'}</span>
              </div>
            </div>
          )}

          {/* Feedback message */}
          {certMessage && (
            <div className={cn(
              'flex items-start gap-2.5 rounded-lg px-4 py-2.5 text-[13px]',
              certMessage.type === 'success'
                ? 'bg-accent-emerald/8 border border-accent-emerald/15 text-accent-emerald'
                : 'bg-accent-rose/8 border border-accent-rose/15 text-accent-rose'
            )}>
              {certMessage.type === 'success' ? <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" /> : <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />}
              <span>{certMessage.text}</span>
            </div>
          )}

          {/* Refresh button */}
          {certStatus?.things_configured && (
            <button
              onClick={handleCertRefresh}
              disabled={certRefreshing}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg text-[13px] font-medium',
                'bg-vyper-500/10 text-vyper-600 dark:text-vyper-400 border border-vyper-500/15',
                'hover:bg-vyper-500/15 hover:border-vyper-500/25',
                'disabled:opacity-40 disabled:cursor-not-allowed',
                'transition-all duration-200'
              )}
            >
              <RefreshCw className={cn('w-3.5 h-3.5', certRefreshing && 'animate-spin')} />
              {certRefreshing ? 'Requesting certificate…' : 'Request CA Certificate from Things'}
            </button>
          )}

          {certStatus && !certStatus.things_configured && (
            <div className="flex items-start gap-3 rounded-lg bg-surface-100 dark:bg-surface-800/40 border border-surface-200 dark:border-surface-700/40 px-4 py-3">
              <Info className="w-4 h-4 text-surface-400 mt-0.5 shrink-0" />
              <p className="text-[12px] text-surface-500 leading-relaxed">
                Set <code className="px-1 py-0.5 rounded bg-surface-200 dark:bg-surface-700/60 text-[11px] font-mono">THINGS_API_TOKEN</code> and <code className="px-1 py-0.5 rounded bg-surface-200 dark:bg-surface-700/60 text-[11px] font-mono">THINGS_TOOL_SLUG</code> in your <code className="px-1 py-0.5 rounded bg-surface-200 dark:bg-surface-700/60 text-[11px] font-mono">.env</code> file to enable CA-signed certificates from the Things platform.
              </p>
            </div>
          )}
        </div>
      </div>}

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  )
}
