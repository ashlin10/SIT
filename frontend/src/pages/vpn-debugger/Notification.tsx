import { useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn } from '@/lib/utils'
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react'

export default function Notification() {
  const { notification, clearNotification } = useVpnDebuggerStore()

  useEffect(() => {
    if (!notification) return
    const t = setTimeout(clearNotification, 4000)
    return () => clearTimeout(t)
  }, [notification, clearNotification])

  if (!notification) return null

  const styles = {
    success: { bg: 'bg-accent-emerald/10 border-accent-emerald/30', text: 'text-accent-emerald', Icon: CheckCircle },
    error: { bg: 'bg-red-500/10 border-red-500/30', text: 'text-red-500', Icon: XCircle },
    warning: { bg: 'bg-accent-amber/10 border-accent-amber/30', text: 'text-accent-amber', Icon: AlertTriangle },
    info: { bg: 'bg-blue-500/10 border-blue-500/30', text: 'text-blue-500', Icon: Info },
  }

  const s = styles[notification.type]

  return (
    <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 animate-[slideDown_0.3s_ease-out]">
      <div className={cn('flex items-center gap-2.5 px-4 py-2.5 rounded-lg border shadow-lg', s.bg)}>
        <s.Icon className={cn('w-4 h-4 shrink-0', s.text)} />
        <span className={cn('text-sm font-medium', s.text)}>{notification.message}</span>
        <button onClick={clearNotification} className="ml-2 p-0.5 rounded hover:bg-white/10 transition-colors">
          <X className="w-3.5 h-3.5 text-surface-400" />
        </button>
      </div>
      <style>{`
        @keyframes slideDown {
          from { opacity: 0; transform: translate(-50%, -100%); }
          to { opacity: 1; transform: translate(-50%, 0); }
        }
      `}</style>
    </div>
  )
}
