import { useEffect, useState, useRef } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn } from '@/lib/utils'
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react'

export default function Notification() {
  const { notification, clearNotification } = useVpnDebuggerStore()
  const [visible, setVisible] = useState(false)
  const [exiting, setExiting] = useState(false)
  const [current, setCurrent] = useState(notification)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (notification) {
      setCurrent(notification)
      setExiting(false)
      setVisible(true)
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => dismiss(), 4000)
    }
    return () => { if (timerRef.current) clearTimeout(timerRef.current) }
  }, [notification])

  const dismiss = () => {
    setExiting(true)
    setTimeout(() => {
      setVisible(false)
      setExiting(false)
      clearNotification()
    }, 250)
  }

  if (!visible || !current) return null

  const styles = {
    success: { bg: 'bg-accent-emerald/10 border-accent-emerald/30', text: 'text-accent-emerald', Icon: CheckCircle },
    error: { bg: 'bg-red-500/10 border-red-500/30', text: 'text-red-500', Icon: XCircle },
    warning: { bg: 'bg-accent-amber/10 border-accent-amber/30', text: 'text-accent-amber', Icon: AlertTriangle },
    info: { bg: 'bg-blue-500/10 border-blue-500/30', text: 'text-blue-500', Icon: Info },
  }

  const s = styles[current.type]

  return (
    <div className="fixed top-4 inset-x-0 z-50 flex justify-center pointer-events-none">
      <div
        className={cn(
          'pointer-events-auto flex items-center gap-2.5 px-4 py-2.5 rounded-lg border shadow-lg backdrop-blur-sm',
          'transition-all duration-250 ease-out',
          s.bg,
          exiting ? 'opacity-0 -translate-y-3 scale-95' : 'opacity-100 translate-y-0 scale-100',
        )}
        style={{
          animation: !exiting ? 'notifIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards' : undefined,
        }}
      >
        <s.Icon className={cn('w-4 h-4 shrink-0', s.text)} />
        <span className={cn('text-sm font-medium', s.text)}>{current.message}</span>
        <button onClick={dismiss} className="ml-2 p-0.5 rounded hover:bg-white/10 transition-colors">
          <X className="w-3.5 h-3.5 text-surface-400" />
        </button>
      </div>
      <style>{`
        @keyframes notifIn {
          0% { opacity: 0; transform: translateY(-12px) scale(0.95); }
          100% { opacity: 1; transform: translateY(0) scale(1); }
        }
      `}</style>
    </div>
  )
}
