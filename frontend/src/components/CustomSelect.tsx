import { useState, useRef, useEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'
import { ChevronDown } from 'lucide-react'

export interface SelectOption {
  value: string
  label: string
}

interface CustomSelectProps {
  value: string
  onChange: (value: string) => void
  options: SelectOption[]
  placeholder?: string
  disabled?: boolean
  className?: string
  mono?: boolean
  minWidth?: string
  dropUp?: boolean
  keepOpen?: boolean
}

export default function CustomSelect({
  value,
  onChange,
  options,
  placeholder = 'Select...',
  disabled = false,
  className,
  mono = false,
  minWidth,
  dropUp = false,
  keepOpen = false,
}: CustomSelectProps) {
  const [open, setOpen] = useState(false)
  const btnRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState<{ top: number; left: number; width: number }>({ top: 0, left: 0, width: 0 })

  const reposition = useCallback(() => {
    if (!btnRef.current) return
    const r = btnRef.current.getBoundingClientRect()
    setPos({
      top: dropUp ? r.top - 4 : r.bottom + 4,
      left: r.left,
      width: Math.max(r.width, minWidth ? parseInt(minWidth) || r.width : r.width),
    })
  }, [dropUp, minWidth])

  useEffect(() => {
    if (!open) return
    reposition()
    const handler = (e: MouseEvent) => {
      const t = e.target as Node
      if (btnRef.current?.contains(t) || menuRef.current?.contains(t)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    window.addEventListener('scroll', reposition, true)
    window.addEventListener('resize', reposition)
    return () => {
      document.removeEventListener('mousedown', handler)
      window.removeEventListener('scroll', reposition, true)
      window.removeEventListener('resize', reposition)
    }
  }, [open, reposition])

  const selectedLabel = options.find(o => o.value === value)?.label

  return (
    <div className={cn('relative', className)} style={minWidth ? { minWidth } : undefined}>
      <button
        ref={btnRef}
        type="button"
        onClick={() => !disabled && setOpen(!open)}
        disabled={disabled}
        className={cn(
          'w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg border text-xs transition-colors',
          disabled
            ? 'border-surface-200 dark:border-surface-700 text-surface-400 bg-surface-50 dark:bg-surface-800/50 cursor-not-allowed opacity-40'
            : 'border-surface-200 dark:border-surface-700 text-surface-700 dark:text-surface-300 bg-white dark:bg-surface-800 hover:border-vyper-400 cursor-pointer',
        )}
      >
        <span className={cn('truncate', mono && 'font-mono')}>
          {selectedLabel || placeholder}
        </span>
        <ChevronDown className={cn('w-3.5 h-3.5 text-surface-400 shrink-0 transition-transform ml-1.5', open && 'rotate-180')} />
      </button>
      {open && options.length > 0 && createPortal(
        <div
          ref={menuRef}
          className={cn(
            'fixed bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-[9999] py-1 max-h-48 overflow-auto whitespace-nowrap',
          )}
          style={{
            top: dropUp ? undefined : pos.top,
            bottom: dropUp ? `${window.innerHeight - pos.top}px` : undefined,
            left: pos.left,
            minWidth: pos.width,
          }}
        >
          {options.map(opt => (
            <div
              key={opt.value}
              onClick={() => { onChange(opt.value); if (!keepOpen) setOpen(false) }}
              className="flex items-center gap-2 px-3 py-1.5 hover:bg-surface-50 dark:hover:bg-surface-800/70 transition-colors cursor-pointer"
            >
              <span
                className={cn(
                  'w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center shrink-0 transition-colors',
                  value === opt.value
                    ? 'border-vyper-600 bg-vyper-600'
                    : 'border-surface-300 dark:border-surface-600',
                )}
              >
                {value === opt.value && <span className="w-1.5 h-1.5 rounded-full bg-white" />}
              </span>
              <span className={cn(
                'text-[11px] truncate flex-1 min-w-0',
                mono ? 'font-mono' : '',
                'text-surface-700 dark:text-surface-300',
              )}>{opt.label}</span>
            </div>
          ))}
        </div>,
        document.body
      )}
    </div>
  )
}
