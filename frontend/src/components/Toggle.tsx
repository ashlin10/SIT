import { cn } from '@/lib/utils'

interface ToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label?: string
  size?: 'sm' | 'md'
  disabled?: boolean
  className?: string
}

export default function Toggle({ checked, onChange, label, size = 'sm', disabled = false, className }: ToggleProps) {
  const w = size === 'sm' ? 'w-6' : 'w-8'
  const h = size === 'sm' ? 'h-3.5' : 'h-[18px]'
  const dot = size === 'sm' ? 'w-2.5 h-2.5' : 'w-3.5 h-3.5'
  const translate = size === 'sm' ? 'translate-x-2.5' : 'translate-x-3.5'

  return (
    <label className={cn('inline-flex items-center gap-1.5 cursor-pointer select-none', disabled && 'opacity-40 pointer-events-none', className)}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        disabled={disabled}
        className={cn(
          'relative inline-flex shrink-0 rounded-full transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-vyper-500/40',
          w, h,
          checked ? 'bg-vyper-600' : 'bg-surface-300 dark:bg-surface-600',
        )}
      >
        <span
          className={cn(
            'pointer-events-none inline-block rounded-full bg-white shadow-sm ring-0 transition-transform duration-200 ease-in-out',
            dot,
            'mt-[2px] ml-[2px]',
            checked && translate,
          )}
        />
      </button>
      {label && <span className="text-[9px] text-surface-500 dark:text-surface-400 whitespace-nowrap">{label}</span>}
    </label>
  )
}
