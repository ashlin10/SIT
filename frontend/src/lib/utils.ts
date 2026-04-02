import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** Consistent button class generator matching FMC Config page styling */
export function btnCls(variant: 'primary' | 'secondary' | 'danger' | 'warning' | 'success' = 'secondary') {
  return cn(
    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors disabled:opacity-40 disabled:pointer-events-none',
    variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
    variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
    variant === 'danger' && 'border border-accent-rose/30 text-accent-rose/70 hover:bg-accent-rose/10 hover:text-accent-rose',
    variant === 'warning' && 'border border-accent-amber/30 text-accent-amber hover:bg-accent-amber/10',
    variant === 'success' && 'border border-accent-emerald/30 text-accent-emerald hover:bg-accent-emerald/10',
  )
}

/** Small icon-only button */
export function iconBtnCls(variant: 'default' | 'danger' | 'success' | 'primary' | 'warning' = 'default') {
  return cn(
    'p-1 rounded-md transition-colors disabled:opacity-40',
    variant === 'default' && 'text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800',
    variant === 'danger' && 'text-surface-400 hover:text-accent-rose hover:bg-accent-rose/10',
    variant === 'success' && 'text-surface-400 hover:text-accent-emerald hover:bg-accent-emerald/10',
    variant === 'primary' && 'text-surface-400 hover:text-vyper-600 hover:bg-vyper-50 dark:hover:bg-vyper-900/20',
    variant === 'warning' && 'text-surface-400 hover:text-accent-amber hover:bg-accent-amber/10',
  )
}

/** Consistent select/dropdown styling */
export const selectCls = cn(
  'px-2.5 py-1.5 text-xs rounded-lg border border-surface-200 dark:border-surface-700',
  'bg-white dark:bg-surface-800 text-surface-700 dark:text-surface-300',
  'focus:outline-none focus:ring-2 focus:ring-vyper-500/30 focus:border-vyper-500',
  'disabled:opacity-40 transition-colors appearance-none',
  'bg-[length:16px_16px] bg-[right_6px_center] bg-no-repeat',
  'bg-[url("data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e")]',
  'pr-7'
)

/** Consistent input styling */
export const inputCls = cn(
  'px-2.5 py-1.5 text-xs rounded-lg border border-surface-200 dark:border-surface-700',
  'bg-white dark:bg-surface-800 text-surface-800 dark:text-surface-200',
  'focus:outline-none focus:ring-2 focus:ring-vyper-500/30 focus:border-vyper-500',
  'disabled:opacity-40 transition-colors'
)
