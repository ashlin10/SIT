import { cn } from '@/lib/utils'

export default function SectionCard({
  title,
  headerRight,
  children,
  className,
}: {
  title: string
  headerRight?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50',
      className,
    )}>
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-surface-100 dark:border-surface-800/50">
        <h2 className="text-sm font-semibold text-surface-800 dark:text-surface-200">{title}</h2>
        {headerRight}
      </div>
      <div className="px-5 py-4">
        {children}
      </div>
    </div>
  )
}
