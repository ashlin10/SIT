import { cn } from '@/lib/utils'

interface Props {
  title: string
  badge?: string
  badgeColor?: 'green' | 'yellow' | 'blue'
  actions?: React.ReactNode
  children: React.ReactNode
}

const badgeColors = {
  green: 'bg-accent-emerald/10 text-accent-emerald',
  yellow: 'bg-accent-amber/10 text-accent-amber',
  blue: 'bg-vyper-500/10 text-vyper-500',
}

export default function SectionCard({ title, badge, badgeColor = 'green', actions, children }: Props) {
  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">{title}</h2>
          {badge && (
            <span className={cn('text-[10px] font-medium px-1.5 py-0.5 rounded-full', badgeColors[badgeColor])}>
              {badge}
            </span>
          )}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      <div className="px-5 py-4">{children}</div>
    </div>
  )
}
