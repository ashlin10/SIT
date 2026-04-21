import { cn } from '@/lib/utils'
import { useThemeStore } from '@/stores/themeStore'
import { Sun, Moon, Check, Info } from 'lucide-react'

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

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  )
}
