import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import {
  Terminal,
  Network,
  Shield,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
} from 'lucide-react'

interface NavItem {
  to: string
  label: string
  icon: React.ReactNode
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard className="w-[18px] h-[18px]" /> },
  { to: '/command-center', label: 'Command Center', icon: <Terminal className="w-[18px] h-[18px]" /> },
  { to: '/fmc-configuration', label: 'FMC Configuration', icon: <Network className="w-[18px] h-[18px]" /> },
  { to: '/vpn-debugger', label: 'VPN Debugger', icon: <Shield className="w-[18px] h-[18px]" /> },
  { to: '/settings', label: 'Settings', icon: <Settings className="w-[18px] h-[18px]" /> },
]

function ViperLogoSmall({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" fill="none" className={className} xmlns="http://www.w3.org/2000/svg">
      <path
        d="M32 6 C26 6, 18 10, 16 18 C14 26, 20 30, 28 30 C36 30, 42 34, 40 42 C38 50, 30 54, 24 52"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        fill="none"
      />
      <path
        d="M32 6 C34 4, 38 3, 40 5 C42 7, 40 10, 38 11 C36 12, 34 10, 32 8"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="currentColor"
        fillOpacity="0.15"
      />
      <circle cx="37" cy="7" r="1.2" fill="var(--color-accent-emerald)" />
      <path d="M40 5 L44 3 M40 5 L44 7" stroke="var(--color-accent-emerald)" strokeWidth="1.2" strokeLinecap="round" />
      <path d="M24 52 C20 50, 18 46, 20 44" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" opacity="0.6" />
    </svg>
  )
}

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('vyper-sidebar-collapsed') === 'true')
  const { username, logout } = useAuthStore()
  const navigate = useNavigate()

  const toggleCollapsed = () => {
    const next = !collapsed
    setCollapsed(next)
    localStorage.setItem('vyper-sidebar-collapsed', String(next))
  }

  const handleLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <aside
      className={cn(
        'flex flex-col h-screen border-r border-surface-200 dark:border-surface-800/60 bg-white dark:bg-surface-900/80 backdrop-blur-sm',
        'transition-[width] duration-300 ease-in-out relative group/sidebar',
        collapsed ? 'w-[68px]' : 'w-[240px]'
      )}
    >
      {/* Brand header */}
      <div className={cn(
        'flex items-center h-14 px-4 border-b border-surface-200 dark:border-surface-800/60 shrink-0',
        collapsed ? 'justify-center' : 'justify-between'
      )}>
        <div className="flex items-center gap-2.5 min-w-0">
          <ViperLogoSmall className="w-7 h-7 text-vyper-500 shrink-0" />
          {!collapsed && (
            <span className="text-[15px] font-semibold text-surface-900 dark:text-surface-100 tracking-tight font-[Outfit] whitespace-nowrap">
              Vyper
            </span>
          )}
        </div>
        {!collapsed && (
          <button
            onClick={toggleCollapsed}
            className="p-1 rounded-md text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors"
            aria-label="Collapse sidebar"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Expand button when collapsed */}
      {collapsed && (
        <button
          onClick={toggleCollapsed}
          className="absolute -right-3 top-[18px] z-20 w-6 h-6 rounded-full border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800 flex items-center justify-center text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 shadow-sm opacity-0 group-hover/sidebar:opacity-100 transition-opacity"
          aria-label="Expand sidebar"
        >
          <ChevronRight className="w-3 h-3" />
        </button>
      )}

      {/* Navigation section label */}
      {!collapsed && (
        <div className="px-4 pt-4 pb-1">
          <span className="text-[10px] font-medium text-surface-400 dark:text-surface-600 uppercase tracking-[0.15em] font-mono">
            Navigation
          </span>
        </div>
      )}

      {/* Nav links */}
      <nav className={cn('flex-1 overflow-y-auto py-2', collapsed ? 'px-2' : 'px-2.5')}>
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg transition-all duration-150 mb-0.5',
                collapsed ? 'justify-center px-0 py-2.5' : 'px-3 py-2',
                isActive
                  ? 'bg-vyper-500/10 text-vyper-600 dark:text-vyper-400 font-medium'
                  : 'text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800/60 hover:text-surface-900 dark:hover:text-surface-200'
              )
            }
            title={collapsed ? item.label : undefined}
          >
            <span className="shrink-0">{item.icon}</span>
            {!collapsed && (
              <span className="text-[13px] whitespace-nowrap">{item.label}</span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User section at bottom */}
      <div className={cn(
        'border-t border-surface-200 dark:border-surface-800/60 shrink-0',
        collapsed ? 'px-2 py-3' : 'px-3 py-3'
      )}>
        {/* User badge */}
        <div className={cn(
          'flex items-center gap-2.5 mb-2',
          collapsed && 'justify-center'
        )}>
          <div className="w-7 h-7 rounded-lg bg-vyper-500/10 flex items-center justify-center text-[11px] font-semibold text-vyper-600 dark:text-vyper-400 shrink-0">
            {(username ?? '?').slice(0, 2).toUpperCase()}
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <p className="text-[12px] font-medium text-surface-800 dark:text-surface-200 truncate">
                {username}
              </p>
              <p className="text-[10px] text-surface-400 dark:text-surface-600">Authenticated</p>
            </div>
          )}
        </div>

        {/* Logout button */}
        <button
          onClick={handleLogout}
          className={cn(
            'flex items-center gap-2.5 w-full rounded-lg transition-colors duration-150',
            'text-surface-500 hover:text-accent-rose hover:bg-accent-rose/5',
            collapsed ? 'justify-center py-2' : 'px-3 py-1.5'
          )}
          title={collapsed ? 'Logout' : undefined}
          aria-label="Logout"
        >
          <LogOut className="w-4 h-4 shrink-0" />
          {!collapsed && <span className="text-[12px]">Logout</span>}
        </button>
      </div>
    </aside>
  )
}
