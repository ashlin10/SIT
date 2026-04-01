import { useState, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { Users, Activity, Clock, ChevronLeft, ChevronRight, CircleDot } from 'lucide-react'

interface OnlineUser {
  username: string
  last_seen: string
  login_time: string
}

interface ActivityItem {
  username: string
  action: string
  ts: string
  details?: Record<string, unknown>
}

const PAGE_SIZE = 5

function formatRelative(ts: string): string {
  if (!ts) return ''
  try {
    const d = new Date(ts)
    const now = new Date()
    const sec = Math.floor((now.getTime() - d.getTime()) / 1000)
    if (sec < 60) return 'just now'
    const min = Math.floor(sec / 60)
    if (min < 60) return `${min}m ago`
    const hr = Math.floor(min / 60)
    if (hr < 24) return `${hr}h ago`
    const days = Math.floor(hr / 24)
    return `${days}d ago`
  } catch {
    return ts
  }
}

function Paginator({
  page,
  totalPages,
  onPrev,
  onNext,
}: {
  page: number
  totalPages: number
  onPrev: () => void
  onNext: () => void
}) {
  return (
    <div className="flex items-center justify-between mt-3 pt-3 border-t border-surface-100 dark:border-surface-800/50">
      <button
        onClick={onPrev}
        disabled={page <= 1}
        className="p-1 rounded text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        aria-label="Previous page"
      >
        <ChevronLeft className="w-4 h-4" />
      </button>
      <span className="text-[11px] text-surface-500 font-mono">
        {page} / {totalPages}
      </span>
      <button
        onClick={onNext}
        disabled={page >= totalPages}
        className="p-1 rounded text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        aria-label="Next page"
      >
        <ChevronRight className="w-4 h-4" />
      </button>
    </div>
  )
}

export default function DashboardPage() {
  const [users, setUsers] = useState<OnlineUser[]>([])
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [usersPage, setUsersPage] = useState(1)
  const [activityPage, setActivityPage] = useState(1)

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetch('/api/users/online', { credentials: 'include' })
      const data = await res.json()
      if (data?.success) setUsers(data.users || [])
    } catch { /* ignore */ }
  }, [])

  const fetchActivity = useCallback(async () => {
    try {
      const res = await fetch('/api/activity/recent', { credentials: 'include' })
      const data = await res.json()
      if (data?.success) setActivities(data.activities || [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    fetchUsers()
    fetchActivity()
    const interval = setInterval(() => {
      fetchUsers()
      fetchActivity()
    }, 5000)
    return () => clearInterval(interval)
  }, [fetchUsers, fetchActivity])

  const usersTotalPages = Math.max(1, Math.ceil(users.length / PAGE_SIZE))
  const activityTotalPages = Math.max(1, Math.ceil(activities.length / PAGE_SIZE))
  const pagedUsers = users.slice((usersPage - 1) * PAGE_SIZE, usersPage * PAGE_SIZE)
  const pagedActivities = activities.slice((activityPage - 1) * PAGE_SIZE, activityPage * PAGE_SIZE)

  return (
    <div className="space-y-6 animate-[fadeIn_0.3s_ease-out]">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">
          Dashboard
        </h1>
        <p className="text-sm text-surface-500 dark:text-surface-500 mt-0.5">
          System overview and recent activity
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Online Users"
          value={String(users.length)}
          icon={<Users className="w-4 h-4" />}
          accent="vyper"
        />
        <StatCard
          label="Recent Events"
          value={String(activities.length)}
          icon={<Activity className="w-4 h-4" />}
          accent="emerald"
        />
        <StatCard
          label="Uptime"
          value="Active"
          icon={<Clock className="w-4 h-4" />}
          accent="amber"
          badge
        />
      </div>

      {/* Two-column grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Online Users */}
        <div className={cn(
          'rounded-xl border border-surface-200 dark:border-surface-800/60',
          'bg-white dark:bg-surface-900/50'
        )}>
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4 text-vyper-500" />
              <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Online Users</h2>
            </div>
            <span className="text-[11px] font-mono text-surface-500 bg-surface-100 dark:bg-surface-800 px-2 py-0.5 rounded-full">
              {users.length}
            </span>
          </div>
          <div className="px-5 py-3">
            {pagedUsers.length === 0 ? (
              <p className="text-sm text-surface-400 dark:text-surface-600 py-4 text-center">No users online</p>
            ) : (
              <div className="space-y-2.5">
                {pagedUsers.map((u) => (
                  <div key={u.username} className="flex items-center justify-between py-1.5">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-vyper-500/10 flex items-center justify-center text-[11px] font-semibold text-vyper-600 dark:text-vyper-400">
                        {u.username.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-surface-800 dark:text-surface-200">{u.username}</p>
                        <p className="text-[11px] text-surface-400 dark:text-surface-600">
                          Last seen {formatRelative(u.last_seen)}
                        </p>
                      </div>
                    </div>
                    <span className="flex items-center gap-1 text-[11px] font-medium text-accent-emerald">
                      <CircleDot className="w-3 h-3" />
                      Online
                    </span>
                  </div>
                ))}
              </div>
            )}
            <Paginator
              page={usersPage}
              totalPages={usersTotalPages}
              onPrev={() => setUsersPage((p) => Math.max(1, p - 1))}
              onNext={() => setUsersPage((p) => Math.min(usersTotalPages, p + 1))}
            />
          </div>
        </div>

        {/* Recent Activity */}
        <div className={cn(
          'rounded-xl border border-surface-200 dark:border-surface-800/60',
          'bg-white dark:bg-surface-900/50'
        )}>
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-accent-violet" />
              <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Recent Activity</h2>
            </div>
          </div>
          <div className="px-5 py-3">
            {pagedActivities.length === 0 ? (
              <p className="text-sm text-surface-400 dark:text-surface-600 py-4 text-center">No recent activity</p>
            ) : (
              <div className="space-y-2.5">
                {pagedActivities.map((a, i) => (
                  <div key={`${a.ts}-${i}`} className="flex items-start gap-3 py-1.5">
                    <div className="w-8 h-8 rounded-lg bg-accent-violet/10 flex items-center justify-center text-[11px] font-semibold text-accent-violet shrink-0">
                      {a.username.slice(0, 2).toUpperCase()}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-surface-800 dark:text-surface-200">
                        {a.username}{' '}
                        <span className="font-normal text-surface-500">{a.action}</span>
                      </p>
                      <p className="text-[11px] text-surface-400 dark:text-surface-600 truncate">
                        {formatRelative(a.ts)}
                        {a.details && Object.keys(a.details).length > 0 && (
                          <> &mdash; {JSON.stringify(a.details)}</>
                        )}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <Paginator
              page={activityPage}
              totalPages={activityTotalPages}
              onPrev={() => setActivityPage((p) => Math.max(1, p - 1))}
              onNext={() => setActivityPage((p) => Math.min(activityTotalPages, p + 1))}
            />
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

function StatCard({
  label,
  value,
  icon,
  accent,
  badge,
}: {
  label: string
  value: string
  icon: React.ReactNode
  accent: 'vyper' | 'emerald' | 'amber'
  badge?: boolean
}) {
  const colors = {
    vyper: 'bg-vyper-500/10 text-vyper-600 dark:text-vyper-400',
    emerald: 'bg-accent-emerald/10 text-accent-emerald',
    amber: 'bg-accent-amber/10 text-accent-amber',
  }
  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60 p-4',
      'bg-white dark:bg-surface-900/50'
    )}>
      <div className="flex items-center justify-between">
        <span className="text-[12px] text-surface-500 font-medium">{label}</span>
        <span className={cn('w-7 h-7 rounded-lg flex items-center justify-center', colors[accent])}>
          {icon}
        </span>
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold text-surface-900 dark:text-surface-100 tracking-tight">{value}</span>
        {badge && (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium text-accent-emerald bg-accent-emerald/10 px-1.5 py-0.5 rounded-full">
            <span className="w-1 h-1 rounded-full bg-accent-emerald animate-pulse" />
            Live
          </span>
        )}
      </div>
    </div>
  )
}
