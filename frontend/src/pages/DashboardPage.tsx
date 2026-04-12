import { useState, useEffect, useCallback, useMemo } from 'react'
import { cn } from '@/lib/utils'
import {
  Users, Activity, ChevronLeft, ChevronRight,
  Cpu, HardDrive, Server,
  Filter, X, RefreshCw,
} from 'lucide-react'
import {
  AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'

// ── Types ──

interface TimePoint { time: string; [key: string]: unknown }

interface SystemHealth {
  cpu_percent: number
  memory_percent: number
  memory_used_mb: number
  memory_total_mb: number
  disk_percent: number
  uptime_seconds: number
  status: 'healthy' | 'warning' | 'critical' | 'unknown'
}

interface OnlineUser { username: string; last_seen: string; login_time: string }
interface ActivityItem { username: string; action: string; ts: string; details?: string | null }
type TimeRange = '1h' | '24h' | '7d'

// ── Helpers ──

const PAGE_SIZE = 6

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
    return `${Math.floor(hr / 24)}d ago`
  } catch { return ts }
}

function formatUptime(sec: number): string {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const r = await fetch(url, { credentials: 'include' })
    const d = await r.json()
    return d?.success !== false ? d : null
  } catch { return null }
}

// ── Stagger animation delay helper ──
const stagger = (i: number) => ({ animationDelay: `${i * 60}ms` })

// ── Reusable card wrapper ──
const cardCls = cn(
  'rounded-xl border border-surface-200 dark:border-surface-800/60',
  'bg-white dark:bg-surface-900/50'
)

// ── Chart theme colors (CSS vars not accessible in recharts, use hex) ──
const CHART_COLORS = {
  vyper: '#16a34a',
  vyperFill: 'rgba(22,163,74,0.08)',
  blue: '#3b82f6',
  blueFill: 'rgba(59,130,246,0.08)',
  rose: '#f43f5e',
  roseFill: 'rgba(244,63,94,0.08)',
  amber: '#f59e0b',
  amberFill: 'rgba(245,158,11,0.08)',
  grid: 'rgba(148,163,184,0.08)',
}

// ── Custom chart tooltip ──
function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-lg px-3 py-2 text-[11px]">
      <div className="font-medium text-surface-500 mb-1">{label}</div>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-surface-600 dark:text-surface-300">{p.name}: <strong>{p.value}</strong></span>
        </div>
      ))}
    </div>
  )
}

// ═══════════════════════════════════════════
// ██  MAIN DASHBOARD
// ═══════════════════════════════════════════

export default function DashboardPage() {
  const [range, setRange] = useState<TimeRange>('1h')
  const [userTs, setUserTs] = useState<TimePoint[]>([])
  const [sysHealth, setSysHealth] = useState<SystemHealth | null>(null)
  const [sysTs, setSysTs] = useState<TimePoint[]>([])
  const [onlineUsers, setOnlineUsers] = useState<OnlineUser[]>([])
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [actFilter, setActFilter] = useState('')
  const [usersPage, setUsersPage] = useState(1)
  const [actPage, setActPage] = useState(1)
  const [refreshing, setRefreshing] = useState(false)

  const fetchAll = useCallback(async () => {
    const [ut, sh, st, ou, act] = await Promise.all([
      fetchJson<{ data: TimePoint[] }>(`/api/dashboard/users-timeseries?range=${range}`),
      fetchJson<SystemHealth & { success: boolean }>('/api/dashboard/system-health'),
      fetchJson<{ data: TimePoint[] }>(`/api/dashboard/system-timeseries?range=${range}`),
      fetchJson<{ users: OnlineUser[] }>('/api/users/online'),
      fetchJson<{ activities: ActivityItem[] }>('/api/dashboard/activities?limit=100'),
    ])
    if (ut) setUserTs((ut as { data: TimePoint[] }).data || [])
    if (sh) setSysHealth(sh as SystemHealth)
    if (st) setSysTs((st as { data: TimePoint[] }).data || [])
    if (ou) setOnlineUsers((ou as { users: OnlineUser[] }).users || [])
    if (act) setActivities((act as { activities: ActivityItem[] }).activities || [])
  }, [range])

  useEffect(() => {
    fetchAll()
    const iv = setInterval(fetchAll, 10000)
    return () => clearInterval(iv)
  }, [fetchAll])

  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchAll()
    setTimeout(() => setRefreshing(false), 400)
  }

  // Filtered activities
  const filteredActs = useMemo(() => {
    if (!actFilter) return activities
    const q = actFilter.toLowerCase()
    return activities.filter(a =>
      a.username.toLowerCase().includes(q) || a.action.toLowerCase().includes(q)
    )
  }, [activities, actFilter])

  const actTotalPages = Math.max(1, Math.ceil(filteredActs.length / PAGE_SIZE))
  const pagedActs = filteredActs.slice((actPage - 1) * PAGE_SIZE, actPage * PAGE_SIZE)
  const usersTotalPages = Math.max(1, Math.ceil(onlineUsers.length / PAGE_SIZE))
  const pagedUsers = onlineUsers.slice((usersPage - 1) * PAGE_SIZE, usersPage * PAGE_SIZE)


  return (
    <div className="space-y-5">
      {/* ── Header + Time Range ── */}
      <div className="flex items-end justify-between gap-4 animate-[fadeIn_0.3s_ease-out]">
        <div>
          <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">
            Dashboard
          </h1>
          <p className="text-[13px] text-surface-500 mt-0.5">
            System metrics &amp; activity overview
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleRefresh} className="p-1.5 rounded-lg text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors" title="Refresh">
            <RefreshCw className={cn('w-3.5 h-3.5', refreshing && 'animate-spin')} />
          </button>
          <div className="flex items-center bg-surface-100 dark:bg-surface-800 rounded-lg p-0.5">
            {(['1h', '24h', '7d'] as TimeRange[]).map(r => (
              <button
                key={r}
                onClick={() => { setRange(r); setActPage(1) }}
                className={cn(
                  'px-3 py-1 rounded-md text-[11px] font-medium transition-all',
                  range === r
                    ? 'bg-white dark:bg-surface-700 text-surface-800 dark:text-surface-200 shadow-sm'
                    : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300',
                )}
              >
                {r === '1h' ? 'Last Hour' : r === '24h' ? 'Last 24h' : 'Last 7d'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Charts Row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-[fadeIn_0.35s_ease-out]" style={stagger(1)}>
        {/* User Activity Over Time */}
        <div className={cardCls}>
          <div className="px-4 py-3 border-b border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <Users className="w-3.5 h-3.5 text-vyper-500" />
              <h3 className="text-[12px] font-semibold text-surface-700 dark:text-surface-300">User Activity</h3>
            </div>
          </div>
          <div className="px-2 py-3 h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={userTs}>
                <defs>
                  <linearGradient id="gradUsers" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={CHART_COLORS.vyper} stopOpacity={0.15} />
                    <stop offset="100%" stopColor={CHART_COLORS.vyper} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.grid} />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" tickLine={false} axisLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" tickLine={false} axisLine={false} width={28} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="users" stroke={CHART_COLORS.vyper} fill="url(#gradUsers)" strokeWidth={2} dot={false} name="Users" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Online Users */}
        <div className={cardCls}>
          <div className="flex items-center justify-between px-4 py-3 border-b border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <Users className="w-3.5 h-3.5 text-vyper-500" />
              <h3 className="text-[12px] font-semibold text-surface-700 dark:text-surface-300">Online Users</h3>
            </div>
            <span className="text-[10px] font-mono text-surface-400 bg-surface-100 dark:bg-surface-800 px-1.5 py-0.5 rounded-full">
              {onlineUsers.length}
            </span>
          </div>
          <div className="px-4 py-2">
            {pagedUsers.length === 0 ? (
              <p className="text-[12px] text-surface-400 py-6 text-center">No users online</p>
            ) : (
              <div className="space-y-1">
                {pagedUsers.map(u => (
                  <div key={u.username} className="flex items-center justify-between py-2 px-2 -mx-2 rounded-lg hover:bg-surface-50 dark:hover:bg-surface-800/30 transition-colors">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-lg bg-vyper-500/10 flex items-center justify-center text-[10px] font-bold text-vyper-600 dark:text-vyper-400">
                        {u.username.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-[12px] font-medium text-surface-800 dark:text-surface-200">{u.username}</p>
                        <p className="text-[10px] text-surface-400">Seen {formatRelative(u.last_seen)}</p>
                      </div>
                    </div>
                    <span className="flex items-center gap-1 text-[10px] font-medium text-accent-emerald">
                      <span className="w-1.5 h-1.5 rounded-full bg-accent-emerald animate-pulse" />
                      Online
                    </span>
                  </div>
                ))}
              </div>
            )}
            <Paginator
              page={usersPage}
              totalPages={usersTotalPages}
              onPrev={() => setUsersPage(p => Math.max(1, p - 1))}
              onNext={() => setUsersPage(p => Math.min(usersTotalPages, p + 1))}
            />
          </div>
        </div>
      </div>

      {/* ── System Health + Activity Row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-[fadeIn_0.4s_ease-out]" style={stagger(5)}>

        {/* System Health */}
        <div className={cardCls}>
          <div className="px-4 py-3 border-b border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-accent-violet" />
              <h3 className="text-[12px] font-semibold text-surface-700 dark:text-surface-300">System Health</h3>
            </div>
          </div>
          <div className="px-4 py-3 space-y-3">
            {/* Server status badge */}
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-surface-500">Status</span>
              <ServerStatusBadge status={sysHealth?.status || 'unknown'} />
            </div>

            {/* Uptime */}
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-surface-500">Uptime</span>
              <span className="text-[12px] font-mono font-medium text-surface-700 dark:text-surface-300">
                {sysHealth ? formatUptime(sysHealth.uptime_seconds) : '—'}
              </span>
            </div>

            {/* CPU */}
            <UsageBar label="CPU" percent={sysHealth?.cpu_percent ?? 0} icon={<Cpu className="w-3 h-3" />} />

            {/* Memory */}
            <UsageBar
              label="Memory"
              percent={sysHealth?.memory_percent ?? 0}
              sub={sysHealth ? `${Math.round(sysHealth.memory_used_mb)}/${Math.round(sysHealth.memory_total_mb)} MB` : ''}
              icon={<HardDrive className="w-3 h-3" />}
            />

            {/* Disk */}
            <UsageBar label="Disk" percent={sysHealth?.disk_percent ?? 0} icon={<HardDrive className="w-3 h-3" />} />

            {/* Mini CPU/Memory chart */}
            <div className="pt-1 h-[80px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={sysTs}>
                  <XAxis dataKey="time" hide />
                  <YAxis domain={[0, 100]} hide />
                  <Tooltip content={<ChartTooltip />} />
                  <Line type="monotone" dataKey="cpu" stroke={CHART_COLORS.blue} strokeWidth={1.5} dot={false} name="CPU %" />
                  <Line type="monotone" dataKey="memory" stroke={CHART_COLORS.amber} strokeWidth={1.5} dot={false} name="Mem %" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className={cn(cardCls, 'lg:col-span-2')}>
          <div className="flex items-center justify-between px-4 py-3 border-b border-surface-100 dark:border-surface-800/50">
            <div className="flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-accent-violet" />
              <h3 className="text-[12px] font-semibold text-surface-700 dark:text-surface-300">Recent Activity</h3>
              <span className="text-[10px] font-mono text-surface-400 bg-surface-100 dark:bg-surface-800 px-1.5 py-0.5 rounded-full">
                {filteredActs.length}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="relative">
                <Filter className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-surface-400" />
                <input
                  value={actFilter}
                  onChange={e => { setActFilter(e.target.value); setActPage(1) }}
                  placeholder="Filter..."
                  className="pl-7 pr-6 py-1 w-36 text-[11px] rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800 text-surface-700 dark:text-surface-300 placeholder:text-surface-400 focus:outline-none focus:ring-1 focus:ring-vyper-500/30 focus:border-vyper-500 transition-colors hover:border-vyper-400"
                />
                {actFilter && (
                  <button onClick={() => setActFilter('')} className="absolute right-1.5 top-1/2 -translate-y-1/2 text-surface-400 hover:text-surface-600 transition-colors">
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>
          </div>
          <div className="px-4 py-2">
            {pagedActs.length === 0 ? (
              <p className="text-[12px] text-surface-400 py-6 text-center">No activity recorded</p>
            ) : (
              <div className="space-y-0.5">
                {pagedActs.map((a, i) => (
                  <div key={`${a.ts}-${i}`} className="flex items-start gap-3 py-2 rounded-lg hover:bg-surface-50 dark:hover:bg-surface-800/30 px-2 -mx-2 transition-colors">
                    <div className="w-7 h-7 rounded-lg bg-accent-violet/10 flex items-center justify-center text-[10px] font-bold text-accent-violet shrink-0 mt-0.5">
                      {a.username.slice(0, 2).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-[12px] text-surface-800 dark:text-surface-200">
                        <span className="font-semibold">{a.username}</span>{' '}
                        <span className="text-surface-500">{a.action}</span>
                      </p>
                      <p className="text-[10px] text-surface-400 truncate mt-0.5">
                        {formatRelative(a.ts)}
                        {a.details && a.details !== '{}' && a.details !== 'null' && (
                          <> &mdash; <span className="font-mono">{a.details}</span></>
                        )}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <Paginator
              page={actPage}
              totalPages={actTotalPages}
              onPrev={() => setActPage(p => Math.max(1, p - 1))}
              onNext={() => setActPage(p => Math.min(actTotalPages, p + 1))}
            />
          </div>
        </div>
      </div>

    </div>
  )
}

// ═══════════════════════════════════════════
// ██  SUB-COMPONENTS
// ═══════════════════════════════════════════

function UsageBar({ label, percent, sub, icon }: { label: string; percent: number; sub?: string; icon: React.ReactNode }) {
  const color = percent > 85 ? 'bg-accent-rose' : percent > 65 ? 'bg-accent-amber' : 'bg-vyper-500'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5 text-[11px] text-surface-500">
          {icon} {label}
        </div>
        <div className="flex items-center gap-1.5">
          {sub && <span className="text-[9px] text-surface-400 font-mono">{sub}</span>}
          <span className="text-[11px] font-mono font-semibold text-surface-700 dark:text-surface-300">{percent}%</span>
        </div>
      </div>
      <div className="h-1.5 bg-surface-100 dark:bg-surface-800 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all duration-700', color)} style={{ width: `${Math.min(percent, 100)}%` }} />
      </div>
    </div>
  )
}

function ServerStatusBadge({ status }: { status: string }) {
  const cfg: Record<string, { label: string; cls: string; dot: string }> = {
    healthy: { label: 'Healthy', cls: 'text-accent-emerald bg-accent-emerald/10', dot: 'bg-accent-emerald' },
    warning: { label: 'Warning', cls: 'text-accent-amber bg-accent-amber/10', dot: 'bg-accent-amber' },
    critical: { label: 'Critical', cls: 'text-accent-rose bg-accent-rose/10', dot: 'bg-accent-rose' },
    unknown: { label: 'Unknown', cls: 'text-surface-400 bg-surface-100 dark:bg-surface-800', dot: 'bg-surface-400' },
  }
  const c = cfg[status] || cfg.unknown
  return (
    <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium', c.cls)}>
      <span className={cn('w-1.5 h-1.5 rounded-full animate-pulse', c.dot)} />
      {c.label}
    </span>
  )
}

function Paginator({ page, totalPages, onPrev, onNext }: { page: number; totalPages: number; onPrev: () => void; onNext: () => void }) {
  if (totalPages <= 1) return null
  return (
    <div className="flex items-center justify-between mt-2 pt-2 border-t border-surface-100 dark:border-surface-800/50">
      <button onClick={onPrev} disabled={page <= 1} className="p-1 rounded text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 disabled:opacity-30 transition-colors">
        <ChevronLeft className="w-3.5 h-3.5" />
      </button>
      <span className="text-[10px] text-surface-500 font-mono">{page} / {totalPages}</span>
      <button onClick={onNext} disabled={page >= totalPages} className="p-1 rounded text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 disabled:opacity-30 transition-colors">
        <ChevronRight className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
