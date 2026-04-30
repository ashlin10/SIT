import { useState, useCallback, useRef, useMemo, useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, inputCls, selectCls } from '@/lib/utils'
import {
  X, Plus, Trash2, ChevronRight, Loader2, Play, Settings,
  CircleDot, CheckCircle, Ban, RotateCcw, Network, Route, RefreshCw,
} from 'lucide-react'
import Toggle from '@/components/Toggle'
import { fetchFrrServiceStatus, frrServiceAction } from './api'

// ── IP scaling helpers ──

function incrementIPv4(ip: string, octet: number, amount: number) {
  const parts = ip.split('/')
  const mask = parts[1] || ''
  const octets = parts[0].split('.').map(Number)
  const idx = octet - 1
  octets[idx] = (octets[idx] + amount) & 0xff
  return octets.join('.') + (mask ? '/' + mask : '')
}

function expandIPv6(addr: string) {
  const parts = addr.split('/')
  const mask = parts[1] || ''
  let ip = parts[0]
  if (ip.includes('::')) {
    const sides = ip.split('::')
    const left = sides[0] ? sides[0].split(':') : []
    const right = sides[1] ? sides[1].split(':') : []
    const missing = 8 - left.length - right.length
    const middle = Array(missing).fill('0000')
    ip = [...left, ...middle, ...right].map((h) => h.padStart(4, '0')).join(':')
  } else {
    ip = ip.split(':').map((h) => h.padStart(4, '0')).join(':')
  }
  return { ip, mask }
}

function incrementIPv6(addr: string, hextetPos: number, amount: number) {
  const { ip, mask } = expandIPv6(addr)
  const hextets = ip.split(':')
  const idx = hextetPos - 1
  const val = parseInt(hextets[idx], 10) + amount
  hextets[idx] = String(val)
  let result = hextets.map((h) => h.replace(/^0+/, '') || '0').join(':')
  result = result.replace(/(^|:)0(:0)+(:|$)/, '::').replace(/:{3,}/, '::')
  return result + (mask ? '/' + mask : '')
}

// ── Layout helpers ──

function Section({ title, children, defaultOpen = true, actions }: { title: string; children: React.ReactNode; defaultOpen?: boolean; actions?: React.ReactNode }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-surface-200 dark:border-surface-700 rounded-lg overflow-hidden">
      <div className="w-full flex items-center gap-1.5 pr-2 bg-surface-50 dark:bg-surface-800/50 text-[11px] font-semibold text-surface-600 dark:text-surface-400">
        <button onClick={() => setOpen(!open)} className="flex items-center gap-1.5 flex-1 px-3 py-2 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors text-left">
          <ChevronRight className={cn('w-3 h-3 transition-transform', open && 'rotate-90')} />
          {title}
        </button>
        {actions && <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>{actions}</div>}
      </div>
      {open && <div className="p-3 space-y-2">{children}</div>}
    </div>
  )
}

function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <label className="block text-[9px] font-medium text-surface-500 mb-0.5">{label}</label>
      {children}
    </div>
  )
}

// ── OSPF Interface Types ──

interface OspfIntfCmds {
  area: string; cost: string; bfdProfile: string
  helloInterval: string; deadInterval: string; priority: string
  retransmitInterval: string; transmitDelay: string; networkType: string
  passive: boolean; mtuIgnore: boolean; bfd: boolean
  authType: string; authKey: string; mdKeyId: string; mdKey: string
  instanceId: string; ifmtu: string; advertisePrefix: boolean
}

const defaultOspfIntfCmds: OspfIntfCmds = {
  area: '0', cost: '', bfdProfile: '', helloInterval: '', deadInterval: '', priority: '',
  retransmitInterval: '', transmitDelay: '', networkType: '', passive: false,
  mtuIgnore: false, bfd: false, authType: '', authKey: '', mdKeyId: '', mdKey: '',
  instanceId: '', ifmtu: '', advertisePrefix: false,
}

interface OspfInterfaceEntry {
  name: string; scale: boolean; count: number; cmds: OspfIntfCmds
}

const defaultOspfIntfEntry = (): OspfInterfaceEntry => ({
  name: '', scale: false, count: 1, cmds: { ...defaultOspfIntfCmds },
})

function OspfIntfCmdsPopup({ entry, isV3, profiles, onChange, onClose }: {
  entry: OspfInterfaceEntry; isV3: boolean; profiles: string[]
  onChange: (cmds: OspfIntfCmds) => void; onClose: () => void
}) {
  const [c, setC] = useState<OspfIntfCmds>({ ...entry.cmds })
  const upd = (patch: Partial<OspfIntfCmds>) => setC(prev => ({ ...prev, ...patch }))
  const pCls = cn(inputCls, 'w-full')
  const pSel = cn(selectCls, 'w-full')
  const NETWORK_TYPES = ['', 'broadcast', 'non-broadcast', 'point-to-point', 'point-to-multipoint']

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-[600px] max-h-[80vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden border border-surface-200 dark:border-surface-800">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <div>
            <span className="text-[11px] font-semibold text-surface-700 dark:text-surface-300">
              {isV3 ? 'ipv6 ospf6' : 'ip ospf'} — {entry.name || '(unnamed)'}
            </span>
            <span className="text-[9px] text-surface-400 ml-2">Interface commands</span>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-surface-200 dark:hover:bg-surface-700 text-surface-400"><X className="w-3.5 h-3.5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="grid grid-cols-3 gap-2">
            <Field label="Area"><input value={c.area} onChange={e => upd({ area: e.target.value })} placeholder="0" className={pCls} /></Field>
            <Field label="Cost"><input value={c.cost} onChange={e => upd({ cost: e.target.value })} placeholder="" className={pCls} /></Field>
            <Field label="Priority"><input value={c.priority} onChange={e => upd({ priority: e.target.value })} placeholder="" className={pCls} /></Field>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Hello Interval (sec)"><input value={c.helloInterval} onChange={e => upd({ helloInterval: e.target.value })} placeholder="10" className={pCls} /></Field>
            <Field label="Dead Interval (sec)"><input value={c.deadInterval} onChange={e => upd({ deadInterval: e.target.value })} placeholder="40" className={pCls} /></Field>
            <Field label="Retransmit Interval (sec)"><input value={c.retransmitInterval} onChange={e => upd({ retransmitInterval: e.target.value })} placeholder="" className={pCls} /></Field>
            <Field label="Transmit Delay (sec)"><input value={c.transmitDelay} onChange={e => upd({ transmitDelay: e.target.value })} placeholder="" className={pCls} /></Field>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Network Type">
              <select value={c.networkType} onChange={e => upd({ networkType: e.target.value })} className={pSel}>
                {NETWORK_TYPES.map(t => <option key={t} value={t}>{t || '(default)'}</option>)}
              </select>
            </Field>
            {!isV3 && <Field label="Instance ID (1-65535)"><input value={c.instanceId} onChange={e => upd({ instanceId: e.target.value })} placeholder="" className={pCls} /></Field>}
            {isV3 && <Field label="Interface MTU"><input value={c.ifmtu} onChange={e => upd({ ifmtu: e.target.value })} placeholder="" className={pCls} /></Field>}
          </div>
          <div className="grid grid-cols-3 gap-x-4 gap-y-1">
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.passive} onChange={e => upd({ passive: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Passive
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.mtuIgnore} onChange={e => upd({ mtuIgnore: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> MTU Ignore
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.bfd} onChange={e => upd({ bfd: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> BFD
            </label>
            {c.bfd && (
              <Field label="BFD Profile">
                <select value={c.bfdProfile} onChange={e => upd({ bfdProfile: e.target.value })} className={pSel}>
                  <option value="">(default — no profile)</option>
                  {profiles.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </Field>
            )}
            {isV3 && (
              <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
                <input type="checkbox" checked={c.advertisePrefix} onChange={e => upd({ advertisePrefix: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Advertise Prefix
              </label>
            )}
          </div>
          <div className="space-y-2 pt-1 border-t border-surface-200 dark:border-surface-700">
            <div className="text-[9px] font-semibold text-surface-500 uppercase tracking-wider">Authentication</div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Auth Type">
                <select value={c.authType} onChange={e => upd({ authType: e.target.value })} className={pSel}>
                  <option value="">None</option>
                  <option value="null">Null (clear text)</option>
                  <option value="message-digest">Message Digest (MD5)</option>
                </select>
              </Field>
              {c.authType === 'null' && (
                <Field label="Authentication Key"><input value={c.authKey} onChange={e => upd({ authKey: e.target.value })} placeholder="password" className={pCls} /></Field>
              )}
              {c.authType === 'message-digest' && (
                <>
                  <Field label="MD Key ID"><input value={c.mdKeyId} onChange={e => upd({ mdKeyId: e.target.value })} placeholder="1" className={pCls} /></Field>
                  <Field label="MD Key"><input value={c.mdKey} onChange={e => upd({ mdKey: e.target.value })} placeholder="secret" className={pCls} /></Field>
                </>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center justify-end gap-2 px-4 py-2.5 border-t border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <button onClick={onClose} className={btnCls()}>Cancel</button>
          <button onClick={() => { onChange(c); onClose() }} className={btnCls('primary')}>Apply</button>
        </div>
      </div>
    </div>
  )
}

function ospfCmdsSummary(cmds: OspfIntfCmds, isV3: boolean): string {
  const parts: string[] = []
  if (cmds.area && cmds.area !== '0') parts.push(`area ${cmds.area}`)
  if (cmds.cost) parts.push(`cost ${cmds.cost}`)
  if (cmds.helloInterval) parts.push(`hello ${cmds.helloInterval}s`)
  if (cmds.deadInterval) parts.push(`dead ${cmds.deadInterval}s`)
  if (cmds.priority) parts.push(`pri ${cmds.priority}`)
  if (cmds.networkType) parts.push(cmds.networkType)
  if (cmds.passive) parts.push('passive')
  if (cmds.mtuIgnore) parts.push('mtu-ignore')
  if (cmds.bfd) parts.push(cmds.bfdProfile ? `bfd profile ${cmds.bfdProfile}` : 'bfd')
  if (cmds.authType) parts.push(`auth:${cmds.authType}`)
  if (!isV3 && cmds.instanceId) parts.push(`inst ${cmds.instanceId}`)
  if (isV3 && cmds.ifmtu) parts.push(`ifmtu ${cmds.ifmtu}`)
  if (isV3 && cmds.advertisePrefix) parts.push('adv-prefix')
  return parts.join(', ')
}

// ── BGP Neighbor Types ──

interface BgpNeighborCmds {
  password: string; ebgpMultihop: string; bfd: boolean; bfdProfile: string
  updateSource: string; nextHopSelf: boolean; defaultOriginate: boolean
  softReconfigInbound: boolean; routeMapIn: string; routeMapOut: string
  prefixListIn: string; prefixListOut: string
  keepAlive: string; holdTime: string; weight: string; allowasIn: string
}

const defaultBgpNeighborCmds: BgpNeighborCmds = {
  password: '', ebgpMultihop: '', bfd: false, bfdProfile: '', updateSource: '',
  nextHopSelf: false, defaultOriginate: false, softReconfigInbound: false,
  routeMapIn: '', routeMapOut: '', prefixListIn: '', prefixListOut: '',
  keepAlive: '', holdTime: '', weight: '', allowasIn: '',
}

interface BgpNeighborEntry {
  addr: string; remoteAs: string; scale: boolean; count: number
  octet: number; hextet: number; cmds: BgpNeighborCmds
}

const defaultBgpNeighborEntry = (): BgpNeighborEntry => ({
  addr: '', remoteAs: '', scale: false, count: 1, octet: 4, hextet: 8,
  cmds: { ...defaultBgpNeighborCmds },
})

function BgpNeighborCmdsPopup({ entry, isV6, profiles, onChange, onClose }: {
  entry: BgpNeighborEntry; isV6: boolean; profiles: string[]
  onChange: (cmds: BgpNeighborCmds) => void; onClose: () => void
}) {
  const [c, setC] = useState<BgpNeighborCmds>({ ...entry.cmds })
  const upd = (patch: Partial<BgpNeighborCmds>) => setC(prev => ({ ...prev, ...patch }))
  const pCls = cn(inputCls, 'w-full')
  const pSel = cn(selectCls, 'w-full')

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-[600px] max-h-[80vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden border border-surface-200 dark:border-surface-800">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <div>
            <span className="text-[11px] font-semibold text-surface-700 dark:text-surface-300">
              BGP Neighbor — {entry.addr || '(unnamed)'}
            </span>
            <span className="text-[9px] text-surface-400 ml-2">Neighbor commands</span>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-surface-200 dark:hover:bg-surface-700 text-surface-400"><X className="w-3.5 h-3.5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="space-y-2">
            <div className="text-[9px] font-semibold text-surface-500 uppercase tracking-wider">Authentication</div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Password"><input value={c.password} onChange={e => upd({ password: e.target.value })} placeholder="" className={pCls} /></Field>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Keep-Alive (sec)"><input value={c.keepAlive} onChange={e => upd({ keepAlive: e.target.value })} placeholder="60" className={pCls} /></Field>
            <Field label="Hold Time (sec)"><input value={c.holdTime} onChange={e => upd({ holdTime: e.target.value })} placeholder="180" className={pCls} /></Field>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Field label="eBGP Multihop (TTL)"><input value={c.ebgpMultihop} onChange={e => upd({ ebgpMultihop: e.target.value })} placeholder="" className={pCls} /></Field>
            <Field label="Update Source"><input value={c.updateSource} onChange={e => upd({ updateSource: e.target.value })} placeholder={isV6 ? 'lo' : '10.0.0.1'} className={pCls} /></Field>
          </div>
          <Field label="Weight"><input value={c.weight} onChange={e => upd({ weight: e.target.value })} placeholder="" className={pCls} /></Field>
          <Field label="Allowas-In (occurrences)"><input value={c.allowasIn} onChange={e => upd({ allowasIn: e.target.value })} placeholder="" className={pCls} /></Field>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.bfd} onChange={e => upd({ bfd: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> BFD
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.nextHopSelf} onChange={e => upd({ nextHopSelf: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Next-Hop Self
            </label>
          </div>
          {c.bfd && (
            <Field label="BFD Profile">
              <select value={c.bfdProfile} onChange={e => upd({ bfdProfile: e.target.value })} className={pSel}>
                <option value="">(default — no profile)</option>
                {profiles.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </Field>
          )}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.defaultOriginate} onChange={e => upd({ defaultOriginate: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Default Originate
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.softReconfigInbound} onChange={e => upd({ softReconfigInbound: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Soft Reconfiguration Inbound
            </label>
          </div>
          <div className="space-y-2 pt-1 border-t border-surface-200 dark:border-surface-700">
            <div className="text-[9px] font-semibold text-surface-500 uppercase tracking-wider">Route Policy</div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Route-Map In"><input value={c.routeMapIn} onChange={e => upd({ routeMapIn: e.target.value })} placeholder="" className={pCls} /></Field>
              <Field label="Route-Map Out"><input value={c.routeMapOut} onChange={e => upd({ routeMapOut: e.target.value })} placeholder="" className={pCls} /></Field>
              <Field label="Prefix-List In"><input value={c.prefixListIn} onChange={e => upd({ prefixListIn: e.target.value })} placeholder="" className={pCls} /></Field>
              <Field label="Prefix-List Out"><input value={c.prefixListOut} onChange={e => upd({ prefixListOut: e.target.value })} placeholder="" className={pCls} /></Field>
            </div>
          </div>
        </div>
        <div className="flex items-center justify-end gap-2 px-4 py-2.5 border-t border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <button onClick={onClose} className={btnCls()}>Cancel</button>
          <button onClick={() => { onChange(c); onClose() }} className={btnCls('primary')}>Apply</button>
        </div>
      </div>
    </div>
  )
}

function bgpNeighborCmdsSummary(cmds: BgpNeighborCmds): string {
  const parts: string[] = []
  if (cmds.password) parts.push('password')
  if (cmds.ebgpMultihop) parts.push(`ebgp-multihop ${cmds.ebgpMultihop}`)
  if (cmds.bfd) parts.push(cmds.bfdProfile ? `bfd profile ${cmds.bfdProfile}` : 'bfd')
  if (cmds.updateSource) parts.push(`update-src ${cmds.updateSource}`)
  if (cmds.nextHopSelf) parts.push('next-hop-self')
  if (cmds.defaultOriginate) parts.push('default-originate')
  if (cmds.softReconfigInbound) parts.push('soft-reconfig')
  if (cmds.keepAlive || cmds.holdTime) parts.push(`timers ${cmds.keepAlive || '60'}/${cmds.holdTime || '180'}`)
  if (cmds.weight) parts.push(`weight ${cmds.weight}`)
  if (cmds.allowasIn) parts.push(`allowas-in ${cmds.allowasIn}`)
  if (cmds.routeMapIn) parts.push(`rm-in:${cmds.routeMapIn}`)
  if (cmds.routeMapOut) parts.push(`rm-out:${cmds.routeMapOut}`)
  if (cmds.prefixListIn) parts.push(`pfx-in:${cmds.prefixListIn}`)
  if (cmds.prefixListOut) parts.push(`pfx-out:${cmds.prefixListOut}`)
  return parts.join(', ')
}

// ── BFD Types ──

interface BfdProfile {
  name: string; transmitInterval: string; receiveInterval: string; detectMultiplier: string
  passiveMode: boolean; echoMode: boolean; echoInterval: string; minimumTtl: string
}

const defaultBfdProfile = (): BfdProfile => ({
  name: '', transmitInterval: '300', receiveInterval: '300', detectMultiplier: '3',
  passiveMode: false, echoMode: false, echoInterval: '', minimumTtl: '',
})

interface BfdBinding {
  intf: string; peerAddr: string; profile: string; isV6: boolean
  scale: boolean; count: number; octet: number; hextet: number; intfHasNumericSuffix: boolean
}

const defaultBfdBinding = (): BfdBinding => ({
  intf: '', peerAddr: '', profile: '', isV6: false,
  scale: false, count: 1, octet: 4, hextet: 8, intfHasNumericSuffix: true,
})

// ── FRR Service Status Panel ──

function FrrServicePanel() {
  const { frrServiceStatus, localConnected } = useVpnDebuggerStore()
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  useEffect(() => {
    if (localConnected) fetchFrrServiceStatus()
  }, [localConnected])

  const doAction = async (action: 'enable' | 'disable' | 'restart') => {
    setActionLoading(action)
    await frrServiceAction(action)
    setActionLoading(null)
  }

  const statusStyles: Record<string, string> = {
    active: 'bg-accent-emerald/10 text-accent-emerald',
    inactive: 'bg-red-500/10 text-red-500',
    unknown: 'bg-surface-100 dark:bg-surface-800 text-surface-500',
  }

  return (
    <div className="flex items-center gap-3 p-2 rounded-lg border border-surface-100 dark:border-surface-800 bg-surface-50/50 dark:bg-surface-800/30">
      <span className="text-xs font-medium text-surface-700 dark:text-surface-300 min-w-[80px]">FR Routing</span>
      <span className={cn('inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full', statusStyles[frrServiceStatus] || statusStyles.unknown)}>
        <CircleDot className="w-2.5 h-2.5" />
        {frrServiceStatus === 'active' ? 'Active' : frrServiceStatus === 'inactive' ? 'Inactive' : 'Unknown'}
      </span>
      <div className="flex items-center gap-1 ml-auto">
        <button onClick={() => doAction('enable')} disabled={!localConnected || actionLoading !== null} className={btnCls('success')}>
          {actionLoading === 'enable' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />} Enable
        </button>
        <button onClick={() => doAction('disable')} disabled={!localConnected || actionLoading !== null} className={btnCls('danger')}>
          {actionLoading === 'disable' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Ban className="w-3.5 h-3.5" />} Disable
        </button>
        <button onClick={() => doAction('restart')} disabled={!localConnected || actionLoading !== null} className={btnCls('warning')}>
          {actionLoading === 'restart' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5" />} Restart
        </button>
      </div>
    </div>
  )
}

// ── Routing Status Popup (FRR config + per-protocol route table) ──

interface RoutingStatusData {
  config: string
  route_table: string
  route_sections: Record<string, string>
  protocol_info: Record<string, string>
}

function RoutingStatusPopup({ open, onClose }: { open: boolean; onClose: () => void }) {
  const store = useVpnDebuggerStore()
  const { localConnected } = store
  const [tab, setTab] = useState<'config' | 'routes'>('config')
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState<RoutingStatusData | null>(null)

  const fetchStatus = useCallback(async () => {
    if (!localConnected) return
    setLoading(true)
    try {
      const r = await fetch('/api/strongswan/overlay-routing/status', { credentials: 'include' })
      const d = await r.json()
      if (d.success) {
        setData({
          config: d.config || '',
          route_table: d.route_table || '',
          route_sections: d.route_sections || {},
          protocol_info: d.protocol_info || {},
        })
      } else {
        store.notify(d.message || 'Failed to fetch routing status', 'error')
      }
    } catch {
      store.notify('Failed to fetch routing status', 'error')
    }
    setLoading(false)
  }, [localConnected, store])

  useEffect(() => {
    if (open && localConnected) fetchStatus()
  }, [open, localConnected, fetchStatus])

  if (!open) return null

  const sectionLabels: Record<string, string> = {
    static_v4: 'Static (IPv4)', static_v6: 'Static (IPv6)',
    bgp_v4: 'BGP (IPv4)', bgp_v6: 'BGP (IPv6)',
    ospf_v4: 'OSPF (IPv4)', ospf_v6: 'OSPF (IPv6)',
    eigrp_v4: 'EIGRP (IPv4)', eigrp_v6: 'EIGRP (IPv6)',
  }
  const sectionEntries = Object.entries(data?.route_sections || {})
  const protoEntries = Object.entries(data?.protocol_info || {})

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-[95%] max-w-[850px] max-h-[85vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200 flex items-center gap-2">
            <Route className="w-4 h-4 text-surface-400" /> Routing Status
            <span className="text-[10px] font-normal text-surface-400">(live from connected server)</span>
          </h3>
          <div className="flex items-center gap-2">
            <button onClick={fetchStatus} disabled={!localConnected || loading} className={cn(btnCls(), 'text-[10px]')} title="Refresh">
              <RefreshCw className={cn('w-3.5 h-3.5', loading && 'animate-spin')} /> Refresh
            </button>
            <button onClick={onClose} className="p-1 rounded-lg hover:bg-surface-200 dark:hover:bg-surface-700 transition-colors">
              <X className="w-4 h-4 text-surface-500" />
            </button>
          </div>
        </div>
        <div className="flex border-b border-surface-200 dark:border-surface-800 px-4 bg-surface-50/40 dark:bg-surface-800/20">
          {(['config', 'routes'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                'px-3 py-2 text-[11px] font-medium border-b-2 transition-colors',
                tab === t
                  ? 'border-vyper-500 text-vyper-600 dark:text-vyper-400'
                  : 'border-transparent text-surface-500 hover:text-surface-700 dark:hover:text-surface-300',
              )}
            >
              {t === 'config' ? 'Routing Config' : 'Route Table'}
            </button>
          ))}
        </div>
        <div className="flex-1 overflow-auto p-4 space-y-3">
          {!localConnected ? (
            <div className="text-xs text-surface-400 italic py-6 text-center">Connect to the server to view routing status.</div>
          ) : loading && !data ? (
            <div className="text-xs text-surface-400 italic py-6 text-center flex items-center justify-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading...
            </div>
          ) : tab === 'config' ? (
            <div className="space-y-3">
              <div>
                <div className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider mb-1">FR Routing — show running-config</div>
                <pre className="text-[10px] font-mono p-2.5 rounded-md bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700 whitespace-pre-wrap break-words text-surface-700 dark:text-surface-300 max-h-[40vh] overflow-auto">
{data?.config || '(empty)'}
                </pre>
              </div>
              {protoEntries.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Protocol Status</div>
                  {protoEntries.map(([k, v]) => (
                    <div key={k}>
                      <div className="text-[10px] font-medium text-surface-600 dark:text-surface-400 mb-0.5">{k}</div>
                      <pre className="text-[10px] font-mono p-2 rounded-md bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700 whitespace-pre-wrap break-words text-surface-700 dark:text-surface-300 max-h-[25vh] overflow-auto">{v}</pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {sectionEntries.length === 0 && !data?.route_table ? (
                <div className="text-xs text-surface-400 italic py-6 text-center">No routes found.</div>
              ) : (
                <>
                  {sectionEntries.map(([k, v]) => (
                    <div key={k}>
                      <div className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider mb-1">{sectionLabels[k] || k}</div>
                      <pre className="text-[10px] font-mono p-2.5 rounded-md bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700 whitespace-pre-wrap break-words text-surface-700 dark:text-surface-300 max-h-[30vh] overflow-auto">{v}</pre>
                    </div>
                  ))}
                  {data?.route_table && (
                    <div>
                      <div className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider mb-1">XFRM Routes (kernel)</div>
                      <pre className="text-[10px] font-mono p-2.5 rounded-md bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700 whitespace-pre-wrap break-words text-surface-700 dark:text-surface-300 max-h-[30vh] overflow-auto">{data.route_table}</pre>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Routing Builder ──

type RoutingType = 'static' | 'bgpv4' | 'bgpv6' | 'ospfv2' | 'ospfv3' | 'eigrpv4' | 'eigrpv6' | 'bfd'

function RoutingBuilder() {
  const store = useVpnDebuggerStore()
  const { localConnected } = store

  const [routingType, setRoutingTypeRaw] = useState<RoutingType>('static')
  const [staticRoutes, setStaticRoutes] = useState<{ dest: string; via: string; dev: string }[]>([{ dest: '', via: '', dev: '' }])
  const [bgpLocalAs, setBgpLocalAs] = useState('')
  const [bgpRouterId, setBgpRouterId] = useState('')
  const [bgpNeighbors, setBgpNeighbors] = useState<BgpNeighborEntry[]>([defaultBgpNeighborEntry()])
  const [bgpNeighborPopupIdx, setBgpNeighborPopupIdx] = useState<number | null>(null)
  const [bgpNetworks, setBgpNetworks] = useState<string[]>([''])
  const [bgpEbgpRequiresPolicy, setBgpEbgpRequiresPolicy] = useState(false)
  const [bgpDefaultIpv4Unicast, setBgpDefaultIpv4Unicast] = useState(false)
  const [ospfRouterId, setOspfRouterId] = useState('')
  const [ospfNetworks, setOspfNetworks] = useState<{ network: string; area: string }[]>([{ network: '', area: '0' }])
  const [ospfInterfaces, setOspfInterfaces] = useState<OspfInterfaceEntry[]>([defaultOspfIntfEntry()])
  const [ospfCmdPopupIdx, setOspfCmdPopupIdx] = useState<number | null>(null)
  const [eigrpAs, setEigrpAs] = useState('')
  const [eigrpRouterId, setEigrpRouterId] = useState('')
  const [eigrpNetworks, setEigrpNetworks] = useState<string[]>([''])
  const [eigrpInterface, setEigrpInterface] = useState('')
  const [bfdProfiles, setBfdProfiles] = useState<BfdProfile[]>([defaultBfdProfile()])
  const [bfdBindings, setBfdBindings] = useState<BfdBinding[]>([defaultBfdBinding()])
  const bfdProfileNames = useMemo(() => bfdProfiles.map(p => p.name).filter(Boolean), [bfdProfiles])
  const [routingApplying, setRoutingApplying] = useState(false)
  const [routingDeleting, setRoutingDeleting] = useState(false)
  const [statusPopupOpen, setStatusPopupOpen] = useState(false)

  // Per-routing-type stash: preserves config when switching between types
  const routingStashRef = useRef<Record<string, Record<string, unknown>>>({})

  const stashCurrentRouting = useCallback((type: RoutingType) => {
    if (type === 'static') {
      routingStashRef.current.static = { routes: staticRoutes }
    } else if (type === 'bgpv4' || type === 'bgpv6') {
      routingStashRef.current[type] = { localAs: bgpLocalAs, routerId: bgpRouterId, neighbors: bgpNeighbors, networks: bgpNetworks, ebgpRequiresPolicy: bgpEbgpRequiresPolicy, defaultIpv4Unicast: bgpDefaultIpv4Unicast }
    } else if (type === 'ospfv2' || type === 'ospfv3') {
      routingStashRef.current[type] = { routerId: ospfRouterId, networks: ospfNetworks, interfaces: ospfInterfaces }
    } else if (type === 'eigrpv4' || type === 'eigrpv6') {
      routingStashRef.current[type] = { as: eigrpAs, routerId: eigrpRouterId, networks: eigrpNetworks, iface: eigrpInterface }
    } else if (type === 'bfd') {
      routingStashRef.current.bfd = { profiles: bfdProfiles, bindings: bfdBindings }
    }
  }, [staticRoutes, bgpLocalAs, bgpRouterId, bgpNeighbors, bgpNetworks, bgpEbgpRequiresPolicy, bgpDefaultIpv4Unicast, ospfRouterId, ospfNetworks, ospfInterfaces, eigrpAs, eigrpRouterId, eigrpNetworks, eigrpInterface, bfdProfiles, bfdBindings])

  const restoreRouting = useCallback((type: RoutingType) => {
    const s = routingStashRef.current[type]
    if (type === 'static') {
      setStaticRoutes(s?.routes as { dest: string; via: string; dev: string }[] || [{ dest: '', via: '', dev: '' }])
    } else if (type === 'bgpv4' || type === 'bgpv6') {
      setBgpLocalAs((s?.localAs as string) ?? ''); setBgpRouterId((s?.routerId as string) ?? '')
      setBgpNeighbors((s?.neighbors as BgpNeighborEntry[]) || [defaultBgpNeighborEntry()])
      setBgpNetworks((s?.networks as string[]) || [''])
      setBgpEbgpRequiresPolicy((s?.ebgpRequiresPolicy as boolean) ?? false)
      setBgpDefaultIpv4Unicast((s?.defaultIpv4Unicast as boolean) ?? false)
    } else if (type === 'ospfv2' || type === 'ospfv3') {
      setOspfRouterId((s?.routerId as string) ?? '')
      setOspfNetworks((s?.networks as { network: string; area: string }[]) || [{ network: '', area: '0' }])
      setOspfInterfaces((s?.interfaces as OspfInterfaceEntry[]) || [defaultOspfIntfEntry()])
    } else if (type === 'eigrpv4' || type === 'eigrpv6') {
      setEigrpAs((s?.as as string) ?? ''); setEigrpRouterId((s?.routerId as string) ?? '')
      setEigrpNetworks((s?.networks as string[]) || [''])
      setEigrpInterface((s?.iface as string) ?? '')
    } else if (type === 'bfd') {
      setBfdProfiles((s?.profiles as BfdProfile[]) || [defaultBfdProfile()])
      setBfdBindings((s?.bindings as BfdBinding[]) || [defaultBfdBinding()])
    }
  }, [])

  const setRoutingType = useCallback((newType: RoutingType) => {
    setRoutingTypeRaw(prev => {
      if (prev !== newType) stashCurrentRouting(prev)
      return newType
    })
    restoreRouting(newType)
  }, [stashCurrentRouting, restoreRouting])

  const handleRoutingApply = useCallback(async () => {
    setRoutingApplying(true)
    try {
      let payload: Record<string, unknown> = { type: routingType }
      if (routingType === 'static') {
        payload.routes = staticRoutes.filter(r => r.dest)
      } else if (routingType === 'bgpv4' || routingType === 'bgpv6') {
        const isV6 = routingType === 'bgpv6'
        const expandedNeighbors: { addr: string; remoteAs: string; cmds: BgpNeighborCmds }[] = []
        for (const nb of bgpNeighbors) {
          if (!nb.addr) continue
          if (nb.scale && nb.count > 1) {
            for (let i = 0; i < nb.count; i++) {
              const addr = isV6
                ? incrementIPv6(nb.addr, nb.hextet, i)
                : incrementIPv4(nb.addr, nb.octet, i)
              expandedNeighbors.push({ addr, remoteAs: nb.remoteAs, cmds: nb.cmds })
            }
          } else {
            expandedNeighbors.push({ addr: nb.addr, remoteAs: nb.remoteAs, cmds: nb.cmds })
          }
        }
        const expandedNets = bgpNetworks.flatMap(n => n.split(',').map(s => s.trim()).filter(Boolean))
        payload = {
          ...payload, local_as: bgpLocalAs, router_id: bgpRouterId,
          networks: expandedNets,
          bgp_neighbors: expandedNeighbors.map(n => ({ addr: n.addr, remote_as: n.remoteAs, ...n.cmds })),
          bgp_ebgp_requires_policy: bgpEbgpRequiresPolicy,
          bgp_default_ipv4_unicast: bgpDefaultIpv4Unicast,
        }
      } else if (routingType === 'ospfv2' || routingType === 'ospfv3') {
        const expandedIfaces: { name: string; cmds: OspfIntfCmds }[] = []
        for (const entry of ospfInterfaces) {
          if (!entry.name) continue
          if (entry.scale) {
            const m = entry.name.match(/^(.*?)(\d+)$/)
            if (m) {
              const base = m[1], start = parseInt(m[2], 10)
              for (let i = 0; i < entry.count; i++) {
                expandedIfaces.push({ name: `${base}${start + i}`, cmds: entry.cmds })
              }
            } else {
              expandedIfaces.push({ name: entry.name, cmds: entry.cmds })
            }
          } else {
            const names = entry.name.split(',').map(n => n.trim()).filter(Boolean)
            for (const n of names) expandedIfaces.push({ name: n, cmds: entry.cmds })
          }
        }
        const ifaceStr = expandedIfaces.map(e => e.name).join(',') || undefined
        const passiveIfaces = expandedIfaces.filter(e => e.cmds.passive).map(e => e.name)
        const firstWithTimers = expandedIfaces.find(e => e.cmds.helloInterval || e.cmds.deadInterval)
        const expandedNetworks = ospfNetworks.flatMap(entry => {
          const nets = entry.network.split(',').map(n => n.trim()).filter(Boolean)
          return nets.map(n => ({ network: n, area: entry.area || '0' }))
        })
        const defaultArea = expandedIfaces[0]?.cmds.area || '0'
        payload = {
          ...payload, router_id: ospfRouterId, ospf_networks: expandedNetworks,
          ospf_passive_interfaces: passiveIfaces,
          ospf_hello_interval: firstWithTimers?.cmds.helloInterval || undefined,
          ospf_dead_interval: firstWithTimers?.cmds.deadInterval || undefined,
          ospf_interface: ifaceStr, ospf_area: defaultArea,
          ospf_interface_cmds: expandedIfaces.map(e => ({ name: e.name, ...e.cmds })),
        }
      } else if (routingType === 'eigrpv4' || routingType === 'eigrpv6') {
        payload = { ...payload, eigrp_as: eigrpAs, eigrp_router_id: eigrpRouterId || undefined, eigrp_networks: eigrpNetworks.filter(Boolean), ospf_interface: eigrpInterface || undefined }
      } else if (routingType === 'bfd') {
        const expandedBindings: { intf: string; peer_addr: string; profile: string }[] = []
        for (const b of bfdBindings) {
          if (!b.profile) continue
          if (b.scale && b.count > 1) {
            const m = b.intfHasNumericSuffix ? b.intf.match(/^(.*?)(\d+)$/) : null
            for (let i = 0; i < b.count; i++) {
              const intf = m ? `${m[1]}${parseInt(m[2], 10) + i}` : b.intf
              const peer = b.peerAddr
                ? (b.isV6 ? incrementIPv6(b.peerAddr, b.hextet, i) : incrementIPv4(b.peerAddr, b.octet, i))
                : ''
              expandedBindings.push({ intf, peer_addr: peer, profile: b.profile })
            }
          } else {
            expandedBindings.push({ intf: b.intf, peer_addr: b.peerAddr, profile: b.profile })
          }
        }
        payload = {
          ...payload,
          bfd_profiles: bfdProfiles.filter(p => p.name).map(p => ({
            name: p.name,
            transmit_interval: p.transmitInterval || undefined,
            receive_interval: p.receiveInterval || undefined,
            detect_multiplier: p.detectMultiplier || undefined,
            passive_mode: p.passiveMode,
            echo_mode: p.echoMode,
            echo_interval: p.echoInterval || undefined,
            minimum_ttl: p.minimumTtl || undefined,
          })),
          bfd_bindings: expandedBindings,
        }
      }
      const res = await fetch('/api/strongswan/overlay-routing/apply', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
        body: JSON.stringify(payload),
      })
      const d = await res.json()
      store.notify(d.message || 'Routing applied', d.success ? 'success' : d.partial ? 'warning' : 'error')
    } catch { store.notify('Routing apply failed', 'error') }
    setRoutingApplying(false)
  }, [routingType, staticRoutes, bgpLocalAs, bgpRouterId, bgpNeighbors, bgpNetworks, bgpEbgpRequiresPolicy, bgpDefaultIpv4Unicast, ospfRouterId, ospfNetworks, ospfInterfaces, eigrpAs, eigrpRouterId, eigrpNetworks, eigrpInterface, bfdProfiles, bfdBindings, store])

  const handleRoutingDelete = useCallback(async () => {
    if (!confirm('Delete routing configuration?')) return
    setRoutingDeleting(true)
    try {
      const res = await fetch('/api/strongswan/overlay-routing/delete', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
        body: JSON.stringify({ type: routingType }),
      })
      const d = await res.json()
      store.notify(d.message || 'Routing deleted', d.success ? 'success' : 'error')
    } catch { store.notify('Routing delete failed', 'error') }
    setRoutingDeleting(false)
  }, [routingType, store])

  const fCls = cn(inputCls, 'w-full')

  return (
    <Section
      title="Routing Configuration"
      defaultOpen
      actions={
        <button
          onClick={() => setStatusPopupOpen(true)}
          disabled={!localConnected}
          className={cn(
            'p-1.5 rounded-md transition-colors',
            localConnected
              ? 'text-surface-500 hover:text-vyper-600 hover:bg-surface-100 dark:hover:bg-surface-800'
              : 'text-surface-300 dark:text-surface-700 cursor-not-allowed',
          )}
          title="View routing config & route table from server"
        >
          <Route className="w-3.5 h-3.5" />
        </button>
      }
    >
      <RoutingStatusPopup open={statusPopupOpen} onClose={() => setStatusPopupOpen(false)} />
      <div className="space-y-2 p-2.5 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50/50 dark:bg-surface-800/30">
        <Field label="Routing Type">
          <select value={routingType} onChange={(e) => setRoutingType(e.target.value as RoutingType)} className={cn(selectCls, 'w-full max-w-[220px]')}>
            <option value="static">Static Routing</option>
            <optgroup label="BGP">
              <option value="bgpv4">BGPv4 (Dynamic)</option>
              <option value="bgpv6">BGPv6 (Dynamic)</option>
            </optgroup>
            <optgroup label="OSPF">
              <option value="ospfv2">OSPFv2</option>
              <option value="ospfv3">OSPFv3</option>
            </optgroup>
            <optgroup label="EIGRP">
              <option value="eigrpv4">EIGRPv4</option>
              <option value="eigrpv6">EIGRPv6</option>
            </optgroup>
            <optgroup label="BFD">
              <option value="bfd">BFD (Profiles & Bindings)</option>
            </optgroup>
          </select>
        </Field>

        {/* Static Routes */}
        {routingType === 'static' && (
          <div className="space-y-1.5">
            <div className="text-[9px] font-medium text-surface-500">Static Routes</div>
            {staticRoutes.map((r, idx) => (
              <div key={idx} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-1.5 items-end">
                <Field label="Destination">
                  <input value={r.dest} onChange={(e) => { const n = [...staticRoutes]; n[idx] = { ...n[idx], dest: e.target.value }; setStaticRoutes(n) }} placeholder="10.0.0.0/8" className={fCls} />
                </Field>
                <Field label="Via (Gateway)">
                  <input value={r.via} onChange={(e) => { const n = [...staticRoutes]; n[idx] = { ...n[idx], via: e.target.value }; setStaticRoutes(n) }} placeholder="169.254.0.2" className={fCls} />
                </Field>
                <Field label="Device">
                  <input value={r.dev} onChange={(e) => { const n = [...staticRoutes]; n[idx] = { ...n[idx], dev: e.target.value }; setStaticRoutes(n) }} placeholder="xfrm1" className={fCls} />
                </Field>
                <button onClick={() => setStaticRoutes(staticRoutes.filter((_, i) => i !== idx))} disabled={staticRoutes.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors pb-1">
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            ))}
            <button onClick={() => setStaticRoutes([...staticRoutes, { dest: '', via: '', dev: '' }])} className={cn(btnCls(), 'text-[10px]')}>
              <Plus className="w-3 h-3" /> Add Route
            </button>
          </div>
        )}

        {/* BGP Configuration */}
        {(routingType === 'bgpv4' || routingType === 'bgpv6') && (
          <div className="space-y-2">
            <div className="text-[9px] font-medium text-surface-500">{routingType === 'bgpv4' ? 'BGPv4' : 'BGPv6'} Configuration</div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Local AS"><input value={bgpLocalAs} onChange={(e) => setBgpLocalAs(e.target.value)} placeholder="65001" className={fCls} /></Field>
              <Field label="Router ID"><input value={bgpRouterId} onChange={(e) => setBgpRouterId(e.target.value)} placeholder="1.1.1.1" className={fCls} /></Field>
            </div>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={bgpEbgpRequiresPolicy} onChange={(e) => setBgpEbgpRequiresPolicy(e.target.checked)} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
              eBGP Requires Policy <span className="text-surface-400">(unchecked = <code className="text-[9px]">no bgp ebgp-requires-policy</code>)</span>
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={bgpDefaultIpv4Unicast} onChange={(e) => setBgpDefaultIpv4Unicast(e.target.checked)} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
              Default IPv4 Unicast <span className="text-surface-400">(unchecked = <code className="text-[9px]">no bgp default ipv4-unicast</code>)</span>
            </label>
            <div className="space-y-1.5">
              <div className="text-[9px] font-medium text-surface-500">Neighbors</div>
              {bgpNeighbors.map((nb, idx) => {
                const isV6 = routingType === 'bgpv6'
                const summary = bgpNeighborCmdsSummary(nb.cmds)
                const updNb = (patch: Partial<BgpNeighborEntry>) => {
                  const n = [...bgpNeighbors]; n[idx] = { ...n[idx], ...patch }; setBgpNeighbors(n)
                }
                return (
                  <div key={idx} className="space-y-1 p-2 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50">
                    <div className="flex items-center gap-1.5">
                      <input value={nb.addr} onChange={(e) => updNb({ addr: e.target.value })} placeholder={isV6 ? 'fd00::2' : '169.254.0.2'} className={cn(fCls, 'flex-1')} />
                      <input value={nb.remoteAs} onChange={(e) => updNb({ remoteAs: e.target.value })} placeholder="Remote AS" className={cn(fCls, 'w-24')} />
                      <div className="flex items-center gap-1">
                        <Toggle checked={nb.scale} onChange={(v) => updNb({ scale: v })} />
                        <span className="text-[9px] text-surface-500">Scale</span>
                      </div>
                      {nb.scale && (
                        <>
                          <input type="number" min={1} value={nb.count} onChange={(e) => updNb({ count: parseInt(e.target.value) || 1 })} className={cn(fCls, 'w-14 text-center')} />
                          <select value={isV6 ? nb.hextet : nb.octet} onChange={(e) => updNb(isV6 ? { hextet: parseInt(e.target.value) } : { octet: parseInt(e.target.value) })} className={cn(selectCls, 'w-20')}>
                            {(isV6 ? [1,2,3,4,5,6,7,8] : [1,2,3,4]).map(n => (
                              <option key={n} value={n}>{isV6 ? `Hextet ${n}` : `Octet ${n}`}</option>
                            ))}
                          </select>
                        </>
                      )}
                      <button onClick={() => setBgpNeighborPopupIdx(idx)} className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-700 text-surface-400 hover:text-vyper-600 transition-colors" title="Neighbor commands">
                        <Settings className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setBgpNeighbors(bgpNeighbors.filter((_, i) => i !== idx))} disabled={bgpNeighbors.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                    {summary && (
                      <div className="text-[9px] text-surface-400 pl-1 truncate" title={summary}>
                        neighbor: {summary}
                      </div>
                    )}
                  </div>
                )
              })}
              <button onClick={() => setBgpNeighbors([...bgpNeighbors, defaultBgpNeighborEntry()])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Neighbor
              </button>
            </div>
            {bgpNeighborPopupIdx != null && bgpNeighbors[bgpNeighborPopupIdx] && (
              <BgpNeighborCmdsPopup
                entry={bgpNeighbors[bgpNeighborPopupIdx]}
                isV6={routingType === 'bgpv6'}
                profiles={bfdProfileNames}
                onChange={(cmds) => {
                  const n = [...bgpNeighbors]; n[bgpNeighborPopupIdx] = { ...n[bgpNeighborPopupIdx], cmds }; setBgpNeighbors(n)
                }}
                onClose={() => setBgpNeighborPopupIdx(null)}
              />
            )}
            <div className="space-y-1">
              <div className="text-[9px] font-medium text-surface-500">Advertised Networks <span className="text-surface-400">(comma-separated per row)</span></div>
              {bgpNetworks.map((net, idx) => (
                <div key={idx} className="flex items-center gap-1.5">
                  <input value={net} onChange={(e) => { const n = [...bgpNetworks]; n[idx] = e.target.value; setBgpNetworks(n) }} placeholder={routingType === 'bgpv6' ? 'fd01::/64, fd02::/64' : '192.168.1.0/24, 10.0.0.0/8'} className={fCls} />
                  <button onClick={() => setBgpNetworks(bgpNetworks.filter((_, i) => i !== idx))} disabled={bgpNetworks.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
              <button onClick={() => setBgpNetworks([...bgpNetworks, ''])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Network
              </button>
            </div>
          </div>
        )}

        {/* OSPF Configuration */}
        {(routingType === 'ospfv2' || routingType === 'ospfv3') && (
          <div className="space-y-2">
            <div className="text-[9px] font-medium text-surface-500">{routingType === 'ospfv2' ? 'OSPFv2' : 'OSPFv3'} Configuration</div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Router ID"><input value={ospfRouterId} onChange={(e) => setOspfRouterId(e.target.value)} placeholder="1.1.1.1" className={fCls} /></Field>
            </div>
            <div className="space-y-1.5">
              <div className="text-[9px] font-medium text-surface-500">Interfaces</div>
              {ospfInterfaces.map((entry, idx) => {
                const isV3 = routingType === 'ospfv3'
                const summary = ospfCmdsSummary(entry.cmds, isV3)
                const updIntf = (patch: Partial<OspfInterfaceEntry>) => {
                  const n = [...ospfInterfaces]; n[idx] = { ...n[idx], ...patch }; setOspfInterfaces(n)
                }
                return (
                  <div key={idx} className="space-y-1 p-2 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50">
                    <div className="flex items-center gap-1.5">
                      <input value={entry.name} onChange={(e) => updIntf({ name: e.target.value })} placeholder={entry.scale ? 'xfrm1' : 'xfrm1, xfrm2, xfrm3'} title={entry.scale ? 'Single interface name (will be scaled)' : 'Comma-separated interface names'} className={cn(fCls, 'flex-1')} />
                      <Toggle checked={entry.scale} onChange={(v) => updIntf({ scale: v })} label="Scale" />
                      {entry.scale && (
                        <input type="number" value={entry.count || ''} min={1} max={500}
                          onChange={(e) => updIntf({ count: e.target.value === '' ? 0 : Math.max(1, Number(e.target.value)) })}
                          onBlur={() => { if (!entry.count) updIntf({ count: 1 }) }}
                          className={cn(inputCls, 'w-16')} placeholder="Count" />
                      )}
                      <button onClick={() => setOspfCmdPopupIdx(idx)} className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-700 text-surface-500 hover:text-vyper-500 transition-colors" title={`Configure ${isV3 ? 'ipv6 ospf6' : 'ip ospf'} commands`}>
                        <Settings className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => setOspfInterfaces(ospfInterfaces.filter((_, i) => i !== idx))} disabled={ospfInterfaces.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors disabled:opacity-30">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                    {entry.scale && entry.name && entry.count > 1 && (() => {
                      const m = entry.name.match(/^(.*?)(\d+)$/)
                      if (!m) return null
                      const items = Array.from({ length: Math.min(entry.count, 5) }, (_, i) => `${m[1]}${parseInt(m[2], 10) + i}`)
                      if (entry.count > 5) items.push('...')
                      return <div className="text-[9px] text-surface-400 font-mono pl-0.5">{items.join(', ')}</div>
                    })()}
                    {summary && (
                      <div className="text-[9px] text-vyper-500 dark:text-vyper-400 font-mono pl-0.5 truncate" title={summary}>
                        {isV3 ? 'ipv6 ospf6' : 'ip ospf'}: {summary}
                      </div>
                    )}
                  </div>
                )
              })}
              <button onClick={() => setOspfInterfaces([...ospfInterfaces, defaultOspfIntfEntry()])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Interface
              </button>
            </div>
            {ospfCmdPopupIdx !== null && ospfInterfaces[ospfCmdPopupIdx] && (
              <OspfIntfCmdsPopup
                entry={ospfInterfaces[ospfCmdPopupIdx]}
                isV3={routingType === 'ospfv3'}
                profiles={bfdProfileNames}
                onChange={(cmds) => {
                  const n = [...ospfInterfaces]; n[ospfCmdPopupIdx] = { ...n[ospfCmdPopupIdx], cmds }; setOspfInterfaces(n)
                }}
                onClose={() => setOspfCmdPopupIdx(null)}
              />
            )}
            <div className="space-y-1">
              <div className="text-[9px] font-medium text-surface-500">{routingType === 'ospfv2' ? 'Networks (with area)' : 'Networks'}</div>
              {ospfNetworks.map((entry, idx) => (
                <div key={idx} className="flex items-center gap-1.5">
                  <input value={entry.network} onChange={(e) => { const n = [...ospfNetworks]; n[idx] = { ...n[idx], network: e.target.value }; setOspfNetworks(n) }} placeholder={routingType === 'ospfv3' ? 'fd01::/64' : '192.168.1.0/24, 10.0.0.0/8'} title="Comma-separated networks allowed" className={cn(fCls, 'flex-1')} />
                  {routingType === 'ospfv2' && (
                    <input value={entry.area} onChange={(e) => { const n = [...ospfNetworks]; n[idx] = { ...n[idx], area: e.target.value }; setOspfNetworks(n) }} placeholder="0" className={cn(fCls, 'w-16')} title="Area" />
                  )}
                  <button onClick={() => setOspfNetworks(ospfNetworks.filter((_, i) => i !== idx))} disabled={ospfNetworks.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
              <button onClick={() => setOspfNetworks([...ospfNetworks, { network: '', area: '0' }])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Network
              </button>
            </div>
          </div>
        )}

        {/* BFD Configuration */}
        {routingType === 'bfd' && (
          <div className="space-y-3">
            <div className="text-[9px] font-medium text-surface-500">BFD Profiles &amp; Interface Bindings</div>
            <div className="text-[9px] text-surface-500 bg-surface-100 dark:bg-surface-800/40 border border-surface-200 dark:border-surface-700 rounded px-2 py-1">
              Define BFD profiles here, then reference them by name from OSPFv2/v3 interface commands or BGPv4/v6 neighbor commands. Optionally, bind profiles to specific interfaces below to create standalone BFD peers (FRR <code className="text-[9px]">bfd peer X interface Y profile Z</code>).
            </div>
            <div className="space-y-1.5">
              <div className="text-[9px] font-medium text-surface-500">Profiles</div>
              {bfdProfiles.map((p, idx) => {
                const updP = (patch: Partial<BfdProfile>) => {
                  const n = [...bfdProfiles]; n[idx] = { ...n[idx], ...patch }; setBfdProfiles(n)
                }
                return (
                  <div key={idx} className="space-y-1.5 p-2 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50">
                    <div className="grid grid-cols-[1fr_1fr_1fr_1fr_auto] gap-1.5 items-end">
                      <Field label="Profile Name"><input value={p.name} onChange={e => updP({ name: e.target.value })} placeholder="VTI_BFDTEMPLATE_1" className={fCls} /></Field>
                      <Field label="TX Interval (ms)"><input value={p.transmitInterval} onChange={e => updP({ transmitInterval: e.target.value })} placeholder="300" className={fCls} /></Field>
                      <Field label="RX Interval (ms)"><input value={p.receiveInterval} onChange={e => updP({ receiveInterval: e.target.value })} placeholder="300" className={fCls} /></Field>
                      <Field label="Multiplier"><input value={p.detectMultiplier} onChange={e => updP({ detectMultiplier: e.target.value })} placeholder="3" className={fCls} /></Field>
                      <button onClick={() => setBfdProfiles(bfdProfiles.filter((_, i) => i !== idx))} disabled={bfdProfiles.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors pb-1">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                    <div className="grid grid-cols-[auto_auto_1fr_1fr] gap-x-3 gap-y-1 items-end">
                      <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
                        <input type="checkbox" checked={p.passiveMode} onChange={e => updP({ passiveMode: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Passive Mode
                      </label>
                      <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
                        <input type="checkbox" checked={p.echoMode} onChange={e => updP({ echoMode: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Echo Mode
                      </label>
                      {p.echoMode ? (
                        <Field label="Echo Interval (ms)"><input value={p.echoInterval} onChange={e => updP({ echoInterval: e.target.value })} placeholder="50" className={fCls} /></Field>
                      ) : <div />}
                      <Field label="Minimum TTL (multihop)"><input value={p.minimumTtl} onChange={e => updP({ minimumTtl: e.target.value })} placeholder="" className={fCls} /></Field>
                    </div>
                  </div>
                )
              })}
              <button onClick={() => setBfdProfiles([...bfdProfiles, defaultBfdProfile()])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Profile
              </button>
            </div>
            <div className="space-y-1.5">
              <div className="text-[9px] font-medium text-surface-500">Interface Bindings <span className="text-surface-400">(applies profile to a BFD peer reachable via this interface)</span></div>
              {bfdBindings.map((b, idx) => {
                const updB = (patch: Partial<BfdBinding>) => {
                  const n = [...bfdBindings]; n[idx] = { ...n[idx], ...patch }; setBfdBindings(n)
                }
                return (
                  <div key={idx} className="space-y-1 p-2 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <input value={b.intf} onChange={e => updB({ intf: e.target.value })} placeholder="xfrm1" className={cn(fCls, 'w-28')} />
                      <input value={b.peerAddr} onChange={e => updB({ peerAddr: e.target.value })} placeholder={b.isV6 ? 'fd00::2' : '169.254.0.2'} className={cn(fCls, 'w-40')} />
                      <select value={b.isV6 ? 'v6' : 'v4'} onChange={e => updB({ isV6: e.target.value === 'v6' })} className={cn(selectCls, 'w-16')}>
                        <option value="v4">IPv4</option>
                        <option value="v6">IPv6</option>
                      </select>
                      <select value={b.profile} onChange={e => updB({ profile: e.target.value })} className={cn(selectCls, 'flex-1 min-w-[120px]')}>
                        <option value="">(select profile)</option>
                        {bfdProfileNames.map(p => <option key={p} value={p}>{p}</option>)}
                      </select>
                      <div className="flex items-center gap-1">
                        <Toggle checked={b.scale} onChange={(v) => updB({ scale: v })} />
                        <span className="text-[9px] text-surface-500">Scale</span>
                      </div>
                      {b.scale && (
                        <>
                          <input type="number" min={1} value={b.count} onChange={e => updB({ count: parseInt(e.target.value) || 1 })} className={cn(fCls, 'w-14 text-center')} />
                          <select value={b.isV6 ? b.hextet : b.octet} onChange={e => updB(b.isV6 ? { hextet: parseInt(e.target.value) } : { octet: parseInt(e.target.value) })} className={cn(selectCls, 'w-20')}>
                            {(b.isV6 ? [1,2,3,4,5,6,7,8] : [1,2,3,4]).map(n => (
                              <option key={n} value={n}>{b.isV6 ? `Hextet ${n}` : `Octet ${n}`}</option>
                            ))}
                          </select>
                        </>
                      )}
                      <button onClick={() => setBfdBindings(bfdBindings.filter((_, i) => i !== idx))} disabled={bfdBindings.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                    {b.scale && b.intf && b.count > 1 && (() => {
                      const m = b.intf.match(/^(.*?)(\d+)$/)
                      if (!m) return null
                      const items = Array.from({ length: Math.min(b.count, 4) }, (_, i) => `${m[1]}${parseInt(m[2], 10) + i}`)
                      if (b.count > 4) items.push('...')
                      return <div className="text-[9px] text-surface-400 font-mono pl-0.5">interfaces: {items.join(', ')}</div>
                    })()}
                  </div>
                )
              })}
              <button onClick={() => setBfdBindings([...bfdBindings, defaultBfdBinding()])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Binding
              </button>
            </div>
          </div>
        )}

        {/* EIGRP Configuration */}
        {(routingType === 'eigrpv4' || routingType === 'eigrpv6') && (
          <div className="space-y-2">
            <div className="text-[9px] font-medium text-surface-500">{routingType === 'eigrpv4' ? 'EIGRPv4' : 'EIGRPv6'} Configuration</div>
            <div className="text-[9px] text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/50 rounded px-2 py-1">
              <strong>Note:</strong> FRR's <code className="text-[9px]">eigrpd</code> does not support BFD. Use the BFD section to bind profiles to interfaces directly via <code className="text-[9px]">bfd peer ... interface</code>.
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="EIGRP AS Number"><input value={eigrpAs} onChange={(e) => setEigrpAs(e.target.value)} placeholder="100" className={fCls} /></Field>
              <Field label="Router ID"><input value={eigrpRouterId} onChange={(e) => setEigrpRouterId(e.target.value)} placeholder="1.1.1.1" className={fCls} /></Field>
              {routingType === 'eigrpv6' && (
                <Field label="Interface"><input value={eigrpInterface} onChange={(e) => setEigrpInterface(e.target.value)} placeholder="xfrm1" className={fCls} /></Field>
              )}
            </div>
            <div className="space-y-1">
              <div className="text-[9px] font-medium text-surface-500">Advertised Networks</div>
              {eigrpNetworks.map((net, idx) => (
                <div key={idx} className="flex items-center gap-1.5">
                  <input value={net} onChange={(e) => { const n = [...eigrpNetworks]; n[idx] = e.target.value; setEigrpNetworks(n) }} placeholder={routingType === 'eigrpv6' ? 'fd01::/64' : '192.168.1.0/24'} className={fCls} />
                  <button onClick={() => setEigrpNetworks(eigrpNetworks.filter((_, i) => i !== idx))} disabled={eigrpNetworks.length <= 1} className="text-surface-400 hover:text-red-500 transition-colors">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
              <button onClick={() => setEigrpNetworks([...eigrpNetworks, ''])} className={cn(btnCls(), 'text-[10px]')}>
                <Plus className="w-3 h-3" /> Add Network
              </button>
            </div>
          </div>
        )}

        {/* Apply / Delete buttons */}
        <div className="flex items-center gap-2 pt-1">
          <button onClick={handleRoutingApply} disabled={!localConnected || routingApplying} className={btnCls('success')}>
            {routingApplying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />} Apply
          </button>
          <button onClick={handleRoutingDelete} disabled={!localConnected || routingDeleting} className={btnCls('danger')}>
            {routingDeleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />} Delete
          </button>
          <span className="text-[9px] text-surface-400 ml-auto">Applies/removes routing via FR Routing/vtysh on the connected server</span>
        </div>
      </div>
    </Section>
  )
}

// ── Main exported component ──

export default function RoutingAdministration() {
  return (
    <div className="space-y-3">
      <h5 className="flex items-center gap-1.5 text-[11px] font-semibold text-surface-600 dark:text-surface-400 border-b border-surface-100 dark:border-surface-800 pb-1.5">
        <Network className="w-3.5 h-3.5 text-surface-400" /> Administration
      </h5>
      <FrrServicePanel />
      <RoutingBuilder />
    </div>
  )
}
