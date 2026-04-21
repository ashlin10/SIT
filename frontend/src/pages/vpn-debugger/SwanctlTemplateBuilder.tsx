import { useState, useCallback, useEffect, useRef } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, inputCls, selectCls } from '@/lib/utils'
import { X, Eye, Save, Plus, Trash2, ChevronRight, Download, FolderOpen, Network, Loader2, Play, Settings } from 'lucide-react'
import Toggle from '@/components/Toggle'

// ── IP Helpers ──

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

function incrementIP(ip: string, octet: number, amount: number) {
  if (ip.split('/')[0].includes(':')) return incrementIPv6(ip, octet, amount)
  return incrementIPv4(ip, octet, amount)
}

// ── Types ──

interface IPBlock {
  enabled: boolean
  tunnelCount: number
  connPrefix: string
  childPrefix: string
  startIndex: number
  localAddr: string; localAddrInc: boolean; localAddrOctet: number
  remoteAddr: string; remoteAddrInc: boolean; remoteAddrOctet: number
  localTs: string; localTsInc: boolean; localTsOctet: number
  remoteTs: string; remoteTsInc: boolean; remoteTsOctet: number
}

const defaultIPv4Block: IPBlock = {
  enabled: true, tunnelCount: 1, connPrefix: 'tunnel', childPrefix: 'ipsec', startIndex: 1,
  localAddr: '', localAddrInc: false, localAddrOctet: 4,
  remoteAddr: '', remoteAddrInc: false, remoteAddrOctet: 4,
  localTs: '', localTsInc: false, localTsOctet: 4,
  remoteTs: '', remoteTsInc: false, remoteTsOctet: 4,
}

const defaultIPv6Block: IPBlock = {
  enabled: true, tunnelCount: 0, connPrefix: 'tunnel6', childPrefix: 'ipsec6', startIndex: 1,
  localAddr: '', localAddrInc: false, localAddrOctet: 8,
  remoteAddr: '', remoteAddrInc: false, remoteAddrOctet: 8,
  localTs: '', localTsInc: false, localTsOctet: 8,
  remoteTs: '', remoteTsInc: false, remoteTsOctet: 8,
}

// ── Collapsible Section ──

function Section({ title, children, defaultOpen = true }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-surface-200 dark:border-surface-700 rounded-lg overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-1.5 px-3 py-2 bg-surface-50 dark:bg-surface-800/50 text-[11px] font-semibold text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
        <ChevronRight className={cn('w-3 h-3 transition-transform', open && 'rotate-90')} />
        {title}
      </button>
      {open && <div className="p-3 space-y-2">{children}</div>}
    </div>
  )
}

// ── Field Helper ──

function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <label className="block text-[9px] font-medium text-surface-500 mb-0.5">{label}</label>
      {children}
    </div>
  )
}

// ── OSPF Interface Entry Type ──

interface OspfIntfCmds {
  area: string
  cost: string
  helloInterval: string
  deadInterval: string
  priority: string
  retransmitInterval: string
  transmitDelay: string
  networkType: string   // '' | 'broadcast' | 'non-broadcast' | 'point-to-point' | 'point-to-multipoint'
  passive: boolean
  mtuIgnore: boolean
  bfd: boolean
  authType: string      // '' | 'null' | 'message-digest'
  authKey: string
  mdKeyId: string
  mdKey: string
  instanceId: string    // OSPFv2 only: 1-65535
  // OSPFv3 extras
  ifmtu: string
  advertisePrefix: boolean
}

const defaultOspfIntfCmds: OspfIntfCmds = {
  area: '0', cost: '', helloInterval: '', deadInterval: '', priority: '',
  retransmitInterval: '', transmitDelay: '', networkType: '', passive: false,
  mtuIgnore: false, bfd: false, authType: '', authKey: '', mdKeyId: '', mdKey: '',
  instanceId: '', ifmtu: '', advertisePrefix: false,
}

interface OspfInterfaceEntry {
  name: string
  scale: boolean
  count: number
  cmds: OspfIntfCmds
}

const defaultOspfIntfEntry = (): OspfInterfaceEntry => ({
  name: '', scale: false, count: 1, cmds: { ...defaultOspfIntfCmds },
})

// ── OSPF Interface Commands Popup ──

function OspfIntfCmdsPopup({ entry, isV3, onChange, onClose }: {
  entry: OspfInterfaceEntry
  isV3: boolean
  onChange: (cmds: OspfIntfCmds) => void
  onClose: () => void
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
            {isV3 && (
              <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
                <input type="checkbox" checked={c.advertisePrefix} onChange={e => upd({ advertisePrefix: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Advertise Prefix
              </label>
            )}
          </div>
          {/* Authentication */}
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

// ── OSPF Interface Commands Summary ──

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
  if (cmds.bfd) parts.push('bfd')
  if (cmds.authType) parts.push(`auth:${cmds.authType}`)
  if (!isV3 && cmds.instanceId) parts.push(`inst ${cmds.instanceId}`)
  if (isV3 && cmds.ifmtu) parts.push(`ifmtu ${cmds.ifmtu}`)
  if (isV3 && cmds.advertisePrefix) parts.push('adv-prefix')
  return parts.join(', ')
}

// ── BGP Neighbor Entry Type ──

interface BgpNeighborCmds {
  password: string
  ebgpMultihop: string        // TTL value, '' = disabled
  bfd: boolean
  updateSource: string        // interface or IP
  nextHopSelf: boolean
  defaultOriginate: boolean
  softReconfigInbound: boolean
  routeMapIn: string
  routeMapOut: string
  prefixListIn: string
  prefixListOut: string
  keepAlive: string           // seconds
  holdTime: string            // seconds
  weight: string
  allowasIn: string           // number of occurrences, '' = disabled
}

const defaultBgpNeighborCmds: BgpNeighborCmds = {
  password: '', ebgpMultihop: '', bfd: false, updateSource: '',
  nextHopSelf: false, defaultOriginate: false, softReconfigInbound: false,
  routeMapIn: '', routeMapOut: '', prefixListIn: '', prefixListOut: '',
  keepAlive: '', holdTime: '', weight: '', allowasIn: '',
}

interface BgpNeighborEntry {
  addr: string
  remoteAs: string
  scale: boolean
  count: number
  octet: number    // 1-4 for IPv4
  hextet: number   // 1-8 for IPv6
  cmds: BgpNeighborCmds
}

const defaultBgpNeighborEntry = (): BgpNeighborEntry => ({
  addr: '', remoteAs: '', scale: false, count: 1, octet: 4, hextet: 8,
  cmds: { ...defaultBgpNeighborCmds },
})

function BgpNeighborCmdsPopup({ entry, isV6, onChange, onClose }: {
  entry: BgpNeighborEntry
  isV6: boolean
  onChange: (cmds: BgpNeighborCmds) => void
  onClose: () => void
}) {
  const [c, setC] = useState<BgpNeighborCmds>({ ...entry.cmds })
  const upd = (patch: Partial<BgpNeighborCmds>) => setC(prev => ({ ...prev, ...patch }))
  const pCls = cn(inputCls, 'w-full')

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
          {/* Authentication */}
          <div className="space-y-2">
            <div className="text-[9px] font-semibold text-surface-500 uppercase tracking-wider">Authentication</div>
            <div className="grid grid-cols-2 gap-2">
              <Field label="Password"><input value={c.password} onChange={e => upd({ password: e.target.value })} placeholder="" className={pCls} /></Field>
            </div>
          </div>
          {/* Timers */}
          <div className="grid grid-cols-2 gap-2">
            <Field label="Keep-Alive (sec)"><input value={c.keepAlive} onChange={e => upd({ keepAlive: e.target.value })} placeholder="60" className={pCls} /></Field>
            <Field label="Hold Time (sec)"><input value={c.holdTime} onChange={e => upd({ holdTime: e.target.value })} placeholder="180" className={pCls} /></Field>
          </div>
          {/* eBGP Multihop / BFD */}
          <div className="grid grid-cols-2 gap-2">
            <Field label="eBGP Multihop (TTL)"><input value={c.ebgpMultihop} onChange={e => upd({ ebgpMultihop: e.target.value })} placeholder="" className={pCls} /></Field>
            <Field label="Update Source"><input value={c.updateSource} onChange={e => upd({ updateSource: e.target.value })} placeholder={isV6 ? 'lo' : '10.0.0.1'} className={pCls} /></Field>
          </div>
          <Field label="Weight"><input value={c.weight} onChange={e => upd({ weight: e.target.value })} placeholder="" className={pCls} /></Field>
          <Field label="Allowas-In (occurrences)"><input value={c.allowasIn} onChange={e => upd({ allowasIn: e.target.value })} placeholder="" className={pCls} /></Field>
          {/* Checkboxes */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.bfd} onChange={e => upd({ bfd: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> BFD
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.nextHopSelf} onChange={e => upd({ nextHopSelf: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Next-Hop Self
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.defaultOriginate} onChange={e => upd({ defaultOriginate: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Default Originate
            </label>
            <label className="flex items-center gap-1.5 text-[10px] text-surface-600 dark:text-surface-400">
              <input type="checkbox" checked={c.softReconfigInbound} onChange={e => upd({ softReconfigInbound: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" /> Soft Reconfiguration Inbound
            </label>
          </div>
          {/* Route Maps & Prefix Lists */}
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
  if (cmds.bfd) parts.push('bfd')
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

// ── Proposal Algorithms ──

const ALGORITHMS = {
  encryption: ['aes128', 'aes192', 'aes256', 'aes128ctr', 'aes192ctr', 'aes256ctr', '3des', 'blowfish128', 'blowfish192', 'blowfish256', 'camellia128', 'camellia192', 'camellia256', 'cast128', 'chacha20poly1305', 'null'],
  integrity: ['sha1', 'sha256', 'sha384', 'sha512', 'md5', 'aesxcbc', 'aescmac'],
  prf: ['prfsha1', 'prfsha256', 'prfsha384', 'prfsha512', 'prfmd5', 'prfaesxcbc', 'prfaescmac'],
  dh: ['modp768', 'modp1024', 'modp1536', 'modp2048', 'modp3072', 'modp4096', 'modp6144', 'modp8192', 'ecp256', 'ecp384', 'ecp521', 'ecp256bp', 'ecp384bp', 'ecp512bp', 'x25519', 'x448', 'curve25519', 'curve448'],
  ake: ['mlkem512', 'mlkem768', 'mlkem1024', 'modp768', 'modp1024', 'modp1536', 'modp2048', 'modp3072', 'modp4096', 'modp6144', 'modp8192', 'ecp256', 'ecp384', 'ecp521', 'ecp256bp', 'ecp384bp', 'ecp512bp', 'x25519', 'x448', 'curve25519', 'curve448', 'none'],
  aead: ['aes128gcm8', 'aes128gcm12', 'aes128gcm16', 'aes192gcm8', 'aes192gcm12', 'aes192gcm16', 'aes256gcm8', 'aes256gcm12', 'aes256gcm16', 'aes128ccm8', 'aes128ccm12', 'aes128ccm16', 'aes192ccm8', 'aes192ccm12', 'aes192ccm16', 'aes256ccm8', 'aes256ccm12', 'aes256ccm16', 'chacha20poly1305'],
  esn: ['esn', 'noesn'],
}

const DH_NUMBERS: Record<string, number> = {
  modp768: 1, modp1024: 2, modp1536: 5, modp2048: 14, modp3072: 15,
  modp4096: 16, modp6144: 17, modp8192: 18, ecp256: 19, ecp384: 20,
  ecp521: 21, ecp256bp: 28, ecp384bp: 29, ecp512bp: 30,
  x25519: 31, x448: 32, curve25519: 31, curve448: 32,
  mlkem512: 35, mlkem768: 36, mlkem1024: 37,
}

const DH_KEYS = new Set(['dh', 'ake1', 'ake2', 'ake3', 'ake4', 'ake5', 'ake6', 'ake7'])

function algLabel(algo: string, group: string): string {
  if (DH_KEYS.has(group) && DH_NUMBERS[algo] !== undefined) return `${algo} (${DH_NUMBERS[algo]})`
  return algo
}

interface ProposalState {
  enc: string[]; integ: string[]; prf: string[]; dh: string[]; aead: string[]; esn: string[]
  ake1: string[]; ake2: string[]; ake3: string[]; ake4: string[]; ake5: string[]; ake6: string[]; ake7: string[]
}

const emptyProposal = (): ProposalState => ({
  enc: [], integ: [], prf: [], dh: [], aead: [], esn: [],
  ake1: [], ake2: [], ake3: [], ake4: [], ake5: [], ake6: [], ake7: [],
})

function buildProposalString(p: ProposalState, isIke: boolean): string {
  const akeParts: string[] = []
  for (let n = 1; n <= 7; n++) {
    const vals = p[`ake${n}` as keyof ProposalState] as string[]
    vals.forEach(a => akeParts.push(`ke${n}_${a}`))
  }
  if (p.aead.length > 0) {
    const parts = [...p.aead]
    if (p.dh.length > 0) parts.push(...p.dh)
    parts.push(...akeParts)
    if (isIke && p.prf.length > 0) parts.push(...p.prf)
    if (!isIke && p.esn.length > 0) parts.push(...p.esn)
    return parts.join('-')
  }
  if (p.enc.length === 0 && p.integ.length === 0 && p.dh.length === 0 && akeParts.length === 0) return ''
  const parts: string[] = []
  if (p.enc.length > 0) parts.push(...p.enc)
  if (p.integ.length > 0) parts.push(...p.integ)
  if (isIke && p.prf.length > 0) parts.push(...p.prf)
  if (p.dh.length > 0) parts.push(...p.dh)
  parts.push(...akeParts)
  if (!isIke && p.esn.length > 0) parts.push(...p.esn)
  return parts.join('-')
}

// ── Multi-Select Dropdown ──

function MultiSelectDropdown({ label, group, options, selected, onChange }: {
  label: string; group: string; options: string[]; selected: string[]; onChange: (vals: string[]) => void
}) {
  const [open, setOpen] = useState(false)
  const toggle = (val: string) => {
    if (selected.includes(val)) onChange(selected.filter(v => v !== val))
    else onChange([...selected, val])
  }
  const remove = (val: string) => onChange(selected.filter(v => v !== val))
  return (
    <div className="space-y-1">
      <label className="block text-[9px] font-medium text-surface-500">{label}</label>
      <div className="relative">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          className={cn(
            'w-full flex items-center justify-between gap-1 px-2 py-1 rounded-md border text-[10px] transition-colors',
            'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800',
            'hover:border-vyper-400 dark:hover:border-vyper-500',
            open && 'ring-1 ring-vyper-500/20 border-vyper-500',
          )}
        >
          <span className="truncate text-surface-600 dark:text-surface-400">
            {selected.length > 0 ? selected.map(v => algLabel(v, group)).join(', ') : 'Select...'}
          </span>
          <ChevronRight className={cn('w-3 h-3 shrink-0 text-surface-400 transition-transform', open && 'rotate-90')} />
        </button>
        {open && (
          <div className="absolute z-20 left-0 right-0 mt-1 max-h-40 overflow-auto rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800 shadow-lg py-0.5">
            {options.map(a => (
              <label key={a} className="flex items-center gap-1.5 px-2 py-0.5 text-[10px] text-surface-700 dark:text-surface-300 hover:bg-surface-50 dark:hover:bg-surface-700/50 cursor-pointer">
                <input type="checkbox" checked={selected.includes(a)} onChange={() => toggle(a)} className="rounded border-surface-300 dark:border-surface-600 text-vyper-500 w-3 h-3" />
                {algLabel(a, group)}
              </label>
            ))}
          </div>
        )}
      </div>
      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {selected.map(v => (
            <span key={v} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-vyper-500/10 text-vyper-600 dark:text-vyper-400 text-[9px] font-medium">
              {algLabel(v, group)}
              <button onClick={() => remove(v)} className="text-vyper-500/60 hover:text-vyper-500 transition-colors">
                <X className="w-2.5 h-2.5" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Proposal Builder Section ──

function ProposalBuilder({ title, isIke, state, onChange }: {
  title: string; isIke: boolean; state: ProposalState; onChange: (s: ProposalState) => void
}) {
  const set = (key: keyof ProposalState, vals: string[]) => onChange({ ...state, [key]: vals })
  const [showAke, setShowAke] = useState(false)
  return (
    <Section title={title} defaultOpen={false}>
      <div className="grid grid-cols-2 gap-3">
        <MultiSelectDropdown label="Encryption" group="enc" options={ALGORITHMS.encryption} selected={state.enc} onChange={v => set('enc', v)} />
        <MultiSelectDropdown label="Integrity" group="integ" options={ALGORITHMS.integrity} selected={state.integ} onChange={v => set('integ', v)} />
      </div>
      <div className="grid grid-cols-2 gap-3 mt-2">
        {isIke && <MultiSelectDropdown label="PRF (Pseudo-Random Function)" group="prf" options={ALGORITHMS.prf} selected={state.prf} onChange={v => set('prf', v)} />}
        <MultiSelectDropdown label="Key Exchange (DH Group)" group="dh" options={ALGORITHMS.dh} selected={state.dh} onChange={v => set('dh', v)} />
      </div>
      <div className={cn('grid gap-3 mt-2', isIke ? 'grid-cols-1' : 'grid-cols-2')}>
        <MultiSelectDropdown label="AEAD (Combined Mode)" group="aead" options={ALGORITHMS.aead} selected={state.aead} onChange={v => set('aead', v)} />
        {!isIke && <MultiSelectDropdown label="ESN (Extended Sequence Numbers)" group="esn" options={ALGORITHMS.esn} selected={state.esn} onChange={v => set('esn', v)} />}
      </div>
      <div className="mt-3 pt-2 border-t border-surface-200 dark:border-surface-700">
        <button type="button" onClick={() => setShowAke(!showAke)} className="text-[10px] font-semibold text-surface-500 hover:text-surface-700 dark:hover:text-surface-400 transition-colors flex items-center gap-1">
          <ChevronRight className={cn('w-3 h-3 transition-transform', showAke && 'rotate-90')} />
          Additional Key Exchanges (ke1_ .. ke7_)
        </button>
        {showAke && (
          <div className="grid grid-cols-4 gap-2 mt-2">
            {([1,2,3,4,5,6,7] as const).map(n => (
              <MultiSelectDropdown key={n} label={`ke${n}_`} group={`ake${n}`} options={ALGORITHMS.ake} selected={state[`ake${n}` as keyof ProposalState] as string[]} onChange={v => set(`ake${n}` as keyof ProposalState, v)} />
            ))}
          </div>
        )}
      </div>
      {/* Preview of assembled proposal string */}
      {(() => {
        const str = buildProposalString(state, isIke)
        return str ? (
          <div className="mt-2 px-2 py-1 rounded-md bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700">
            <span className="text-[9px] font-medium text-surface-400">Proposal:</span>
            <span className="text-[10px] font-mono text-surface-700 dark:text-surface-300 ml-1.5 break-all">{str}</span>
          </div>
        ) : null
      })()}
    </Section>
  )
}

// ── IP Block Editor ──

function IPBlockEditor({ block, onChange, isV6, onDelete, tsDisabled }: { block: IPBlock; onChange: (b: IPBlock) => void; isV6: boolean; onDelete?: () => void; tsDisabled?: boolean }) {
  const octetOptions = isV6
    ? [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ v: n, l: `${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}${n === 8 ? ' (last)' : ''}` }))
    : [4, 3, 2, 1].map((n) => ({ v: n, l: `${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}` }))

  const ipRow = (label: string, val: string, setVal: (v: string) => void, inc: boolean, setInc: (v: boolean) => void, octet: number, setOctet: (v: number) => void, placeholder: string, disabled?: boolean) => (
    <div className="grid grid-cols-[1fr_auto_auto] gap-1.5 items-end">
      <Field label={label}>
        <input value={val} onChange={(e) => setVal(e.target.value)} placeholder={placeholder} disabled={disabled} className={cn(inputCls, 'w-full', disabled && 'opacity-50 cursor-not-allowed bg-surface-100 dark:bg-surface-800')} />
      </Field>
      {!disabled && <div className="pb-0.5"><Toggle checked={inc} onChange={setInc} label="Scale" /></div>}
      {!disabled && inc && (
        <Field label={isV6 ? 'Hextet' : 'Octet'}>
          <select value={octet} onChange={(e) => setOctet(Number(e.target.value))} className={selectCls}>
            {octetOptions.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
          </select>
        </Field>
      )}
    </div>
  )

  return (
    <div className="space-y-2 p-2.5 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50/50 dark:bg-surface-800/30">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold text-surface-600 dark:text-surface-400">{isV6 ? 'IPv6 Tunnels' : 'IPv4 Tunnels'}</span>
        {onDelete && <button onClick={onDelete} className="text-surface-400 hover:text-red-500 transition-colors"><Trash2 className="w-3 h-3" /></button>}
      </div>
      <div className="grid grid-cols-4 gap-2">
        <Field label="Tunnel Count"><input type="number" value={block.tunnelCount === 0 ? '0' : (block.tunnelCount || '')} onChange={(e) => onChange({ ...block, tunnelCount: e.target.value === '' ? 0 : Math.max(0, Number(e.target.value)) })} min={0} max={500} className={cn(inputCls, 'w-full')} /></Field>
        <Field label="Conn Prefix"><input value={block.connPrefix} onChange={(e) => onChange({ ...block, connPrefix: e.target.value })} className={cn(inputCls, 'w-full')} /></Field>
        <Field label="Child Prefix"><input value={block.childPrefix} onChange={(e) => onChange({ ...block, childPrefix: e.target.value })} className={cn(inputCls, 'w-full')} /></Field>
        <Field label="Start Index"><input type="number" value={block.startIndex || ''} onChange={(e) => onChange({ ...block, startIndex: e.target.value === '' ? 0 : Math.max(1, Number(e.target.value)) })} onBlur={() => { if (!block.startIndex) onChange({ ...block, startIndex: 1 }) }} min={1} className={cn(inputCls, 'w-full')} /></Field>
      </div>
      {ipRow('Local Address', block.localAddr, (v) => onChange({ ...block, localAddr: v }), block.localAddrInc, (v) => onChange({ ...block, localAddrInc: v }), block.localAddrOctet, (v) => onChange({ ...block, localAddrOctet: v }), isV6 ? 'fd00::1' : '10.0.0.1')}
      {ipRow('Remote Address', block.remoteAddr, (v) => onChange({ ...block, remoteAddr: v }), block.remoteAddrInc, (v) => onChange({ ...block, remoteAddrInc: v }), block.remoteAddrOctet, (v) => onChange({ ...block, remoteAddrOctet: v }), isV6 ? 'fd00::2' : '10.0.0.2')}
      {ipRow('Local Traffic Selector', block.localTs, (v) => onChange({ ...block, localTs: v }), block.localTsInc, (v) => onChange({ ...block, localTsInc: v }), block.localTsOctet, (v) => onChange({ ...block, localTsOctet: v }), isV6 ? 'fd01::/64' : '192.168.1.0/24', tsDisabled)}
      {ipRow('Remote Traffic Selector', block.remoteTs, (v) => onChange({ ...block, remoteTs: v }), block.remoteTsInc, (v) => onChange({ ...block, remoteTsInc: v }), block.remoteTsOctet, (v) => onChange({ ...block, remoteTsOctet: v }), isV6 ? 'fd02::/64' : '192.168.2.0/24', tsDisabled)}
    </div>
  )
}

// ── Config Generator ──

function generateConfig(
  ipv4: IPBlock, ipv6: IPBlock,
  ike: Record<string, string>,
  auth: Record<string, string>,
  child: Record<string, string>,
  secret: Record<string, string>,
  ikeP: ProposalState,
  espP: ProposalState,
) {
  const ikeProposalStr = buildProposalString(ikeP, true)
  const espProposalStr = buildProposalString(espP, false)
  const indent = (level: number) => '    '.repeat(level)
  const opt = (level: number, key: string, val: string, def: string) => (!val || val === def) ? '' : `${indent(level)}${key} = ${val}\n`

  function getIP(base: string, inc: boolean, octet: number, idx: number) {
    if (!base || idx === 0) return base
    if (!inc) return base
    return incrementIP(base, octet, idx)
  }

  function emitBlocks(block: IPBlock) {
    let out = ''
    for (let i = 0; i < block.tunnelCount; i++) {
      const idx = block.startIndex + i
      const connName = block.tunnelCount === 1 ? block.connPrefix : `${block.connPrefix}-${idx}`
      const childName = block.tunnelCount === 1 ? block.childPrefix : `${block.childPrefix}-${idx}`
      const la = getIP(block.localAddr, block.localAddrInc, block.localAddrOctet, i)
      const ra = getIP(block.remoteAddr, block.remoteAddrInc, block.remoteAddrOctet, i)
      const lt = getIP(block.localTs, block.localTsInc, block.localTsOctet, i)
      const rt = getIP(block.remoteTs, block.remoteTsInc, block.remoteTsOctet, i)
      const effLocalId = auth.localId || la
      const effRemoteId = auth.remoteId || ra

      out += `${indent(1)}${connName} {\n`
      out += `${indent(2)}version = ${ike.version || '2'}\n`
      out += `${indent(2)}local_addrs = ${la}\n`
      out += `${indent(2)}remote_addrs = ${ra}\n`
      out += opt(2, 'local_port', ike.localPort, '500')
      out += opt(2, 'remote_port', ike.remotePort, '500')
      if (ikeProposalStr) out += `${indent(2)}proposals = ${ikeProposalStr}\n`
      out += opt(2, 'vips', ike.vips, '')
      out += opt(2, 'aggressive', ike.aggressive, 'no')
      out += opt(2, 'pull', ike.pull, 'yes')
      out += opt(2, 'encap', ike.encap, 'no')
      out += `${indent(2)}mobike = ${ike.mobike || 'no'}\n`
      out += `${indent(2)}dpd_delay = ${ike.dpdDelay || '30s'}\n`
      out += opt(2, 'dpd_timeout', ike.dpdTimeout, '0s')
      out += opt(2, 'fragmentation', ike.fragmentation, 'yes')
      out += opt(2, 'send_certreq', ike.sendCertreq, 'yes')
      out += opt(2, 'send_cert', ike.sendCert, 'ifasked')
      out += opt(2, 'keyingtries', ike.keyingtries, '1')
      out += opt(2, 'unique', ike.unique, 'no')
      if (ike.rekeyTime) out += `${indent(2)}rekey_time = ${ike.rekeyTime}\n`
      out += opt(2, 'reauth_time', ike.reauthTime, '0s')
      out += opt(2, 'over_time', ike.overTime, '')
      out += opt(2, 'rand_time', ike.randTime, '')
      out += opt(2, 'pools', ike.pools, '')
      // Auto-increment if_id when value is numeric
      if (ike.ifIdIn) {
        const numIn = parseInt(ike.ifIdIn, 10)
        out += `${indent(2)}if_id_in = ${!isNaN(numIn) ? numIn + i : ike.ifIdIn}\n`
      }
      if (ike.ifIdOut) {
        const numOut = parseInt(ike.ifIdOut, 10)
        out += `${indent(2)}if_id_out = ${!isNaN(numOut) ? numOut + i : ike.ifIdOut}\n`
      }
      out += opt(2, 'mediation', ike.mediation, 'no')
      out += opt(2, 'mediated_by', ike.mediatedBy, '')

      // Local auth
      out += `${indent(2)}local {\n`
      out += `${indent(3)}auth = ${auth.localAuth || 'pubkey'}\n`
      out += `${indent(3)}id = ${effLocalId}\n`
      if (auth.localCerts) out += `${indent(3)}certs = ${auth.localCerts}\n`
      if (auth.localEapId) out += `${indent(3)}eap_id = ${auth.localEapId}\n`
      out += `${indent(2)}}\n`

      // Remote auth
      out += `${indent(2)}remote {\n`
      out += `${indent(3)}auth = ${auth.remoteAuth || 'pubkey'}\n`
      out += `${indent(3)}id = ${effRemoteId}\n`
      if (auth.remoteCerts) out += `${indent(3)}certs = ${auth.remoteCerts}\n`
      out += opt(3, 'revocation', auth.remoteRevocation, 'relaxed')
      out += `${indent(2)}}\n`

      // Children
      out += `${indent(2)}children {\n`
      out += `${indent(3)}${childName} {\n`
      out += `${indent(4)}local_ts = ${lt}\n`
      out += `${indent(4)}remote_ts = ${rt}\n`
      if (espProposalStr) out += `${indent(4)}esp_proposals = ${espProposalStr}\n`
      if (child.rekeyTime) out += `${indent(4)}rekey_time = ${child.rekeyTime}\n`
      out += opt(4, 'life_time', child.lifeTime, '')
      out += opt(4, 'mode', child.mode, 'tunnel')
      out += `${indent(4)}start_action = ${child.startAction || 'start'}\n`
      out += opt(4, 'close_action', child.closeAction, 'none')
      out += opt(4, 'dpd_action', child.dpdAction, 'clear')
      out += opt(4, 'ipcomp', child.ipcomp, 'no')
      out += opt(4, 'replay_window', child.replayWindow, '32')
      out += opt(4, 'inactivity', child.inactivity, '0s')
      out += opt(4, 'hw_offload', child.hwOffload, 'no')
      out += opt(4, 'updown', child.updown, '')
      out += opt(4, 'mark_in', child.markIn, '')
      out += opt(4, 'mark_out', child.markOut, '')
      out += opt(4, 'if_id_in', child.ifIdIn, '')
      out += opt(4, 'if_id_out', child.ifIdOut, '')
      out += `${indent(3)}}\n`
      out += `${indent(2)}}\n`
      out += `${indent(1)}}\n`
    }
    return out
  }

  const hasContent = (b: IPBlock) => b.enabled && b.tunnelCount > 0 && (b.localAddr || b.remoteAddr || b.localTs || b.remoteTs)
  let config = 'connections {\n'
  if (hasContent(ipv4)) config += emitBlocks(ipv4)
  if (hasContent(ipv6)) config += emitBlocks(ipv6)
  config += '}\n'

  // Secrets
  if (auth.localAuth === 'pubkey' && auth.localCerts) {
    const certName = auth.localCerts.replace(/\.crt\.pem$|\.crt$|\.pem$/, '')
    config += '\nsecrets {\n'
    config += `${indent(1)}private-${certName.replace(/[^a-zA-Z0-9_-]/g, '-')} {\n`
    config += `${indent(2)}file = /etc/swanctl/private/${certName}.key.pem\n`
    config += `${indent(1)}}\n`
    config += '}\n'
    const caName = secret.caName || 'vpn-ca'
    config += `\nauthorities {\n`
    config += `${indent(1)}${caName} {\n`
    config += `${indent(2)}cacert = /etc/swanctl/x509ca/${caName}.crt.pem\n`
    config += `${indent(1)}}\n`
    config += '}\n'
  } else if (secret.type !== 'none' && secret.value) {
    config += '\nsecrets {\n'
    const keyTypes = ['private', 'rsa', 'ecdsa', 'pkcs8', 'pkcs12']
    const isKeyType = keyTypes.includes(secret.type)
    const isToken = secret.type === 'token'
    config += `${indent(1)}${secret.type}-1 {\n`
    if (isToken) config += `${indent(2)}handle = ${secret.value}\n`
    else if (isKeyType) config += `${indent(2)}file = ${secret.value}\n`
    else config += `${indent(2)}secret = ${secret.value}\n`
    if (secret.ids && !isToken) {
      secret.ids.split(',').map((s) => s.trim()).filter(Boolean).forEach((id, i) => {
        config += `${indent(2)}id${i > 0 ? String(i + 1) : ''} = ${id}\n`
      })
    }
    config += `${indent(1)}}\n`
    config += '}\n'
  }

  return config
}

// ── Main Component ──

export default function SwanctlTemplateBuilder() {
  const store = useVpnDebuggerStore()
  const { templateBuilderOpen, localConnected } = store
  const [mode, setMode] = useState<'policy' | 'route'>('policy')
  const isRoute = mode === 'route'

  const [ipv4, setIpv4] = useState<IPBlock>({ ...defaultIPv4Block })
  const [ipv6, setIpv6] = useState<IPBlock>({ ...defaultIPv6Block })

  // IKE Proposals
  const [ikeProposal, setIkeProposal] = useState<ProposalState>(emptyProposal())

  // IKE settings
  const [ike, setIke] = useState<Record<string, string>>({
    version: '2', rekeyTime: '86400s', reauthTime: '0s', overTime: '', randTime: '',
    dpdDelay: '30s', dpdTimeout: '0s', mobike: 'no', fragmentation: 'yes',
    aggressive: 'no', encap: 'no', keyingtries: '1', unique: 'no',
    sendCert: 'ifasked', sendCertreq: 'yes', pull: 'yes',
    localPort: '', remotePort: '', vips: '', pools: '',
    ifIdIn: '', ifIdOut: '', mediation: 'no', mediatedBy: '',
  })

  // Auth settings
  const [auth, setAuth] = useState<Record<string, string>>({
    localAuth: 'pubkey', localId: '', localCerts: '', localEapId: '',
    remoteAuth: 'pubkey', remoteId: '', remoteCerts: '', remoteRevocation: 'relaxed',
  })

  // ESP Proposals
  const [espProposal, setEspProposal] = useState<ProposalState>(emptyProposal())

  // Child SA settings
  const [child, setChild] = useState<Record<string, string>>({
    rekeyTime: '28800s', lifeTime: '', mode: 'tunnel',
    startAction: 'start', closeAction: 'none', dpdAction: 'clear',
    ipcomp: 'no', replayWindow: '32', inactivity: '0s', hwOffload: 'no',
    updown: '', markIn: '', markOut: '', ifIdIn: '', ifIdOut: '',
  })

  // Secret
  const [secret, setSecret] = useState<Record<string, string>>({
    type: 'none', value: '', ids: '', caName: 'vpn-ca',
  })

  // XFRM interface settings (route-based only)
  const [xfrmCount, setXfrmCount] = useState(1)
  const [xfrmStartId, setXfrmStartId] = useState(1)
  const [xfrmAddr4, setXfrmAddr4] = useState('')
  const [xfrmAddr4Scale, setXfrmAddr4Scale] = useState(false)
  const [xfrmAddr4Octet, setXfrmAddr4Octet] = useState(4)
  const [xfrmAddr6, setXfrmAddr6] = useState('')
  const [xfrmAddr6Scale, setXfrmAddr6Scale] = useState(false)
  const [xfrmAddr6Hextet, setXfrmAddr6Hextet] = useState(8)
  const [xfrmPhysDev, setXfrmPhysDev] = useState('')
  const [xfrmPhysDevScale, setXfrmPhysDevScale] = useState(false)
  const [xfrmApplying, setXfrmApplying] = useState(false)
  const [xfrmDeleting, setXfrmDeleting] = useState(false)

  // Routing (route-based only)
  type RoutingType = 'static' | 'bgpv4' | 'bgpv6' | 'ospfv2' | 'ospfv3' | 'eigrpv4' | 'eigrpv6'
  const [routingType, setRoutingTypeRaw] = useState<RoutingType>('static')
  // Static routing
  const [staticRoutes, setStaticRoutes] = useState<{ dest: string; via: string; dev: string }[]>([{ dest: '', via: '', dev: '' }])
  // BGP settings
  const [bgpLocalAs, setBgpLocalAs] = useState('')
  const [bgpRouterId, setBgpRouterId] = useState('')
  const [bgpNeighbors, setBgpNeighbors] = useState<BgpNeighborEntry[]>([defaultBgpNeighborEntry()])
  const [bgpNeighborPopupIdx, setBgpNeighborPopupIdx] = useState<number | null>(null)
  const [bgpNetworks, setBgpNetworks] = useState<string[]>([''])
  const [bgpEbgpRequiresPolicy, setBgpEbgpRequiresPolicy] = useState(false) // false = 'no bgp ebgp-requires-policy' applied
  // OSPF settings
  const [ospfRouterId, setOspfRouterId] = useState('')
  const [ospfNetworks, setOspfNetworks] = useState<{ network: string; area: string }[]>([{ network: '', area: '0' }])
  const [ospfInterfaces, setOspfInterfaces] = useState<OspfInterfaceEntry[]>([defaultOspfIntfEntry()])
  const [ospfCmdPopupIdx, setOspfCmdPopupIdx] = useState<number | null>(null)
  // EIGRP settings
  const [eigrpAs, setEigrpAs] = useState('')
  const [eigrpRouterId, setEigrpRouterId] = useState('')
  const [eigrpNetworks, setEigrpNetworks] = useState<string[]>([''])
  const [eigrpInterface, setEigrpInterface] = useState('')
  const [routingApplying, setRoutingApplying] = useState(false)
  const [routingDeleting, setRoutingDeleting] = useState(false)

  // Per-routing-type stash: preserves config when switching between types
  const routingStashRef = useRef<Record<string, Record<string, unknown>>>({})

  const stashCurrentRouting = useCallback((type: RoutingType) => {
    if (type === 'static') {
      routingStashRef.current.static = { routes: staticRoutes }
    } else if (type === 'bgpv4' || type === 'bgpv6') {
      routingStashRef.current[type] = { localAs: bgpLocalAs, routerId: bgpRouterId, neighbors: bgpNeighbors, networks: bgpNetworks, ebgpRequiresPolicy: bgpEbgpRequiresPolicy }
    } else if (type === 'ospfv2' || type === 'ospfv3') {
      routingStashRef.current[type] = { routerId: ospfRouterId, networks: ospfNetworks, interfaces: ospfInterfaces }
    } else if (type === 'eigrpv4' || type === 'eigrpv6') {
      routingStashRef.current[type] = { as: eigrpAs, routerId: eigrpRouterId, networks: eigrpNetworks, iface: eigrpInterface }
    }
  }, [staticRoutes, bgpLocalAs, bgpRouterId, bgpNeighbors, bgpNetworks, bgpEbgpRequiresPolicy, ospfRouterId, ospfNetworks, ospfInterfaces, eigrpAs, eigrpRouterId, eigrpNetworks, eigrpInterface])

  const restoreRouting = useCallback((type: RoutingType) => {
    const s = routingStashRef.current[type]
    if (type === 'static') {
      setStaticRoutes(s?.routes as { dest: string; via: string; dev: string }[] || [{ dest: '', via: '', dev: '' }])
    } else if (type === 'bgpv4' || type === 'bgpv6') {
      setBgpLocalAs((s?.localAs as string) ?? ''); setBgpRouterId((s?.routerId as string) ?? '')
      setBgpNeighbors((s?.neighbors as BgpNeighborEntry[]) ?? [defaultBgpNeighborEntry()])
      setBgpNetworks((s?.networks as string[]) ?? ['']); setBgpEbgpRequiresPolicy((s?.ebgpRequiresPolicy as boolean) ?? false)
    } else if (type === 'ospfv2' || type === 'ospfv3') {
      setOspfRouterId((s?.routerId as string) ?? ''); setOspfNetworks((s?.networks as { network: string; area: string }[]) ?? [{ network: '', area: '0' }])
      setOspfInterfaces((s?.interfaces as OspfInterfaceEntry[]) ?? [defaultOspfIntfEntry()])
    } else if (type === 'eigrpv4' || type === 'eigrpv6') {
      setEigrpAs((s?.as as string) ?? ''); setEigrpRouterId((s?.routerId as string) ?? '')
      setEigrpNetworks((s?.networks as string[]) ?? ['']); setEigrpInterface((s?.iface as string) ?? '')
    }
  }, [])

  const setRoutingType = useCallback((newType: RoutingType) => {
    setRoutingTypeRaw(prev => {
      if (prev !== newType) stashCurrentRouting(prev)
      return newType
    })
    restoreRouting(newType)
  }, [stashCurrentRouting, restoreRouting])

  const [preview, setPreview] = useState('')
  const [filename, setFilename] = useState('tunnel.conf')
  const [saving, setSaving] = useState(false)

  // Presets (separate per mode)
  interface TemplatePreset { id: string; name: string; data: Record<string, unknown> }
  const [policyPresets, setPolicyPresets] = useState<TemplatePreset[]>([])
  const [routePresets, setRoutePresets] = useState<TemplatePreset[]>([])
  const presets = isRoute ? routePresets : policyPresets
  const setPresets = isRoute ? setRoutePresets : setPolicyPresets
  const [presetName, setPresetName] = useState('')
  const [savingPreset, setSavingPreset] = useState(false)

  const serializeState = useCallback(() => {
    const base: Record<string, unknown> = { ipv4, ipv6, ikeProposal, ike, auth, espProposal, child, secret, filename }
    if (isRoute) {
      base.xfrm = { count: xfrmCount, startId: xfrmStartId, addr4: xfrmAddr4, addr4Scale: xfrmAddr4Scale, addr4Octet: xfrmAddr4Octet, addr6: xfrmAddr6, addr6Scale: xfrmAddr6Scale, addr6Hextet: xfrmAddr6Hextet, physDev: xfrmPhysDev, physDevScale: xfrmPhysDevScale }
      // Stash the currently active routing type before serializing
      stashCurrentRouting(routingType)
      const stash = routingStashRef.current
      base.routing = {
        type: routingType,
        static: stash.static || { routes: staticRoutes },
        bgpv4: stash.bgpv4 || { localAs: '', routerId: '', neighbors: [defaultBgpNeighborEntry()], networks: [''], ebgpRequiresPolicy: false },
        bgpv6: stash.bgpv6 || { localAs: '', routerId: '', neighbors: [defaultBgpNeighborEntry()], networks: [''], ebgpRequiresPolicy: false },
        ospfv2: stash.ospfv2 || { routerId: '', networks: [{ network: '', area: '0' }], interfaces: [defaultOspfIntfEntry()] },
        ospfv3: stash.ospfv3 || { routerId: '', networks: [{ network: '', area: '0' }], interfaces: [defaultOspfIntfEntry()] },
        eigrpv4: stash.eigrpv4 || { as: '', routerId: '', networks: [''], iface: '' },
        eigrpv6: stash.eigrpv6 || { as: '', routerId: '', networks: [''], iface: '' },
      }
    }
    return base
  }, [ipv4, ipv6, ikeProposal, ike, auth, espProposal, child, secret, filename, isRoute,
    xfrmCount, xfrmStartId, xfrmAddr4, xfrmAddr4Scale, xfrmAddr4Octet, xfrmAddr6, xfrmAddr6Scale, xfrmAddr6Hextet, xfrmPhysDev, xfrmPhysDevScale,
    routingType, staticRoutes, bgpLocalAs, bgpRouterId, bgpNeighbors, bgpNetworks, bgpEbgpRequiresPolicy,
    ospfRouterId, ospfNetworks, ospfInterfaces,
    eigrpAs, eigrpRouterId, eigrpNetworks, eigrpInterface, stashCurrentRouting])

  const loadPresetData = useCallback((data: Record<string, unknown>) => {
    if (data.ipv4) setIpv4(data.ipv4 as IPBlock)
    if (data.ipv6) setIpv6(data.ipv6 as IPBlock)
    if (data.ikeProposal) setIkeProposal(data.ikeProposal as ProposalState)
    if (data.ike) setIke(data.ike as Record<string, string>)
    if (data.auth) setAuth(data.auth as Record<string, string>)
    if (data.espProposal) setEspProposal(data.espProposal as ProposalState)
    if (data.child) setChild(data.child as Record<string, string>)
    if (data.secret) setSecret(data.secret as Record<string, string>)
    if (data.filename) setFilename(data.filename as string)
    // Restore XFRM interface settings
    if (data.xfrm) {
      const x = data.xfrm as Record<string, unknown>
      if (x.count != null) setXfrmCount(x.count as number)
      if (x.startId != null) setXfrmStartId(x.startId as number)
      if (x.addr4 != null) setXfrmAddr4(x.addr4 as string)
      if (x.addr4Scale != null) setXfrmAddr4Scale(x.addr4Scale as boolean)
      if (x.addr4Octet != null) setXfrmAddr4Octet(x.addr4Octet as number)
      if (x.addr6 != null) setXfrmAddr6(x.addr6 as string)
      if (x.addr6Scale != null) setXfrmAddr6Scale(x.addr6Scale as boolean)
      if (x.addr6Hextet != null) setXfrmAddr6Hextet(x.addr6Hextet as number)
      if (x.physDev != null) setXfrmPhysDev(x.physDev as string)
      if (x.physDevScale != null) setXfrmPhysDevScale(x.physDevScale as boolean)
    }
    // Restore routing settings
    if (data.routing) {
      const r = data.routing as Record<string, unknown>
      const rType = (r.type || 'static') as RoutingType
      // Backward compat: old presets stored flat keys; new presets store per-type sub-objects
      const hasPerType = !!(r.static || r.bgpv4 || r.ospfv2 || r.eigrpv4)
      if (hasPerType) {
        // Populate the stash with all per-type data from the preset
        if (r.static) routingStashRef.current.static = r.static as Record<string, unknown>
        if (r.bgpv4) routingStashRef.current.bgpv4 = r.bgpv4 as Record<string, unknown>
        if (r.bgpv6) routingStashRef.current.bgpv6 = r.bgpv6 as Record<string, unknown>
        if (r.ospfv2) routingStashRef.current.ospfv2 = r.ospfv2 as Record<string, unknown>
        if (r.ospfv3) routingStashRef.current.ospfv3 = r.ospfv3 as Record<string, unknown>
        if (r.eigrpv4) routingStashRef.current.eigrpv4 = r.eigrpv4 as Record<string, unknown>
        if (r.eigrpv6) routingStashRef.current.eigrpv6 = r.eigrpv6 as Record<string, unknown>
        // Restore the active type's values into the live state
        restoreRouting(rType)
      } else {
        // Backward compat: old flat format — load into live state directly
        if (r.staticRoutes) setStaticRoutes(r.staticRoutes as { dest: string; via: string; dev: string }[])
        if (r.bgpLocalAs != null) setBgpLocalAs(r.bgpLocalAs as string)
        if (r.bgpRouterId != null) setBgpRouterId(r.bgpRouterId as string)
        if (r.bgpNeighborAddr != null || r.bgpNeighborAs != null) {
          setBgpNeighbors([{ ...defaultBgpNeighborEntry(), addr: (r.bgpNeighborAddr as string) ?? '', remoteAs: (r.bgpNeighborAs as string) ?? '' }])
        }
        if (r.bgpNetworks) setBgpNetworks(r.bgpNetworks as string[])
        if (r.ospfRouterId != null) setOspfRouterId(r.ospfRouterId as string)
        if (r.ospfNetworks) setOspfNetworks(r.ospfNetworks as { network: string; area: string }[])
        // Backward compat: convert old single-interface + passiveInterfaces into new interfaces array
        if (r.ospfInterface != null || r.ospfPassiveInterfaces) {
          const legacyEntry: OspfInterfaceEntry = {
            name: (r.ospfInterface as string) ?? '',
            scale: (r.ospfInterfaceScale as boolean) ?? false,
            count: (r.ospfInterfaceCount as number) ?? 1,
            cmds: { ...defaultOspfIntfCmds, area: (r.ospfArea as string) ?? '0', helloInterval: (r.ospfHelloInterval as string) ?? '', deadInterval: (r.ospfDeadInterval as string) ?? '' },
          }
          setOspfInterfaces([legacyEntry])
        }
        if (r.eigrpAs != null) setEigrpAs(r.eigrpAs as string)
        if (r.eigrpRouterId != null) setEigrpRouterId(r.eigrpRouterId as string)
        if (r.eigrpNetworks) setEigrpNetworks(r.eigrpNetworks as string[])
        if (r.eigrpInterface != null) setEigrpInterface(r.eigrpInterface as string)
      }
      setRoutingTypeRaw(rType)
    }
    setPreview('')
  }, [restoreRouting])

  // Fetch presets for the current mode
  const fetchPresetsForMode = useCallback((m: 'policy' | 'route') => {
    fetch(`/api/strongswan/template-presets?mode=${m}`, { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d.success) (m === 'route' ? setRoutePresets : setPolicyPresets)(d.presets) })
      .catch(() => {})
  }, [])

  // Reset state when mode changes
  useEffect(() => {
    if (!templateBuilderOpen) return
    if (isRoute) {
      setIpv4({ ...defaultIPv4Block, connPrefix: 'rconn', childPrefix: 'rchild', localTs: '0.0.0.0/0', remoteTs: '0.0.0.0/0' })
      setIpv6({ ...defaultIPv6Block, enabled: true, tunnelCount: 0, connPrefix: 'rconn6', childPrefix: 'rchild6', localTs: '::/0', remoteTs: '::/0' })
      setChild(c => ({ ...c, mode: 'pass' }))
      setIke(k => ({ ...k, ifIdIn: '1', ifIdOut: '1' }))
      setXfrmCount(1); setXfrmStartId(1); setXfrmAddr4(''); setXfrmAddr4Scale(false); setXfrmAddr4Octet(4)
      setXfrmAddr6(''); setXfrmAddr6Scale(false); setXfrmAddr6Hextet(8); setXfrmPhysDev(''); setXfrmPhysDevScale(false)
      setRoutingTypeRaw('static'); setStaticRoutes([{ dest: '', via: '', dev: '' }])
      setBgpLocalAs(''); setBgpRouterId(''); setBgpNeighbors([defaultBgpNeighborEntry()]); setBgpNetworks(['']); setBgpEbgpRequiresPolicy(false)
      setOspfRouterId(''); setOspfNetworks([{ network: '', area: '0' }]); setOspfInterfaces([defaultOspfIntfEntry()])
      setEigrpAs(''); setEigrpRouterId(''); setEigrpNetworks(['']); setEigrpInterface('')
      routingStashRef.current = {}
    } else {
      setIpv4({ ...defaultIPv4Block })
      setIpv6({ ...defaultIPv6Block, enabled: true, tunnelCount: 0 })
      setChild(c => ({ ...c, mode: 'tunnel' }))
      setIke(k => ({ ...k, ifIdIn: '', ifIdOut: '' }))
    }
    setPreview('')
    setPresetName('')
    fetchPresetsForMode(mode)
  }, [templateBuilderOpen, mode, isRoute, fetchPresetsForMode])

  const handleSavePreset = useCallback(async () => {
    const name = presetName.trim()
    if (!name) { store.notify('Enter a preset name', 'warning'); return }
    setSavingPreset(true)
    try {
      const res = await fetch('/api/strongswan/template-presets/save', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
        body: JSON.stringify({ name, mode, data: serializeState() }),
      })
      const d = await res.json()
      if (d.success) { setPresets(d.presets); setPresetName(''); store.notify(`Preset "${name}" saved`, 'success') }
      else store.notify(d.message || 'Save failed', 'error')
    } catch { store.notify('Save failed', 'error') }
    setSavingPreset(false)
  }, [presetName, mode, serializeState, store])

  const handleDeletePreset = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/strongswan/template-presets/${id}?mode=${mode}`, { method: 'DELETE', credentials: 'include' })
      const d = await res.json()
      if (d.success) { setPresets(d.presets); store.notify('Preset deleted', 'success') }
    } catch { store.notify('Delete failed', 'error') }
  }, [mode, store])

  const handlePreview = useCallback(() => {
    setPreview(generateConfig(ipv4, ipv6, ike, auth, child, secret, ikeProposal, espProposal))
  }, [ipv4, ipv6, ike, auth, child, secret, ikeProposal, espProposal])

  const handleSave = useCallback(async () => {
    if (!filename || !filename.endsWith('.conf')) {
      store.notify('Filename must end with .conf', 'warning')
      return
    }
    const config = generateConfig(ipv4, ipv6, ike, auth, child, secret, ikeProposal, espProposal)
    setSaving(true)
    try {
      const res = await fetch('/api/strongswan/config-file-save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ filename, content: config }),
      })
      const data = await res.json()
      if (data.success) {
        store.notify(`Config saved to /etc/swanctl/conf.d/${filename}`, 'success')
        store.closeTemplateBuilder()
      } else {
        store.notify(data.message || 'Save failed', 'error')
      }
    } catch {
      store.notify('Save failed', 'error')
    }
    setSaving(false)
  }, [filename, ipv4, ipv6, ike, auth, child, secret, ikeProposal, espProposal, store])

  // ── XFRM Apply / Delete handlers ──
  const handleXfrmApply = useCallback(async () => {
    setXfrmApplying(true)
    try {
      const intfs = Array.from({ length: xfrmCount }, (_, i) => {
        const ifId = xfrmStartId + i
        const addresses: string[] = []
        if (xfrmAddr4) addresses.push(xfrmAddr4Scale && i > 0 ? incrementIP(xfrmAddr4, xfrmAddr4Octet, i) : xfrmAddr4)
        if (xfrmAddr6) addresses.push(xfrmAddr6Scale && i > 0 ? incrementIP(xfrmAddr6, xfrmAddr6Hextet, i) : xfrmAddr6)
        let physDev: string | undefined = xfrmPhysDev || undefined
        if (xfrmPhysDev && xfrmPhysDevScale) {
          const m = xfrmPhysDev.match(/^(.*?)(\d+)$/)
          if (m) {
            physDev = `${m[1]}${parseInt(m[2], 10) + i}`
          } else {
            physDev = `${xfrmPhysDev}${i}`
          }
        }
        return { if_id: ifId, addresses, phys_dev: physDev }
      })
      const res = await fetch('/api/strongswan/interfaces/batch-create', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
        body: JSON.stringify({ interfaces: intfs }),
      })
      const d = await res.json()
      store.notify(d.message || `Created ${xfrmCount} interface(s)`, d.success ? 'success' : 'error')
    } catch { store.notify('XFRM apply failed', 'error') }
    setXfrmApplying(false)
  }, [xfrmCount, xfrmStartId, xfrmAddr4, xfrmAddr4Scale, xfrmAddr4Octet, xfrmAddr6, xfrmAddr6Scale, xfrmAddr6Hextet, xfrmPhysDev, xfrmPhysDevScale, store])

  const handleXfrmDelete = useCallback(async () => {
    if (!confirm(`Delete ${xfrmCount} XFRM interface(s) starting from xfrm${xfrmStartId}?`)) return
    setXfrmDeleting(true)
    try {
      const names = Array.from({ length: xfrmCount }, (_, i) => `xfrm${xfrmStartId + i}`)
      for (const name of names) {
        await fetch('/api/strongswan/interfaces/delete', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
          body: JSON.stringify({ name }),
        })
      }
      store.notify(`Deleted ${xfrmCount} XFRM interface(s)`, 'success')
    } catch { store.notify('XFRM delete failed', 'error') }
    setXfrmDeleting(false)
  }, [xfrmCount, xfrmStartId, store])

  // ── Routing Apply / Delete handlers ──
  const handleRoutingApply = useCallback(async () => {
    setRoutingApplying(true)
    try {
      let payload: Record<string, unknown> = { type: routingType }
      if (routingType === 'static') {
        payload.routes = staticRoutes.filter(r => r.dest)
      } else if (routingType === 'bgpv4' || routingType === 'bgpv6') {
        const isV6 = routingType === 'bgpv6'
        // Expand neighbors (scale by octet/hextet)
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
        // Expand comma-separated networks
        const expandedNets = bgpNetworks.flatMap(n => n.split(',').map(s => s.trim()).filter(Boolean))
        payload = {
          ...payload, local_as: bgpLocalAs, router_id: bgpRouterId,
          networks: expandedNets,
          bgp_neighbors: expandedNeighbors.map(n => ({ addr: n.addr, remote_as: n.remoteAs, ...n.cmds })),
          bgp_ebgp_requires_policy: bgpEbgpRequiresPolicy,
        }
      } else if (routingType === 'ospfv2' || routingType === 'ospfv3') {
        // Build expanded interface list with per-interface commands
        const expandedIfaces: { name: string; cmds: OspfIntfCmds }[] = []
        for (const entry of ospfInterfaces) {
          if (!entry.name) continue
          if (entry.scale) {
            // Scale: single interface name with trailing number, expanded by count
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
            // No scale: may be comma-separated list of interfaces
            const names = entry.name.split(',').map(n => n.trim()).filter(Boolean)
            for (const n of names) {
              expandedIfaces.push({ name: n, cmds: entry.cmds })
            }
          }
        }
        const ifaceStr = expandedIfaces.map(e => e.name).join(',') || undefined
        // Collect passive interfaces from per-interface cmds
        const passiveIfaces = expandedIfaces.filter(e => e.cmds.passive).map(e => e.name)
        // Use hello/dead from first interface that has them set (backward compat with backend)
        const firstWithTimers = expandedIfaces.find(e => e.cmds.helloInterval || e.cmds.deadInterval)
        // Expand comma-separated networks into individual entries (each inherits the row's area)
        const expandedNetworks = ospfNetworks.flatMap(entry => {
          const nets = entry.network.split(',').map(n => n.trim()).filter(Boolean)
          return nets.map(n => ({ network: n, area: entry.area || '0' }))
        })
        // Default area from first interface
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
      }
      const res = await fetch('/api/strongswan/overlay-routing/apply', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
        body: JSON.stringify(payload),
      })
      const d = await res.json()
      store.notify(d.message || 'Routing applied', d.success ? 'success' : d.partial ? 'warning' : 'error')
    } catch { store.notify('Routing apply failed', 'error') }
    setRoutingApplying(false)
  }, [routingType, staticRoutes, bgpLocalAs, bgpRouterId, bgpNeighbors, bgpNetworks, bgpEbgpRequiresPolicy, ospfRouterId, ospfNetworks, ospfInterfaces, eigrpAs, eigrpRouterId, eigrpNetworks, eigrpInterface, store])

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

  if (!templateBuilderOpen) return null

  const setIkeField = (k: string, v: string) => setIke((prev) => ({ ...prev, [k]: v }))
  const setAuthField = (k: string, v: string) => setAuth((prev) => ({ ...prev, [k]: v }))
  const setChildField = (k: string, v: string) => setChild((prev) => ({ ...prev, [k]: v }))
  const setSecretField = (k: string, v: string) => setSecret((prev) => ({ ...prev, [k]: v }))

  const fCls = cn(inputCls, 'w-full')
  const sCls = cn(selectCls, 'w-full')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => store.closeTemplateBuilder()} />
      <div className="relative w-[95%] max-w-[1100px] max-h-[90vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">SwanCtl Template Builder</h3>
            {/* Mode Toggle */}
            <div className="flex p-0.5 rounded-lg bg-surface-200/60 dark:bg-surface-700/60">
              <button
                onClick={() => setMode('policy')}
                className={cn(
                  'px-3 py-1 rounded-md text-[10px] font-semibold transition-all duration-200',
                  !isRoute
                    ? 'bg-white dark:bg-surface-600 text-vyper-600 dark:text-vyper-400 shadow-sm'
                    : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300',
                )}
              >
                Policy-Based
              </button>
              <button
                onClick={() => setMode('route')}
                className={cn(
                  'px-3 py-1 rounded-md text-[10px] font-semibold transition-all duration-200',
                  isRoute
                    ? 'bg-white dark:bg-surface-600 text-accent-amber shadow-sm'
                    : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300',
                )}
              >
                Route-Based
              </button>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Load Preset */}
            {presets.length > 0 && (
              <div className="flex items-center gap-1">
                <FolderOpen className="w-3.5 h-3.5 text-surface-400" />
                <select
                  value=""
                  onChange={(e) => {
                    const p = presets.find(pr => pr.id === e.target.value)
                    if (p) loadPresetData(p.data)
                  }}
                  className={cn(selectCls, 'text-[10px] min-w-[130px]')}
                >
                  <option value="">Load Preset...</option>
                  {presets.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
                {presets.length > 0 && (
                  <select
                    value=""
                    onChange={(e) => { if (e.target.value) handleDeletePreset(e.target.value) }}
                    className={cn(selectCls, 'text-[10px] min-w-[80px] text-red-500')}
                  >
                    <option value="">Delete...</option>
                    {presets.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                  </select>
                )}
              </div>
            )}
            {/* Save Preset */}
            <div className="flex items-center gap-1">
              <input
                value={presetName}
                onChange={(e) => setPresetName(e.target.value)}
                placeholder="Preset name"
                className={cn(inputCls, 'text-[10px] w-28')}
                onKeyDown={(e) => { if (e.key === 'Enter') handleSavePreset() }}
              />
              <button onClick={handleSavePreset} disabled={savingPreset} className={btnCls('primary')} title={`Save ${isRoute ? 'route' : 'policy'} preset`}>
                <Download className="w-3 h-3" /> Save Preset
              </button>
            </div>
            <button onClick={() => store.closeTemplateBuilder()} className="p-1 rounded-lg hover:bg-surface-200 dark:hover:bg-surface-700 transition-colors">
              <X className="w-4 h-4 text-surface-500" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-auto p-4 space-y-3">
          {isRoute && (
            <>
            <div className="flex items-start gap-2 p-3 rounded-lg border border-accent-amber/30 bg-accent-amber/5">
              <Network className="w-4 h-4 text-accent-amber shrink-0 mt-0.5" />
              <div>
                <div className="text-xs font-medium text-surface-700 dark:text-surface-300">Route-Based VPN Template</div>
                <div className="text-[10px] text-surface-500 mt-0.5">
                  Route-based tunnels use XFRM interfaces with <code className="px-1 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-[9px]">if_id</code> instead of traffic selectors.
                  Use Apply to create XFRM interfaces and configure routing independently of saving the template.
                </div>
              </div>
            </div>

            {/* XFRM Interface Settings */}
            <Section title="XFRM Interfaces" defaultOpen={false}>
              <div className="space-y-2 p-2.5 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50/50 dark:bg-surface-800/30">
                <div className="grid grid-cols-3 gap-2">
                  <Field label="Interface Count">
                    <input type="number" value={xfrmCount} onChange={(e) => setXfrmCount(Math.max(1, Number(e.target.value) || 1))} min={1} max={500} className={fCls} />
                  </Field>
                  <Field label="Starting IF ID">
                    <input type="number" value={xfrmStartId} onChange={(e) => setXfrmStartId(Number(e.target.value) || 1)} min={1} className={fCls} />
                  </Field>
                  <div />
                </div>
                {/* Physical Device with Scale */}
                <div className="grid grid-cols-[1fr_auto] gap-1.5 items-end">
                  <Field label="Physical Device (optional)">
                    <input value={xfrmPhysDev} onChange={(e) => setXfrmPhysDev(e.target.value)} placeholder="e.g. eth0" className={fCls} />
                  </Field>
                  <div className="pb-0.5"><Toggle checked={xfrmPhysDevScale} onChange={setXfrmPhysDevScale} label="Scale" /></div>
                </div>
                {/* IPv4 Address with Scale */}
                <div className="grid grid-cols-[1fr_auto_auto] gap-1.5 items-end">
                  <Field label="IPv4 Address">
                    <input value={xfrmAddr4} onChange={(e) => setXfrmAddr4(e.target.value)} placeholder="e.g. 169.254.0.1/30" className={fCls} />
                  </Field>
                  <div className="pb-0.5"><Toggle checked={xfrmAddr4Scale} onChange={setXfrmAddr4Scale} label="Scale" /></div>
                  {xfrmAddr4Scale && (
                    <Field label="Octet">
                      <select value={xfrmAddr4Octet} onChange={(e) => setXfrmAddr4Octet(Number(e.target.value))} className={cn(selectCls, 'w-full')}>
                        {[4, 3, 2, 1].map((n) => <option key={n} value={n}>{`${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}`}</option>)}
                      </select>
                    </Field>
                  )}
                </div>
                {/* IPv6 Address with Scale */}
                <div className="grid grid-cols-[1fr_auto_auto] gap-1.5 items-end">
                  <Field label="IPv6 Address">
                    <input value={xfrmAddr6} onChange={(e) => setXfrmAddr6(e.target.value)} placeholder="e.g. fd00::1/128" className={fCls} />
                  </Field>
                  <div className="pb-0.5"><Toggle checked={xfrmAddr6Scale} onChange={setXfrmAddr6Scale} label="Scale" /></div>
                  {xfrmAddr6Scale && (
                    <Field label="Hextet">
                      <select value={xfrmAddr6Hextet} onChange={(e) => setXfrmAddr6Hextet(Number(e.target.value))} className={cn(selectCls, 'w-full')}>
                        {[1, 2, 3, 4, 5, 6, 7, 8].map((n) => <option key={n} value={n}>{`${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}${n === 8 ? ' (last)' : ''}`}</option>)}
                      </select>
                    </Field>
                  )}
                </div>
                {/* Preview */}
                {(() => {
                  const items = Array.from({ length: Math.min(xfrmCount, 5) }, (_, i) => {
                    const ifId = xfrmStartId + i
                    const addrs: string[] = []
                    if (xfrmAddr4) addrs.push(xfrmAddr4Scale && i > 0 ? incrementIP(xfrmAddr4, xfrmAddr4Octet, i) : xfrmAddr4)
                    if (xfrmAddr6) addrs.push(xfrmAddr6Scale && i > 0 ? incrementIP(xfrmAddr6, xfrmAddr6Hextet, i) : xfrmAddr6)
                    let dev = xfrmPhysDev || ''
                    if (xfrmPhysDev && xfrmPhysDevScale) {
                      const m = xfrmPhysDev.match(/^(.*?)(\d+)$/)
                      dev = m ? `${m[1]}${parseInt(m[2], 10) + i}` : `${xfrmPhysDev}${i}`
                    }
                    return `xfrm${ifId}${addrs.length ? ` → ${addrs.join(', ')}` : ''}${dev ? ` (dev ${dev})` : ''}`
                  })
                  if (xfrmCount > 5) items.push(`... and ${xfrmCount - 5} more`)
                  return items.length > 0 ? (
                    <div className="mt-1 px-2 py-1.5 rounded-md bg-surface-50 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700">
                      <span className="text-[9px] font-medium text-surface-400">Preview:</span>
                      <div className="text-[10px] font-mono text-surface-600 dark:text-surface-400 mt-0.5 space-y-0.5">
                        {items.map((item, i) => <div key={i}>{item}</div>)}
                      </div>
                    </div>
                  ) : null
                })()}
                {/* Apply / Delete buttons */}
                <div className="flex items-center gap-2 pt-1">
                  <button onClick={handleXfrmApply} disabled={!localConnected || xfrmApplying} className={btnCls('success')}>
                    {xfrmApplying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />} Apply
                  </button>
                  <button onClick={handleXfrmDelete} disabled={!localConnected || xfrmDeleting} className={btnCls('danger')}>
                    {xfrmDeleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />} Delete
                  </button>
                  <span className="text-[9px] text-surface-400 ml-auto">Creates/deletes {xfrmCount} interface(s) independently</span>
                </div>
              </div>
            </Section>

            {/* Routing */}
            <Section title="Routing" defaultOpen={false}>
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
                    {/* Neighbors */}
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
                              <input
                                value={nb.addr}
                                onChange={(e) => updNb({ addr: e.target.value })}
                                placeholder={isV6 ? 'fd00::2' : '169.254.0.2'}
                                className={cn(fCls, 'flex-1')}
                              />
                              <input
                                value={nb.remoteAs}
                                onChange={(e) => updNb({ remoteAs: e.target.value })}
                                placeholder="Remote AS"
                                className={cn(fCls, 'w-24')}
                              />
                              <div className="flex items-center gap-1">
                                <Toggle checked={nb.scale} onChange={(v) => updNb({ scale: v })} />
                                <span className="text-[9px] text-surface-500">Scale</span>
                              </div>
                              {nb.scale && (
                                <>
                                  <input
                                    type="number" min={1} value={nb.count}
                                    onChange={(e) => updNb({ count: parseInt(e.target.value) || 1 })}
                                    className={cn(fCls, 'w-14 text-center')}
                                  />
                                  <select
                                    value={isV6 ? nb.hextet : nb.octet}
                                    onChange={(e) => updNb(isV6 ? { hextet: parseInt(e.target.value) } : { octet: parseInt(e.target.value) })}
                                    className={cn(selectCls, 'w-20')}
                                  >
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
                    {/* Neighbor popup */}
                    {bgpNeighborPopupIdx != null && bgpNeighbors[bgpNeighborPopupIdx] && (
                      <BgpNeighborCmdsPopup
                        entry={bgpNeighbors[bgpNeighborPopupIdx]}
                        isV6={routingType === 'bgpv6'}
                        onChange={(cmds) => {
                          const n = [...bgpNeighbors]; n[bgpNeighborPopupIdx] = { ...n[bgpNeighborPopupIdx], cmds }; setBgpNeighbors(n)
                        }}
                        onClose={() => setBgpNeighborPopupIdx(null)}
                      />
                    )}
                    {/* Advertised Networks */}
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
                    {/* Interfaces */}
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
                              <input
                                value={entry.name}
                                onChange={(e) => updIntf({ name: e.target.value })}
                                placeholder={entry.scale ? 'xfrm1' : 'xfrm1, xfrm2, xfrm3'}
                                title={entry.scale ? 'Single interface name (will be scaled)' : 'Comma-separated interface names'}
                                className={cn(fCls, 'flex-1')}
                              />
                              <Toggle checked={entry.scale} onChange={(v) => updIntf({ scale: v })} label="Scale" />
                              {entry.scale && (
                                <input
                                  type="number" value={entry.count || ''} min={1} max={500}
                                  onChange={(e) => updIntf({ count: e.target.value === '' ? 0 : Math.max(1, Number(e.target.value)) })}
                                  onBlur={() => { if (!entry.count) updIntf({ count: 1 }) }}
                                  className={cn(inputCls, 'w-16')} placeholder="Count"
                                />
                              )}
                              <button
                                onClick={() => setOspfCmdPopupIdx(idx)}
                                className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-700 text-surface-500 hover:text-vyper-500 transition-colors"
                                title={`Configure ${isV3 ? 'ipv6 ospf6' : 'ip ospf'} commands`}
                              >
                                <Settings className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => setOspfInterfaces(ospfInterfaces.filter((_, i) => i !== idx))}
                                disabled={ospfInterfaces.length <= 1}
                                className="text-surface-400 hover:text-red-500 transition-colors disabled:opacity-30"
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>
                            {/* Scale preview */}
                            {entry.scale && entry.name && entry.count > 1 && (() => {
                              const m = entry.name.match(/^(.*?)(\d+)$/)
                              if (!m) return null
                              const items = Array.from({ length: Math.min(entry.count, 5) }, (_, i) => `${m[1]}${parseInt(m[2], 10) + i}`)
                              if (entry.count > 5) items.push('...')
                              return <div className="text-[9px] text-surface-400 font-mono pl-0.5">{items.join(', ')}</div>
                            })()}
                            {/* Per-interface OSPF commands summary */}
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
                    {/* OSPF interface commands popup */}
                    {ospfCmdPopupIdx !== null && ospfInterfaces[ospfCmdPopupIdx] && (
                      <OspfIntfCmdsPopup
                        entry={ospfInterfaces[ospfCmdPopupIdx]}
                        isV3={routingType === 'ospfv3'}
                        onChange={(cmds) => {
                          const n = [...ospfInterfaces]; n[ospfCmdPopupIdx] = { ...n[ospfCmdPopupIdx], cmds }; setOspfInterfaces(n)
                        }}
                        onClose={() => setOspfCmdPopupIdx(null)}
                      />
                    )}
                    {/* Networks */}
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

                {/* EIGRP Configuration */}
                {(routingType === 'eigrpv4' || routingType === 'eigrpv6') && (
                  <div className="space-y-2">
                    <div className="text-[9px] font-medium text-surface-500">{routingType === 'eigrpv4' ? 'EIGRPv4' : 'EIGRPv6'} Configuration</div>
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
                  <span className="text-[9px] text-surface-400 ml-auto">Applies/removes routing independently</span>
                </div>
              </div>
            </Section>
            </>
          )}
          {/* IP Address Blocks */}
          <Section title="IP Address Blocks" defaultOpen={false}>
            <IPBlockEditor block={ipv4} onChange={setIpv4} isV6={false} tsDisabled={isRoute} />
            <IPBlockEditor block={ipv6} onChange={setIpv6} isV6 tsDisabled={isRoute} />
          </Section>

          {/* IKE Settings */}
          <Section title="IKE / Connection Settings" defaultOpen={false}>
            <div className="grid grid-cols-4 gap-2">
              <Field label="IKE Version"><select value={ike.version} onChange={(e) => setIkeField('version', e.target.value)} className={sCls}><option value="2">IKEv2</option><option value="1">IKEv1</option><option value="0">Any</option></select></Field>
              <Field label="Rekey Time"><input value={ike.rekeyTime} onChange={(e) => setIkeField('rekeyTime', e.target.value)} placeholder="4h" className={fCls} /></Field>
              <Field label="Reauth Time"><input value={ike.reauthTime} onChange={(e) => setIkeField('reauthTime', e.target.value)} placeholder="0s" className={fCls} /></Field>
              <Field label="Over Time"><input value={ike.overTime} onChange={(e) => setIkeField('overTime', e.target.value)} placeholder="" className={fCls} /></Field>
              <Field label="DPD Delay"><input value={ike.dpdDelay} onChange={(e) => setIkeField('dpdDelay', e.target.value)} placeholder="30s" className={fCls} /></Field>
              <Field label="DPD Timeout"><input value={ike.dpdTimeout} onChange={(e) => setIkeField('dpdTimeout', e.target.value)} placeholder="0s" className={fCls} /></Field>
              <Field label="MOBIKE"><select value={ike.mobike} onChange={(e) => setIkeField('mobike', e.target.value)} className={sCls}><option value="no">no</option><option value="yes">yes</option></select></Field>
              <Field label="Fragmentation"><select value={ike.fragmentation} onChange={(e) => setIkeField('fragmentation', e.target.value)} className={sCls}><option value="yes">yes</option><option value="no">no</option><option value="force">force</option></select></Field>
              <Field label="Encap"><select value={ike.encap} onChange={(e) => setIkeField('encap', e.target.value)} className={sCls}><option value="no">no</option><option value="yes">yes</option></select></Field>
              <Field label="Keyingtries"><input value={ike.keyingtries} onChange={(e) => setIkeField('keyingtries', e.target.value)} placeholder="1" className={fCls} /></Field>
              <Field label="Unique"><select value={ike.unique} onChange={(e) => setIkeField('unique', e.target.value)} className={sCls}><option value="no">no</option><option value="never">never</option><option value="keep">keep</option><option value="replace">replace</option></select></Field>
              <Field label="Aggressive"><select value={ike.aggressive} onChange={(e) => setIkeField('aggressive', e.target.value)} className={sCls}><option value="no">no</option><option value="yes">yes</option></select></Field>
              <Field label="VIPs"><input value={ike.vips} onChange={(e) => setIkeField('vips', e.target.value)} placeholder="" className={fCls} /></Field>
              <Field label="Pools"><input value={ike.pools} onChange={(e) => setIkeField('pools', e.target.value)} placeholder="" className={fCls} /></Field>
              <Field label="Local Port"><input value={ike.localPort} onChange={(e) => setIkeField('localPort', e.target.value)} placeholder="500" className={fCls} /></Field>
              <Field label="Remote Port"><input value={ike.remotePort} onChange={(e) => setIkeField('remotePort', e.target.value)} placeholder="500" className={fCls} /></Field>
              <Field label={isRoute ? 'IF ID In (start, auto-increments)' : 'IF ID In'}><input value={ike.ifIdIn} onChange={(e) => setIkeField('ifIdIn', e.target.value)} placeholder={isRoute ? '1' : ''} className={cn(fCls, isRoute && ike.ifIdIn && 'ring-1 ring-accent-amber/50 border-accent-amber/30')} /></Field>
              <Field label={isRoute ? 'IF ID Out (start, auto-increments)' : 'IF ID Out'}><input value={ike.ifIdOut} onChange={(e) => setIkeField('ifIdOut', e.target.value)} placeholder={isRoute ? '1' : ''} className={cn(fCls, isRoute && ike.ifIdOut && 'ring-1 ring-accent-amber/50 border-accent-amber/30')} /></Field>
              <Field label="Send Cert"><select value={ike.sendCert} onChange={(e) => setIkeField('sendCert', e.target.value)} className={sCls}><option value="ifasked">ifasked</option><option value="always">always</option><option value="never">never</option></select></Field>
            </div>
          </Section>

          {/* IKE Proposals */}
          <ProposalBuilder title="IKE Proposals" isIke state={ikeProposal} onChange={setIkeProposal} />

          {/* Authentication */}
          <Section title="Authentication" defaultOpen={false}>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="text-[10px] font-semibold text-surface-500">Local</div>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Auth Method"><select value={auth.localAuth} onChange={(e) => setAuthField('localAuth', e.target.value)} className={sCls}><option value="pubkey">pubkey</option><option value="psk">psk</option><option value="eap-mschapv2">eap-mschapv2</option><option value="eap-tls">eap-tls</option><option value="eap-radius">eap-radius</option></select></Field>
                  <Field label="ID"><input value={auth.localId} onChange={(e) => setAuthField('localId', e.target.value)} placeholder="(auto)" className={fCls} /></Field>
                  <Field label="Certs"><input value={auth.localCerts} onChange={(e) => setAuthField('localCerts', e.target.value)} placeholder="server.crt.pem" className={fCls} /></Field>
                  <Field label="EAP ID"><input value={auth.localEapId} onChange={(e) => setAuthField('localEapId', e.target.value)} className={fCls} /></Field>
                </div>
              </div>
              <div className="space-y-2">
                <div className="text-[10px] font-semibold text-surface-500">Remote</div>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Auth Method"><select value={auth.remoteAuth} onChange={(e) => setAuthField('remoteAuth', e.target.value)} className={sCls}><option value="pubkey">pubkey</option><option value="psk">psk</option><option value="eap-mschapv2">eap-mschapv2</option><option value="eap-tls">eap-tls</option><option value="eap-radius">eap-radius</option></select></Field>
                  <Field label="ID"><input value={auth.remoteId} onChange={(e) => setAuthField('remoteId', e.target.value)} placeholder="(auto)" className={fCls} /></Field>
                  <Field label="Certs"><input value={auth.remoteCerts} onChange={(e) => setAuthField('remoteCerts', e.target.value)} className={fCls} /></Field>
                  <Field label="Revocation"><select value={auth.remoteRevocation} onChange={(e) => setAuthField('remoteRevocation', e.target.value)} className={sCls}><option value="relaxed">relaxed</option><option value="strict">strict</option><option value="ifuri">ifuri</option></select></Field>
                </div>
              </div>
            </div>
          </Section>

          {/* Child SA */}
          <Section title="Child SA Settings" defaultOpen={false}>
            <div className="grid grid-cols-4 gap-2">
              <Field label="Rekey Time"><input value={child.rekeyTime} onChange={(e) => setChildField('rekeyTime', e.target.value)} placeholder="1h" className={fCls} /></Field>
              <Field label="Life Time"><input value={child.lifeTime} onChange={(e) => setChildField('lifeTime', e.target.value)} className={fCls} /></Field>
              <Field label="Mode"><select value={child.mode} onChange={(e) => setChildField('mode', e.target.value)} className={cn(sCls, isRoute && child.mode === 'pass' && 'ring-1 ring-accent-amber/50 border-accent-amber/30')}><option value="tunnel">tunnel</option><option value="transport">transport</option><option value="beet">beet</option><option value="pass">pass</option><option value="drop">drop</option></select></Field>
              <Field label="Start Action"><select value={child.startAction} onChange={(e) => setChildField('startAction', e.target.value)} className={sCls}><option value="none">none</option><option value="start">start</option><option value="trap">trap</option></select></Field>
              <Field label="Close Action"><select value={child.closeAction} onChange={(e) => setChildField('closeAction', e.target.value)} className={sCls}><option value="none">none</option><option value="start">start</option><option value="trap">trap</option></select></Field>
              <Field label="DPD Action"><select value={child.dpdAction} onChange={(e) => setChildField('dpdAction', e.target.value)} className={sCls}><option value="clear">clear</option><option value="trap">trap</option><option value="restart">restart</option></select></Field>
              <Field label="Replay Window"><input value={child.replayWindow} onChange={(e) => setChildField('replayWindow', e.target.value)} placeholder="32" className={fCls} /></Field>
              <Field label="HW Offload"><select value={child.hwOffload} onChange={(e) => setChildField('hwOffload', e.target.value)} className={sCls}><option value="no">no</option><option value="yes">yes</option><option value="auto">auto</option></select></Field>
              <Field label="Updown"><input value={child.updown} onChange={(e) => setChildField('updown', e.target.value)} className={fCls} /></Field>
              <Field label="Mark In"><input value={child.markIn} onChange={(e) => setChildField('markIn', e.target.value)} className={fCls} /></Field>
              <Field label="Mark Out"><input value={child.markOut} onChange={(e) => setChildField('markOut', e.target.value)} className={fCls} /></Field>
            </div>
          </Section>

          {/* ESP Proposals (Child SA) */}
          <ProposalBuilder title="ESP Proposals (Child SA)" isIke={false} state={espProposal} onChange={setEspProposal} />

          {/* Secrets */}
          <Section title="Secrets" defaultOpen={false}>
            <div className="grid grid-cols-4 gap-2">
              <Field label="Secret Type">
                <select value={secret.type} onChange={(e) => setSecretField('type', e.target.value)} className={sCls}>
                  <option value="none">None</option>
                  <option value="ike">IKE (PSK)</option>
                  <option value="eap">EAP</option>
                  <option value="xauth">XAuth</option>
                  <option value="private">Private Key</option>
                  <option value="rsa">RSA</option>
                  <option value="ecdsa">ECDSA</option>
                  <option value="pkcs8">PKCS8</option>
                  <option value="pkcs12">PKCS12</option>
                  <option value="token">Token</option>
                </select>
              </Field>
              {secret.type !== 'none' && (
                <>
                  <Field label="Secret / File / Handle"><input value={secret.value} onChange={(e) => setSecretField('value', e.target.value)} className={fCls} /></Field>
                  <Field label="IDs (comma-sep)"><input value={secret.ids} onChange={(e) => setSecretField('ids', e.target.value)} className={fCls} /></Field>
                </>
              )}
              {auth.localAuth === 'pubkey' && (
                <Field label="CA Name"><input value={secret.caName} onChange={(e) => setSecretField('caName', e.target.value)} placeholder="vpn-ca" className={fCls} /></Field>
              )}
            </div>
          </Section>

          {/* Preview & Save (always visible) */}
          <div className="border border-surface-200 dark:border-surface-700 rounded-lg overflow-hidden">
            <div className="px-3 py-2 bg-surface-50 dark:bg-surface-800/50 text-[11px] font-semibold text-surface-600 dark:text-surface-400">
              Preview & Save
            </div>
            <div className="p-3 space-y-2">
              <div className="flex items-center gap-2">
                <button onClick={handlePreview} className={btnCls('primary')}>
                  <Eye className="w-3.5 h-3.5" /> Preview Config
                </button>
                <input value={filename} onChange={(e) => setFilename(e.target.value)} placeholder="tunnel.conf" className={cn(inputCls, 'flex-1')} />
                <button onClick={handleSave} disabled={!localConnected || saving} className={btnCls('success')}>
                  <Save className="w-3.5 h-3.5" /> Save to Server
                </button>
              </div>
              {preview && (
                <pre className="max-h-80 overflow-auto rounded-lg bg-surface-900 text-surface-300 text-[10px] font-mono p-3 leading-relaxed whitespace-pre-wrap break-all">
                  {preview}
                </pre>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
