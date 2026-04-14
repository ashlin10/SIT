import { useRef, useState, useCallback } from 'react'
import { cn } from '@/lib/utils'
import CustomSelect from '@/components/CustomSelect'
import { useFmcConfigStore, type VpnPeer } from '@/stores/fmcConfigStore'
import { uploadVpn, fetchVpnTopologies, applyVpn, deleteVpnTopologies, downloadVpnYaml, replaceVpnEndpoints, reUploadVpnYaml } from './api'
import VpnTemplateBuilder from './VpnTemplateBuilder'
import {
  Upload, Download, Send, Trash2, RefreshCw, ChevronDown, ChevronUp,
  Replace, Users, FileCode, Layers,
} from 'lucide-react'

export default function VpnSection() {
  const {
    vpnTopologies, vpnFilename, vpnYaml,
    devices, isOperationRunning,
    setVpnEnabled, toggleVpnTopology, selectAllVpn, openViewer,
  } = useFmcConfigStore()

  const fileRef = useRef<HTMLInputElement>(null)
  const [collapsed, setCollapsed] = useState(false)
  const [replaceCollapsed, setReplaceCollapsed] = useState(true)
  const [templateOpen, setTemplateOpen] = useState(false)
  const [srcDevice, setSrcDevice] = useState('')
  const [dstDevice, setDstDevice] = useState('')

  const handleUpload = async (file: File) => {
    const result = await uploadVpn(file)
    if (!result.success) alert(result.message || 'Upload failed')
    else setVpnEnabled(true)
  }

  const handleFetch = async () => {
    const result = await fetchVpnTopologies()
    if (!result.success) alert(result.message || 'Fetch failed')
    else setVpnEnabled(true)
  }

  const handleApply = async () => {
    const selected = vpnTopologies.filter((t) => t.selected).map((t) => t.raw)
    if (selected.length === 0) { alert('Select at least one VPN topology'); return }
    const result = await applyVpn(selected)
    if (!result.success) alert(result.message || 'Apply failed')
  }

  const handleDelete = async () => {
    const selected = vpnTopologies.filter((t) => t.selected).map((t) => t.raw)
    if (selected.length === 0) { alert('Select at least one VPN topology'); return }
    if (!confirm(`Delete ${selected.length} VPN topology(ies)?`)) return
    const result = await deleteVpnTopologies(selected)
    if (!result.success) alert(result.message || 'Delete failed')
  }

  const handleDownload = async () => {
    const selected = vpnTopologies.filter((t) => t.selected).map((t) => t.raw)
    if (selected.length === 0) { alert('Select at least one VPN topology'); return }
    const result = await downloadVpnYaml(selected)
    if (!result.success) alert(result.message || 'Download failed')
  }

  const allSelected = vpnTopologies.length > 0 && vpnTopologies.every((t) => t.selected)

  const btnCls = (variant: 'primary' | 'secondary' | 'danger' = 'secondary') =>
    cn(
      'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
      variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
      variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
      variant === 'danger' && 'border border-accent-rose/30 text-accent-rose/70 hover:bg-accent-rose/10 hover:text-accent-rose',
    )


  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50'
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          {vpnFilename && (
            <>
              <span className="text-[11px] font-medium text-surface-500">File</span>
              <button
                onClick={() => openViewer(`VPN — ${vpnFilename}`, vpnYaml, (yaml) => reUploadVpnYaml(yaml))}
                className="text-[10px] font-medium text-accent-violet bg-accent-violet/10 border border-accent-violet/20 rounded-full px-2.5 py-0.5 hover:bg-accent-violet/20 transition-colors cursor-pointer"
              >
                <FileCode className="w-3 h-3 inline mr-1" />
                {vpnFilename}
              </button>
            </>
          )}
        </div>
      </div>

        <div className="px-5 py-4 space-y-4">
          {/* ── Create VPN Topology ── */}
          <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 bg-surface-50 dark:bg-surface-800/50">
              <div className="flex items-center gap-2">
                <button onClick={() => setCollapsed(!collapsed)} className="p-0.5 text-surface-400">
                  {collapsed ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
                </button>
                <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Create VPN Topology</span>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => setTemplateOpen(true)} className={btnCls()}>
                  <Layers className="w-3.5 h-3.5" /> Template
                </button>
                <button onClick={handleFetch} disabled={isOperationRunning} className={cn(btnCls(), isOperationRunning && 'opacity-40 pointer-events-none')}>
                  <RefreshCw className="w-3.5 h-3.5" /> Fetch from FMC
                </button>
                <button onClick={() => fileRef.current?.click()} className={btnCls()}>
                  <Upload className="w-3.5 h-3.5" /> Upload YAML
                </button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".yaml,.yml"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0]
                    if (f) handleUpload(f)
                    e.target.value = ''
                  }}
                />
                <button onClick={handleDownload} disabled={vpnTopologies.length === 0} className={cn(btnCls(), vpnTopologies.length === 0 && 'opacity-40 pointer-events-none')}>
                  <Download className="w-3.5 h-3.5" /> Download
                </button>
              </div>
            </div>

            {!collapsed && (
              <div className="p-3 space-y-3">
                {vpnTopologies.length === 0 ? (
                  <p className="text-[11px] text-surface-400 text-center py-3">
                    No VPN topologies loaded. Upload a YAML or fetch from FMC.
                  </p>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <label className="flex items-center gap-2 text-[10px] text-surface-500">
                        <input
                          type="checkbox"
                          checked={allSelected}
                          onChange={(e) => selectAllVpn(e.target.checked)}
                          className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
                        />
                        Select All ({vpnTopologies.length})
                      </label>
                    </div>

                    <div className="overflow-auto max-h-64 rounded-lg border border-surface-200 dark:border-surface-700">
                      <table className="w-full text-[11px]">
                        <thead className="sticky top-0 z-10">
                          <tr className="bg-surface-50 dark:bg-surface-800/80">
                            <th className="px-3 py-1.5 text-left font-medium text-surface-500 w-8"></th>
                            <th className="px-3 py-1.5 text-left font-medium text-surface-500">Topology Name</th>
                            <th className="px-3 py-1.5 text-left font-medium text-surface-500">Topology Type</th>
                            <th className="px-3 py-1.5 text-left font-medium text-surface-500">Sub Type</th>
                            <th className="px-3 py-1.5 text-left font-medium text-surface-500">Peers</th>
                          </tr>
                        </thead>
                        <tbody>
                          {vpnTopologies.map((t, i) => (
                            <tr
                              key={i}
                              onClick={() => toggleVpnTopology(i)}
                              className={cn(
                                'border-b border-surface-100 dark:border-surface-800/50 last:border-b-0 cursor-pointer transition-colors',
                                t.selected ? 'bg-vyper-500/5' : 'hover:bg-surface-50 dark:hover:bg-surface-800/30'
                              )}
                            >
                              <td className="px-3 py-1.5">
                                <input
                                  type="checkbox"
                                  checked={!!t.selected}
                                  onChange={() => toggleVpnTopology(i)}
                                  onClick={(e) => e.stopPropagation()}
                                  className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
                                />
                              </td>
                              <td className="px-3 py-1.5 font-medium text-surface-700 dark:text-surface-300">{t.name}</td>
                              <td className="px-3 py-1.5 text-surface-500">{t.topologyType}</td>
                              <td className="px-3 py-1.5 text-surface-500">{t.subType || '—'}</td>
                              <td className="px-3 py-1.5">
                                <PeersCell peers={t.peers} topologyType={t.topologyType} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <div className="flex items-center gap-2 pt-1">
                      <button onClick={handleApply} disabled={isOperationRunning} className={cn(btnCls('primary'), isOperationRunning && 'opacity-40 pointer-events-none')}>
                        <Send className="w-3.5 h-3.5" /> Push VPN
                      </button>
                      <button onClick={handleDelete} disabled={isOperationRunning} className={cn(btnCls('danger'), isOperationRunning && 'opacity-40 pointer-events-none')}>
                        <Trash2 className="w-3.5 h-3.5" /> Delete VPN
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>

          {/* ── Replace VPN Endpoints ── */}
          <div className="rounded-lg border border-surface-200 dark:border-surface-700">
            <div className="flex items-center justify-between px-3 py-2 bg-surface-50 dark:bg-surface-800/50">
              <div className="flex items-center gap-2">
                <button onClick={() => setReplaceCollapsed(!replaceCollapsed)} className="p-0.5 text-surface-400">
                  {replaceCollapsed ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
                </button>
                <Replace className="w-3.5 h-3.5 text-surface-500" />
                <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">Replace VPN Endpoints</span>
              </div>
            </div>

            {!replaceCollapsed && (
              <div className="p-3 space-y-3">
                <p className="text-[10px] text-surface-400">
                  Replace all VPN endpoints of the source device with the destination device across all VPN topologies.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] font-medium text-surface-500 mb-1">Source Device</label>
                    <CustomSelect
                      value={srcDevice}
                      onChange={setSrcDevice}
                      placeholder="— Select Source —"
                      dropUp
                      options={devices.map(d => ({ value: d.id, label: `${d.name}${d.hostname ? ` (${d.hostname})` : ''}` }))}
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-medium text-surface-500 mb-1">Destination Device</label>
                    <CustomSelect
                      value={dstDevice}
                      onChange={setDstDevice}
                      placeholder="— Select Destination —"
                      dropUp
                      options={devices.map(d => ({ value: d.id, label: `${d.name}${d.hostname ? ` (${d.hostname})` : ''}` }))}
                    />
                  </div>
                </div>
                <button
                  onClick={async () => {
                    if (!srcDevice || !dstDevice) { alert('Select both source and destination'); return }
                    const result = await replaceVpnEndpoints(srcDevice, dstDevice)
                    if (!result.success) alert(result.message || 'Replace failed')
                  }}
                  disabled={isOperationRunning || !srcDevice || !dstDevice}
                  className={cn(btnCls('primary'), (isOperationRunning || !srcDevice || !dstDevice) && 'opacity-40 pointer-events-none')}
                >
                  <Replace className="w-3.5 h-3.5" /> Replace Endpoints
                </button>
              </div>
            )}
          </div>
        </div>
      <VpnTemplateBuilder open={templateOpen} onClose={() => setTemplateOpen(false)} />
    </div>
  )
}

// ── Peers cell with count + hover tooltip ──

function PeersCell({ peers, topologyType }: { peers: VpnPeer[]; topologyType: string }) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isHubSpoke = topologyType.toUpperCase().includes('HUB') && topologyType.toUpperCase().includes('SPOKE')

  const hubs = isHubSpoke ? peers.filter((p) => (p.peerType || '').toUpperCase() === 'HUB') : []
  const spokes = isHubSpoke ? peers.filter((p) => (p.peerType || '').toUpperCase() === 'SPOKE') : []
  const other = isHubSpoke
    ? peers.filter((p) => !['HUB', 'SPOKE'].includes((p.peerType || '').toUpperCase()))
    : peers

  const show = useCallback((e: React.MouseEvent) => {
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null }
    setPos({ x: e.clientX + 12, y: e.clientY + 12 })
  }, [])
  const scheduleHide = useCallback(() => {
    hideTimer.current = setTimeout(() => setPos(null), 200)
  }, [])
  const cancelHide = useCallback(() => {
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null }
  }, [])

  return (
    <span
      className="relative inline-flex items-center gap-1 cursor-default text-accent-violet"
      onMouseEnter={show}
      onMouseLeave={scheduleHide}
      onClick={(e) => e.stopPropagation()}
    >
      <Users className="w-3.5 h-3.5" />
      <span className="text-[10px] font-mono">{peers.length}</span>

      {pos && peers.length > 0 && (
        <div
          className="fixed min-w-48 max-w-72 bg-surface-900 dark:bg-surface-800 border border-surface-700 rounded-lg shadow-xl p-2.5 text-[10px] text-surface-200"
          style={{ zIndex: 9999, left: Math.min(pos.x, window.innerWidth - 300), top: Math.min(pos.y, window.innerHeight - 250) }}
          onMouseEnter={cancelHide}
          onMouseLeave={scheduleHide}
        >
          <div className="font-medium text-surface-100 mb-1.5">Peers</div>
          <div className="max-h-48 overflow-y-auto">
            {isHubSpoke ? (
              <>
                {hubs.length > 0 && (
                  <div className="mb-1">
                    <div className="font-semibold text-accent-amber text-[9px] uppercase tracking-wider mb-0.5">Hub</div>
                    {hubs.map((p, i) => <div key={i} className="pl-2 text-surface-300">{p.name}</div>)}
                  </div>
                )}
                {spokes.length > 0 && (
                  <div className="mb-1">
                    <div className="font-semibold text-accent-emerald text-[9px] uppercase tracking-wider mb-0.5">Spoke</div>
                    {spokes.map((p, i) => <div key={i} className="pl-2 text-surface-300">{p.name}</div>)}
                  </div>
                )}
                {other.length > 0 && (
                  <div>
                    <div className="font-semibold text-surface-400 text-[9px] uppercase tracking-wider mb-0.5">Other</div>
                    {other.map((p, i) => <div key={i} className="pl-2 text-surface-300">{p.name}</div>)}
                  </div>
                )}
              </>
            ) : (
              other.map((p, i) => <div key={i} className="text-surface-300">{p.name}</div>)
            )}
          </div>
        </div>
      )}
    </span>
  )
}
