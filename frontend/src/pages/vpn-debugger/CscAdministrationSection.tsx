import { useState, useEffect, useCallback, useRef } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls, inputCls as sharedInputCls } from '@/lib/utils'
import {
  Settings, Loader2, CircleDot, RefreshCw, Play, Square, Trash2,
  RotateCcw, Upload, ChevronRight, ChevronDown, BarChart3, Server, Box,
} from 'lucide-react'
import {
  cscCheckInstallStatus, cscInstallDocker, cscDeleteImage,
  cscDeploy, cscContainerAction, cscGetContainers, cscGetResources,
  cscBuildImage, cscGetBuildProgress, cscGetBuildLogsLive,
} from './api'

interface ContainerInfo {
  id: string
  name: string
  status: string
  ip?: string
  protocol?: string
}

interface ResourceInfo {
  server_cpu?: string
  server_ram?: string
  server_disk?: string
  container_cpu?: string
  container_ram?: string
  container_avg?: string
  recommended_max?: number
}

export default function CscAdministrationSection() {
  const { localConnected } = useVpnDebuggerStore()

  // Docker state
  const [dockerInstalled, setDockerInstalled] = useState<boolean | null>(null)
  const [dockerVersion, setDockerVersion] = useState('')
  const [installingDocker, setInstallingDocker] = useState(false)

  // Image state
  const [images, setImages] = useState<{ id: string; tag: string; repoTag: string }[]>([])
  const [selectedImages, setSelectedImages] = useState<Set<string>>(new Set())
  const [buildPercent, setBuildPercent] = useState(0)
  const [buildElapsed, setBuildElapsed] = useState(0)
  const [buildLogs, setBuildLogs] = useState('')
  const [showBuildLogs, setShowBuildLogs] = useState(false)
  const buildTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const buildPollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [imageDropdownOpen, setImageDropdownOpen] = useState(false)
  const imageDropdownRef = useRef<HTMLDivElement>(null)
  const [debFile, setDebFile] = useState<File | null>(null)
  const [building, setBuilding] = useState(false)
  const [buildProgress, setBuildProgress] = useState('')
  const [allowUntrusted, setAllowUntrusted] = useState(true)

  // Proxy state
  const [proxyOpen, setProxyOpen] = useState(false)
  const [httpProxy, setHttpProxy] = useState('')
  const [httpsProxy, setHttpsProxy] = useState('')
  const [noProxy, setNoProxy] = useState('')

  // Scale state
  const [scaleTab, setScaleTab] = useState<'v4' | 'v6'>('v4')
  const [v4Headend, setV4Headend] = useState('')
  const [v4ConnType, setV4ConnType] = useState('ssl')
  const [v4Dtls, setV4Dtls] = useState(true)
  const [v4Pqc, setV4Pqc] = useState(false)
  const [v4VpnGroup, setV4VpnGroup] = useState('')
  const [v4VpnUser, setV4VpnUser] = useState('')
  const [v4VpnPass, setV4VpnPass] = useState('')
  const [v4UserIncr, setV4UserIncr] = useState(false)
  const [v4PassIncr, setV4PassIncr] = useState(false)
  const [v4StartIp, setV4StartIp] = useState('')
  const [v4Octet, setV4Octet] = useState(4)
  const [v4Count, setV4Count] = useState(1)
  const [v6Headend, setV6Headend] = useState('')
  const [v6ConnType, setV6ConnType] = useState('ssl')
  const [v6Dtls, setV6Dtls] = useState(true)
  const [v6Pqc, setV6Pqc] = useState(false)
  const [v6VpnGroup, setV6VpnGroup] = useState('')
  const [v6VpnUser, setV6VpnUser] = useState('')
  const [v6VpnPass, setV6VpnPass] = useState('')
  const [v6UserIncr, setV6UserIncr] = useState(false)
  const [v6PassIncr, setV6PassIncr] = useState(false)
  const [v6StartIp, setV6StartIp] = useState('')
  const [v6Hextet, setV6Hextet] = useState(8)
  const [v6Count, setV6Count] = useState(1)
  const [deploying, setDeploying] = useState(false)
  const [deployStatus, setDeployStatus] = useState('')

  // Tracking state
  const [containers, setContainers] = useState<ContainerInfo[]>([])
  const [resources, setResources] = useState<ResourceInfo>({})
  const [refreshingTracking, setRefreshingTracking] = useState(false)

  const runningCount = containers.filter(c => c.status?.toLowerCase().includes('running') || c.status?.toLowerCase() === 'up').length
  const stoppedCount = containers.filter(c => c.status?.toLowerCase().includes('exited') || c.status?.toLowerCase() === 'stopped').length
  const errorCount = containers.filter(c => c.status?.toLowerCase().includes('error') || c.status?.toLowerCase().includes('dead')).length

  const refreshInstallStatus = useCallback(async () => {
    const data = await cscCheckInstallStatus()
    if (data.success !== false) {
      setDockerInstalled(data.docker_installed ?? null)
      setDockerVersion(data.docker_version || '')
      setImages((data.images || []).map((img: { id?: string; tag?: string; repo?: string; Id?: string; RepoTags?: string[] }) => {
        const repo = img.repo || 'cisco-secure-client'
        const tag = img.tag || 'latest'
        return {
          id: img.id || img.Id || '',
          tag: `${repo}:${tag}`,
          repoTag: `${repo}:${tag}`,
        }
      }))
    }
  }, [])

  const refreshContainers = useCallback(async () => {
    const data = await cscGetContainers()
    if (data.success !== false) {
      setContainers(data.containers || [])
    }
  }, [])

  const refreshResources = useCallback(async () => {
    const data = await cscGetResources()
    if (data.success !== false) {
      setResources(data)
    }
  }, [])

  const refreshAll = useCallback(async () => {
    setRefreshingTracking(true)
    await Promise.all([refreshInstallStatus(), refreshContainers(), refreshResources()])
    setRefreshingTracking(false)
  }, [refreshInstallStatus, refreshContainers, refreshResources])

  useEffect(() => {
    if (localConnected) refreshAll()
  }, [localConnected, refreshAll])

  const handleInstallDocker = async () => {
    setInstallingDocker(true)
    await cscInstallDocker()
    await refreshInstallStatus()
    setInstallingDocker(false)
  }

  const handleDeleteImage = async (repoTag: string) => {
    if (!confirm(`Delete image ${repoTag}?`)) return
    await cscDeleteImage(repoTag)
    setSelectedImages(prev => { const s = new Set(prev); s.delete(repoTag); return s })
    await refreshInstallStatus()
  }

  // Selection is for choosing which image to deploy, not for deletion
  const toggleImageSelection = (tag: string) => {
    // Single-select: only one image can be selected for deployment
    setSelectedImages(new Set([tag]))
  }

  const stopBuildPolling = useCallback(() => {
    if (buildTimerRef.current) { clearInterval(buildTimerRef.current); buildTimerRef.current = null }
    if (buildPollRef.current) { clearInterval(buildPollRef.current); buildPollRef.current = null }
  }, [])

  const startBuildPolling = useCallback(() => {
    stopBuildPolling()
    const start = Date.now()
    buildTimerRef.current = setInterval(() => setBuildElapsed(Math.floor((Date.now() - start) / 1000)), 1000)
    buildPollRef.current = setInterval(async () => {
      const [prog, logs] = await Promise.all([cscGetBuildProgress(), cscGetBuildLogsLive()])
      setBuildPercent(prog.percent)
      setBuildProgress(prog.label)
      setBuildLogs(logs)
      if (!prog.active && prog.percent >= 100) stopBuildPolling()
    }, 2000)
  }, [stopBuildPolling])

  useEffect(() => { return () => stopBuildPolling() }, [stopBuildPolling])

  const handleBuildImage = async () => {
    if (!debFile) return
    setBuilding(true)
    setBuildProgress('Uploading .deb file...')
    setBuildPercent(0)
    setBuildElapsed(0)
    setBuildLogs('')
    setShowBuildLogs(true)
    try {
      const formData = new FormData()
      formData.append('file', debFile)
      const uploadRes = await fetch('/api/csc/upload-deb', { method: 'POST', credentials: 'include', body: formData })
      const uploadData = await uploadRes.json()
      if (!uploadData.success) { setBuildProgress(`Upload failed: ${uploadData.message}`); setBuilding(false); return }

      setBuildProgress('Building image...')
      startBuildPolling()
      const data = await cscBuildImage({
        allow_untrusted: allowUntrusted,
        http_proxy: httpProxy || undefined,
        https_proxy: httpsProxy || undefined,
        no_proxy: noProxy || undefined,
      })
      stopBuildPolling()
      if (data.success) {
        setBuildProgress('Build complete')
        setBuildPercent(100)
      } else {
        setBuildProgress(`Error: ${data.message || 'Build failed'}`)
      }
      // Final log fetch
      const finalLogs = await cscGetBuildLogsLive()
      setBuildLogs(finalLogs)
      await refreshInstallStatus()
    } catch (err) {
      stopBuildPolling()
      setBuildProgress(`Error: ${err instanceof Error ? err.message : 'Build failed'}`)
    }
    setBuilding(false)
  }

  const formatElapsed = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  const handleDeploy = async () => {
    const isV4 = scaleTab === 'v4'
    const headend = isV4 ? v4Headend : v6Headend
    const vpnUser = isV4 ? v4VpnUser : v6VpnUser
    const vpnPass = isV4 ? v4VpnPass : v6VpnPass
    if (!headend || !vpnUser || !vpnPass) {
      setDeployStatus('VPN Headend, Username, and Password are required.')
      return
    }
    setDeploying(true)
    const count = isV4 ? v4Count : v6Count
    setDeployStatus(`Deploying ${count} ${isV4 ? 'IPv4' : 'IPv6'} container(s)...`)
    const selectedTag = selectedImages.size > 0 ? [...selectedImages][0] : null
    const params: Record<string, unknown> = {
      count,
      headend,
      vpn_user: vpnUser,
      vpn_password: vpnPass,
      vpn_user_increment: isV4 ? v4UserIncr : v6UserIncr,
      vpn_password_increment: isV4 ? v4PassIncr : v6PassIncr,
      vpn_group: (isV4 ? v4VpnGroup : v6VpnGroup) || null,
      allow_untrusted_cert: allowUntrusted,
      image_tag: selectedTag,
      protocol: isV4 ? 'v4' : 'v6',
      connection_type: isV4 ? v4ConnType : v6ConnType,
      enable_dtls: isV4 ? v4Dtls : v6Dtls,
      enable_pqc: isV4 ? v4Pqc : v6Pqc,
    }
    if (isV4) {
      params.local_ipv4_start = v4StartIp || null
      params.ipv4_increment_octet = v4Octet
    } else {
      params.local_ipv6_start = v6StartIp || null
      params.ipv6_increment_hextet = v6Hextet
    }
    const data = await cscDeploy(params as Parameters<typeof cscDeploy>[0])
    if (data.success) {
      setDeployStatus(data.message || `Deployed ${data.deployed || count} containers`)
    } else {
      setDeployStatus(data.message || 'Deploy failed')
    }
    await refreshContainers()
    await refreshResources()
    setDeploying(false)
  }

  const handleContainerAction = async (action: 'stop-all' | 'restart-all' | 'delete-all') => {
    const protocol = scaleTab === 'v4' ? 'v4' : 'v6'
    await cscContainerAction(action, protocol)
    await refreshContainers()
    await refreshResources()
  }

  const inputCls = cn(sharedInputCls, 'w-full')
  const lblCls = 'block text-[10px] font-medium text-surface-500 mb-0.5'
  const subHdr = 'flex items-center gap-1.5 text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-1.5'

  // Render scale fields inline (not as a sub-component) to prevent input focus loss
  const renderScalePanel = (isV4: boolean) => {
    const headend = isV4 ? v4Headend : v6Headend
    const setHeadend = isV4 ? setV4Headend : setV6Headend
    const connType = isV4 ? v4ConnType : v6ConnType
    const setConnType = isV4 ? setV4ConnType : setV6ConnType
    const dtls = isV4 ? v4Dtls : v6Dtls
    const setDtls = isV4 ? setV4Dtls : setV6Dtls
    const pqc = isV4 ? v4Pqc : v6Pqc
    const setPqc = isV4 ? setV4Pqc : setV6Pqc
    const vpnGroup = isV4 ? v4VpnGroup : v6VpnGroup
    const setVpnGroup = isV4 ? setV4VpnGroup : setV6VpnGroup
    const vpnUser = isV4 ? v4VpnUser : v6VpnUser
    const setVpnUser = isV4 ? setV4VpnUser : setV6VpnUser
    const vpnPass = isV4 ? v4VpnPass : v6VpnPass
    const setVpnPass = isV4 ? setV4VpnPass : setV6VpnPass
    const userIncr = isV4 ? v4UserIncr : v6UserIncr
    const setUserIncr = isV4 ? setV4UserIncr : setV6UserIncr
    const passIncr = isV4 ? v4PassIncr : v6PassIncr
    const setPassIncr = isV4 ? setV4PassIncr : setV6PassIncr
    const startIp = isV4 ? v4StartIp : v6StartIp
    const setStartIp = isV4 ? setV4StartIp : setV6StartIp
    const count = isV4 ? v4Count : v6Count
    const setCount = isV4 ? setV4Count : setV6Count

    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-semibold text-surface-500">{isV4 ? 'IPv4' : 'IPv6'}</span>
          <div className="flex items-center gap-1">
            <button onClick={handleDeploy} disabled={!localConnected || deploying || !headend} className={iconBtnCls('primary')} title="Deploy"><Play className="w-3 h-3" /></button>
            <button onClick={() => handleContainerAction('stop-all')} disabled={!localConnected} className={iconBtnCls()} title="Stop All"><Square className="w-3 h-3" /></button>
            <button onClick={() => handleContainerAction('restart-all')} disabled={!localConnected} className={iconBtnCls('warning')} title="Restart All"><RotateCcw className="w-3 h-3" /></button>
            <button onClick={() => handleContainerAction('delete-all')} disabled={!localConnected} className={iconBtnCls('danger')} title="Delete All"><Trash2 className="w-3 h-3" /></button>
            <button onClick={refreshAll} disabled={!localConnected || refreshingTracking} className={iconBtnCls()} title="Refresh"><RefreshCw className={cn('w-3 h-3', refreshingTracking && 'animate-spin')} /></button>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className={lblCls}>VPN Headend</label>
            <input value={headend} onChange={e => setHeadend(e.target.value)} placeholder={isV4 ? 'e.g. vpn.example.com' : 'e.g. vpn.example.com'} className={inputCls} />
          </div>
          <div>
            <label className={lblCls}>Connection Type</label>
            <div className="flex items-center gap-1.5">
              <select value={connType} onChange={e => { setConnType(e.target.value); if (e.target.value === 'ipsec') setDtls(false) }} className={cn(inputCls, 'flex-1')}>
                <option value="ssl">SSL</option>
                <option value="ipsec">IPSec-IKEv2</option>
              </select>
              {connType === 'ssl' && (
                <label className="flex items-center gap-0.5 text-[9px] text-surface-400 whitespace-nowrap cursor-pointer">
                  <input type="checkbox" checked={dtls} onChange={e => setDtls(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" /> DTLS
                </label>
              )}
              {connType === 'ipsec' && (
                <label className="flex items-center gap-0.5 text-[9px] text-surface-400 whitespace-nowrap cursor-pointer">
                  <input type="checkbox" checked={pqc} onChange={e => setPqc(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" /> PQC
                </label>
              )}
            </div>
          </div>
          <div>
            <label className={lblCls}>VPN Group / Profile</label>
            <input value={vpnGroup} onChange={e => setVpnGroup(e.target.value)} placeholder="(optional)" className={inputCls} />
          </div>
          <div>
            <div className="flex items-center justify-between mb-0.5">
              <label className="text-[10px] font-medium text-surface-500">VPN Username</label>
              <label className="flex items-center gap-0.5 text-[9px] text-surface-400 cursor-pointer">
                <input type="checkbox" checked={userIncr} onChange={e => setUserIncr(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" /> Incr
              </label>
            </div>
            <input value={vpnUser} onChange={e => setVpnUser(e.target.value)} placeholder="vpnuser" className={inputCls} />
            {userIncr && <span className="text-[9px] text-surface-400">e.g. admin → admin1, admin2…</span>}
          </div>
          <div>
            <div className="flex items-center justify-between mb-0.5">
              <label className="text-[10px] font-medium text-surface-500">VPN Password</label>
              <label className="flex items-center gap-0.5 text-[9px] text-surface-400 cursor-pointer">
                <input type="checkbox" checked={passIncr} onChange={e => setPassIncr(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" /> Incr
              </label>
            </div>
            <input value={vpnPass} onChange={e => setVpnPass(e.target.value)} type="password" placeholder="vpnpass" className={inputCls} />
            {passIncr && <span className="text-[9px] text-surface-400">e.g. cisco → cisco1, cisco2…</span>}
          </div>
          <div>
            <label className={lblCls}>{isV4 ? 'Start IP' : 'Start IP (IPv6)'}</label>
            <input value={startIp} onChange={e => setStartIp(e.target.value)} placeholder={isV4 ? 'e.g. 10.10.10.1' : 'e.g. fd00::1'} className={inputCls} />
          </div>
          <div>
            <label className={lblCls}>{isV4 ? 'Incr. Octet' : 'Incr. Hextet'}</label>
            {isV4 ? (
              <select value={v4Octet} onChange={e => setV4Octet(parseInt(e.target.value))} className={inputCls}>
                <option value={4}>4th (x.x.x.N)</option>
                <option value={3}>3rd (x.x.N.x)</option>
                <option value={2}>2nd (x.N.x.x)</option>
                <option value={1}>1st (N.x.x.x)</option>
              </select>
            ) : (
              <select value={v6Hextet} onChange={e => setV6Hextet(parseInt(e.target.value))} className={inputCls}>
                {[8, 7, 6, 5, 4, 3, 2, 1].map(n => <option key={n} value={n}>{n === 8 ? '8th (last)' : `${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}`}</option>)}
              </select>
            )}
          </div>
          <div>
            <label className={lblCls}>Containers</label>
            <input type="number" value={count} onChange={e => setCount(parseInt(e.target.value) || 1)} min={1} max={200} className={inputCls} />
          </div>
        </div>
        {deployStatus && <div className="text-[10px] text-surface-500 dark:text-surface-400 mt-1">{deployStatus}</div>}
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <h5 className="flex items-center gap-1.5 text-[11px] font-semibold text-surface-600 dark:text-surface-400 border-b border-surface-100 dark:border-surface-800 pb-1.5">
        <Settings className="w-3.5 h-3.5 text-surface-400" /> Administration
      </h5>

      {/* Docker */}
      <div className="p-2.5 rounded-xl border border-surface-200 dark:border-surface-800 space-y-1.5">
        <div className={subHdr}><Box className="w-3 h-3 text-blue-500" /> Docker</div>
        {dockerInstalled === null ? (
          <div className="text-[10px] text-surface-400 italic">{localConnected ? 'Checking...' : 'Connect to check status'}</div>
        ) : dockerInstalled ? (
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-accent-emerald font-medium">{dockerVersion || 'Installed'}</span>
            <CircleDot className="w-2 h-2 text-accent-emerald" />
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-red-500 font-medium">Not installed</span>
            <button onClick={handleInstallDocker} disabled={installingDocker || !localConnected} className={btnCls('primary')}>
              {installingDocker ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Box className="w-3.5 h-3.5" />} Install Docker
            </button>
          </div>
        )}
      </div>

      {/* Image */}
      <div className="p-2.5 rounded-xl border border-surface-200 dark:border-surface-800 space-y-2">
        <div className={subHdr}><Box className="w-3 h-3 text-purple-500" /> Image</div>

        {/* Images dropdown with checkboxes */}
        <div className="relative" ref={imageDropdownRef}>
          <button
            onClick={() => setImageDropdownOpen(!imageDropdownOpen)}
            disabled={images.length === 0}
            className={cn(
              'w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg border text-xs transition-colors',
              images.length === 0
                ? 'border-surface-200 dark:border-surface-700 text-surface-400 bg-surface-50 dark:bg-surface-800/50'
                : 'border-surface-200 dark:border-surface-700 text-surface-700 dark:text-surface-300 bg-white dark:bg-surface-800 hover:border-vyper-400',
            )}
          >
            <span className="truncate">
              {images.length === 0
                ? 'No images available'
                : selectedImages.size === 0
                  ? `Select image for deployment`
                  : [...selectedImages][0]}
            </span>
            <ChevronDown className={cn('w-3.5 h-3.5 text-surface-400 shrink-0 transition-transform', imageDropdownOpen && 'rotate-180')} />
          </button>
          {imageDropdownOpen && images.length > 0 && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setImageDropdownOpen(false)} />
              <div className="absolute left-0 right-0 mt-1 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 py-1 max-h-48 overflow-auto">
                {images.map(img => (
                  <div key={img.repoTag} onClick={() => toggleImageSelection(img.repoTag)} className="flex items-center gap-2 px-3 py-1.5 hover:bg-surface-50 dark:hover:bg-surface-800/70 transition-colors group cursor-pointer">
                    <span
                      className={cn(
                        'w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center shrink-0 transition-colors',
                        selectedImages.has(img.repoTag)
                          ? 'border-vyper-600 bg-vyper-600'
                          : 'border-surface-300 dark:border-surface-600 hover:border-vyper-400',
                      )}
                    >
                      {selectedImages.has(img.repoTag) && <span className="w-1.5 h-1.5 rounded-full bg-white" />}
                    </span>
                    <span className="text-[11px] font-mono text-surface-700 dark:text-surface-300 truncate flex-1 min-w-0">{img.repoTag}</span>
                    <button onClick={(e) => { e.stopPropagation(); handleDeleteImage(img.repoTag) }} className={iconBtnCls('danger')} title="Delete image">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Build */}
        <div className="flex items-center gap-2">
          <label className="flex-1 min-w-0 border-2 border-dashed border-surface-300 dark:border-surface-700 rounded-lg px-2.5 py-1.5 text-center cursor-pointer text-[10px] text-surface-500 hover:border-vyper-400 transition-colors truncate">
            <Upload className="w-3 h-3 inline mr-1" />
            {debFile ? debFile.name : 'Drop or click to upload .deb'}
            <input type="file" accept=".deb" className="hidden" onChange={e => setDebFile(e.target.files?.[0] || null)} />
          </label>
          <button onClick={handleBuildImage} disabled={!debFile || building || !localConnected} className={btnCls('primary')}>
            {building ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Settings className="w-3.5 h-3.5" />} Build
          </button>
        </div>
        {(building || buildProgress) && (
          <div className="space-y-1.5">
            {/* Progress bar with elapsed time */}
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 rounded-full bg-surface-200 dark:bg-surface-700 overflow-hidden">
                <div className="h-full rounded-full bg-vyper-600 transition-all duration-500" style={{ width: `${buildPercent}%` }} />
              </div>
              <span className="text-[9px] font-mono text-surface-400 shrink-0">{buildPercent}%</span>
              {building && <span className="text-[9px] font-mono text-surface-400 shrink-0">{formatElapsed(buildElapsed)}</span>}
            </div>
            {/* Status message */}
            <div className="flex items-center gap-1.5 text-[10px] text-blue-600 dark:text-blue-400">
              {building && <Loader2 className="w-3 h-3 animate-spin shrink-0" />}
              <span className="truncate">{buildProgress}</span>
            </div>
            {/* Build logs toggle */}
            <button
              onClick={() => setShowBuildLogs(!showBuildLogs)}
              className="flex items-center gap-1 text-[10px] text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 transition-colors"
            >
              <ChevronRight className={cn('w-2.5 h-2.5 transition-transform', showBuildLogs && 'rotate-90')} />
              Build Logs
            </button>
            {showBuildLogs && (
              <pre className="max-h-48 overflow-auto rounded-lg bg-surface-900 text-surface-300 text-[10px] font-mono p-2.5 leading-relaxed whitespace-pre-wrap break-all">
                {buildLogs || '(waiting for logs...)'}
              </pre>
            )}
          </div>
        )}
        <label className="flex items-center gap-1.5 text-[10px] text-surface-500 cursor-pointer">
          <input type="checkbox" checked={allowUntrusted} onChange={e => setAllowUntrusted(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" />
          Allow Untrusted Certificate
        </label>

        {/* Proxy */}
        <button onClick={() => setProxyOpen(!proxyOpen)} className="flex items-center gap-1 text-[10px] text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 transition-colors">
          <ChevronRight className={cn('w-2.5 h-2.5 transition-transform', proxyOpen && 'rotate-90')} />
          Proxy Settings (optional)
        </button>
        {proxyOpen && (
          <div className="grid grid-cols-2 gap-2 pl-3">
            <div>
              <label className={lblCls}>HTTP Proxy</label>
              <input value={httpProxy} onChange={e => setHttpProxy(e.target.value)} placeholder="http://proxy:8080" className={inputCls} />
            </div>
            <div>
              <label className={lblCls}>HTTPS Proxy</label>
              <input value={httpsProxy} onChange={e => setHttpsProxy(e.target.value)} placeholder="http://proxy:8080" className={inputCls} />
            </div>
            <div className="col-span-2">
              <label className={lblCls}>No Proxy</label>
              <input value={noProxy} onChange={e => setNoProxy(e.target.value)} placeholder="localhost,127.0.0.1,.local" className={inputCls} />
            </div>
          </div>
        )}
      </div>

      {/* Scale */}
      <div className="p-2.5 rounded-xl border border-surface-200 dark:border-surface-800 space-y-2">
        <div className={subHdr}><Server className="w-3 h-3 text-accent-violet" /> Scale</div>
        <div className="flex border-b border-surface-200 dark:border-surface-700 mb-2">
          <button onClick={() => setScaleTab('v4')} className={cn('px-3 py-1.5 text-[10px] font-medium border-b-2 transition-colors', scaleTab === 'v4' ? 'border-vyper-600 text-vyper-600' : 'border-transparent text-surface-400 hover:text-surface-600')}>IPv4</button>
          <button onClick={() => setScaleTab('v6')} className={cn('px-3 py-1.5 text-[10px] font-medium border-b-2 transition-colors', scaleTab === 'v6' ? 'border-vyper-600 text-vyper-600' : 'border-transparent text-surface-400 hover:text-surface-600')}>IPv6</button>
        </div>
        {renderScalePanel(scaleTab === 'v4')}
      </div>

      {/* Tracking */}
      <div className="p-2.5 rounded-xl border border-surface-200 dark:border-surface-800 space-y-2.5">
        <div className="flex items-center justify-between">
          <div className={subHdr}><BarChart3 className="w-3 h-3 text-accent-amber" /> Tracking</div>
          <button onClick={refreshAll} disabled={!localConnected || refreshingTracking} className={iconBtnCls()} title="Refresh">
            <RefreshCw className={cn('w-3.5 h-3.5', refreshingTracking && 'animate-spin')} />
          </button>
        </div>

        {/* Compact status row */}
        <div className="flex items-center gap-3 text-[10px] text-surface-600 dark:text-surface-300">
          <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-accent-emerald" /><strong>{runningCount}</strong> running</span>
          <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-surface-400" /><strong>{stoppedCount}</strong> stopped</span>
          <span className={cn('flex items-center gap-1', errorCount > 0 && 'text-red-500')}><span className={cn('w-1.5 h-1.5 rounded-full', errorCount > 0 ? 'bg-red-500' : 'bg-surface-300 dark:bg-surface-600')} /><strong>{errorCount}</strong> error</span>
          <span className="text-surface-500 dark:text-surface-400 ml-auto">{containers.length} total</span>
        </div>

        {/* Resources — compact inline */}
        {(resources.server_cpu || resources.server_ram) && (
          <div className="grid grid-cols-2 gap-2 text-[10px]">
            <div className="space-y-0.5">
              <div className="text-[9px] font-medium text-surface-400 uppercase tracking-wider">Server</div>
              <div className="flex gap-2 text-surface-600 dark:text-surface-400">
                {resources.server_cpu && <span>CPU {resources.server_cpu}</span>}
                {resources.server_ram && <span>RAM {resources.server_ram}</span>}
                {resources.server_disk && <span>Disk {resources.server_disk}</span>}
              </div>
            </div>
            <div className="space-y-0.5">
              <div className="text-[9px] font-medium text-surface-400 uppercase tracking-wider">Containers</div>
              <div className="flex gap-2 text-surface-600 dark:text-surface-400">
                {resources.container_cpu && <span>CPU {resources.container_cpu}</span>}
                {resources.container_ram && <span>RAM {resources.container_ram}</span>}
                {resources.container_avg && <span>Avg {resources.container_avg}</span>}
              </div>
            </div>
          </div>
        )}
        {resources.recommended_max != null && (
          <div className="text-[9px] text-accent-amber">Max recommended: <strong>{resources.recommended_max}</strong> containers</div>
        )}
      </div>
    </div>
  )
}
