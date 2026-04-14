import { useState, useEffect, useCallback, useRef } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, iconBtnCls, inputCls as sharedInputCls } from '@/lib/utils'
import CustomSelect from '@/components/CustomSelect'
import {
  Settings, Loader2, CircleDot, RefreshCw, Play, Square, Trash2,
  RotateCcw, Upload, ChevronRight, ChevronDown, BarChart3, Server, Box,
  X, FileText, Copy, Check, Save, FolderOpen,
} from 'lucide-react'
import Toggle from '@/components/Toggle'
import {
  cscCheckInstallStatus, cscInstallDocker, cscDeleteImage,
  cscDeploy, cscContainerAction, cscGetContainers, cscGetResources,
  cscBuildImage, cscGetBuildProgress, cscGetBuildLogsLive,
  cscSingleContainerAction, cscGetContainerLogs,
} from './api'

interface DeployPreset {
  name: string
  v4: { headend: string; connType: string; dtls: boolean; pqc: boolean; vpnGroup: string; vpnUser: string; vpnPass: string; userIncr: boolean; passIncr: boolean; startIp: string; octet: number; count: number }
  v6: { headend: string; connType: string; dtls: boolean; pqc: boolean; vpnGroup: string; vpnUser: string; vpnPass: string; userIncr: boolean; passIncr: boolean; startIp: string; hextet: number; count: number }
}

const DEPLOY_PRESETS_KEY = 'csc-deploy-presets'

function loadPresetsFromStorage(): DeployPreset[] {
  try {
    return JSON.parse(localStorage.getItem(DEPLOY_PRESETS_KEY) || '[]')
  } catch { return [] }
}

function savePresetsToStorage(presets: DeployPreset[]) {
  localStorage.setItem(DEPLOY_PRESETS_KEY, JSON.stringify(presets))
}

interface ContainerInfo {
  id: string
  name: string
  status: string
  state: string
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
  const [statusLoading, setStatusLoading] = useState(false)

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

  // Deploy presets
  const [deployPresets, setDeployPresets] = useState<DeployPreset[]>(loadPresetsFromStorage)
  const [presetDropdownOpen, setPresetDropdownOpen] = useState(false)
  const [presetName, setPresetName] = useState('')
  const [showSavePreset, setShowSavePreset] = useState(false)
  const presetDropdownRef = useRef<HTMLDivElement>(null)

  // Tracking state
  const [containers, setContainers] = useState<ContainerInfo[]>([])
  const [resources, setResources] = useState<ResourceInfo>({})
  const [refreshingTracking, setRefreshingTracking] = useState(false)

  // Use backend-computed counts (from state field), with fallback to local filtering
  const [runningCountApi, setRunningCountApi] = useState(0)
  const [stoppedCountApi, setStoppedCountApi] = useState(0)
  const [errorCountApi, setErrorCountApi] = useState(0)

  // Container popup state
  const [containerPopupOpen, setContainerPopupOpen] = useState(false)
  const [containerPopupFilter, setContainerPopupFilter] = useState<'running' | 'stopped' | 'error' | null>(null)
  const [expandedLogs, setExpandedLogs] = useState<Record<string, string>>({})
  const [loadingLogs, setLoadingLogs] = useState<Record<string, boolean>>({})
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Bulk action loading state
  const [bulkActionLoading, setBulkActionLoading] = useState<string | null>(null)

  const notify = useVpnDebuggerStore.getState().notify
  const bumpCscContainerRefresh = useVpnDebuggerStore.getState().bumpCscContainerRefresh

  const refreshInstallStatus = useCallback(async () => {
    setStatusLoading(true)
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
    setStatusLoading(false)
  }, [])

  const refreshContainers = useCallback(async () => {
    const data = await cscGetContainers()
    if (data.success !== false) {
      setContainers(data.containers || [])
      setRunningCountApi(data.running ?? 0)
      setStoppedCountApi(data.stopped ?? 0)
      setErrorCountApi(data.error ?? 0)
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
      notify('VPN Headend, Username, and Password are required.', 'warning')
      return
    }
    setDeploying(true)
    const count = isV4 ? v4Count : v6Count
    notify(`Deploying ${count} ${isV4 ? 'IPv4' : 'IPv6'} container(s)...`, 'info')
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
      notify(data.message || `Deployed ${data.deployed || count} containers`, 'success')
    } else {
      notify(data.message || 'Deploy failed', 'error')
    }
    await refreshContainers()
    await refreshResources()
    bumpCscContainerRefresh()
    setDeploying(false)
  }

  const handleContainerAction = async (action: 'stop-all' | 'restart-all' | 'delete-all') => {
    const protocol = scaleTab === 'v4' ? 'v4' : 'v6'
    const labels: Record<string, [string, string]> = {
      'stop-all': ['Stopping all containers...', 'All containers stopped'],
      'restart-all': ['Restarting all containers...', 'All containers restarted'],
      'delete-all': ['Deleting all containers...', 'All containers deleted'],
    }
    const [ing, ed] = labels[action]
    setBulkActionLoading(action)
    notify(ing, 'info')
    const data = await cscContainerAction(action, protocol)
    if (data.success !== false) {
      notify(data.message || ed, 'success')
    } else {
      notify(data.message || 'Action failed', 'error')
    }
    await refreshContainers()
    await refreshResources()
    bumpCscContainerRefresh()
    setBulkActionLoading(null)
  }

  // Container popup helpers
  const openContainerPopup = (filter: 'running' | 'stopped' | 'error') => {
    setContainerPopupFilter(filter)
    setExpandedLogs({})
    setLoadingLogs({})
    setCopiedId(null)
    setContainerPopupOpen(true)
  }

  const filteredPopupContainers = containers.filter(c => {
    const st = (c.state || '').toLowerCase()
    if (containerPopupFilter === 'running') return st === 'running'
    if (containerPopupFilter === 'stopped') return st === 'exited'
    if (containerPopupFilter === 'error') return st !== 'running' && st !== 'exited'
    return true
  })

  const popupTitle = containerPopupFilter === 'running' ? 'Running' : containerPopupFilter === 'stopped' ? 'Stopped' : 'Error'

  const handleToggleLogs = async (id: string) => {
    if (expandedLogs[id] !== undefined) {
      setExpandedLogs(prev => { const n = { ...prev }; delete n[id]; return n })
      return
    }
    setLoadingLogs(prev => ({ ...prev, [id]: true }))
    const logs = await cscGetContainerLogs(id)
    setExpandedLogs(prev => ({ ...prev, [id]: logs }))
    setLoadingLogs(prev => ({ ...prev, [id]: false }))
  }

  const handleCopyLogs = (id: string) => {
    const logs = expandedLogs[id]
    if (!logs) return
    navigator.clipboard.writeText(logs).then(() => {
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 1500)
    })
  }

  const handlePopupContainerAction = async (action: 'stop' | 'restart', id: string) => {
    notify(action === 'stop' ? 'Stopping container...' : 'Restarting container...', 'info')
    const data = await cscSingleContainerAction(action, id)
    if (data.success !== false) {
      notify(data.message || (action === 'stop' ? 'Container stopped' : 'Container restarted'), 'success')
    } else {
      notify(data.message || 'Action failed', 'error')
    }
    await refreshContainers()
    await refreshResources()
    bumpCscContainerRefresh()
  }

  const saveDeployPreset = () => {
    const name = presetName.trim()
    if (!name) { notify('Enter a preset name', 'warning'); return }
    const preset: DeployPreset = {
      name,
      v4: { headend: v4Headend, connType: v4ConnType, dtls: v4Dtls, pqc: v4Pqc, vpnGroup: v4VpnGroup, vpnUser: v4VpnUser, vpnPass: v4VpnPass, userIncr: v4UserIncr, passIncr: v4PassIncr, startIp: v4StartIp, octet: v4Octet, count: v4Count },
      v6: { headend: v6Headend, connType: v6ConnType, dtls: v6Dtls, pqc: v6Pqc, vpnGroup: v6VpnGroup, vpnUser: v6VpnUser, vpnPass: v6VpnPass, userIncr: v6UserIncr, passIncr: v6PassIncr, startIp: v6StartIp, hextet: v6Hextet, count: v6Count },
    }
    const updated = [...deployPresets.filter(p => p.name !== name), preset]
    setDeployPresets(updated)
    savePresetsToStorage(updated)
    setPresetName('')
    setShowSavePreset(false)
    notify(`Preset "${name}" saved`, 'success')
  }

  const loadDeployPreset = (preset: DeployPreset) => {
    setV4Headend(preset.v4.headend); setV4ConnType(preset.v4.connType); setV4Dtls(preset.v4.dtls); setV4Pqc(preset.v4.pqc)
    setV4VpnGroup(preset.v4.vpnGroup); setV4VpnUser(preset.v4.vpnUser); setV4VpnPass(preset.v4.vpnPass)
    setV4UserIncr(preset.v4.userIncr); setV4PassIncr(preset.v4.passIncr); setV4StartIp(preset.v4.startIp); setV4Octet(preset.v4.octet); setV4Count(preset.v4.count)
    setV6Headend(preset.v6.headend); setV6ConnType(preset.v6.connType); setV6Dtls(preset.v6.dtls); setV6Pqc(preset.v6.pqc)
    setV6VpnGroup(preset.v6.vpnGroup); setV6VpnUser(preset.v6.vpnUser); setV6VpnPass(preset.v6.vpnPass)
    setV6UserIncr(preset.v6.userIncr); setV6PassIncr(preset.v6.passIncr); setV6StartIp(preset.v6.startIp); setV6Hextet(preset.v6.hextet); setV6Count(preset.v6.count)
    setPresetDropdownOpen(false)
    notify(`Preset "${preset.name}" loaded`, 'success')
  }

  const deleteDeployPreset = (name: string) => {
    const updated = deployPresets.filter(p => p.name !== name)
    setDeployPresets(updated)
    savePresetsToStorage(updated)
    notify(`Preset "${name}" deleted`, 'info')
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
            <button onClick={handleDeploy} disabled={!localConnected || deploying || !headend} className={iconBtnCls('primary')} title="Start"><Play className="w-3 h-3" /></button>
            <button onClick={() => handleContainerAction('stop-all')} disabled={!localConnected || bulkActionLoading !== null} className={iconBtnCls()} title="Stop All">{bulkActionLoading === 'stop-all' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Square className="w-3 h-3" />}</button>
            <button onClick={() => handleContainerAction('restart-all')} disabled={!localConnected || bulkActionLoading !== null} className={iconBtnCls('warning')} title="Restart All">{bulkActionLoading === 'restart-all' ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCcw className="w-3 h-3" />}</button>
            <button onClick={() => handleContainerAction('delete-all')} disabled={!localConnected || bulkActionLoading !== null} className={iconBtnCls('danger')} title="Delete All">{bulkActionLoading === 'delete-all' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}</button>
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
              <CustomSelect value={connType} onChange={v => { setConnType(v); if (v === 'ipsec') setDtls(false) }} className="flex-1" options={[
                { value: 'ssl', label: 'SSL' },
                { value: 'ipsec', label: 'IPSec-IKEv2' },
              ]} />
              {connType === 'ssl' && (
                <Toggle checked={dtls} onChange={setDtls} label="DTLS" />
              )}
              {connType === 'ipsec' && (
                <Toggle checked={pqc} onChange={setPqc} label="PQC" />
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
              <Toggle checked={userIncr} onChange={setUserIncr} label="Scale" />
            </div>
            <input value={vpnUser} onChange={e => setVpnUser(e.target.value)} placeholder="vpnuser" className={inputCls} />
          </div>
          <div>
            <div className="flex items-center justify-between mb-0.5">
              <label className="text-[10px] font-medium text-surface-500">VPN Password</label>
              <Toggle checked={passIncr} onChange={setPassIncr} label="Scale" />
            </div>
            <input value={vpnPass} onChange={e => setVpnPass(e.target.value)} type="password" placeholder="vpnpass" className={inputCls} />
          </div>
          <div>
            <label className={lblCls}>{isV4 ? 'Start IP' : 'Start IP (IPv6)'}</label>
            <input value={startIp} onChange={e => setStartIp(e.target.value)} placeholder={isV4 ? 'e.g. 10.10.10.1' : 'e.g. fd00::1'} className={inputCls} />
          </div>
          <div>
            <label className={lblCls}>{isV4 ? 'Incr. Octet' : 'Incr. Hextet'}</label>
            {isV4 ? (
              <CustomSelect value={String(v4Octet)} onChange={v => setV4Octet(parseInt(v))} options={[
                { value: '4', label: '4th (x.x.x.N)' },
                { value: '3', label: '3rd (x.x.N.x)' },
                { value: '2', label: '2nd (x.N.x.x)' },
                { value: '1', label: '1st (N.x.x.x)' },
              ]} />
            ) : (
              <CustomSelect value={String(v6Hextet)} onChange={v => setV6Hextet(parseInt(v))} options={
                [8, 7, 6, 5, 4, 3, 2, 1].map(n => ({ value: String(n), label: n === 8 ? '8th (last)' : `${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}` }))
              } />
            )}
          </div>
          <div>
            <label className={lblCls}>Containers</label>
            <input type="number" value={count} onChange={e => setCount(parseInt(e.target.value) || 1)} min={1} max={200} className={inputCls} />
          </div>
        </div>
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
          <div className="flex items-center gap-1.5 text-[10px] text-surface-400 italic">
            {localConnected ? <><Loader2 className="w-3 h-3 animate-spin" /> Loading Docker status...</> : 'Connect to check status'}
          </div>
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
            <span className="truncate flex items-center gap-1.5">
              {statusLoading && images.length === 0
                ? <><Loader2 className="w-3 h-3 animate-spin" /> Loading images...</>
                : images.length === 0
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
        <Toggle checked={allowUntrusted} onChange={setAllowUntrusted} label="Allow Untrusted Certificate" />

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
        <div className="flex items-center justify-between">
          <div className={subHdr}><Server className="w-3 h-3 text-accent-violet" /> Deploy</div>
          <div className="flex items-center gap-1 relative" ref={presetDropdownRef}>
            <button onClick={() => { setPresetDropdownOpen(!presetDropdownOpen); setShowSavePreset(false) }} className={iconBtnCls()} title="Load Preset">
              <FolderOpen className="w-3 h-3" />
            </button>
            <button onClick={() => { setShowSavePreset(!showSavePreset); setPresetDropdownOpen(false) }} className={iconBtnCls()} title="Save Preset">
              <Save className="w-3 h-3" />
            </button>
            {presetDropdownOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setPresetDropdownOpen(false)} />
                <div className="absolute right-0 top-full mt-1 w-56 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 py-1 max-h-48 overflow-auto">
                  {deployPresets.length === 0 ? (
                    <div className="px-3 py-2 text-[10px] text-surface-400 italic">No saved presets</div>
                  ) : deployPresets.map(p => (
                    <div key={p.name} className="flex items-center gap-2 px-3 py-1.5 hover:bg-surface-50 dark:hover:bg-surface-800/70 transition-colors group cursor-pointer" onClick={() => loadDeployPreset(p)}>
                      <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300 truncate flex-1 min-w-0">{p.name}</span>
                      <button onClick={(e) => { e.stopPropagation(); deleteDeployPreset(p.name) }} className={iconBtnCls('danger')} title="Delete preset">
                        <Trash2 className="w-2.5 h-2.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}
            {showSavePreset && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setShowSavePreset(false)} />
                <div className="absolute right-0 top-full mt-1 w-56 bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 z-20 p-2.5">
                  <label className="block text-[10px] font-medium text-surface-500 mb-1">Preset Name</label>
                  <div className="flex gap-1.5">
                    <input value={presetName} onChange={e => setPresetName(e.target.value)} onKeyDown={e => e.key === 'Enter' && saveDeployPreset()} placeholder="My preset" className={cn(sharedInputCls, 'flex-1')} autoFocus />
                    <button onClick={saveDeployPreset} disabled={!presetName.trim()} className={btnCls('primary')}><Save className="w-3 h-3" /> Save</button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
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
          <button onClick={() => openContainerPopup('running')} className="flex items-center gap-1 px-1.5 py-0.5 rounded-full border border-surface-200 dark:border-surface-700 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors cursor-pointer" title="Click to view running containers"><span className="w-1.5 h-1.5 rounded-full bg-accent-emerald" /><strong>{runningCountApi}</strong> running</button>
          <button onClick={() => openContainerPopup('stopped')} className="flex items-center gap-1 px-1.5 py-0.5 rounded-full border border-surface-200 dark:border-surface-700 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors cursor-pointer" title="Click to view stopped containers"><span className="w-1.5 h-1.5 rounded-full bg-surface-400" /><strong>{stoppedCountApi}</strong> stopped</button>
          <button onClick={() => openContainerPopup('error')} className={cn('flex items-center gap-1 px-1.5 py-0.5 rounded-full border border-surface-200 dark:border-surface-700 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors cursor-pointer', errorCountApi > 0 && 'text-red-500')} title="Click to view error containers"><span className={cn('w-1.5 h-1.5 rounded-full', errorCountApi > 0 ? 'bg-red-500' : 'bg-surface-300 dark:bg-surface-600')} /><strong>{errorCountApi}</strong> error</button>
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

      {/* Container Details Popup */}
      {containerPopupOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setContainerPopupOpen(false)} />
          <div className="relative w-[720px] max-w-[90vw] max-h-[85vh] bg-white dark:bg-surface-900 rounded-xl shadow-2xl flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50">
              <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">{popupTitle} Containers ({filteredPopupContainers.length})</h3>
              <button onClick={() => setContainerPopupOpen(false)} className="p-1 rounded-lg hover:bg-surface-200 dark:hover:bg-surface-700 transition-colors"><X className="w-4 h-4 text-surface-500" /></button>
            </div>
            <div className="flex-1 overflow-auto p-3">
              {filteredPopupContainers.length === 0 ? (
                <div className="text-xs text-surface-400 italic py-4 text-center">No containers in this category.</div>
              ) : (
                <div className="space-y-0.5">
                  {filteredPopupContainers.map(c => (
                    <div key={c.id}>
                      <div className="flex items-center gap-2 px-2.5 py-2 rounded-lg hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors border-b border-surface-100 dark:border-surface-800 last:border-b-0">
                        <span className="text-[10px] font-mono text-surface-400 w-[72px] shrink-0 truncate" title={c.id}>{c.id.slice(0, 12)}</span>
                        <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300 flex-1 min-w-0 truncate">{c.name}</span>
                        <span className="text-[10px] text-surface-500 shrink-0">{c.status}</span>
                        <div className="flex items-center gap-0.5 shrink-0">
                          <button onClick={() => handlePopupContainerAction('stop', c.id)} className={iconBtnCls('danger')} title="Stop"><Square className="w-3 h-3" /></button>
                          <button onClick={() => handlePopupContainerAction('restart', c.id)} className={iconBtnCls('warning')} title="Restart"><RotateCcw className="w-3 h-3" /></button>
                          <button onClick={() => handleToggleLogs(c.id)} className={iconBtnCls()} title="Logs">
                            {loadingLogs[c.id] ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />}
                          </button>
                        </div>
                      </div>
                      {expandedLogs[c.id] !== undefined && (
                        <div className="mx-2 mb-1">
                          <div className="flex items-center justify-end mb-1">
                            <button onClick={() => handleCopyLogs(c.id)} className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-surface-700 hover:bg-surface-600 text-surface-300 transition-colors" title="Copy to clipboard">
                              {copiedId === c.id ? <><Check className="w-3 h-3 text-accent-emerald" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
                            </button>
                          </div>
                          <pre className="max-h-48 overflow-auto rounded-lg bg-surface-900 text-surface-300 text-[10px] font-mono p-2.5 leading-relaxed whitespace-pre-wrap break-all">
                            {expandedLogs[c.id]}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
