import { useState, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { reUploadVpnYaml, fetchTemplateLookups } from './api'
import {
  X, Plus, Layers, AlertCircle, RefreshCw, Loader2,
} from 'lucide-react'
import yaml from 'js-yaml'

// ── IP increment helpers ──

function incrementIpv4(ip: string, octet: number, step: number): string {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || octet < 1 || octet > 4) return ip
  parts[octet - 1] += step
  // Handle overflow
  for (let i = 3; i >= 0; i--) {
    if (parts[i] > 255) {
      const carry = Math.floor(parts[i] / 256)
      parts[i] = parts[i] % 256
      if (i > 0) parts[i - 1] += carry
    }
  }
  return parts.join('.')
}

function incrementIpv6(ip: string, hextet: number, step: number): string {
  // Expand :: notation
  const halves = ip.split('::')
  let groups: string[]
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : []
    const right = halves[1] ? halves[1].split(':') : []
    const fill = 8 - left.length - right.length
    groups = [...left, ...Array(fill).fill('0'), ...right]
  } else {
    groups = ip.split(':')
  }
  while (groups.length < 8) groups.push('0')
  const idx = hextet - 1
  if (idx < 0 || idx >= 8) return ip
  groups[idx] = (parseInt(groups[idx], 16) + step).toString(16)
  // Compress back
  const full = groups.map(g => g.replace(/^0+/, '') || '0')
  // Find longest run of 0s for :: compression
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
  for (let i = 0; i < 8; i++) {
    if (full[i] === '0') {
      if (curStart === -1) curStart = i
      curLen++
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen }
    } else {
      curStart = -1; curLen = 0
    }
  }
  if (bestLen >= 2) {
    const before = full.slice(0, bestStart).join(':')
    const after = full.slice(bestStart + bestLen).join(':')
    return `${before}::${after}`
  }
  return full.join(':')
}

// ── Types ──

type VpnCategory = 'route-based' | 'policy-based' | 'sd-wan'
type TopologyType = 'POINT_TO_POINT' | 'HUB_AND_SPOKE' | 'FULL_MESH'
type PeerMode = 'ftd-to-ftd' | 'ftd-to-extranet'

interface ExtranetPeer {
  name: string
  ipAddress: string
  isDynamic: boolean
}

interface FtdPeer {
  deviceName: string
  interfaceName: string
  interfaceType: string
}

// Lookup item from FMC (full expanded object)
interface PolicyObj {
  [key: string]: unknown
  id?: string
  name?: string
  type?: string
}

interface RouteBasedP2PConfig {
  peerMode: PeerMode
  // Scaling
  count: string
  startNameSuffix: string
  namePrefix: string
  // Non-extranet peer (local FTD)
  ftdPeer: FtdPeer
  // Extranet or second FTD peer
  extranetPeer: ExtranetPeer
  ftdPeer2: FtdPeer
  // Extranet IP scaling
  extranetIpVersion: 'ipv4' | 'ipv6'
  extranetIncOctet: string
  extranetIncHextet: string
  // Interface scaling
  intfStartNum: string
  // IKE version flags
  ikeV1Enabled: boolean
  ikeV2Enabled: boolean
  // IKE settings
  preSharedKey: string
  // Selected policy/proposal names (matched to fetched objects)
  ikev1PolicyName: string
  ikev2PolicyName: string
  ikev1IpsecProposalName: string
  ikev2IpsecProposalName: string
  // IPSec
  enableRRI: boolean
  // Advanced
  enableBFD: boolean
  sgtPropagation: boolean
}

const defaultRouteBasedP2P: RouteBasedP2PConfig = {
  peerMode: 'ftd-to-extranet',
  count: '1',
  startNameSuffix: '0',
  namePrefix: 'ROUTE-BASED-VPN-',
  ftdPeer: { deviceName: '', interfaceName: 'svti_inside_', interfaceType: 'VTI' },
  extranetPeer: { name: 'Extranet-', ipAddress: '10.0.0.1', isDynamic: false },
  ftdPeer2: { deviceName: '', interfaceName: 'svti_inside_', interfaceType: 'VTI' },
  extranetIpVersion: 'ipv4',
  extranetIncOctet: '4',
  extranetIncHextet: '8',
  intfStartNum: '0',
  ikeV1Enabled: false,
  ikeV2Enabled: true,
  preSharedKey: 'cisco123',
  ikev1PolicyName: '',
  ikev2PolicyName: '',
  ikev1IpsecProposalName: '',
  ikev2IpsecProposalName: '',
  enableRRI: true,
  enableBFD: false,
  sgtPropagation: false,
}

// Policy lookup state
interface PolicyLookups {
  ikev1Policies: PolicyObj[]
  ikev2Policies: PolicyObj[]
  ikev1IpsecProposals: PolicyObj[]
  ikev2IpsecProposals: PolicyObj[]
  loaded: boolean
  loading: boolean
}

// ── YAML Generation ──

function stripMetaKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(stripMetaKeys)
  if (obj && typeof obj === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'metadata' || k === 'links') continue
      out[k] = stripMetaKeys(v)
    }
    return out
  }
  return obj
}

function generateRouteBasedP2PYaml(cfg: RouteBasedP2PConfig, lookups: PolicyLookups): string {
  const count = parseInt(cfg.count) || 1
  const startSuffix = isNaN(parseInt(cfg.startNameSuffix)) ? 0 : parseInt(cfg.startNameSuffix)
  const intfStart = isNaN(parseInt(cfg.intfStartNum)) ? 0 : parseInt(cfg.intfStartNum)

  // Resolve selected policy objects
  const ikev1Policy = lookups.ikev1Policies.find(p => p.name === cfg.ikev1PolicyName)
  const ikev2Policy = lookups.ikev2Policies.find(p => p.name === cfg.ikev2PolicyName)
  const ikev1Proposal = lookups.ikev1IpsecProposals.find(p => p.name === cfg.ikev1IpsecProposalName)
  const ikev2Proposal = lookups.ikev2IpsecProposals.find(p => p.name === cfg.ikev2IpsecProposalName)

  const topologies: Record<string, unknown>[] = []

  for (let i = 0; i < count; i++) {
    const suffix = startSuffix + i
    const topoName = `${cfg.namePrefix}${suffix}`

    // Build local FTD endpoint
    const intfNum = intfStart + i
    const localEndpoint: Record<string, unknown> = {
      extranet: false,
      dynamicRRIEnabled: false,
      allowIncomingIKEv2Routes: true,
      enableNATExempt: false,
      sendTunnelInterfaceIpToPeer: true,
      enableNatTraversal: true,
      overrideRemoteVpnFilter: false,
      protectedNetworks: {},
      isLocalTunnelIdEnabled: false,
      connectionType: 'BIDIRECTIONAL',
      peerType: 'PEER',
      device: {
        name: cfg.ftdPeer.deviceName,
        id: '<DEVICE_UUID>',
        type: 'Device',
      },
      interface: {
        name: `${cfg.ftdPeer.interfaceName}${intfNum}`,
        id: '<INTERFACE_UUID>',
        type: cfg.ftdPeer.interfaceType,
      },
      name: cfg.ftdPeer.deviceName,
      type: 'EndPoint',
    }

    // Build remote endpoint
    let remoteEndpoint: Record<string, unknown>
    if (cfg.peerMode === 'ftd-to-extranet') {
      const epName = `${cfg.extranetPeer.name}${suffix}`
      let epIp = cfg.extranetPeer.ipAddress
      if (i > 0) {
        if (cfg.extranetIpVersion === 'ipv4') {
          epIp = incrementIpv4(cfg.extranetPeer.ipAddress, parseInt(cfg.extranetIncOctet) || 4, i)
        } else {
          epIp = incrementIpv6(cfg.extranetPeer.ipAddress, parseInt(cfg.extranetIncHextet) || 8, i)
        }
      }
      remoteEndpoint = {
        extranet: true,
        dynamicRRIEnabled: false,
        extranetInfo: {
          name: 'Extranet',
          ipAddress: epIp,
          isDynamicIP: cfg.extranetPeer.isDynamic,
        },
        allowIncomingIKEv2Routes: true,
        enableNATExempt: false,
        enableNatTraversal: true,
        overrideRemoteVpnFilter: false,
        protectedNetworks: {},
        isLocalTunnelIdEnabled: false,
        connectionType: 'ORIGINATE_ONLY',
        peerType: 'PEER',
        name: epName,
        type: 'EndPoint',
      }
    } else {
      // FTD-to-FTD
      remoteEndpoint = {
        extranet: false,
        dynamicRRIEnabled: false,
        allowIncomingIKEv2Routes: true,
        enableNATExempt: false,
        sendTunnelInterfaceIpToPeer: true,
        enableNatTraversal: true,
        overrideRemoteVpnFilter: false,
        protectedNetworks: {},
        isLocalTunnelIdEnabled: false,
        connectionType: 'BIDIRECTIONAL',
        peerType: 'PEER',
        device: {
          name: cfg.ftdPeer2.deviceName,
          id: '<DEVICE_UUID>',
          type: 'Device',
        },
        interface: {
          name: `${cfg.ftdPeer2.interfaceName}${intfNum}`,
          id: '<INTERFACE_UUID>',
          type: cfg.ftdPeer2.interfaceType,
        },
        name: cfg.ftdPeer2.deviceName,
        type: 'EndPoint',
      }
    }

    // IKE Settings — build based on enabled versions
    const ikeSetting: Record<string, unknown> = {
      id: '<IKE_SETTINGS_UUID>',
      type: 'IkeSetting',
    }
    if (cfg.ikeV1Enabled && ikev1Policy) {
      ikeSetting.ikeV1Settings = {
        manualPreSharedKey: cfg.preSharedKey,
        authenticationType: 'MANUAL_PRE_SHARED_KEY',
        policies: [stripMetaKeys(ikev1Policy)],
      }
    }
    if (cfg.ikeV2Enabled && ikev2Policy) {
      ikeSetting.ikeV2Settings = {
        manualPreSharedKey: cfg.preSharedKey,
        enforceHexBasedPreSharedKeyOnly: false,
        authenticationType: 'MANUAL_PRE_SHARED_KEY',
        policies: [stripMetaKeys(ikev2Policy)],
      }
    }
    const ikeSettings = [ikeSetting]

    // IPSec Settings — include proposals for enabled IKE versions
    const ipsecSetting: Record<string, unknown> = {
      tfcPackets: { payloadBytes: 0, timeoutSeconds: 0, burstBytes: 0, enabled: false },
      enableSaStrengthEnforcement: false,
      validateIncomingIcmpErrorMessage: false,
      perfectForwardSecrecy: { enabled: false },
      ikeV2Mode: 'TUNNEL',
      enableRRI: cfg.enableRRI,
      lifetimeSeconds: 28800,
      lifetimeKilobytes: 4608000,
      doNotFragmentPolicy: 'NONE',
      cryptoMapType: 'STATIC',
      id: '<IPSEC_SETTINGS_UUID>',
      type: 'IPSecSetting',
    }
    if (cfg.ikeV1Enabled && ikev1Proposal) {
      ipsecSetting.ikeV1IpsecProposal = [stripMetaKeys(ikev1Proposal)]
    }
    if (cfg.ikeV2Enabled && ikev2Proposal) {
      ipsecSetting.ikeV2IpsecProposal = [stripMetaKeys(ikev2Proposal)]
    }
    const ipsecSettings = [ipsecSetting]

    // Advanced Settings
    const advancedSettings = [{
      id: '<ADVANCED_SETTINGS_UUID>',
      type: 'AdvancedSetting',
      advancedTunnelSetting: {
        vpnIdleTimeout: { timeoutMinutes: 30, enabled: true },
        certificateMapSettings: {
          useCertificateOuToDetermineTunnel: true,
          useIkeIdentityOuToDetermineTunnel: true,
          usePeerIpAddressToDetermineTunnel: true,
          useCertMapConfiguredInEndpointToDetermineTunnel: false,
        },
        tunnelBFDSettings: { enableBFD: cfg.enableBFD },
        enableSpokeToSpokeConnectivityThroughHub: false,
        bypassAccessControlTrafficForDecryptedTraffic: false,
        natKeepaliveMessageTraversal: { enabled: true, intervalSeconds: 20 },
        enableSGTPropagationOverVTI: cfg.sgtPropagation,
      },
      advancedIpsecSetting: {
        maximumTransmissionUnitAging: { enabled: false },
        enableFragmentationBeforeEncryption: true,
      },
      advancedIkeSetting: {
        ikeKeepaliveSettings: { ikeKeepalive: 'ENABLED', threshold: 10, retryInterval: 2 },
        enableNotificationOnTunnelDisconnect: false,
        thresholdToChallengeIncomingCookies: 50,
        percentageOfSAsAllowedInNegotiation: 100,
        identitySentToPeer: 'AUTO_OR_DN',
        peerIdentityValidation: 'REQUIRED',
        cookieChallenge: 'CUSTOM',
        enableAggressiveMode: false,
      },
    }]

    topologies.push({
      name: topoName,
      routeBased: true,
      ikeV1Enabled: cfg.ikeV1Enabled,
      ikeV2Enabled: cfg.ikeV2Enabled,
      topologyType: 'POINT_TO_POINT',
      endpoints: [localEndpoint, remoteEndpoint],
      ikeSettings,
      ipsecSettings,
      advancedSettings,
    })
  }

  return yaml.dump({ vpn_topologies: topologies }, { sortKeys: false, lineWidth: -1 })
}

// ── Shared CSS classes ──

const labelCls = 'text-[10px] font-medium text-surface-500 dark:text-surface-400 whitespace-nowrap'
const inputCls = 'rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800 px-2 py-1 text-[11px] text-surface-800 dark:text-surface-200 focus:ring-1 focus:ring-vyper-500/30 focus:border-vyper-500 transition-colors outline-none'
const selectCls = 'rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800 px-2 py-1 text-[11px] text-surface-800 dark:text-surface-200 focus:ring-1 focus:ring-vyper-500/30 focus:border-vyper-500 transition-colors outline-none'

const TABS: { key: VpnCategory; label: string }[] = [
  { key: 'route-based', label: 'Route-Based VPN' },
  { key: 'policy-based', label: 'Policy-Based VPN' },
  { key: 'sd-wan', label: 'SD-WAN Topology' },
]

const TOPOLOGY_OPTIONS: Record<VpnCategory, TopologyType[]> = {
  'route-based': ['POINT_TO_POINT', 'HUB_AND_SPOKE'],
  'policy-based': ['POINT_TO_POINT', 'HUB_AND_SPOKE', 'FULL_MESH'],
  'sd-wan': ['HUB_AND_SPOKE'],
}

const TOPOLOGY_LABELS: Record<TopologyType, string> = {
  'POINT_TO_POINT': 'Point to Point',
  'HUB_AND_SPOKE': 'Hub and Spoke',
  'FULL_MESH': 'Full Mesh',
}

const OCT_OPTIONS = [1, 2, 3, 4]
const HEX_OPTIONS = [1, 2, 3, 4, 5, 6, 7, 8]

// ── Component ──

interface Props {
  open: boolean
  onClose: () => void
}

export default function VpnTemplateBuilder({ open, onClose }: Props) {
  const { setVpnFilename, setVpnEnabled, openViewer } = useFmcConfigStore()

  const [activeTab, setActiveTab] = useState<VpnCategory>('route-based')
  const [topoType, setTopoType] = useState<TopologyType>('POINT_TO_POINT')
  const [peerMode, setPeerMode] = useState<PeerMode>('ftd-to-extranet')
  const [cfg, setCfg] = useState<RouteBasedP2PConfig>({ ...defaultRouteBasedP2P })
  const [lookups, setLookups] = useState<PolicyLookups>({
    ikev1Policies: [], ikev2Policies: [], ikev1IpsecProposals: [], ikev2IpsecProposals: [],
    loaded: false, loading: false,
  })

  const loadLookups = useCallback(async () => {
    setLookups(prev => ({ ...prev, loading: true }))
    try {
      const data = await fetchTemplateLookups()
      if (data.success) {
        setLookups({
          ikev1Policies: data.ikev1Policies || [],
          ikev2Policies: data.ikev2Policies || [],
          ikev1IpsecProposals: data.ikev1IpsecProposals || [],
          ikev2IpsecProposals: data.ikev2IpsecProposals || [],
          loaded: true,
          loading: false,
        })
      } else {
        setLookups(prev => ({ ...prev, loading: false }))
      }
    } catch {
      setLookups(prev => ({ ...prev, loading: false }))
    }
  }, [])

  useEffect(() => {
    if (open && !lookups.loaded && !lookups.loading) {
      loadLookups()
    }
  }, [open, lookups.loaded, lookups.loading, loadLookups])

  if (!open) return null

  const upd = (patch: Partial<RouteBasedP2PConfig>) => setCfg(prev => ({ ...prev, ...patch }))

  const isActiveConfig = activeTab === 'route-based' && topoType === 'POINT_TO_POINT'

  const handleGenerate = async () => {
    if (!isActiveConfig) return
    const yamlText = generateRouteBasedP2PYaml(cfg, lookups)
    try {
      const result = await reUploadVpnYaml(yamlText)
      if (result.success) {
        setVpnFilename(`vpn-template-${Date.now()}.yaml`)
        setVpnEnabled(true)
        onClose()
      } else {
        alert(result.message || 'Failed to load generated template')
      }
    } catch (e) {
      alert('Failed to load template: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  const handlePreview = () => {
    if (!isActiveConfig) return
    const yamlText = generateRouteBasedP2PYaml(cfg, lookups)
    openViewer('VPN Template Preview', yamlText, async (edited) => {
      await reUploadVpnYaml(edited)
      setVpnEnabled(true)
      onClose()
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className={cn(
        'relative w-[92vw] max-w-4xl max-h-[88vh] flex flex-col',
        'bg-white dark:bg-surface-900 rounded-xl border border-surface-200 dark:border-surface-800',
        'shadow-2xl overflow-hidden'
      )}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-200 dark:border-surface-800/50 shrink-0">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-vyper-500" />
            <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200">VPN Template Builder</h3>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-surface-200 dark:border-surface-800/50 shrink-0">
          {TABS.map(tab => (
            <button
              key={tab.key}
              onClick={() => { setActiveTab(tab.key); setTopoType(TOPOLOGY_OPTIONS[tab.key][0]) }}
              className={cn(
                'px-4 py-2 text-[11px] font-medium transition-colors border-b-2 -mb-px',
                activeTab === tab.key
                  ? 'border-vyper-500 text-vyper-600 dark:text-vyper-400'
                  : 'border-transparent text-surface-500 hover:text-surface-700 dark:hover:text-surface-300'
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Topology Type Selector */}
          <div className="flex items-center gap-3">
            <label className={labelCls}>Topology Type</label>
            <div className="flex gap-1.5">
              {TOPOLOGY_OPTIONS[activeTab].map(tt => (
                <button
                  key={tt}
                  onClick={() => setTopoType(tt)}
                  className={cn(
                    'px-3 py-1 rounded-md text-[11px] font-medium transition-all',
                    topoType === tt
                      ? 'bg-vyper-600 text-white shadow-sm'
                      : 'bg-surface-100 dark:bg-surface-800 text-surface-500 hover:bg-surface-200 dark:hover:bg-surface-700'
                  )}
                >
                  {TOPOLOGY_LABELS[tt]}
                </button>
              ))}
            </div>
          </div>

          {/* Content */}
          {!isActiveConfig ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <AlertCircle className="w-8 h-8 text-surface-300 dark:text-surface-600 mb-3" />
              <p className="text-[12px] font-medium text-surface-500 dark:text-surface-400">Coming Soon</p>
              <p className="text-[11px] text-surface-400 dark:text-surface-500 mt-1">
                This template configuration is not yet available.
              </p>
            </div>
          ) : (
            <RouteBasedP2PForm cfg={cfg} upd={upd} peerMode={peerMode} setPeerMode={setPeerMode} lookups={lookups} onRefreshLookups={loadLookups} />
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-surface-200 dark:border-surface-800/50 shrink-0">
          <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-[11px] font-medium border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
            Cancel
          </button>
          <button
            onClick={handlePreview}
            disabled={!isActiveConfig}
            className={cn(
              'px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
              isActiveConfig
                ? 'border border-vyper-500/30 text-vyper-600 dark:text-vyper-400 bg-vyper-500/10 hover:bg-vyper-500/20'
                : 'opacity-40 pointer-events-none border border-surface-200 dark:border-surface-700 text-surface-400'
            )}
          >
            Preview YAML
          </button>
          <button
            onClick={handleGenerate}
            disabled={!isActiveConfig}
            className={cn(
              'px-4 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
              isActiveConfig
                ? 'bg-vyper-600 hover:bg-vyper-700 text-white'
                : 'opacity-40 pointer-events-none bg-surface-200 dark:bg-surface-700 text-surface-400'
            )}
          >
            <Plus className="w-3.5 h-3.5 inline mr-1" />
            Generate Topologies
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Route-Based P2P Form ──

function RouteBasedP2PForm({ cfg, upd, peerMode, setPeerMode, lookups, onRefreshLookups }: {
  cfg: RouteBasedP2PConfig
  upd: (p: Partial<RouteBasedP2PConfig>) => void
  peerMode: PeerMode
  setPeerMode: (m: PeerMode) => void
  lookups: PolicyLookups
  onRefreshLookups: () => void
}) {
  return (
    <div className="space-y-4">
      {/* Peer Mode */}
      <div className="flex items-center gap-3">
        <label className={labelCls}>Peer Mode</label>
        <div className="flex gap-1.5">
          {(['ftd-to-extranet', 'ftd-to-ftd'] as PeerMode[]).map(m => (
            <button
              key={m}
              onClick={() => { setPeerMode(m); upd({ peerMode: m }) }}
              className={cn(
                'px-3 py-1 rounded-md text-[11px] font-medium transition-all',
                peerMode === m
                  ? 'bg-vyper-600 text-white shadow-sm'
                  : 'bg-surface-100 dark:bg-surface-800 text-surface-500 hover:bg-surface-200 dark:hover:bg-surface-700'
              )}
            >
              {m === 'ftd-to-extranet' ? 'FTD to Extranet' : 'FTD to FTD'}
            </button>
          ))}
        </div>
      </div>

      {/* Scaling */}
      <SectionCard title="Scaling">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Name Prefix</label>
            <input value={cfg.namePrefix} onChange={e => upd({ namePrefix: e.target.value })} className={cn(inputCls, 'w-44')} />
          </div>
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Start #</label>
            <input type="number" value={cfg.startNameSuffix} onChange={e => upd({ startNameSuffix: e.target.value })} className={cn(inputCls, 'w-20')} min={0} />
          </div>
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Count</label>
            <input type="number" value={cfg.count} onChange={e => upd({ count: e.target.value })} className={cn(inputCls, 'w-20')} min={1} />
          </div>
        </div>
      </SectionCard>

      {/* Local FTD Peer */}
      <SectionCard title="Local FTD Peer">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Device Name</label>
            <input value={cfg.ftdPeer.deviceName} onChange={e => upd({ ftdPeer: { ...cfg.ftdPeer, deviceName: e.target.value } })} className={cn(inputCls, 'w-36')} placeholder="e.g. wpk-1" />
          </div>
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Interface Prefix</label>
            <input value={cfg.ftdPeer.interfaceName} onChange={e => upd({ ftdPeer: { ...cfg.ftdPeer, interfaceName: e.target.value } })} className={cn(inputCls, 'w-36')} placeholder="e.g. svti_inside_" />
          </div>
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Intf Start #</label>
            <input type="number" value={cfg.intfStartNum} onChange={e => upd({ intfStartNum: e.target.value })} className={cn(inputCls, 'w-20')} min={0} />
          </div>
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Intf Type</label>
            <select value={cfg.ftdPeer.interfaceType} onChange={e => upd({ ftdPeer: { ...cfg.ftdPeer, interfaceType: e.target.value } })} className={cn(selectCls, 'w-28')}>
              <option value="VTI">VTI</option>
              <option value="SubInterface">SubInterface</option>
              <option value="PhysicalInterface">PhysicalInterface</option>
            </select>
          </div>
        </div>
      </SectionCard>

      {/* Remote Peer */}
      {peerMode === 'ftd-to-extranet' ? (
        <SectionCard title="Extranet Peer">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Name Prefix</label>
              <input value={cfg.extranetPeer.name} onChange={e => upd({ extranetPeer: { ...cfg.extranetPeer, name: e.target.value } })} className={cn(inputCls, 'w-36')} placeholder="e.g. Peer-" />
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>IP Version</label>
              <select value={cfg.extranetIpVersion} onChange={e => upd({ extranetIpVersion: e.target.value as 'ipv4' | 'ipv6' })} className={cn(selectCls, 'w-20')}>
                <option value="ipv4">IPv4</option>
                <option value="ipv6">IPv6</option>
              </select>
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Start IP</label>
              <input value={cfg.extranetPeer.ipAddress} onChange={e => upd({ extranetPeer: { ...cfg.extranetPeer, ipAddress: e.target.value } })} className={cn(inputCls, 'w-40')} placeholder={cfg.extranetIpVersion === 'ipv4' ? '10.0.0.1' : '2001:db8::1'} />
            </div>
            {cfg.extranetIpVersion === 'ipv4' ? (
              <div className="flex items-center gap-1.5">
                <label className={labelCls}>Inc Octet</label>
                <select value={cfg.extranetIncOctet} onChange={e => upd({ extranetIncOctet: e.target.value })} className={cn(selectCls, 'w-16')}>
                  {OCT_OPTIONS.map(o => <option key={o} value={String(o)}>{o}</option>)}
                </select>
              </div>
            ) : (
              <div className="flex items-center gap-1.5">
                <label className={labelCls}>Inc Hextet</label>
                <select value={cfg.extranetIncHextet} onChange={e => upd({ extranetIncHextet: e.target.value })} className={cn(selectCls, 'w-16')}>
                  {HEX_OPTIONS.map(h => <option key={h} value={String(h)}>{h}</option>)}
                </select>
              </div>
            )}
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Dynamic IP</label>
              <input type="checkbox" checked={cfg.extranetPeer.isDynamic} onChange={e => upd({ extranetPeer: { ...cfg.extranetPeer, isDynamic: e.target.checked } })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
            </div>
          </div>
        </SectionCard>
      ) : (
        <SectionCard title="Remote FTD Peer">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Device Name</label>
              <input value={cfg.ftdPeer2.deviceName} onChange={e => upd({ ftdPeer2: { ...cfg.ftdPeer2, deviceName: e.target.value } })} className={cn(inputCls, 'w-36')} placeholder="e.g. wpk-2" />
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Interface Prefix</label>
              <input value={cfg.ftdPeer2.interfaceName} onChange={e => upd({ ftdPeer2: { ...cfg.ftdPeer2, interfaceName: e.target.value } })} className={cn(inputCls, 'w-36')} placeholder="e.g. svti_inside_" />
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Intf Type</label>
              <select value={cfg.ftdPeer2.interfaceType} onChange={e => upd({ ftdPeer2: { ...cfg.ftdPeer2, interfaceType: e.target.value } })} className={cn(selectCls, 'w-28')}>
                <option value="VTI">VTI</option>
                <option value="SubInterface">SubInterface</option>
                <option value="PhysicalInterface">PhysicalInterface</option>
              </select>
            </div>
          </div>
        </SectionCard>
      )}

      {/* IKE & IPSec Settings */}
      <SectionCard title="IKE & IPSec Settings">
        <div className="space-y-3">
          {/* IKE version toggles + refresh */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="flex items-center gap-1.5">
              <input type="checkbox" checked={cfg.ikeV1Enabled} onChange={e => upd({ ikeV1Enabled: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
              <label className={labelCls}>IKEv1 Enabled</label>
            </div>
            <div className="flex items-center gap-1.5">
              <input type="checkbox" checked={cfg.ikeV2Enabled} onChange={e => upd({ ikeV2Enabled: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
              <label className={labelCls}>IKEv2 Enabled</label>
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Pre-Shared Key</label>
              <input value={cfg.preSharedKey} onChange={e => upd({ preSharedKey: e.target.value })} className={cn(inputCls, 'w-36')} />
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>Enable RRI</label>
              <input type="checkbox" checked={cfg.enableRRI} onChange={e => upd({ enableRRI: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
            </div>
            <button onClick={onRefreshLookups} disabled={lookups.loading} className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium text-surface-500 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors border border-surface-200 dark:border-surface-700">
              {lookups.loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
              {lookups.loading ? 'Loading...' : 'Refresh Policies'}
            </button>
          </div>

          {/* IKEv1 row */}
          <div className={cn('flex flex-wrap items-center gap-x-4 gap-y-2', !cfg.ikeV1Enabled && 'opacity-40 pointer-events-none')}>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>IKEv1 Policy</label>
              <select value={cfg.ikev1PolicyName} onChange={e => upd({ ikev1PolicyName: e.target.value })} className={cn(selectCls, 'w-48')} disabled={!cfg.ikeV1Enabled}>
                <option value="">— Select —</option>
                {lookups.ikev1Policies.map(p => <option key={String(p.name)} value={String(p.name)}>{String(p.name)}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>IKEv1 IPSec Proposal</label>
              <select value={cfg.ikev1IpsecProposalName} onChange={e => upd({ ikev1IpsecProposalName: e.target.value })} className={cn(selectCls, 'w-48')} disabled={!cfg.ikeV1Enabled}>
                <option value="">— Select —</option>
                {lookups.ikev1IpsecProposals.map(p => <option key={String(p.name)} value={String(p.name)}>{String(p.name)}</option>)}
              </select>
            </div>
          </div>

          {/* IKEv2 row */}
          <div className={cn('flex flex-wrap items-center gap-x-4 gap-y-2', !cfg.ikeV2Enabled && 'opacity-40 pointer-events-none')}>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>IKEv2 Policy</label>
              <select value={cfg.ikev2PolicyName} onChange={e => upd({ ikev2PolicyName: e.target.value })} className={cn(selectCls, 'w-48')} disabled={!cfg.ikeV2Enabled}>
                <option value="">— Select —</option>
                {lookups.ikev2Policies.map(p => <option key={String(p.name)} value={String(p.name)}>{String(p.name)}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-1.5">
              <label className={labelCls}>IKEv2 IPSec Proposal</label>
              <select value={cfg.ikev2IpsecProposalName} onChange={e => upd({ ikev2IpsecProposalName: e.target.value })} className={cn(selectCls, 'w-48')} disabled={!cfg.ikeV2Enabled}>
                <option value="">— Select —</option>
                {lookups.ikev2IpsecProposals.map(p => <option key={String(p.name)} value={String(p.name)}>{String(p.name)}</option>)}
              </select>
            </div>
          </div>
        </div>
      </SectionCard>

      {/* Advanced Settings */}
      <SectionCard title="Advanced Settings">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>Enable BFD</label>
            <input type="checkbox" checked={cfg.enableBFD} onChange={e => upd({ enableBFD: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
          </div>
          <div className="flex items-center gap-1.5">
            <label className={labelCls}>SGT Propagation over VTI</label>
            <input type="checkbox" checked={cfg.sgtPropagation} onChange={e => upd({ sgtPropagation: e.target.checked })} className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30" />
          </div>
        </div>
      </SectionCard>
    </div>
  )
}

// ── Section Card ──

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
      <div className="px-3 py-1.5 bg-surface-50 dark:bg-surface-800/50">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 dark:text-surface-400">{title}</span>
      </div>
      <div className="px-3 py-2.5">
        {children}
      </div>
    </div>
  )
}
