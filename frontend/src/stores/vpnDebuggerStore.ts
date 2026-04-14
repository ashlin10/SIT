import { create } from 'zustand'

// ── Types ──

export interface ConnectionInfo {
  ip: string
  port: string
  username: string
  password: string
}

export interface Preset {
  id: string
  name: string
  ip: string
  port: string
  username: string
  password: string
}

export interface ConfigFile {
  name: string
  hidden?: boolean
  vpnType?: 'policy' | 'route'
}

export interface TunnelData {
  name: string
  local_name?: string
  remote_name?: string
  local_id?: string
  remote_id?: string
  local_addr?: string
  remote_addr?: string
  local_port?: string
  remote_port?: string
  ike_state?: string
  ipsec_state?: string
  ike_crypto?: string
  ipsec_crypto?: string
  is_inactive?: boolean
  traffic_in?: boolean
  traffic_in_bytes?: string
  traffic_in_packets?: string
  traffic_out_bytes?: string
  traffic_out_packets?: string
  raw_output?: string
  vpn_type?: 'policy' | 'route' | 'ravpn'
}

export type ServiceStatus = 'active' | 'inactive' | 'unknown'
export type MonitoringStatus = 'running' | 'stopped' | 'unknown'
export type NodeType = 'strongswan' | 'csc'

export interface XfrmInterface {
  name: string
  ifId: number
  state: 'UP' | 'DOWN' | string
  mtu?: number
  physDev?: string
  addresses?: string[]
}

export interface ParamFilters {
  encryption: string[]
  integrity: string[]
  prf: string[]
  dh_group: string[]
  ake: string[]
}

// ── Store ──

interface VpnDebuggerState {
  // Connection
  localConn: ConnectionInfo
  remoteConn: ConnectionInfo
  localConnected: boolean
  remoteConnected: boolean
  localNodeType: NodeType
  remoteNodeType: 'asa_ftd'

  // Presets
  presets: Preset[]
  cscPresets: Preset[]

  // Service status
  serviceStatus: ServiceStatus
  swanctlLogStatus: ServiceStatus
  swanctlLogPid: string

  // XFRM interfaces (route-based VPN)
  xfrmInterfaces: XfrmInterface[]
  xfrmLoading: boolean

  // Config files
  configFiles: ConfigFile[]
  netplanFiles: ConfigFile[]
  remoteConfigFiles: ConfigFile[]
  remoteNetplanFiles: ConfigFile[]

  // File viewer/editor
  fileViewerOpen: boolean
  fileViewerTitle: string
  fileViewerContent: string
  fileViewerEditable: boolean
  fileViewerFilename: string
  fileViewerSide: 'local' | 'remote'
  fileViewerType: 'config' | 'netplan' | 'tunnel-traffic'
  fileViewerLoading: boolean
  fileViewerLiveRefreshMs: number  // 0 = disabled, >0 = poll interval in ms

  // Tunnel traffic connection popup
  ttConnPopupOpen: boolean
  ttConnPopupSide: 'local' | 'remote'
  ttConn: ConnectionInfo

  // Tunnel traffic files
  localTtFiles: ConfigFile[]
  remoteTtFiles: ConfigFile[]
  localTtConnected: boolean
  remoteTtConnected: boolean

  // Tunnels
  tunnels: TunnelData[]
  filteredTunnels: TunnelData[]
  searchQuery: string
  paramFilters: ParamFilters
  statusFilter: string | null
  currentPage: number
  pageSize: number
  refreshInterval: number
  lastUpdated: string | null

  // Troubleshooting / Monitoring
  troubleshootConnected: boolean
  monitoringStatus: MonitoringStatus
  monitoringPid: string
  disconnectCount: number
  monitorInterval: number
  monitorIntervalSecs: number
  monitorLeeway: number
  localLogFiles: string[]
  remoteLogFiles: string[]
  selectedLocalLog: string
  selectedRemoteLog: string

  // Report viewer
  reportViewerOpen: boolean
  reportContent: string

  // Template builder
  templateBuilderOpen: boolean
  templateBuilderMode: 'policy' | 'route'

  // Notification
  notification: { message: string; type: 'success' | 'error' | 'warning' | 'info' } | null

  // CSC container refresh trigger
  cscContainerRefreshKey: number

  // Loading states
  connecting: boolean
  refreshing: boolean
  configFilesLoading: boolean
  netplanFilesLoading: boolean
  remoteConfigFilesLoading: boolean
  remoteNetplanFilesLoading: boolean
  localTtFilesLoading: boolean
  remoteTtFilesLoading: boolean

  // Troubleshoot / Tunnel Summary connection popup
  tsConnPopupOpen: boolean
  tsConn: ConnectionInfo
  summaryConnPopupOpen: boolean
  summaryConn: ConnectionInfo

  // Actions
  setLocalConn: (c: Partial<ConnectionInfo>) => void
  setRemoteConn: (c: Partial<ConnectionInfo>) => void
  setLocalConnected: (v: boolean) => void
  setRemoteConnected: (v: boolean) => void
  setLocalNodeType: (v: NodeType) => void
  setRemoteNodeType: (v: 'asa_ftd') => void
  setPresets: (p: Preset[]) => void
  setCscPresets: (p: Preset[]) => void
  setServiceStatus: (s: ServiceStatus) => void
  setXfrmInterfaces: (i: XfrmInterface[]) => void
  setXfrmLoading: (v: boolean) => void
  setSwanctlLogStatus: (s: ServiceStatus, pid?: string) => void
  setConfigFiles: (f: ConfigFile[]) => void
  setNetplanFiles: (f: ConfigFile[]) => void
  setRemoteConfigFiles: (f: ConfigFile[]) => void
  setRemoteNetplanFiles: (f: ConfigFile[]) => void
  openFileViewer: (title: string, content: string, editable: boolean, filename: string, side: 'local' | 'remote', type: 'config' | 'netplan' | 'tunnel-traffic') => void
  openFileViewerLoading: (title: string, filename: string, side: 'local' | 'remote', type: 'config' | 'netplan' | 'tunnel-traffic') => void
  setFileViewerLoaded: (content: string, editable?: boolean) => void
  closeFileViewer: () => void
  setFileViewerContent: (c: string) => void
  openTtConnPopup: (side: 'local' | 'remote') => void
  closeTtConnPopup: () => void
  setTtConn: (c: Partial<ConnectionInfo>) => void
  openTsConnPopup: () => void
  closeTsConnPopup: () => void
  setTsConn: (c: Partial<ConnectionInfo>) => void
  openSummaryConnPopup: () => void
  closeSummaryConnPopup: () => void
  setSummaryConn: (c: Partial<ConnectionInfo>) => void
  setLocalTtFiles: (f: ConfigFile[]) => void
  setRemoteTtFiles: (f: ConfigFile[]) => void
  setLocalTtConnected: (v: boolean) => void
  setRemoteTtConnected: (v: boolean) => void
  setTunnels: (t: TunnelData[]) => void
  setFilteredTunnels: (t: TunnelData[]) => void
  setSearchQuery: (q: string) => void
  setParamFilters: (f: ParamFilters) => void
  setStatusFilter: (s: string | null) => void
  setCurrentPage: (p: number) => void
  setPageSize: (s: number) => void
  setRefreshInterval: (i: number) => void
  setLastUpdated: (t: string | null) => void
  setTroubleshootConnected: (v: boolean) => void
  setMonitoringStatus: (s: MonitoringStatus, pid?: string) => void
  setDisconnectCount: (c: number) => void
  setMonitorInterval: (i: number) => void
  setMonitorIntervalSecs: (s: number) => void
  setMonitorLeeway: (l: number) => void
  setLocalLogFiles: (f: string[]) => void
  setRemoteLogFiles: (f: string[]) => void
  setSelectedLocalLog: (f: string) => void
  setSelectedRemoteLog: (f: string) => void
  openReportViewer: (content: string) => void
  closeReportViewer: () => void
  openTemplateBuilder: (mode?: 'policy' | 'route') => void
  closeTemplateBuilder: () => void
  notify: (message: string, type: 'success' | 'error' | 'warning' | 'info') => void
  clearNotification: () => void
  setConnecting: (v: boolean) => void
  setRefreshing: (v: boolean) => void
  setConfigFilesLoading: (v: boolean) => void
  setNetplanFilesLoading: (v: boolean) => void
  setRemoteConfigFilesLoading: (v: boolean) => void
  setRemoteNetplanFilesLoading: (v: boolean) => void
  setLocalTtFilesLoading: (v: boolean) => void
  setRemoteTtFilesLoading: (v: boolean) => void
  bumpCscContainerRefresh: () => void
}

export const useVpnDebuggerStore = create<VpnDebuggerState>((set) => ({
  // Connection
  localConn: { ip: '', port: '22', username: 'root', password: '' },
  remoteConn: { ip: '', port: '22', username: 'root', password: '' },
  localConnected: false,
  remoteConnected: false,
  localNodeType: 'strongswan',
  remoteNodeType: 'asa_ftd',

  // Presets
  presets: [],
  cscPresets: [],

  // Service status
  serviceStatus: 'unknown',
  swanctlLogStatus: 'unknown',
  swanctlLogPid: '',

  // XFRM interfaces
  xfrmInterfaces: [],
  xfrmLoading: false,

  // Config files
  configFiles: [],
  netplanFiles: [],
  remoteConfigFiles: [],
  remoteNetplanFiles: [],

  // File viewer/editor
  fileViewerOpen: false,
  fileViewerTitle: '',
  fileViewerContent: '',
  fileViewerEditable: false,
  fileViewerFilename: '',
  fileViewerSide: 'local',
  fileViewerType: 'config',
  fileViewerLoading: false,
  fileViewerLiveRefreshMs: 0,

  // CSC container refresh trigger
  cscContainerRefreshKey: 0,

  // Tunnel traffic connection popup
  ttConnPopupOpen: false,
  ttConnPopupSide: 'local',
  ttConn: { ip: '', port: '22', username: 'root', password: '' },

  // Tunnel traffic files
  localTtFiles: [],
  remoteTtFiles: [],
  localTtConnected: false,
  remoteTtConnected: false,

  // Tunnels
  tunnels: [],
  filteredTunnels: [],
  searchQuery: '',
  paramFilters: { encryption: [], integrity: [], prf: [], dh_group: [], ake: [] },
  statusFilter: null,
  currentPage: 1,
  pageSize: 15,
  refreshInterval: 300,
  lastUpdated: null,

  // Troubleshooting
  troubleshootConnected: false,
  monitoringStatus: 'stopped',
  monitoringPid: '',
  disconnectCount: 0,
  monitorInterval: 5,
  monitorIntervalSecs: 0,
  monitorLeeway: 5,
  localLogFiles: [],
  remoteLogFiles: [],
  selectedLocalLog: '',
  selectedRemoteLog: '',

  // Report viewer
  reportViewerOpen: false,
  reportContent: '',

  // Template builder
  templateBuilderOpen: false,
  templateBuilderMode: 'policy' as const,

  // Notification
  notification: null,

  // Loading states
  connecting: false,
  refreshing: false,
  configFilesLoading: false,
  netplanFilesLoading: false,
  remoteConfigFilesLoading: false,
  remoteNetplanFilesLoading: false,
  localTtFilesLoading: false,
  remoteTtFilesLoading: false,

  // Troubleshoot / Tunnel Summary connection popup
  tsConnPopupOpen: false,
  tsConn: { ip: '', port: '22', username: 'root', password: '' },
  summaryConnPopupOpen: false,
  summaryConn: { ip: '', port: '22', username: 'root', password: '' },

  // Actions
  setLocalConn: (c) => set((s) => ({ localConn: { ...s.localConn, ...c } })),
  setRemoteConn: (c) => set((s) => ({ remoteConn: { ...s.remoteConn, ...c } })),
  setLocalConnected: (v) => set({ localConnected: v }),
  setRemoteConnected: (v) => set({ remoteConnected: v }),
  setLocalNodeType: (v) => set({ localNodeType: v }),
  setRemoteNodeType: (v) => set({ remoteNodeType: v }),
  setPresets: (p) => set({ presets: p }),
  setCscPresets: (p) => set({ cscPresets: p }),
  setServiceStatus: (s) => set({ serviceStatus: s }),
  setXfrmInterfaces: (i) => set({ xfrmInterfaces: i }),
  setXfrmLoading: (v) => set({ xfrmLoading: v }),
  setSwanctlLogStatus: (s, pid) => set({ swanctlLogStatus: s, ...(pid !== undefined ? { swanctlLogPid: pid } : {}) }),
  setConfigFiles: (f) => set({ configFiles: f }),
  setNetplanFiles: (f) => set({ netplanFiles: f }),
  setRemoteConfigFiles: (f) => set({ remoteConfigFiles: f }),
  setRemoteNetplanFiles: (f) => set({ remoteNetplanFiles: f }),
  openFileViewer: (title, content, editable, filename, side, type) => set({
    fileViewerOpen: true, fileViewerTitle: title, fileViewerContent: content,
    fileViewerEditable: editable, fileViewerFilename: filename, fileViewerSide: side, fileViewerType: type,
    fileViewerLoading: false,
  }),
  openFileViewerLoading: (title, filename, side, type) => set({
    fileViewerOpen: true, fileViewerTitle: title, fileViewerContent: '',
    fileViewerEditable: false, fileViewerFilename: filename, fileViewerSide: side, fileViewerType: type,
    fileViewerLoading: true,
  }),
  setFileViewerLoaded: (content, editable) => set({
    fileViewerContent: content, fileViewerLoading: false,
    ...(editable !== undefined ? { fileViewerEditable: editable } : {}),
  }),
  closeFileViewer: () => set({ fileViewerOpen: false, fileViewerLoading: false, fileViewerLiveRefreshMs: 0 }),
  setFileViewerContent: (c) => set({ fileViewerContent: c }),
  openTtConnPopup: (side) => set({ ttConnPopupOpen: true, ttConnPopupSide: side }),
  closeTtConnPopup: () => set({ ttConnPopupOpen: false }),
  setTtConn: (c) => set((s) => ({ ttConn: { ...s.ttConn, ...c } })),
  openTsConnPopup: () => set({ tsConnPopupOpen: true }),
  closeTsConnPopup: () => set({ tsConnPopupOpen: false }),
  setTsConn: (c) => set((s) => ({ tsConn: { ...s.tsConn, ...c } })),
  openSummaryConnPopup: () => set({ summaryConnPopupOpen: true }),
  closeSummaryConnPopup: () => set({ summaryConnPopupOpen: false }),
  setSummaryConn: (c) => set((s) => ({ summaryConn: { ...s.summaryConn, ...c } })),
  setLocalTtFiles: (f) => set({ localTtFiles: f }),
  setRemoteTtFiles: (f) => set({ remoteTtFiles: f }),
  setLocalTtConnected: (v) => set({ localTtConnected: v }),
  setRemoteTtConnected: (v) => set({ remoteTtConnected: v }),
  setTunnels: (t) => set({ tunnels: t }),
  setFilteredTunnels: (t) => set({ filteredTunnels: t }),
  setSearchQuery: (q) => set({ searchQuery: q, currentPage: 1 }),
  setParamFilters: (f) => set({ paramFilters: f, currentPage: 1 }),
  setStatusFilter: (s) => set({ statusFilter: s, currentPage: 1 }),
  setCurrentPage: (p) => set({ currentPage: p }),
  setPageSize: (s) => set({ pageSize: s, currentPage: 1 }),
  setRefreshInterval: (i) => set({ refreshInterval: i }),
  setLastUpdated: (t) => set({ lastUpdated: t }),
  setTroubleshootConnected: (v) => set({ troubleshootConnected: v }),
  setMonitoringStatus: (s, pid) => set({ monitoringStatus: s, monitoringPid: s === 'stopped' ? '' : (pid ?? '') }),
  setDisconnectCount: (c) => set({ disconnectCount: c }),
  setMonitorInterval: (i) => set({ monitorInterval: i }),
  setMonitorIntervalSecs: (s) => set({ monitorIntervalSecs: s }),
  setMonitorLeeway: (l) => set({ monitorLeeway: l }),
  setLocalLogFiles: (f) => set({ localLogFiles: f }),
  setRemoteLogFiles: (f) => set({ remoteLogFiles: f }),
  setSelectedLocalLog: (f) => set({ selectedLocalLog: f }),
  setSelectedRemoteLog: (f) => set({ selectedRemoteLog: f }),
  openReportViewer: (content) => set({ reportViewerOpen: true, reportContent: content }),
  closeReportViewer: () => set({ reportViewerOpen: false }),
  openTemplateBuilder: (mode) => set({ templateBuilderOpen: true, templateBuilderMode: mode || 'policy' }),
  closeTemplateBuilder: () => set({ templateBuilderOpen: false }),
  notify: (message, type) => set({ notification: { message, type } }),
  clearNotification: () => set({ notification: null }),
  setConnecting: (v) => set({ connecting: v }),
  setRefreshing: (v) => set({ refreshing: v }),
  setConfigFilesLoading: (v) => set({ configFilesLoading: v }),
  setNetplanFilesLoading: (v) => set({ netplanFilesLoading: v }),
  setRemoteConfigFilesLoading: (v) => set({ remoteConfigFilesLoading: v }),
  setRemoteNetplanFilesLoading: (v) => set({ remoteNetplanFilesLoading: v }),
  setLocalTtFilesLoading: (v) => set({ localTtFilesLoading: v }),
  setRemoteTtFilesLoading: (v) => set({ remoteTtFilesLoading: v }),
  bumpCscContainerRefresh: () => set((s) => ({ cscContainerRefreshKey: s.cscContainerRefreshKey + 1 })),
}))
