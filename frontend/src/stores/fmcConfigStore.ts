import { create } from 'zustand'

export interface FmcPreset {
  id: string
  name: string
  fmc_ip: string
  fmc_port: number
  username: string
  password: string
}

export interface FmcDevice {
  id: string
  name: string
  hostname: string
  type: string
  sw_version: string
  ftdMode: string
  model: string
  healthStatus: string
  isConnected: boolean
}

// Helper to extract first non-empty value from multiple possible keys
function getField(obj: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = obj[k]
    if (v !== undefined && v !== null && v !== '') return String(v)
  }
  return ''
}

// Map raw FMC API device record to normalized FmcDevice
export function mapRawDevice(raw: Record<string, unknown>): FmcDevice {
  return {
    id: getField(raw, ['id']),
    name: getField(raw, ['name']),
    hostname: getField(raw, ['hostName', 'hostname']),
    type: getField(raw, ['type', 'platformType', 'modelType']),
    sw_version: getField(raw, ['sw_version', 'version', 'softwareVersion', 'swVersion']),
    ftdMode: getField(raw, ['ftdMode', 'deviceMode', 'mode']),
    model: getField(raw, ['model']),
    healthStatus: getField(raw, ['healthStatus', 'status']),
    isConnected: !!raw['isConnected'],
  }
}

export interface ConfigCounts {
  [key: string]: number
}

export type SummaryRow = [string, string, string]

export interface SummaryTables {
  applied: SummaryRow[]
  failed: SummaryRow[]
  skipped: SummaryRow[]
}

export interface VpnPeer {
  name: string
  peerType?: string
}

export interface VpnTopology {
  id?: string
  name: string
  topologyType: string
  subType: string
  peers: VpnPeer[]
  raw: Record<string, unknown>
  selected?: boolean
}

// Map raw VPN topology to normalized VpnTopology
export function mapRawVpnTopology(raw: Record<string, unknown>): VpnTopology {
  const routeBased = raw['routeBased']
  const subType = routeBased === true ? 'Route Based' : routeBased === false ? 'Policy Based' : ''
  const rawPeers = (raw['peers'] || []) as Array<string | Record<string, unknown>>
  const peers: VpnPeer[] = rawPeers.map((p) => {
    if (typeof p === 'string') return { name: p }
    return { name: String((p as Record<string, unknown>).name || ''), peerType: String((p as Record<string, unknown>).peerType || (p as Record<string, unknown>).role || '') }
  })
  return {
    id: raw['id'] as string | undefined,
    name: String(raw['name'] || ''),
    topologyType: String(raw['topologyType'] || ''),
    subType,
    peers,
    raw,
    selected: true,
  }
}

interface FmcConfigState {
  // Connection
  fmcIp: string
  fmcPort: string
  fmcUsername: string
  fmcPassword: string
  connected: boolean
  connecting: boolean
  domains: { uuid: string; name: string }[]
  domainUuid: string
  presets: FmcPreset[]

  // Devices
  devices: FmcDevice[]
  selectedDeviceIds: Set<string>
  devicesCollapsed: boolean

  // Terminal
  terminalLog: string
  terminalVisible: boolean
  isOperationRunning: boolean
  progressPercent: number
  progressLabel: string

  // Summary
  summaryTables: SummaryTables | null
  summaryVisible: boolean

  // Device Config
  uploadedConfig: Record<string, unknown> | null
  uploadedConfigFilename: string
  uploadedConfigYaml: string
  uploadedCounts: ConfigCounts
  configCheckboxes: Record<string, boolean>

  // Chassis Config
  chassisConfig: Record<string, unknown> | null
  chassisConfigFilename: string
  chassisConfigYaml: string
  chassisCounts: ConfigCounts
  chassisCheckboxes: Record<string, boolean>

  // VPN
  vpnEnabled: boolean
  vpnTopologies: VpnTopology[]
  vpnFilename: string
  vpnYaml: string
  vpnReplaceEnabled: boolean

  // Viewer modal
  viewerOpen: boolean
  viewerTitle: string
  viewerContent: string
  viewerOnSave: ((content: string) => void) | null

  // Options
  bulkEnabled: boolean
  batchSize: number
  authOverrides: Record<string, string>

  // Actions
  setConnection: (fields: Partial<Pick<FmcConfigState, 'fmcIp' | 'fmcPort' | 'fmcUsername' | 'fmcPassword'>>) => void
  setConnected: (v: boolean) => void
  setConnecting: (v: boolean) => void
  setDomains: (d: { uuid: string; name: string }[]) => void
  setDomainUuid: (v: string) => void
  setPresets: (p: FmcPreset[]) => void

  setDevices: (d: FmcDevice[]) => void
  toggleDevice: (id: string) => void
  selectAllDevices: (selected: boolean) => void
  setDevicesCollapsed: (v: boolean) => void

  appendLog: (line: string) => void
  clearLog: () => void
  setTerminalVisible: (v: boolean) => void
  setOperationRunning: (v: boolean) => void
  setProgress: (percent: number, label: string) => void

  setSummary: (s: SummaryTables | null) => void
  setSummaryVisible: (v: boolean) => void

  setUploadedConfig: (config: Record<string, unknown> | null, filename: string, counts: ConfigCounts, yaml?: string) => void
  setUploadedConfigYaml: (yaml: string) => void
  setConfigCheckbox: (key: string, value: boolean) => void
  setAllConfigCheckboxes: (value: boolean) => void

  setChassisConfig: (config: Record<string, unknown> | null, filename: string, counts: ConfigCounts, yaml?: string) => void
  setChassisConfigYaml: (yaml: string) => void
  setChassisCheckbox: (key: string, value: boolean) => void

  setVpnEnabled: (v: boolean) => void
  setVpnTopologies: (t: VpnTopology[]) => void
  toggleVpnTopology: (idx: number) => void
  selectAllVpn: (selected: boolean) => void
  setVpnFilename: (f: string) => void
  setVpnYaml: (y: string) => void
  setVpnReplaceEnabled: (v: boolean) => void

  openViewer: (title: string, content: string, onSave?: (content: string) => void) => void
  closeViewer: () => void

  setBulkEnabled: (v: boolean) => void
  setBatchSize: (v: number) => void
  setAuthOverride: (key: string, value: string) => void
}

export const useFmcConfigStore = create<FmcConfigState>((set, get) => ({
  fmcIp: '',
  fmcPort: '443',
  fmcUsername: '',
  fmcPassword: '',
  connected: false,
  connecting: false,
  domains: [],
  domainUuid: '',
  presets: [],

  devices: [],
  selectedDeviceIds: new Set(),
  devicesCollapsed: false,

  terminalLog: '',
  terminalVisible: false,
  isOperationRunning: false,
  progressPercent: 0,
  progressLabel: '',

  summaryTables: null,
  summaryVisible: false,

  uploadedConfig: null,
  uploadedConfigFilename: '',
  uploadedConfigYaml: '',
  uploadedCounts: {},
  configCheckboxes: {},

  chassisConfig: null,
  chassisConfigFilename: '',
  chassisConfigYaml: '',
  chassisCounts: {},
  chassisCheckboxes: {},

  vpnEnabled: false,
  vpnTopologies: [],
  vpnFilename: '',
  vpnYaml: '',
  vpnReplaceEnabled: false,

  viewerOpen: false,
  viewerTitle: '',
  viewerContent: '',
  viewerOnSave: null,

  bulkEnabled: true,
  batchSize: 50,
  authOverrides: {
    ospf_md5_key: 'cisco',
    ospf_auth_key: 'cisco',
    ospfv3_auth_key: '1234567890123456789012345678901234567890',
    ospfv3_encryption_key: '1234567890123456',
    bfd_auth_key: 'cisco',
    bgp_secret: 'cisco',
    eigrp_password: 'cisco',
  },

  setConnection: (fields) => set((s) => ({ ...s, ...fields })),
  setConnected: (v) => set({ connected: v }),
  setConnecting: (v) => set({ connecting: v }),
  setDomains: (d) => set({ domains: d }),
  setDomainUuid: (v) => set({ domainUuid: v }),
  setPresets: (p) => set({ presets: p }),

  setDevices: (d) => set({ devices: d }),
  toggleDevice: (id) => {
    const s = new Set(get().selectedDeviceIds)
    if (s.has(id)) s.delete(id); else s.add(id)
    set({ selectedDeviceIds: s })
  },
  selectAllDevices: (selected) => {
    if (selected) {
      set({ selectedDeviceIds: new Set(get().devices.map((d) => d.id)) })
    } else {
      set({ selectedDeviceIds: new Set() })
    }
  },
  setDevicesCollapsed: (v) => set({ devicesCollapsed: v }),

  appendLog: (line) => set((s) => ({ terminalLog: s.terminalLog + line + '\n' })),
  clearLog: () => set({ terminalLog: '' }),
  setTerminalVisible: (v) => set({ terminalVisible: v }),
  setOperationRunning: (v) => set({ isOperationRunning: v }),
  setProgress: (percent, label) => set({ progressPercent: percent, progressLabel: label }),

  setSummary: (s) => set({ summaryTables: s }),
  setSummaryVisible: (v) => set({ summaryVisible: v }),

  setUploadedConfig: (config, filename, counts, yaml) => {
    const checkboxes: Record<string, boolean> = {}
    Object.keys(counts).forEach((k) => { checkboxes[k] = (counts[k] || 0) > 0 })
    set({ uploadedConfig: config, uploadedConfigFilename: filename, uploadedConfigYaml: yaml || '', uploadedCounts: counts, configCheckboxes: checkboxes })
  },
  setUploadedConfigYaml: (yaml) => set({ uploadedConfigYaml: yaml }),
  setConfigCheckbox: (key, value) => set((s) => ({
    configCheckboxes: { ...s.configCheckboxes, [key]: value },
  })),
  setAllConfigCheckboxes: (value) => set((s) => {
    const cb: Record<string, boolean> = {}
    Object.keys(s.configCheckboxes).forEach((k) => { cb[k] = value })
    return { configCheckboxes: cb }
  }),

  setChassisConfig: (config, filename, counts, yaml) => {
    const cb: Record<string, boolean> = {}
    Object.keys(counts).forEach((k) => { cb[k] = (counts[k] || 0) > 0 })
    set({ chassisConfig: config, chassisConfigFilename: filename, chassisConfigYaml: yaml || '', chassisCounts: counts, chassisCheckboxes: cb })
  },
  setChassisConfigYaml: (yaml) => set({ chassisConfigYaml: yaml }),
  setChassisCheckbox: (key, value) => set((s) => ({
    chassisCheckboxes: { ...s.chassisCheckboxes, [key]: value },
  })),

  setVpnEnabled: (v) => set({ vpnEnabled: v }),
  setVpnTopologies: (t) => set({ vpnTopologies: t }),
  toggleVpnTopology: (idx) => set((s) => {
    const t = [...s.vpnTopologies]
    t[idx] = { ...t[idx], selected: !t[idx].selected }
    return { vpnTopologies: t }
  }),
  selectAllVpn: (selected) => set((s) => ({
    vpnTopologies: s.vpnTopologies.map((t) => ({ ...t, selected })),
  })),
  setVpnFilename: (f) => set({ vpnFilename: f }),
  setVpnYaml: (y) => set({ vpnYaml: y }),
  setVpnReplaceEnabled: (v) => set({ vpnReplaceEnabled: v }),

  openViewer: (title, content, onSave) => set({ viewerOpen: true, viewerTitle: title, viewerContent: content, viewerOnSave: onSave || null }),
  closeViewer: () => set({ viewerOpen: false, viewerTitle: '', viewerContent: '', viewerOnSave: null }),

  setBulkEnabled: (v) => set({ bulkEnabled: v }),
  setBatchSize: (v) => set({ batchSize: v }),
  setAuthOverride: (key, value) => set((s) => ({
    authOverrides: { ...s.authOverrides, [key]: value },
  })),
}))
