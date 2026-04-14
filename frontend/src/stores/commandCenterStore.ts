import { create } from 'zustand'

export interface Device {
  id: string
  type: string
  name: string
  ip_address: string
  port?: number
  port_spec?: string
  username: string
  password: string
}

export interface StaticRoute {
  ip_version: 'ipv4' | 'ipv6'
  interface: string
  ip_address: string
  netmask_or_prefix: string
  gateway: string
}

export interface ProxyConfig {
  proxy_address: string
  proxy_port: number | ''
  proxy_auth: boolean
  proxy_username: string
  proxy_password: string
}

export interface ProxyPreset extends ProxyConfig {
  id: string
  name: string
}

export interface StaticPreset {
  id: string
  name: string
  routes: StaticRoute[]
}

export interface StreamResult {
  type: string
  name: string
  ip_address: string
  port?: number
  success: boolean
  error?: string
}

interface CommandCenterState {
  // Devices
  ftdDevices: Device[]
  fmcDevices: Device[]
  selectedIds: Set<string>
  devicesCollapsed: boolean

  // Execution
  isExecuting: boolean
  execLog: string
  execStatus: string
  execResults: StreamResult[]

  // Actions
  setDevices: (ftd: Device[], fmc: Device[]) => void
  toggleDevice: (id: string) => void
  selectAll: (type: 'ftd' | 'fmc', selected: boolean) => void
  clearSelection: () => void
  setDevicesCollapsed: (v: boolean) => void

  // Execution
  setExecuting: (v: boolean) => void
  appendLog: (line: string) => void
  setExecStatus: (s: string) => void
  addResult: (r: StreamResult) => void
  clearExec: () => void
}

export const useCommandCenterStore = create<CommandCenterState>((set, get) => ({
  ftdDevices: [],
  fmcDevices: [],
  selectedIds: new Set(),
  devicesCollapsed: false,

  isExecuting: false,
  execLog: '',
  execStatus: '',
  execResults: [],

  setDevices: (ftd, fmc) => set({ ftdDevices: ftd, fmcDevices: fmc }),

  toggleDevice: (id) => {
    const s = new Set(get().selectedIds)
    if (s.has(id)) s.delete(id)
    else s.add(id)
    set({ selectedIds: s })
  },

  selectAll: (type, selected) => {
    const s = new Set(get().selectedIds)
    const devices = type === 'ftd' ? get().ftdDevices : get().fmcDevices
    devices.forEach((d) => {
      if (selected) s.add(d.id)
      else s.delete(d.id)
    })
    set({ selectedIds: s })
  },

  clearSelection: () => set({ selectedIds: new Set() }),

  setDevicesCollapsed: (v) => set({ devicesCollapsed: v }),

  setExecuting: (v) => set({ isExecuting: v }),
  appendLog: (line) => set((s) => ({ execLog: s.execLog + line + '\n' })),
  setExecStatus: (s) => set({ execStatus: s }),
  addResult: (r) => set((s) => ({ execResults: [...s.execResults, r] })),
  clearExec: () => set({ execLog: '', execStatus: '', execResults: [] }),
}))
