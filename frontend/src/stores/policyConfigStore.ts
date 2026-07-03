import { create } from 'zustand'

// ── Types ──

export interface FmcMeta {
  host: string
  domain_uuid: string
  domain_name: string
  version: string
  build: string
  model: string
  status: string // connected | disconnected | error
}

export const EMPTY_META: FmcMeta = {
  host: '', domain_uuid: '', domain_name: '', version: '', build: '', model: '', status: 'disconnected',
}

export interface AssignedPolicyInfo {
  category: string
  type: string
  name: string
  source_id: string
  supported: boolean
}

export interface AcpDetail {
  name: string
  source_id: string
  fetched: boolean
  fetch_error: string
  rule_count: number
  assigned_policies: Record<string, AssignedPolicyInfo>
  settings_keys: string[]
  settings: Record<string, unknown>
  unsupported_settings: string[]
  default_action: Record<string, unknown>
}

export interface AcpRow {
  id: string
  name: string
  description: string
  selected: boolean
  fetching: boolean
  fetched: boolean
  expanded: boolean
  error: string
  detail: AcpDetail | null
}

export interface TargetPolicyOption {
  id: string
  name: string
  type: string
}

// Per-ACP, per-category mapping. Value '__create__' means create new policy.
export type Mappings = Record<string, Record<string, string>>

export interface PreviewResult {
  selected_acps: string[]
  plan: Record<string, unknown>
  validations: Array<Record<string, unknown>>
  assigned_policy_mappings: Array<Record<string, unknown>>
}

interface PolicyConfigState {
  // Source connection form
  srcIp: string
  srcPort: string
  srcUsername: string
  srcPassword: string
  connecting: boolean
  sourceConnected: boolean

  // Metadata
  sourceMeta: FmcMeta
  targetMeta: FmcMeta

  // ACPs
  acps: AcpRow[]
  listing: boolean
  listError: string

  // YAML
  yaml: string
  filename: string
  loaded: boolean

  // Assigned-policy mappings + target policy options
  mappings: Mappings
  targetPolicies: Record<string, TargetPolicyOption[]>
  targetPoliciesLoading: boolean
  targetPoliciesLoaded: boolean
  targetPoliciesError: string

  // Preview / push
  preview: PreviewResult | null
  previewOpen: boolean
  pushSummary: Record<string, unknown> | null
  perRuleFallback: boolean

  // Actions
  setSrc: (fields: Partial<Pick<PolicyConfigState, 'srcIp' | 'srcPort' | 'srcUsername' | 'srcPassword'>>) => void
  setConnecting: (v: boolean) => void
  setSourceConnected: (v: boolean) => void
  setMeta: (source: FmcMeta, target: FmcMeta) => void
  setTargetMeta: (target: FmcMeta) => void

  setAcps: (rows: AcpRow[]) => void
  setListing: (v: boolean) => void
  setListError: (m: string) => void
  toggleAcpSelected: (id: string) => void
  selectAllAcps: (selected: boolean) => void
  setAcpFetching: (id: string, v: boolean) => void
  setAcpError: (id: string, m: string) => void
  setAcpDetail: (id: string, detail: AcpDetail) => void
  toggleAcpExpanded: (id: string) => void

  setYaml: (yaml: string, filename?: string) => void
  setLoaded: (v: boolean) => void

  setMapping: (acp: string, category: string, value: string) => void
  resetMappings: () => void
  setTargetPolicies: (p: Record<string, TargetPolicyOption[]>) => void
  setTargetPoliciesLoading: (v: boolean) => void
  setTargetPoliciesError: (m: string) => void

  setPreview: (p: PreviewResult | null) => void
  setPreviewOpen: (v: boolean) => void
  setPushSummary: (s: Record<string, unknown> | null) => void
  setPerRuleFallback: (v: boolean) => void

  reset: () => void
}

export const usePolicyConfigStore = create<PolicyConfigState>((set) => ({
  srcIp: '',
  srcPort: '443',
  srcUsername: '',
  srcPassword: '',
  connecting: false,
  sourceConnected: false,

  sourceMeta: { ...EMPTY_META },
  targetMeta: { ...EMPTY_META },

  acps: [],
  listing: false,
  listError: '',

  yaml: '',
  filename: '',
  loaded: false,

  mappings: {},
  targetPolicies: {},
  targetPoliciesLoading: false,
  targetPoliciesLoaded: false,
  targetPoliciesError: '',

  preview: null,
  previewOpen: false,
  pushSummary: null,
  perRuleFallback: false,

  setSrc: (fields) => set((s) => ({ ...s, ...fields })),
  setConnecting: (v) => set({ connecting: v }),
  setSourceConnected: (v) => set({ sourceConnected: v }),
  setMeta: (source, target) => set({ sourceMeta: source, targetMeta: target }),
  setTargetMeta: (target) => set({ targetMeta: target }),

  setAcps: (rows) => set({ acps: rows }),
  setListing: (v) => set({ listing: v }),
  setListError: (m) => set({ listError: m }),
  toggleAcpSelected: (id) => set((s) => ({
    acps: s.acps.map((a) => a.id === id && a.fetched ? { ...a, selected: !a.selected } : a),
  })),
  selectAllAcps: (selected) => set((s) => ({
    acps: s.acps.map((a) => a.fetched ? { ...a, selected } : a),
  })),
  setAcpFetching: (id, v) => set((s) => ({
    acps: s.acps.map((a) => a.id === id ? { ...a, fetching: v } : a),
  })),
  setAcpError: (id, m) => set((s) => ({
    acps: s.acps.map((a) => a.id === id ? { ...a, error: m, fetching: false } : a),
  })),
  setAcpDetail: (id, detail) => set((s) => ({
    acps: s.acps.map((a) => a.id === id
      ? { ...a, detail, fetched: true, fetching: false, error: '', expanded: true }
      : a),
  })),
  toggleAcpExpanded: (id) => set((s) => ({
    acps: s.acps.map((a) => a.id === id && a.fetched ? { ...a, expanded: !a.expanded } : a),
  })),

  setYaml: (yaml, filename) => set((s) => ({ yaml, filename: filename ?? s.filename, loaded: true })),
  setLoaded: (v) => set({ loaded: v }),

  setMapping: (acp, category, value) => set((s) => ({
    mappings: { ...s.mappings, [acp]: { ...(s.mappings[acp] || {}), [category]: value } },
  })),
  resetMappings: () => set({ mappings: {} }),
  setTargetPolicies: (p) => set({ targetPolicies: p, targetPoliciesLoaded: true, targetPoliciesError: '' }),
  setTargetPoliciesLoading: (v) => set({ targetPoliciesLoading: v }),
  setTargetPoliciesError: (m) => set({ targetPoliciesError: m, targetPoliciesLoading: false }),

  setPreview: (p) => set({ preview: p }),
  setPreviewOpen: (v) => set({ previewOpen: v }),
  setPushSummary: (s) => set({ pushSummary: s }),
  setPerRuleFallback: (v) => set({ perRuleFallback: v }),

  reset: () => set({
    acps: [], yaml: '', filename: '', loaded: false, mappings: {},
    targetPolicies: {}, targetPoliciesLoading: false, targetPoliciesLoaded: false,
    targetPoliciesError: '', preview: null, previewOpen: false, pushSummary: null,
    perRuleFallback: false, listError: '',
  }),
}))

// Selected ACP names helper.
export function selectedAcpNames(): string[] {
  return usePolicyConfigStore.getState().acps.filter((a) => a.selected).map((a) => a.name)
}
