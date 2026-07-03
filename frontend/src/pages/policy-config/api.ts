import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import {
  usePolicyConfigStore, selectedAcpNames,
  type AcpRow, type FmcMeta, type TargetPolicyOption,
} from '@/stores/policyConfigStore'
import {
  startLogPolling, stopLogPolling, startProgressPolling, stopProgressPolling,
  loadPresets,
} from '../fmc-config/api'

const fmc = () => useFmcConfigStore.getState()
const store = () => usePolicyConfigStore.getState()

// ── Debug-aware fetch (masks passwords) ──

function debugFetch(url: string, init?: RequestInit): Promise<Response> {
  const f = fmc()
  if (f.debugEnabled) {
    const method = (init?.method || 'GET').toUpperCase()
    const ts = new Date().toLocaleTimeString()
    f.appendLog(`\x1b[36m[DEBUG ${ts}]\x1b[0m ${method} ${url}`)
    if (init?.body && typeof init.body === 'string') {
      try {
        const parsed = JSON.parse(init.body)
        const safe = { ...parsed }
        if (safe.password) safe.password = '***'
        f.appendLog(`\x1b[33m  Payload:\x1b[0m ${JSON.stringify(safe, null, 2)}`)
      } catch { /* non-JSON */ }
    }
  }
  return fetch(url, init)
}

/** Source FMC URL built from the policy store fields. */
function buildSourceUrl(): string {
  const { srcIp, srcPort } = store()
  const ip = srcIp.trim()
  if (!ip) return ''
  const base = /^https?:\/\//.test(ip) ? ip : `https://${ip}`
  const port = srcPort.trim()
  return port && port !== '443' ? `${base}:${port}` : base
}

function debugFlag(): boolean {
  return fmc().debugEnabled || false
}

// ── Source connect + metadata ──

export async function connectSource(): Promise<{ success: boolean; message?: string; warning?: string }> {
  const s = store()
  s.setConnecting(true)
  s.setSourceConnected(false)
  fmc().setTerminalVisible(true)
  await startLogPolling()
  try {
    const res = await debugFetch('/api/policy-config/source/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        fmc_ip: buildSourceUrl(),
        username: s.srcUsername.trim(),
        password: s.srcPassword,
        debug: debugFlag(),
      }),
    })
    const data = await res.json()
    if (!data.success) return { success: false, message: data.message || 'Connection failed' }
    s.setSourceConnected(true)
    s.setMeta(data.source as FmcMeta, data.target as FmcMeta)
    return { success: true, warning: data.warning }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    s.setConnecting(false)
    stopLogPolling()
  }
}

// ── ACP listing ──

export async function listAcps(): Promise<{ success: boolean; message?: string }> {
  const s = store()
  s.setListing(true)
  s.setListError('')
  try {
    const res = await debugFetch('/api/policy-config/acp/list', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ debug: debugFlag() }),
    })
    const data = await res.json()
    if (!data.success) {
      s.setListError(data.message || 'Failed to list ACPs')
      return { success: false, message: data.message }
    }
    const rows: AcpRow[] = (data.acps || []).map((a: Record<string, unknown>) => ({
      id: String(a.id || ''),
      name: String(a.name || ''),
      description: String(a.description || ''),
      selected: false,
      fetching: false,
      fetched: false,
      expanded: false,
      error: '',
      detail: null,
    }))
    s.setAcps(rows)
    return { success: true }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    s.setListError(msg)
    return { success: false, message: msg }
  } finally {
    s.setListing(false)
  }
}

// ── Fetch one ACP ──

export async function fetchAcp(id: string): Promise<{ success: boolean; message?: string }> {
  const s = store()
  s.setAcpFetching(id, true)
  fmc().setTerminalVisible(true)
  await startLogPolling()
  try {
    const res = await debugFetch('/api/policy-config/acp/fetch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ acp_id: id, debug: debugFlag() }),
    })
    const data = await res.json()
    if (!data.success) {
      s.setAcpError(id, data.message || 'Fetch failed')
      return { success: false, message: data.message }
    }
    s.setAcpDetail(id, data.acp)
    s.setYaml(data.yaml || '', data.filename)
    // Populate the assigned-policy mapping dropdowns immediately so target
    // policies are available without waiting for a Push Policies run.
    if (s.targetMeta.status === 'connected') {
      loadTargetPolicies().catch(() => { /* surfaced via targetPoliciesError */ })
    }
    return { success: true }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    s.setAcpError(id, msg)
    return { success: false, message: msg }
  } finally {
    stopLogPolling()
  }
}

// ── Upload YAML ──

export async function uploadPolicyYaml(file: File): Promise<{ success: boolean; message?: string; errors?: string[] }> {
  const s = store()
  const fd = new FormData()
  fd.append('file', file)
  try {
    const res = await debugFetch('/api/policy-config/upload', {
      method: 'POST', credentials: 'include', body: fd,
    })
    const data = await res.json()
    if (!data.success) return { success: false, message: data.message, errors: data.errors }
    // Build rows from uploaded ACP summaries.
    const rows: AcpRow[] = (data.acps || []).map((a: Record<string, unknown>) => ({
      id: String(a.source_id || a.name || ''),
      name: String(a.name || ''),
      description: '',
      selected: true,
      fetching: false,
      fetched: true,
      expanded: false,
      error: '',
      detail: a as unknown as AcpRow['detail'],
    }))
    s.setAcps(rows)
    const text = await file.text()
    s.setYaml(text, file.name)
    return { success: true }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  }
}

// ── Current YAML ──

export async function refreshYaml(): Promise<string> {
  const res = await debugFetch('/api/policy-config/yaml', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({}),
  })
  const data = await res.json()
  if (data.success) store().setYaml(data.yaml || '')
  return data.yaml || ''
}

export async function downloadYaml(): Promise<void> {
  const res = await debugFetch('/api/policy-config/download', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({}),
  })
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename=([^;\s]+)/)
  a.download = m ? m[1] : 'policy-config.yaml'
  a.click()
  URL.revokeObjectURL(url)
}

// ── Target policies for mapping dropdowns ──

export async function loadTargetPolicies(categories?: string[]): Promise<void> {
  const s = store()
  s.setTargetPoliciesLoading(true)
  try {
    const res = await debugFetch('/api/policy-config/target-policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ categories, debug: debugFlag() }),
    })
    const data = await res.json()
    if (data.success) {
      s.setTargetPolicies(data.policies as Record<string, TargetPolicyOption[]>)
    } else {
      s.setTargetPoliciesError(data.message || 'Failed to load target policies')
    }
  } catch (err) {
    s.setTargetPoliciesError(err instanceof Error ? err.message : String(err))
  } finally {
    s.setTargetPoliciesLoading(false)
  }
}

// ── Preview ──

export async function previewPush(): Promise<{ success: boolean; message?: string }> {
  const s = store()
  const f = fmc()
  const names = selectedAcpNames()
  if (names.length === 0) return { success: false, message: 'Select at least one ACP' }
  f.setTerminalVisible(true)
  await startLogPolling()
  try {
    const res = await debugFetch('/api/policy-config/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        acp_names: names,
        mappings: s.mappings,
        validate: f.validateConfigEnabled,
        source_version: s.sourceMeta.version,
        target_version: s.targetMeta.version,
        debug: debugFlag(),
      }),
    })
    const data = await res.json()
    if (!data.success) return { success: false, message: data.message }
    s.setPreview(data)
    s.setPreviewOpen(true)
    return { success: true }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
  }
}

// ── Push ──

export async function pushPolicies(
  confirmOverrides: boolean,
  perRuleFallback = false,
): Promise<{ success: boolean; message?: string }> {
  const s = store()
  const f = fmc()
  const names = selectedAcpNames()
  if (names.length === 0) return { success: false, message: 'Select at least one ACP' }
  f.setOperationRunning(true)
  f.setTerminalVisible(true)
  s.setPushSummary(null)
  // Preserve existing terminal logs (e.g. from validation/preview) and append
  // push-phase logs below them rather than clearing.
  await startLogPolling({ preserveLogs: true })
  startProgressPolling()
  try {
    const res = await debugFetch('/api/policy-config/push', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        acp_names: names,
        mappings: s.mappings,
        validate: f.validateConfigEnabled,
        bulk: f.bulkEnabled,
        per_rule_fallback: perRuleFallback,
        confirm_overrides: confirmOverrides,
        source_version: s.sourceMeta.version,
        target_version: s.targetMeta.version,
        debug: debugFlag(),
      }),
    })
    const data = await res.json()
    if (data.summary) s.setPushSummary(data.summary)
    if (data.summary_tables) {
      f.setSummary(data.summary_tables)
      f.setSummaryVisible(true)
    }
    return { success: !!data.success, message: data.message }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    f.setOperationRunning(false)
  }
}

// ── Save source FMC preset ──

export async function saveSourcePreset(
  name: string, ip: string, port: string, username: string, password: string,
): Promise<{ success: boolean; message?: string }> {
  try {
    const res = await debugFetch('/api/fmc-config/presets/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        name,
        fmc_ip: ip.trim(),
        fmc_port: parseInt(port) || 443,
        username: username.trim(),
        password,
      }),
    })
    const data = await res.json()
    if (data.success) await loadPresets()
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  }
}
