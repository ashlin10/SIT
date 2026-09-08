import { useFmcConfigStore, mapRawDevice, mapRawVpnTopology } from '@/stores/fmcConfigStore'
import type { SummaryTables } from '@/stores/fmcConfigStore'
import { usePolicyConfigStore, type FmcMeta, EMPTY_META } from '@/stores/policyConfigStore'

const store = () => useFmcConfigStore.getState()

// ── Debug-aware fetch wrapper ──

function debugFetch(url: string, init?: RequestInit): Promise<Response> {
  const s = store()
  if (s.debugEnabled) {
    const method = (init?.method || 'GET').toUpperCase()
    const ts = new Date().toLocaleTimeString()
    s.appendLog(`\x1b[36m[DEBUG ${ts}]\x1b[0m ${method} ${url}`)
    if (init?.body) {
      try {
        if (typeof init.body === 'string') {
          const parsed = JSON.parse(init.body)
          // Mask password fields for security
          const safe = { ...parsed }
          if (safe.password) safe.password = '***'
          s.appendLog(`\x1b[33m  Payload:\x1b[0m ${JSON.stringify(safe, null, 2)}`)
        } else if (init.body instanceof FormData) {
          const parts: string[] = []
          ;(init.body as FormData).forEach((v, k) => {
            parts.push(`${k}: ${v instanceof File ? `[File: ${v.name}, ${v.size}b]` : String(v).slice(0, 200)}`)
          })
          s.appendLog(`\x1b[33m  FormData:\x1b[0m { ${parts.join(', ')} }`)
        }
      } catch { /* non-JSON body */ }
    }
  }
  // Merge in the current operation abort signal if one is active
  const merged = operationAbort && !init?.signal
    ? { ...init, signal: operationAbort.signal }
    : init
  return fetch(url, merged)
}

// ── Helpers ──

export function buildFmcBaseUrl(): string {
  const { fmcIp, fmcPort } = store()
  const ip = fmcIp.trim()
  if (!ip) return ''
  const hasProto = /^https?:\/\//.test(ip)
  const base = hasProto ? ip : `https://${ip}`
  const port = fmcPort.trim()
  return port && port !== '443' ? `${base}:${port}` : base
}

function fmcPayload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const { fmcUsername, fmcPassword, domainUuid, debugEnabled } = store()
  return {
    fmc_ip: buildFmcBaseUrl(),
    username: fmcUsername.trim(),
    password: fmcPassword,
    domain_uuid: domainUuid || undefined,
    debug: debugEnabled || undefined,
    ...extra,
  }
}

// ── Operation abort controller ──

let operationAbort: AbortController | null = null

export function getOperationSignal(): AbortSignal {
  operationAbort = new AbortController()
  return operationAbort.signal
}

export async function stopOperation() {
  // 1. Tell backend to set the stop flag
  try {
    await fetch('/api/stop-operation', { method: 'POST', credentials: 'include' })
  } catch { /* ignore */ }
  // 2. Abort any in-flight streaming fetch on the frontend
  if (operationAbort) {
    operationAbort.abort()
    operationAbort = null
  }
  // 3. Stop polling and mark operation as done
  stopLogPolling()
  stopProgressPolling()
  store().appendLog('\n⛔ Operation stopped by user')
  store().setOperationRunning(false)
}

// ── Log polling (pulls /api/logs into store terminal) ──

let logPollTimer: ReturnType<typeof setInterval> | null = null
let logCursor = 0

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs', { credentials: 'include' })
    const data = await res.json()
    const txt = data?.logs ? String(data.logs) : ''
    if (logCursor > txt.length) logCursor = 0
    const slice = txt.slice(logCursor)
    if (slice) {
      const lines = slice.split(/\r?\n/).filter((l: string) => l)
      lines.forEach((l: string) => store().appendLog(l))
      logCursor = txt.length
    }
  } catch { /* ignore */ }
}

export async function startLogPolling(opts?: { preserveLogs?: boolean }) {
  if (logPollTimer) return
  if (!opts?.preserveLogs) {
    try { await fetch('/api/clear-logs', { method: 'POST', credentials: 'include' }) } catch { /* */ }
    store().clearLog()
    logCursor = 0
  }
  logPollTimer = setInterval(fetchLogs, 1000)
}

export function stopLogPolling() {
  if (logPollTimer) { clearInterval(logPollTimer); logPollTimer = null }
  setTimeout(fetchLogs, 400)
}

// ── Progress polling ──

let progressTimer: ReturnType<typeof setInterval> | null = null

async function pollProgress() {
  try {
    const res = await fetch('/api/progress', { credentials: 'include' })
    const data = await res.json()
    if (data?.active) {
      store().setProgress(data.percent || 0, data.label || '', data.device || '')
    }
  } catch { /* ignore */ }
}

export function startProgressPolling() {
  if (progressTimer) return
  pollProgress()
  progressTimer = setInterval(pollProgress, 1000)
}

export function stopProgressPolling() {
  if (progressTimer) { clearInterval(progressTimer); progressTimer = null }
  setTimeout(pollProgress, 400)
}

// ── FMC Connection ──

export async function connectToFmc() {
  const s = store()
  s.setConnecting(true)
  s.setConnected(false)
  try {
    const res = await debugFetch('/api/fmc-config/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        fmc_ip: buildFmcBaseUrl(),
        username: s.fmcUsername.trim(),
        password: s.fmcPassword,
      }),
    })
    const data = await res.json()
    if (!data.success) throw new Error(data.message || 'Connection failed')
    s.setConnected(true)
    s.selectAllDevices(false)
    if (data.domains) {
      const mapped = (data.domains as Array<Record<string, unknown>>).map((d) => ({ uuid: String(d.id || d.uuid || ''), name: String(d.name || '') }))
      s.setDomains(mapped)
      const globalDomain = mapped.find((d) => d.name === 'Global')
      if (globalDomain) s.setDomainUuid(globalDomain.uuid)
      else if (mapped.length > 0) s.setDomainUuid(mapped[0].uuid)
    }
    if (data.devices) {
      s.setDevices((data.devices as Array<Record<string, unknown>>).map(mapRawDevice))
    }
    // Sync target FMC metadata to the policy config store (non-blocking).
    syncTargetMetadata().catch(() => { /* best-effort */ })
    return { success: true }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    s.setConnecting(false)
  }
}

/** Fetch target FMC server metadata and sync it to the policy config store. */
export async function syncTargetMetadata(): Promise<void> {
  try {
    const res = await fetch('/api/policy-config/target/metadata', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({}),
    })
    const data = await res.json()
    if (data.success && data.target) {
      usePolicyConfigStore.getState().setTargetMeta(data.target as FmcMeta)
    }
  } catch {
    // If the target is not connected, set disconnected meta.
    usePolicyConfigStore.getState().setTargetMeta({ ...EMPTY_META })
  }
}

// ── Presets ──

export async function loadPresets() {
  try {
    const res = await debugFetch('/api/fmc-config/presets', { credentials: 'include' })
    const data = await res.json()
    if (data.success) store().setPresets(data.presets || [])
  } catch { /* ignore */ }
}

export async function savePreset(name: string) {
  const s = store()
  const res = await debugFetch('/api/fmc-config/presets/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      name,
      fmc_ip: s.fmcIp.trim(),
      fmc_port: parseInt(s.fmcPort) || 443,
      username: s.fmcUsername.trim(),
      password: s.fmcPassword,
    }),
  })
  const data = await res.json()
  if (data.success) await loadPresets()
  return data
}

export async function deletePreset(id: string) {
  const res = await debugFetch(`/api/fmc-config/presets/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  })
  const data = await res.json()
  if (data.success) await loadPresets()
  return data
}

// ── Devices ──

export async function refreshDevices() {
  const res = await debugFetch('/api/fmc-config/connect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(fmcPayload()),
  })
  const data = await res.json()
  if (data.success && data.devices) {
    store().setDevices((data.devices as Array<Record<string, unknown>>).map(mapRawDevice))
  }
  return data
}

export async function deleteDevicesFromFmc(deviceIds: string[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()
  try {
    const res = await debugFetch('/api/fmc-config/delete/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({ device_ids: deviceIds })),
    })
    if (!res.ok || !res.body) throw new Error('Delete stream failed')
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buf = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx)
        buf = buf.slice(idx + 1)
        if (line) s.appendLog(line)
      }
    }
    if (buf) s.appendLog(buf)
    return { success: true }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

// ── Config Upload / Get / Apply / Delete ──

export async function uploadConfig(file: File, yamlText?: string) {
  const fd = new FormData()
  fd.append('file', file)
  const res = await debugFetch('/api/fmc-config/config/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    const yaml = yamlText || await file.text()
    store().setUploadedConfig(data.config || {}, data.filename || file.name, data.counts || {}, yaml)
    if (data.multi && Array.isArray(data.devices)) {
      store().setUploadedDevices((data.devices as Array<Record<string, unknown>>).map((d) => ({
        sourceName: String(d.name || ''),
        metadata: (d.metadata || {}) as Record<string, unknown>,
        config: (d.config || {}) as Record<string, unknown>,
        counts: (d.counts || {}) as Record<string, number>,
      })))
    }
  }
  return data
}

/** Build the per-device config mapping payload for multi-device push/validate. */
function buildDeviceConfigs(): { device_configs: Array<{ device_id: string; config: Record<string, unknown> }>; device_ids: string[] } {
  const s = store()
  const out: Array<{ device_id: string; config: Record<string, unknown> }> = []
  const ids: string[] = []
  s.uploadedDevices.forEach((d) => {
    const target = s.deviceMapping[d.sourceName]
    if (target) {
      out.push({ device_id: target, config: d.config })
      ids.push(target)
    }
  })
  return { device_configs: out, device_ids: ids }
}

export async function getConfigFromFmc(deviceIds: string[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  const metaOf = (id: string) => {
    const m = s.devices.find((d) => d.id === id)
    return m ? { name: m.name, type: m.type, version: m.sw_version, mode: m.ftdMode, uuid: m.id, model: m.model } : {}
  }
  const meta = metaOf(deviceIds[0])
  const deviceMetas: Record<string, unknown> = {}
  deviceIds.forEach((id) => { deviceMetas[id] = metaOf(id) })
  try {
    const res = await debugFetch('/api/fmc-config/config/get', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: deviceIds,
        ui_auth_values: s.authOverrides,
        device_meta: meta,
        device_metas: deviceMetas,
      })),
    })
    // Backend returns StreamingResponse with YAML content (not JSON)
    const contentType = res.headers.get('content-type') || ''
    if (contentType.includes('yaml') || contentType.includes('octet-stream')) {
      const yamlText = await res.text()
      const disposition = res.headers.get('content-disposition') || ''
      const filenameMatch = disposition.match(/filename=([^;\s]+)/)
      const filename = filenameMatch ? filenameMatch[1] : 'config.yaml'
      // Auto-download
      const blob = new Blob([yamlText], { type: 'text/yaml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      // Re-upload to parse into UI
      const f = new File([blob], filename, { type: 'text/yaml' })
      await uploadConfig(f, yamlText)
      return { success: true }
    } else {
      // Error response is JSON
      const data = await res.json()
      return data
    }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function applyConfig(
  deviceIds: string[],
  selectedTypes: Record<string, boolean>,
  configOverride?: Record<string, unknown> | null,
) {
  const s = store()
  const configToApply = configOverride ?? s.uploadedConfig
  if (!configToApply) return { success: false, message: 'No config loaded' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  s.setDeviceSummaries([])
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  // Multi-device: send per-device config mapping (source→target) instead of a shared config.
  const multi = s.isMultiDevice && !configOverride
  const mapping = multi ? buildDeviceConfigs() : null

  try {
    const res = await debugFetch('/api/fmc-config/config/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: mapping ? mapping.device_ids : deviceIds,
        config: configToApply,
        device_configs: mapping ? mapping.device_configs : undefined,
        selected_types: selectedTypes,
        ui_auth_values: s.authOverrides,
        bulk: s.bulkEnabled,
        batch_size: s.batchSize,
      })),
    })
    const data = await res.json()
    if (data.summary_tables) {
      s.setSummary(data.summary_tables)
      s.setSummaryVisible(true)
    }
    // Per-device summaries (multi-device push) so each device gets its own collapsible table.
    if (Array.isArray(data.results) && data.results.length > 1) {
      s.setDeviceSummaries((data.results as Array<Record<string, unknown>>).map((r) => ({
        deviceName: String(r.device_name || r.device_id || 'Device'),
        tables: (r.summary_tables || { applied: [], failed: [], skipped: [] }) as SummaryTables,
      })))
    } else {
      s.setDeviceSummaries([])
    }
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

// ── Config validation ──

/** Run deterministic config validation. Opens the review panel on success. */
export async function validateConfig(deviceIds: string[], selectedTypes: Record<string, boolean>) {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setValidationPhase('validating')
  s.setValidationOpen(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  const mapping = s.isMultiDevice ? buildDeviceConfigs() : null

  try {
    const res = await debugFetch('/api/fmc-config/config/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: mapping ? mapping.device_ids : deviceIds,
        config: s.uploadedConfig,
        device_configs: mapping ? mapping.device_configs : undefined,
        selected_types: selectedTypes,
        schema_source: s.schemaSource,
      })),
    })
    const data = await res.json()
    if (!data.success) {
      s.setValidationPhase('idle')
      s.setValidationOpen(false)
      return data
    }
    s.setValidationResult(data.reports || [], data.fmcVersion || '')
    s.setValidationPhase('review')
    return data
  } catch (err) {
    s.setValidationPhase('idle')
    s.setValidationOpen(false)
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

/** Compute the set of issue ids the user has accepted (auto-fixable, not rejected). */
function acceptedIssueIds(): string[] {
  const s = store()
  const ids: string[] = []
  s.validationReports.forEach((r) => r.issues.forEach((i) => {
    if (!i.autoFixable) return
    const allIds = i.groupIds && i.groupIds.length ? i.groupIds : [i.id]
    allIds.forEach((id) => { if (!s.rejectedIssueIds.has(id)) ids.push(id) })
  }))
  return ids
}

/** Target metadata used for sanitization (first device's resolved model/version). */
function sanitizeTargetMeta(): { model: string; version: string; fmc_version: string } {
  const s = store()
  const t = s.validationReports[0]?.target
  return {
    model: t?.rawModel || '',
    version: t?.rawVersion || '',
    fmc_version: t?.fmcVersion || s.validationFmcVersion || '',
  }
}

/** Interface-correction selections gathered from the review panel. */
function interfaceCorrections(): {
  interface_mappings: Record<string, string>
  speed_changes: Record<string, string>
  interface_removals: string[]
  member_changes: Record<string, Record<string, string>>
  etherchannel_id_changes: Record<string, number>
} {
  const s = store()
  const removals = Array.from(s.interfaceRemovals)
  // Auto-add not-on-device interfaces that have no explicit mapping as implicit removals.
  s.validationReports.forEach((r) => (r.interfaceConflicts || []).forEach((c) => {
    if (c.sourceName && !s.interfaceMappings[c.sourceName] && !removals.includes(c.sourceName)) {
      removals.push(c.sourceName)
    }
  }))
  const removalSet = new Set(removals)
  // Renames whose target is a real interface (exclude any that are being removed).
  const renames: Record<string, string> = {}
  Object.entries(s.interfaceMappings).forEach(([k, v]) => {
    if (v && !removalSet.has(k)) renames[k] = v
  })
  // Only send explicit speed selections (empty string means "keep current").
  // Strip the __ec__ prefix used internally for etherchannel parent speeds so
  // the backend _set_interface_speed matches the real interface name.
  const speeds: Record<string, string> = {}
  Object.entries(s.speedChanges).forEach(([k, v]) => {
    const realKey = k.startsWith('__ec__') ? k.slice(6) : k
    if (v && !removalSet.has(realKey)) speeds[realKey] = v
  })
  // Member changes: only include parents that have at least one real change.
  const mc: Record<string, Record<string, string>> = {}
  Object.entries(s.memberChanges).forEach(([parent, map]) => {
    const filtered: Record<string, string> = {}
    Object.entries(map).forEach(([old, nw]) => { if (nw && nw !== old) filtered[old] = nw })
    if (Object.keys(filtered).length) mc[parent] = filtered
  })
  return {
    interface_mappings: renames,
    speed_changes: speeds,
    interface_removals: removals,
    member_changes: mc,
    etherchannel_id_changes: { ...s.etherchannelIdChanges },
  }
}

/** Build a sanitized config from accepted fixes + interface corrections (no mutation). */
export async function sanitizeConfig() {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }
  const corr = interfaceCorrections()
  const res = await debugFetch('/api/fmc-config/config/sanitize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      config: s.uploadedConfig,
      target_meta: sanitizeTargetMeta(),
      interface_mappings: corr.interface_mappings,
      speed_changes: corr.speed_changes,
      interface_removals: corr.interface_removals,
      member_changes: corr.member_changes,
      etherchannel_id_changes: corr.etherchannel_id_changes,
      accepted_issue_ids: acceptedIssueIds(),
      schema_source: s.schemaSource,
    }),
  })
  const data = await res.json()
  if (data.success) {
    s.setSanitizedResult(data.sanitizedConfig || null, data.sanitizedYaml || '', data.diff || '', data.changes || [])
  }
  return data
}

/**
 * Fix: apply the accepted fixes + interface corrections to the loaded config and
 * update the in-memory/UI YAML in place (so subsequent validation uses it).
 */
export async function applyValidationFixes() {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  await startLogPolling()
  try {
    const res = await sanitizeConfig()
    if (!res.success) return res
    const yamlText: string = res.sanitizedYaml || ''
    if (yamlText) {
      // Re-parse through the backend so config + counts are refreshed in store.
      await reUploadConfigYaml(yamlText)
    } else if (res.sanitizedConfig) {
      s.setUploadedConfig(res.sanitizedConfig, s.uploadedConfigFilename, s.uploadedCounts, yamlText)
    }
    return res
  } finally {
    stopLogPolling()
    s.setOperationRunning(false)
  }
}

/** Revalidate: re-run validation against the (possibly corrected) loaded config. */
export async function revalidate(deviceIds: string[], selectedTypes: Record<string, boolean>) {
  return validateConfig(deviceIds, selectedTypes)
}

/** Continue: close the review panel and push the currently loaded config. */
export async function continueValidatedPush(deviceIds: string[], selectedTypes: Record<string, boolean>) {
  const s = store()
  s.setValidationOpen(false)
  s.setValidationPhase('idle')
  return applyConfig(deviceIds, selectedTypes)
}

/** Cancel the validation flow without pushing. */
export function cancelValidation() {
  store().resetValidation()
}

export async function deleteConfig(deviceIds: string[], selectedTypes: Record<string, boolean>) {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await debugFetch('/api/fmc-config/config/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: deviceIds,
        config: s.uploadedConfig,
        selected_types: selectedTypes,
      })),
    })
    const data = await res.json()
    if (data.summary_tables) {
      s.setSummary(data.summary_tables)
      s.setSummaryVisible(true)
    }
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function deleteObjects(selectedTypes: Record<string, boolean>) {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await debugFetch('/api/fmc-config/objects/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        config: s.uploadedConfig,
        selected_types: selectedTypes,
      })),
    })
    const data = await res.json()
    if (data.summary_tables) {
      s.setSummary(data.summary_tables)
      s.setSummaryVisible(true)
    }
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

/** Re-parse edited device config YAML through backend and refresh store counts/config */
export async function reUploadConfigYaml(yamlText: string) {
  const s = store()
  const blob = new Blob([yamlText], { type: 'application/x-yaml' })
  const fd = new FormData()
  fd.append('file', blob, s.uploadedConfigFilename || 'edited.yaml')
  const res = await debugFetch('/api/fmc-config/config/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    s.setUploadedConfig(data.config || {}, s.uploadedConfigFilename, data.counts || {}, yamlText)
  }
  return data
}

// ── Chassis Config ──

/** Re-parse edited chassis config YAML through backend and refresh store counts/config */
export async function reUploadChassisConfigYaml(yamlText: string) {
  const s = store()
  const blob = new Blob([yamlText], { type: 'application/x-yaml' })
  const fd = new FormData()
  fd.append('file', blob, s.chassisConfigFilename || 'chassis_edited.yaml')
  const res = await debugFetch('/api/fmc-config/chassis-config/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    s.setChassisConfig(data.config || {}, s.chassisConfigFilename, data.counts || {}, yamlText)
  }
  return data
}

export async function uploadChassisConfig(file: File, yamlText?: string) {
  const fd = new FormData()
  fd.append('file', file)
  const res = await debugFetch('/api/fmc-config/chassis-config/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    const yaml = yamlText || await file.text()
    store().setChassisConfig(data.config || {}, data.filename || file.name, data.counts || {}, yaml)
  }
  return data
}

export async function getChassisConfig(deviceIds: string[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()
  try {
    const res = await debugFetch('/api/fmc-config/chassis-config/get', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({ device_ids: deviceIds })),
    })
    // Backend returns StreamingResponse with YAML content (not JSON)
    const contentType = res.headers.get('content-type') || ''
    if (contentType.includes('yaml') || contentType.includes('octet-stream')) {
      const yamlText = await res.text()
      const disposition = res.headers.get('content-disposition') || ''
      const filenameMatch = disposition.match(/filename=([^;\s]+)/)
      const filename = filenameMatch ? filenameMatch[1] : 'chassis_config.yaml'
      // Auto-download
      const blob = new Blob([yamlText], { type: 'text/yaml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      // Re-upload to parse into UI
      const f = new File([blob], filename, { type: 'text/yaml' })
      await uploadChassisConfig(f, yamlText)
      return { success: true }
    } else {
      const data = await res.json()
      return data
    }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function applyChassisConfig(selectedTypes: Record<string, boolean>, adminPassword: string) {
  const s = store()
  if (!s.chassisConfig) return { success: false, message: 'No chassis config loaded' }
  if (s.selectedDeviceIds.size === 0) return { success: false, message: 'No device selected. Please select a chassis device first.' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await debugFetch('/api/fmc-config/chassis-config/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: Array.from(s.selectedDeviceIds),
        config: s.chassisConfig,
        selected_types: selectedTypes,
        admin_password: adminPassword,
      })),
    })
    const data = await res.json()
    if (data.summary_tables) {
      s.setSummary(data.summary_tables)
      s.setSummaryVisible(true)
    }
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

// ── VPN ──

export async function uploadVpn(file: File) {
  const fd = new FormData()
  fd.append('file', file)
  const res = await debugFetch('/api/fmc-config/vpn/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    const topos = (data.topologies || []).map((t: Record<string, unknown>) => mapRawVpnTopology(t))
    store().setVpnTopologies(topos)
    store().setVpnFilename(data.filename || file.name)
    if (data.yaml_content) store().setVpnYaml(data.yaml_content)
    else {
      try { store().setVpnYaml(await file.text()) } catch { /* */ }
    }
  }
  return data
}

/** Re-parse edited VPN YAML through backend and refresh store topologies */
export async function reUploadVpnYaml(yamlText: string) {
  const s = store()
  const blob = new Blob([yamlText], { type: 'application/x-yaml' })
  const fd = new FormData()
  fd.append('file', blob, s.vpnFilename || 'vpn_edited.yaml')
  const res = await debugFetch('/api/fmc-config/vpn/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    const topos = (data.topologies || []).map((t: Record<string, unknown>) => mapRawVpnTopology(t))
    s.setVpnTopologies(topos)
    s.setVpnYaml(yamlText)
  }
  return data
}

export async function fetchVpnTopologies() {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()
  try {
    const res = await debugFetch('/api/fmc-config/vpn/list', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload()),
    })
    const data = await res.json()
    if (data.success) {
      const topos = (data.topologies || []).map((t: Record<string, unknown>) => mapRawVpnTopology(t))
      s.setVpnTopologies(topos)
      if (data.vpn_yaml) s.setVpnYaml(data.vpn_yaml)
      // Set filename from backend or generate one
      const fname = data.vpn_filename || `vpn-topologies-${Date.now()}.yaml`
      s.setVpnFilename(fname)
    }
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function applyVpn(selectedTopologies: Record<string, unknown>[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await debugFetch('/api/fmc-config/vpn/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({ topologies: selectedTopologies })),
    })
    const data = await res.json()
    if (data.summary_tables) {
      s.setSummary(data.summary_tables)
      s.setSummaryVisible(true)
    }
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function deleteVpnTopologies(selectedTopologies: Record<string, unknown>[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await debugFetch('/api/fmc-config/vpn/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({ topologies: selectedTopologies })),
    })
    const data = await res.json()
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function downloadVpnYaml(selectedTopologies: Record<string, unknown>[]) {
  const res = await debugFetch('/api/fmc-config/vpn/download', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ topologies: selectedTopologies }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: 'Download failed' }))
    return { success: false, message: err.message || 'Download failed' }
  }
  // Backend returns raw YAML bytes, not JSON
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  // Extract filename from Content-Disposition header or use default
  const cd = res.headers.get('Content-Disposition') || ''
  const match = cd.match(/filename=(.+)/)
  a.download = match ? match[1] : 'vpn_topologies.yaml'
  a.click()
  URL.revokeObjectURL(url)
  return { success: true }
}

// ── Template Lookups ──

export async function fetchTemplateLookups() {
  const res = await debugFetch('/api/fmc-config/template-lookups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(fmcPayload()),
  })
  return await res.json()
}

export async function createResourceProfile(name: string, description: string, cpuCoreCount: number) {
  const res = await debugFetch('/api/fmc-config/template-resource-profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(fmcPayload({ name, description, cpuCoreCount })),
  })
  return await res.json()
}

// ── HA Pair Creation ──

export async function createHaPairs(pairs: Record<string, unknown>[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await debugFetch('/api/fmc-config/ha/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({ pairs })),
    })
    const data = await res.json()
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

// ── VPN Replace Endpoints ──

export async function replaceVpnEndpoints(srcDeviceId: string, dstDeviceId: string) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  getOperationSignal()
  await startLogPolling()

  try {
    const res = await debugFetch('/api/fmc-config/vpn/replace-endpoints', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({ src_device_id: srcDeviceId, dst_device_id: dstDeviceId })),
    })
    const data = await res.json()
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    s.setOperationRunning(false)
  }
}
