import { useFmcConfigStore, mapRawDevice, mapRawVpnTopology } from '@/stores/fmcConfigStore'

const store = () => useFmcConfigStore.getState()

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
  const { fmcUsername, fmcPassword, domainUuid } = store()
  return {
    fmc_ip: buildFmcBaseUrl(),
    username: fmcUsername.trim(),
    password: fmcPassword,
    domain_uuid: domainUuid || undefined,
    ...extra,
  }
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

export async function startLogPolling() {
  if (logPollTimer) return
  try { await fetch('/api/clear-logs', { method: 'POST', credentials: 'include' }) } catch { /* */ }
  store().clearLog()
  logCursor = 0
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
      store().setProgress(data.percent || 0, data.label || '')
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
    const res = await fetch('/api/fmc-config/connect', {
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
    return { success: true }
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    s.setConnecting(false)
  }
}

// ── Presets ──

export async function loadPresets() {
  try {
    const res = await fetch('/api/fmc-config/presets', { credentials: 'include' })
    const data = await res.json()
    if (data.success) store().setPresets(data.presets || [])
  } catch { /* ignore */ }
}

export async function savePreset(name: string) {
  const s = store()
  const res = await fetch('/api/fmc-config/presets/save', {
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
  const res = await fetch(`/api/fmc-config/presets/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  })
  const data = await res.json()
  if (data.success) await loadPresets()
  return data
}

// ── Devices ──

export async function refreshDevices() {
  const res = await fetch('/api/fmc-config/connect', {
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
  await startLogPolling()
  startProgressPolling()
  try {
    const res = await fetch('/api/fmc-config/delete/stream', {
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
  const res = await fetch('/api/fmc-config/config/upload', {
    method: 'POST',
    credentials: 'include',
    body: fd,
  })
  const data = await res.json()
  if (data.success) {
    const yaml = yamlText || await file.text()
    store().setUploadedConfig(data.config || {}, data.filename || file.name, data.counts || {}, yaml)
  }
  return data
}

export async function getConfigFromFmc(deviceIds: string[]) {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  await startLogPolling()
  startProgressPolling()

  const meta = s.devices.find((d) => d.id === deviceIds[0])
  try {
    const res = await fetch('/api/fmc-config/config/get', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: deviceIds,
        ui_auth_values: s.authOverrides,
        device_meta: meta ? { name: meta.name, type: meta.type, version: meta.sw_version, mode: meta.ftdMode, uuid: meta.id, model: meta.model } : {},
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

export async function applyConfig(deviceIds: string[], selectedTypes: Record<string, boolean>) {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/config/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
        device_ids: deviceIds,
        config: s.uploadedConfig,
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
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : String(err) }
  } finally {
    stopLogPolling()
    stopProgressPolling()
    s.setOperationRunning(false)
  }
}

export async function deleteConfig(deviceIds: string[], selectedTypes: Record<string, boolean>) {
  const s = store()
  if (!s.uploadedConfig) return { success: false, message: 'No config loaded' }

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/config/delete', {
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
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/objects/delete', {
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

// ── Chassis Config ──

export async function uploadChassisConfig(file: File, yamlText?: string) {
  const fd = new FormData()
  fd.append('file', file)
  const res = await fetch('/api/fmc-config/chassis-config/upload', {
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
  await startLogPolling()
  startProgressPolling()
  try {
    const res = await fetch('/api/fmc-config/chassis-config/get', {
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

  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  s.setSummary(null)
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/chassis-config/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(fmcPayload({
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
  const res = await fetch('/api/fmc-config/vpn/upload', {
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

export async function fetchVpnTopologies() {
  const s = store()
  s.setOperationRunning(true)
  s.setTerminalVisible(true)
  await startLogPolling()
  startProgressPolling()
  try {
    const res = await fetch('/api/fmc-config/vpn/list', {
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
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/vpn/apply', {
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
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/vpn/delete', {
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
  const res = await fetch('/api/fmc-config/vpn/download', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ topologies: selectedTopologies }),
  })
  const data = await res.json()
  if (data.success && data.yaml_content) {
    const blob = new Blob([data.yaml_content], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = data.filename || 'vpn_topologies.yaml'
    a.click()
    URL.revokeObjectURL(url)
  }
  return data
}

// ── Template Lookups ──

export async function fetchTemplateLookups() {
  const res = await fetch('/api/fmc-config/template-lookups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(fmcPayload()),
  })
  return await res.json()
}

export async function createResourceProfile(name: string, description: string, cpuCoreCount: number) {
  const res = await fetch('/api/fmc-config/template-resource-profile', {
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
  await startLogPolling()
  startProgressPolling()

  try {
    const res = await fetch('/api/fmc-config/ha/create', {
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
  await startLogPolling()

  try {
    const res = await fetch('/api/fmc-config/vpn/replace-endpoints', {
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
