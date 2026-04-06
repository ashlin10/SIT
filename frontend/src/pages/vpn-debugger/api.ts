import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import type { ConnectionInfo, TunnelData, ConfigFile } from '@/stores/vpnDebuggerStore'

const store = () => useVpnDebuggerStore.getState()

function isCsc() { return store().localNodeType === 'csc' }
function apiBase() { return isCsc() ? '/api/csc' : '/api/strongswan' }

async function json(res: Response) {
  if (!res.ok) {
    const d = await res.json().catch(() => ({}))
    throw new Error((d as { message?: string }).message || `HTTP ${res.status}`)
  }
  return res.json()
}

// ── Connection ──

export async function connectToServer(conn: ConnectionInfo) {
  const s = store()
  s.setConnecting(true)
  try {
    const base = apiBase()
    const data = await json(await fetch(`${base}/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ ip: conn.ip, port: parseInt(conn.port), username: conn.username, password: conn.password }),
    }))
    if (data.success) {
      s.setLocalConnected(true)
      if (data.tunnels) {
        s.setTunnels(data.tunnels)
        s.setFilteredTunnels(data.tunnels)
      }
      s.setLastUpdated(new Date().toLocaleString())
      s.notify('Connected to server', 'success')
      // Auto-fetch dependent data
      fetchServiceStatus()
      fetchSwanctlLogStatus()
      fetchConfigFiles()
      fetchNetplanFiles()
      loadPresets()
    } else {
      s.notify(data.message || 'Connection failed', 'error')
    }
    return data
  } catch (err) {
    s.notify(err instanceof Error ? err.message : 'Connection failed', 'error')
    return { success: false }
  } finally {
    s.setConnecting(false)
  }
}

export async function connectRemoteServer(conn: ConnectionInfo) {
  const s = store()
  try {
    const data = await json(await fetch('/api/strongswan/tunnel-traffic/remote/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ ip: conn.ip, port: parseInt(conn.port), username: conn.username, password: conn.password }),
    }))
    if (data.success) {
      s.setRemoteConnected(true)
      s.notify('Connected to remote server', 'success')
      fetchRemoteConfigFiles()
      fetchRemoteNetplanFiles()
    } else {
      s.notify(data.message || 'Remote connection failed', 'error')
    }
    return data
  } catch (err) {
    s.notify(err instanceof Error ? err.message : 'Remote connection failed', 'error')
    return { success: false }
  }
}

// ── Refresh Tunnels ──

export async function refreshTunnels() {
  const s = store()
  s.setRefreshing(true)
  try {
    const data = await json(await fetch('/api/strongswan/refresh', { credentials: 'include' }))
    if (data.success && data.tunnels) {
      s.setTunnels(data.tunnels)
      applyFilters(data.tunnels)
      s.setLastUpdated(new Date().toLocaleString())
    }
    return data
  } catch { return { success: false } }
  finally { s.setRefreshing(false) }
}

// ── Tunnel Detail ──

export async function fetchTunnelDetail(tunnelName: string): Promise<string> {
  try {
    const data = await json(await fetch('/api/strongswan/tunnel-detail', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ tunnel_name: tunnelName }),
    }))
    return data.detail || data.output || ''
  } catch { return 'Failed to fetch tunnel detail' }
}

// ── Presets ──

export async function loadPresets() {
  try {
    const data = await json(await fetch('/api/strongswan/presets', { credentials: 'include' }))
    if (data.success) store().setPresets(data.presets || [])
  } catch { /* ignore */ }
}

export async function savePreset(name: string, conn: ConnectionInfo) {
  try {
    const data = await json(await fetch('/api/strongswan/presets/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ name, ip: conn.ip, port: conn.port, username: conn.username, password: conn.password }),
    }))
    if (data.success) {
      store().setPresets(data.presets || [])
      store().notify('Preset saved', 'success')
    }
    return data
  } catch { return { success: false } }
}

export async function deletePreset(id: string) {
  try {
    const data = await json(await fetch(`/api/strongswan/presets/${id}`, { method: 'DELETE', credentials: 'include' }))
    if (data.success) store().setPresets(data.presets || [])
    return data
  } catch { return { success: false } }
}

// ── Service Control ──

export async function fetchServiceStatus() {
  try {
    const data = await json(await fetch('/api/strongswan/service/status', { credentials: 'include' }))
    if (data.success) store().setServiceStatus(data.status)
  } catch { /* ignore */ }
}

export async function serviceAction(action: 'enable' | 'disable' | 'restart') {
  const s = store()
  try {
    const data = await json(await fetch(`/api/strongswan/service/${action}`, { method: 'POST', credentials: 'include' }))
    if (data.success) {
      s.notify(data.message || `Service ${action} successful`, 'success')
      fetchServiceStatus()
    } else {
      s.notify(data.message || `Service ${action} failed`, 'error')
    }
    return data
  } catch (err) {
    s.notify(err instanceof Error ? err.message : `Service ${action} failed`, 'error')
    return { success: false }
  }
}

// ── SwanCtl Log ──

export async function fetchSwanctlLogStatus() {
  try {
    const data = await json(await fetch('/api/strongswan/swanctl-log/status', { credentials: 'include' }))
    if (data.success) store().setSwanctlLogStatus(data.status, data.pid)
  } catch { /* ignore */ }
}

export async function swanctlLogAction(action: 'start' | 'stop') {
  const s = store()
  try {
    const data = await json(await fetch(`/api/strongswan/swanctl-log/${action}`, { method: 'POST', credentials: 'include' }))
    if (data.success) {
      s.notify(data.message || `swanctl --log ${action}ed`, 'success')
      fetchSwanctlLogStatus()
    }
    return data
  } catch { return { success: false } }
}

// ── Config Files ──

export async function fetchConfigFiles() {
  const s = store()
  s.setConfigFilesLoading(true)
  try {
    const data = await json(await fetch(`${apiBase()}/config-files`, { credentials: 'include' }))
    if (data.success) s.setConfigFiles((data.files || []).map((f: string | ConfigFile) => typeof f === 'string' ? { name: f } : f))
  } catch { /* ignore */ }
  finally { s.setConfigFilesLoading(false) }
}

export async function fetchRemoteConfigFiles() {
  const s = store()
  s.setRemoteConfigFilesLoading(true)
  try {
    const data = await json(await fetch('/api/strongswan/remote/config-files', { credentials: 'include' }))
    if (data.success) s.setRemoteConfigFiles((data.files || []).map((f: string | ConfigFile) => typeof f === 'string' ? { name: f } : f))
  } catch { /* ignore */ }
  finally { s.setRemoteConfigFilesLoading(false) }
}

export async function fetchFileContent(filename: string): Promise<string> {
  try {
    const base = apiBase()
    if (isCsc()) {
      const data = await json(await fetch(`${base}/config-file?filename=${encodeURIComponent(filename)}`, { credentials: 'include' }))
      return data.content || ''
    }
    const data = await json(await fetch(`${base}/config-file-content`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ filename }),
    }))
    return data.content || ''
  } catch { return '' }
}

export async function saveFileContent(filename: string, content: string) {
  const s = store()
  try {
    const data = await json(await fetch(`${apiBase()}/config-file-save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ filename, content }),
    }))
    if (data.success) {
      s.notify('File saved', 'success')
      fetchConfigFiles()
    }
    return data
  } catch { return { success: false } }
}

export async function deleteFile(filename: string) {
  const s = store()
  try {
    const base = apiBase()
    if (isCsc()) {
      const data = await json(await fetch(`${base}/config-file/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ filename }),
      }))
      return data
    }
    const data = await json(await fetch(`${base}/config-file-delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ filename }),
    }))
    if (data.success) {
      s.notify('File deleted', 'success')
      fetchConfigFiles()
    }
    return data
  } catch { return { success: false } }
}

export async function toggleFileVisibility(filename: string, newFilename: string) {
  try {
    const data = await json(await fetch('/api/strongswan/config-file-toggle-visibility', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ filename, newFilename }),
    }))
    if (data.success) fetchConfigFiles()
    return data
  } catch { return { success: false } }
}

// ── Netplan Files ──

export async function fetchNetplanFiles() {
  const s = store()
  s.setNetplanFilesLoading(true)
  try {
    const data = await json(await fetch(`${apiBase()}/netplan/files`, { credentials: 'include' }))
    if (data.success) s.setNetplanFiles((data.files || []).map((f: string | ConfigFile) => typeof f === 'string' ? { name: f } : f))
  } catch { /* ignore */ }
  finally { s.setNetplanFilesLoading(false) }
}

export async function fetchRemoteNetplanFiles() {
  const s = store()
  s.setRemoteNetplanFilesLoading(true)
  try {
    const data = await json(await fetch('/api/strongswan/remote/netplan/files', { credentials: 'include' }))
    if (data.success) s.setRemoteNetplanFiles((data.files || []).map((f: string | ConfigFile) => typeof f === 'string' ? { name: f } : f))
  } catch { /* ignore */ }
  finally { s.setRemoteNetplanFilesLoading(false) }
}

export async function fetchNetplanContent(filename: string): Promise<string> {
  try {
    const data = await json(await fetch(`${apiBase()}/netplan/file-content`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ filename }),
    }))
    return data.content || ''
  } catch { return '' }
}

export async function saveNetplanContent(filename: string, content: string) {
  const s = store()
  try {
    const data = await json(await fetch(`${apiBase()}/netplan/file-save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ filename, content }),
    }))
    if (data.success) {
      s.notify('Netplan file saved', 'success')
      fetchNetplanFiles()
    }
    return data
  } catch { return { success: false } }
}

export async function netplanApply() {
  const s = store()
  try {
    const data = await json(await fetch(`${apiBase()}/netplan/apply`, { method: 'POST', credentials: 'include' }))
    s.notify(data.success ? 'Netplan applied' : (data.message || 'Netplan apply failed'), data.success ? 'success' : 'error')
    return data
  } catch { return { success: false } }
}

export async function netplanRoutes(): Promise<string> {
  try {
    const base = apiBase()
    const method = isCsc() ? 'GET' : 'POST'
    const data = await json(await fetch(`${base}/netplan/routes`, { method, credentials: 'include' }))
    return data.output || ''
  } catch { return '' }
}

// ── Traffic Control ──

export async function tcShow(): Promise<string> {
  try {
    const data = await json(await fetch(`${apiBase()}/tc/show`, { method: 'POST', credentials: 'include' }))
    return data.output || ''
  } catch { return '' }
}

export async function tcApply(commands: string) {
  const s = store()
  try {
    const data = await json(await fetch(`${apiBase()}/tc/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ commands }),
    }))
    s.notify(data.success ? 'TC rules applied' : (data.message || 'TC apply failed'), data.success ? 'success' : 'error')
    return data
  } catch { return { success: false } }
}

export async function tcRemove() {
  const s = store()
  try {
    const data = await json(await fetch(`${apiBase()}/tc/remove`, { method: 'POST', credentials: 'include' }))
    s.notify(data.success ? 'TC rules removed' : (data.message || 'TC remove failed'), data.success ? 'success' : 'error')
    return data
  } catch { return { success: false } }
}

// ── Syslog Files (for monitoring) ──

export async function fetchSyslogFiles(source?: string) {
  const s = store()
  try {
    const suffix = isCsc() ? '?source=csc' : (source === 'csc' ? '?source=csc' : '')
    const data = await json(await fetch('/api/strongswan/syslog-files' + suffix, { credentials: 'include' }))
    if (data.success && data.files) {
      s.setLocalLogFiles(data.files)
      s.setRemoteLogFiles(data.files)
      if (data.files.length > 0) {
        const def = data.files.find((f: string) => f.includes('swanctl-syslog')) || data.files[0]
        s.setSelectedLocalLog(def)
        if (data.files.length > 1) s.setSelectedRemoteLog(data.files[1])
      }
    }
  } catch { /* ignore */ }
}

// ── Monitoring ──

export async function fetchMonitoringStatus() {
  try {
    const data = await json(await fetch('/api/strongswan/monitoring/status', { credentials: 'include' }))
    if (data.success) {
      store().setMonitoringStatus(data.status || 'stopped', data.pid ? String(data.pid) : '')
      store().setDisconnectCount(data.disconnect_count || 0)
    } else {
      // If the status fetch fails (e.g. not connected), reset to stopped
      store().setMonitoringStatus('stopped', '')
      store().setDisconnectCount(0)
    }
  } catch {
    // On error, assume stopped
    store().setMonitoringStatus('stopped', '')
    store().setDisconnectCount(0)
  }
}

export async function startMonitoring(localLog: string, remoteLog: string, interval: number, leeway: number) {
  const s = store()
  try {
    const data = await json(await fetch('/api/strongswan/monitoring/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ local_log: localLog, remote_log: remoteLog, interval_minutes: interval, leeway_seconds: leeway }),
    }))
    if (data.success) {
      s.notify('Monitoring started', 'success')
      // Show both daemon PID and swanctl PID
      const pidStr = [data.pid && `Daemon: ${data.pid}`, data.swanctl_pid && `swanctl: ${data.swanctl_pid}`].filter(Boolean).join(' | ')
      s.setMonitoringStatus('running', pidStr)
      s.setDisconnectCount(0)
    } else {
      s.notify(data.message || 'Failed to start monitoring', 'error')
    }
    return data
  } catch { return { success: false } }
}

export async function stopMonitoring() {
  const s = store()
  try {
    const data = await json(await fetch('/api/strongswan/monitoring/stop', { method: 'POST', credentials: 'include' }))
    if (data.success) {
      s.notify('Monitoring stopped', 'success')
      s.setMonitoringStatus('stopped', '')
      s.setDisconnectCount(0)
    }
    return data
  } catch { return { success: false } }
}

export async function downloadReport(): Promise<string> {
  try {
    const res = await fetch('/api/strongswan/monitoring/download', { credentials: 'include' })
    if (!res.ok) throw new Error('Download failed')
    return await res.text()
  } catch { return '' }
}

// ── Tunnel Traffic Files ──

export async function fetchLocalTtFiles() {
  const s = store()
  s.setLocalTtFilesLoading(true)
  try {
    const data = await json(await fetch('/api/strongswan/tunnel-traffic/local/files', { credentials: 'include' }))
    if (data.success) s.setLocalTtFiles((data.files || []).map((f: string | ConfigFile) => typeof f === 'string' ? { name: f } : f))
  } catch { /* ignore */ }
  finally { s.setLocalTtFilesLoading(false) }
}

export async function fetchRemoteTtFiles() {
  const s = store()
  s.setRemoteTtFilesLoading(true)
  try {
    const data = await json(await fetch('/api/strongswan/tunnel-traffic/remote/files', { credentials: 'include' }))
    if (data.success) s.setRemoteTtFiles((data.files || []).map((f: string | ConfigFile) => typeof f === 'string' ? { name: f } : f))
  } catch { /* ignore */ }
  finally { s.setRemoteTtFilesLoading(false) }
}

export async function fetchTtFileContent(side: 'local' | 'remote', filename: string): Promise<string> {
  try {
    const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/file-content`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename }),
    }))
    return data.content || ''
  } catch { return '' }
}

export async function saveTtFile(side: 'local' | 'remote', filename: string, content: string) {
  const s = store()
  try {
    const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/file-save`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename, content }),
    }))
    if (data.success) s.notify('File saved', 'success')
    return data
  } catch { return { success: false } }
}

export async function deleteTtFile(side: 'local' | 'remote', filename: string) {
  const s = store()
  try {
    const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/file-delete`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename }),
    }))
    if (data.success) {
      s.notify('File deleted', 'success')
      if (side === 'local') fetchLocalTtFiles(); else fetchRemoteTtFiles()
    }
    return data
  } catch { return { success: false } }
}

export async function toggleTtFileVisibility(side: 'local' | 'remote', filename: string) {
  const isHidden = filename.startsWith('.')
  const newName = isHidden ? filename.slice(1) : `.${filename}`
  try {
    const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/file-toggle-visibility`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename, new_filename: newName }),
    }))
    if (data.success) {
      if (side === 'local') fetchLocalTtFiles(); else fetchRemoteTtFiles()
    }
    return data
  } catch { return { success: false } }
}

// Track PIDs of executed scripts by side+filename
const ttPids: Record<string, Record<string, number>> = { local: {}, remote: {} }

export async function executeTtScript(side: 'local' | 'remote', filename: string) {
  const s = store()
  try {
    const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/execute`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename }),
    }))
    if (data.success && data.pid) {
      ttPids[side][filename] = data.pid
      s.notify(`${filename} started — PID ${data.pid}`, 'success')
    } else if (data.success) {
      s.notify(`Executing ${filename}`, 'success')
    } else {
      s.notify(data.message || 'Execute failed', 'error')
    }
    return data
  } catch { return { success: false } }
}

export async function killTtScript(side: 'local' | 'remote', filename: string) {
  const s = store()
  const pid = ttPids[side]?.[filename]

  // No tracked PID — fall back to pkill -9 iperf3 on the server
  if (!pid) {
    const confirmed = confirm(
      `Cannot locate PID for ${filename}. Attempt to kill all iperf3 processes on the ${side} server?`
    )
    if (!confirmed) return { success: false }
    try {
      const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/execute-command`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'include', body: JSON.stringify({ command: 'pkill -9 iperf3' }),
      }))
      if (data.success) s.notify('Issued pkill -9 iperf3', 'success')
      else s.notify(data.message || 'Kill failed', 'error')
      return data
    } catch { return { success: false } }
  }

  // Kill by tracked PID
  try {
    const data = await json(await fetch(`/api/strongswan/tunnel-traffic/${side}/kill`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename, pid }),
    }))
    if (data.success) {
      s.notify(`PID ${pid} killed`, 'success')
      delete ttPids[side][filename]
    } else {
      s.notify(data.message || 'Kill failed', 'error')
    }
    return data
  } catch { return { success: false } }
}

// ── Filter Logic ──

export interface ParsedCryptoParams {
  encryption: string
  integrity: string
  prf: string
  dh_group: string
  akes: { num: string; alg: string }[]
}

export function parseCryptoParams(cryptoStr: string | undefined, includePrf = true): ParsedCryptoParams | null {
  if (!cryptoStr) return null
  const parts = cryptoStr.split('/')
  const result: ParsedCryptoParams = { encryption: 'NONE', integrity: 'NONE', prf: 'NONE', dh_group: 'NONE', akes: [] }
  parts.forEach(p => {
    const upper = p.trim().toUpperCase()
    if (!upper) return
    if (upper.startsWith('KE') && upper.includes('_')) {
      const keMatch = p.trim().match(/^KE(\d+)_(.+)$/i)
      if (keMatch) result.akes.push({ num: keMatch[1], alg: keMatch[2] })
      else result.akes.push({ num: String(result.akes.length + 1), alg: p.trim() })
    } else if (includePrf && (upper.startsWith('PRF_') || upper.startsWith('PRF-'))) {
      result.prf = p.trim()
    } else if (upper.startsWith('HMAC_') || upper.startsWith('HMAC-')) {
      result.integrity = p.trim()
    } else if (upper.startsWith('ECP_') || upper.startsWith('MODP_') || upper.startsWith('CURVE') || upper.startsWith('X25519') || upper.startsWith('X448')) {
      result.dh_group = p.trim()
    } else if (result.encryption === 'NONE') {
      result.encryption = p.trim()
    }
  })
  return result
}

export function applyFilters(tunnels?: TunnelData[]) {
  const s = store()
  const all = tunnels || s.tunnels
  const q = s.searchQuery.toLowerCase()
  const pf = s.paramFilters
  const sf = s.statusFilter

  let filtered = all.filter((t) => {
    // Status filter
    if (sf) {
      const status = tunnelStatusCategory(t)
      if (sf !== status) return false
    }

    // Param filters (parsed from crypto strings)
    const hasParamFilters = Object.values(pf).some((arr) => arr.length > 0)
    if (hasParamFilters) {
      const ikeP = parseCryptoParams(t.ike_crypto, true)
      const ipsecP = parseCryptoParams(t.ipsec_crypto, false)
      if (pf.encryption.length && !pf.encryption.some((v) =>
        (ikeP?.encryption || '').toUpperCase().includes(v.toUpperCase()) ||
        (ipsecP?.encryption || '').toUpperCase().includes(v.toUpperCase())
      )) return false
      if (pf.integrity.length && !pf.integrity.some((v) =>
        (ikeP?.integrity || '').toUpperCase().includes(v.toUpperCase()) ||
        (ipsecP?.integrity || '').toUpperCase().includes(v.toUpperCase())
      )) return false
      if (pf.prf.length && !pf.prf.some((v) =>
        (ikeP?.prf || '').toUpperCase().includes(v.toUpperCase())
      )) return false
      if (pf.dh_group.length && !pf.dh_group.some((v) =>
        (ikeP?.dh_group || '').toUpperCase().includes(v.toUpperCase()) ||
        (ipsecP?.dh_group || '').toUpperCase().includes(v.toUpperCase())
      )) return false
      if (pf.ake.length) {
        const allAkes = [...(ikeP?.akes || []), ...(ipsecP?.akes || [])].map(a => a.alg.toUpperCase())
        if (!pf.ake.some((v) => allAkes.some(a => a.includes(v.toUpperCase())))) return false
      }
    }

    // Text search across all fields including parsed crypto
    if (q) {
      const ikeP = parseCryptoParams(t.ike_crypto, true)
      const ipsecP = parseCryptoParams(t.ipsec_crypto, false)
      const searchFields = [
        t.name || '', t.local_addr || '', t.remote_addr || '', t.local_name || '', t.remote_name || '',
        t.ike_state || '', t.ipsec_state || '', t.is_inactive ? 'inactive' : '',
        t.ike_crypto || '', t.ipsec_crypto || '',
        ikeP?.encryption || '', ikeP?.integrity || '', ikeP?.prf || '', ikeP?.dh_group || '',
        ikeP?.akes.map(a => a.alg).join(' ') || '',
        ipsecP?.encryption || '', ipsecP?.integrity || '', ipsecP?.dh_group || '',
        ipsecP?.akes.map(a => a.alg).join(' ') || '',
      ].join(' ').toLowerCase()
      if (!searchFields.includes(q)) return false
    }
    return true
  })

  s.setFilteredTunnels(filtered)
}

export function tunnelStatusCategory(t: TunnelData): 'active' | 'inactive' | 'nodata' {
  if (t.is_inactive) return 'inactive'
  const ikeState = (t.ike_state || '').toUpperCase()
  const ipsecState = (t.ipsec_state || '').toUpperCase()
  // Active: IKE ESTABLISHED and IPsec INSTALLED
  if (ikeState === 'ESTABLISHED' && ipsecState === 'INSTALLED') return 'active'
  // Pending/transitional states → still active-ish
  if (['CONNECTING', 'REKEYING', 'REAUTHENTICATING'].includes(ikeState) ||
      ['REKEYING', 'ROUTED', 'CREATED', 'INSTALLING', 'UPDATING'].includes(ipsecState)) return 'active'
  // Failed/error states
  if (['DESTROYING', 'DELETING', 'FAILED'].includes(ikeState) ||
      ['DELETING', 'DESTROYING', 'FAILED'].includes(ipsecState)) return 'inactive'
  // No active data
  return 'nodata'
}

// ── CSC-specific APIs ──

export async function cscCheckInstallStatus() {
  try {
    const data = await json(await fetch('/api/csc/install/status', { credentials: 'include' }))
    return data
  } catch { return { success: false } }
}

export async function cscInstallDocker() {
  try {
    const data = await json(await fetch('/api/csc/install-docker', { method: 'POST', credentials: 'include' }))
    return data
  } catch { return { success: false } }
}

export async function cscDeleteImage(imageTag: string) {
  const s = store()
  try {
    const data = await json(await fetch('/api/csc/image/delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ image: imageTag }),
    }))
    if (data.success) s.notify('Image deleted', 'success')
    else s.notify(data.message || 'Delete failed', 'error')
    return data
  } catch (err) {
    s.notify(err instanceof Error ? err.message : 'Delete failed', 'error')
    return { success: false }
  }
}

export async function cscDeploy(params: {
  headend: string; connection_type: string; enable_dtls: boolean; enable_pqc: boolean;
  vpn_group: string; vpn_user: string; vpn_password: string;
  vpn_user_increment: boolean; vpn_password_increment: boolean;
  local_ipv4_start?: string; ipv4_increment_octet?: number;
  local_ipv6_start?: string; ipv6_increment_hextet?: number;
  count: number; protocol: string; image_tag?: string; allow_untrusted_cert?: boolean;
}) {
  try {
    const data = await json(await fetch('/api/csc/deploy', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify(params),
    }))
    return data
  } catch { return { success: false } }
}

export async function cscContainerAction(action: 'stop-all' | 'restart-all' | 'delete-all', protocol?: string) {
  try {
    const body: Record<string, string> = {}
    if (protocol) body.protocol = protocol
    const data = await json(await fetch(`/api/csc/containers/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify(body),
    }))
    return data
  } catch { return { success: false } }
}

export async function cscSingleContainerAction(action: 'stop' | 'restart', containerId: string) {
  try {
    const data = await json(await fetch(`/api/csc/containers/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ container_id: containerId }),
    }))
    return data
  } catch { return { success: false } }
}

export async function cscGetContainerLogs(containerId: string): Promise<string> {
  try {
    const data = await json(await fetch(`/api/csc/containers/${encodeURIComponent(containerId)}/logs`, { credentials: 'include' }))
    return data.logs || 'No logs available.'
  } catch { return 'Failed to fetch logs.' }
}

export async function cscGetContainers() {
  try {
    const data = await json(await fetch('/api/csc/containers', { credentials: 'include' }))
    return data
  } catch { return { success: false, containers: [] } }
}

export async function cscGetResources() {
  try {
    const data = await json(await fetch('/api/csc/resources', { credentials: 'include' }))
    return data
  } catch { return { success: false } }
}

export async function cscGetContainerConfig(containerId: string) {
  try {
    const data = await json(await fetch(`/api/csc/container-config?container_id=${encodeURIComponent(containerId)}`, { credentials: 'include' }))
    return data
  } catch { return { success: false } }
}

export async function cscGetBuildLogs() {
  try {
    const data = await json(await fetch('/api/csc/install/status', { credentials: 'include' }))
    return data.build_log || ''
  } catch { return '' }
}

export async function cscGetBuildProgress(): Promise<{ percent: number; label: string; active: boolean }> {
  try {
    const data = await json(await fetch('/api/progress', { credentials: 'include' }))
    return { percent: data.percent || 0, label: data.label || '', active: !!data.active }
  } catch { return { percent: 0, label: '', active: false } }
}

export async function cscGetBuildLogsLive(): Promise<string> {
  try {
    const data = await json(await fetch('/api/logs', { credentials: 'include' }))
    return data.logs || ''
  } catch { return '' }
}

export async function cscDeleteConfigFile(filename: string) {
  const s = store()
  try {
    const data = await json(await fetch('/api/csc/config-file/delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'include', body: JSON.stringify({ filename }),
    }))
    if (data.success) {
      s.notify(`${filename} deleted`, 'success')
      fetchConfigFiles()
    } else {
      s.notify(data.message || 'Delete failed', 'error')
    }
    return data
  } catch { return { success: false } }
}

export async function cscBuildImage(opts: {
  allow_untrusted: boolean
  http_proxy?: string
  https_proxy?: string
  no_proxy?: string
}) {
  try {
    const data = await json(await fetch('/api/csc/install', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(opts),
    }))
    return data
  } catch (err) {
    return { success: false, message: err instanceof Error ? err.message : 'Build failed' }
  }
}
