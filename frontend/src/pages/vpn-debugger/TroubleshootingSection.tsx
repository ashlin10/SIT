import { useState, useEffect } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn, btnCls, inputCls, selectCls } from '@/lib/utils'
import {
  Plug, CircleDot, Play, Square, Eye, Download, Loader2,
} from 'lucide-react'
import {
  fetchSyslogFiles, fetchMonitoringStatus,
  startMonitoring, stopMonitoring, downloadReport,
  connectToServer,
} from './api'
import SectionCard from './SectionCard'
import ConnectPopup from './ConnectPopup'

export default function TroubleshootingSection() {
  const store = useVpnDebuggerStore()
  const {
    localConnected, troubleshootConnected,
    monitoringStatus, monitoringPid, disconnectCount,
    monitorInterval, monitorLeeway,
    localLogFiles, remoteLogFiles, selectedLocalLog, selectedRemoteLog,
    setMonitorInterval, setMonitorLeeway, setSelectedLocalLog, setSelectedRemoteLog,
    setTroubleshootConnected,
    tsConnPopupOpen, tsConn, openTsConnPopup, closeTsConnPopup, setTsConn,
  } = store

  const [sameAsLocal, setSameAsLocal] = useState(true)
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)

  const connected = sameAsLocal ? localConnected : troubleshootConnected

  // Fetch syslog file lists when connected
  useEffect(() => {
    if (!connected) return
    fetchSyslogFiles()
  }, [connected])

  // Poll monitoring status only while monitoring is active
  useEffect(() => {
    if (!connected || monitoringStatus !== 'running') return
    const t = setInterval(() => fetchMonitoringStatus(), 30000)
    return () => clearInterval(t)
  }, [connected, monitoringStatus])

  const canStartMonitoring = connected && !starting && !!selectedLocalLog

  const handleStart = async () => {
    setStarting(true)
    await startMonitoring(selectedLocalLog, selectedRemoteLog, monitorInterval, monitorLeeway)
    setStarting(false)
  }

  const handleStop = async () => {
    setStopping(true)
    await stopMonitoring()
    setStopping(false)
  }

  const handleViewReport = async () => {
    setReportLoading(true)
    const content = await downloadReport()
    setReportLoading(false)
    if (content) {
      store.openFileViewer(
        'Tunnel Disconnect Report',
        content,
        false,
        'tunnel-disconnect-syslog.log',
        'local',
        'config'
      )
    } else {
      store.notify('No report data available', 'warning')
    }
  }

  const handleDownloadReport = async () => {
    const content = await downloadReport()
    if (!content) {
      store.notify('No report data available', 'warning')
      return
    }
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `tunnel-disconnect-report-${new Date().toISOString().slice(0, 10)}.log`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleTsConnect = async () => {
    await connectToServer(tsConn)
    setTroubleshootConnected(true)
    closeTsConnPopup()
  }

  return (
    <>
      <SectionCard
        title="Troubleshooting"
        headerRight={
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-[10px] text-surface-500 cursor-pointer">
              <input type="checkbox" checked={sameAsLocal} onChange={(e) => setSameAsLocal(e.target.checked)} className="w-3 h-3 rounded border-surface-300 text-vyper-600" />
              Same as Local Node
            </label>
            {!sameAsLocal && (
              <button onClick={openTsConnPopup} className="p-1 text-vyper-600 hover:text-vyper-700 transition-colors" title="Connect">
                <Plug className="w-3.5 h-3.5" />
              </button>
            )}
            <span className={cn(
              'inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full',
              connected ? 'bg-accent-emerald/10 text-accent-emerald' : 'bg-surface-100 dark:bg-surface-800 text-surface-500'
            )}>
              <CircleDot className="w-2.5 h-2.5" />
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        }
      >
        <div className="space-y-4">
          {/* Monitoring Options */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Monitoring Interval</label>
              <div className="flex items-center gap-1.5">
                <input
                  type="number"
                  value={monitorInterval}
                  onChange={(e) => setMonitorInterval(e.target.value === '' ? 0 : parseInt(e.target.value))}
                  onBlur={(e) => { if (!e.target.value || parseInt(e.target.value) < 1) setMonitorInterval(1) }}
                  min={1} max={60}
                  className={cn(inputCls, 'w-16')}
                />
                <span className="text-[10px] text-surface-400">minutes</span>
              </div>
            </div>
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Log Leeway Interval</label>
              <div className="flex items-center gap-1.5">
                <input
                  type="number"
                  value={monitorLeeway}
                  onChange={(e) => setMonitorLeeway(e.target.value === '' ? 0 : parseInt(e.target.value))}
                  onBlur={(e) => { if (!e.target.value || parseInt(e.target.value) < 1) setMonitorLeeway(1) }}
                  min={1} max={120}
                  className={cn(inputCls, 'w-16')}
                />
                <span className="text-[10px] text-surface-400">seconds</span>
              </div>
            </div>
          </div>

          {/* Log dropdowns */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Local Logs</label>
              <select
                value={selectedLocalLog}
                onChange={(e) => setSelectedLocalLog(e.target.value)}
                disabled={!connected || localLogFiles.length === 0}
                className={cn(selectCls, 'w-full')}
              >
                <option value="">{connected ? 'Select log...' : 'Connect to server first'}</option>
                {localLogFiles.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-medium text-surface-500 mb-1">Remote Logs</label>
              <select
                value={selectedRemoteLog}
                onChange={(e) => setSelectedRemoteLog(e.target.value)}
                disabled={!connected || remoteLogFiles.length === 0}
                className={cn(selectCls, 'w-full')}
              >
                <option value="">{connected ? 'Select log...' : 'Connect to server first'}</option>
                {remoteLogFiles.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
          </div>

          {/* Monitoring Actions */}
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              {monitoringStatus !== 'running' ? (
                <button onClick={handleStart} disabled={!canStartMonitoring} className={btnCls('primary')}>
                  {starting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  Start Monitoring
                </button>
              ) : (
                <button onClick={handleStop} disabled={stopping} className={btnCls('danger')}>
                  {stopping ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Square className="w-3.5 h-3.5" />}
                  Stop Monitoring
                </button>
              )}
            </div>
            <div className="flex items-center gap-2">
              <span className={cn(
                'inline-flex items-center justify-center min-w-[24px] h-6 px-1.5 rounded-full text-[11px] font-bold',
                disconnectCount > 0 ? 'bg-red-500/10 text-red-500' : 'bg-surface-100 dark:bg-surface-800 text-surface-400',
              )} title="Disconnect count">
                {disconnectCount}
              </span>
              <button onClick={handleViewReport} disabled={!connected || reportLoading} className={btnCls()}>
                {reportLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />} View Report
              </button>
              <button onClick={handleDownloadReport} disabled={!connected} className={btnCls()}>
                <Download className="w-3.5 h-3.5" /> Download
              </button>
            </div>
          </div>

          {/* Monitoring Status Bar */}
          {monitoringStatus === 'running' && (
            <div className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl border border-accent-emerald/20 bg-accent-emerald/5">
              <span className="w-2 h-2 rounded-full bg-accent-emerald animate-pulse" />
              <span className="text-xs font-medium text-accent-emerald">Monitoring active</span>
              {monitoringPid && <span className="text-[10px] font-mono text-accent-emerald/60 ml-auto">PID: {monitoringPid}</span>}
            </div>
          )}
        </div>
      </SectionCard>

      {tsConnPopupOpen && (
        <ConnectPopup
          title="Connect to Troubleshooting Server"
          conn={tsConn}
          setConn={setTsConn}
          onConnect={handleTsConnect}
          onClose={closeTsConnPopup}
        />
      )}
    </>
  )
}
