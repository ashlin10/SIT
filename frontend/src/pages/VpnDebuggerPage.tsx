import { useEffect, useCallback } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { refreshTunnels, applyFilters } from './vpn-debugger/api'
import VpnPeersSection from './vpn-debugger/VpnPeersSection'
import TunnelTrafficSection from './vpn-debugger/TunnelTrafficSection'
import TroubleshootingSection from './vpn-debugger/TroubleshootingSection'
import TunnelSummarySection from './vpn-debugger/TunnelSummarySection'
import FileViewerModal from './vpn-debugger/FileViewerModal'
import ReportViewerModal from './vpn-debugger/ReportViewerModal'
import Notification from './vpn-debugger/Notification'

export default function VpnDebuggerPage() {
  const { localConnected, refreshInterval, searchQuery, paramFilters, statusFilter } = useVpnDebuggerStore()

  // Auto-refresh tunnels
  useEffect(() => {
    if (!localConnected || refreshInterval <= 0) return
    const timer = setInterval(() => { refreshTunnels() }, refreshInterval * 1000)
    return () => clearInterval(timer)
  }, [localConnected, refreshInterval])

  // Re-apply filters when search/filter criteria change
  const doFilter = useCallback(() => { applyFilters() }, [])
  useEffect(() => { doFilter() }, [searchQuery, paramFilters, statusFilter, doFilter])

  return (
    <div className="space-y-5 animate-[fadeIn_0.3s_ease-out]">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">
          VPN Debugger
        </h1>
        <p className="text-sm text-surface-500 mt-0.5">
          strongSwan &amp; Cisco Secure Client tunnel management
        </p>
      </div>

      <VpnPeersSection />
      <TunnelTrafficSection />
      <TroubleshootingSection />
      <TunnelSummarySection />

      {/* Modals */}
      <FileViewerModal />
      <ReportViewerModal />
      <Notification />

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  )
}
