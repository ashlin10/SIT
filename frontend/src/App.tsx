import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from '@/pages/LoginPage'
import DashboardPage from '@/pages/DashboardPage'
import SettingsPage from '@/pages/SettingsPage'
import CommandCenterPage from '@/pages/CommandCenterPage'
import FmcConfigPage from '@/pages/FmcConfigPage'
import VpnDebuggerPage from '@/pages/VpnDebuggerPage'
import AppLayout from '@/components/layout/AppLayout'
import ProtectedRoute from '@/components/ProtectedRoute'

function Protected({ children }: { children: React.ReactNode }) {
  return <ProtectedRoute>{children}</ProtectedRoute>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />

        {/* Authenticated routes with sidebar layout */}
        <Route element={<Protected><AppLayout /></Protected>}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/fmc-configuration" element={<FmcConfigPage />} />
          <Route path="/command-center" element={<CommandCenterPage />} />
          <Route path="/vpn-debugger" element={<VpnDebuggerPage />} />
        </Route>

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

