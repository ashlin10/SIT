import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from '@/pages/LoginPage'
import DashboardPage from '@/pages/DashboardPage'
import SettingsPage from '@/pages/SettingsPage'
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
          {/* Placeholder routes — will be built in subsequent steps */}
          <Route path="/fmc-configuration" element={<PlaceholderPage title="FMC Configuration" />} />
          <Route path="/command-center" element={<PlaceholderPage title="Command Center" />} />
          <Route path="/vpn-debugger" element={<PlaceholderPage title="VPN Debugger" />} />
        </Route>

        <Route path="/" element={<Navigate to="/fmc-configuration" replace />} />
        <Route path="*" element={<Navigate to="/fmc-configuration" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="space-y-2">
      <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">{title}</h1>
      <p className="text-sm text-surface-500">Coming soon — React redesign in progress</p>
    </div>
  )
}
