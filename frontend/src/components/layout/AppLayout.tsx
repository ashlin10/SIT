import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import AiChatPanel from '@/components/AiChatPanel'

export default function AppLayout() {
  return (
    <div className="flex h-screen overflow-hidden bg-surface-50 dark:bg-surface-950">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="p-6 max-w-[1400px] mx-auto">
          <Outlet />
        </div>
      </main>
      <AiChatPanel />
    </div>
  )
}
