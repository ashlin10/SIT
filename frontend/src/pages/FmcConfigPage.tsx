import { useState } from 'react'
import { cn } from '@/lib/utils'
import { Monitor, HardDrive, ShieldCheck, Bug } from 'lucide-react'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import FmcConnectionSection from './fmc-config/FmcConnectionSection'
import TerminalPanel from './fmc-config/TerminalPanel'
import DevicesSection from './fmc-config/DevicesSection'
import DeviceConfigSection from './fmc-config/DeviceConfigSection'
import ChassisConfigSection from './fmc-config/ChassisConfigSection'
import VpnSection from './fmc-config/VpnSection'
import ConfigViewerModal from './fmc-config/ConfigViewerModal'
import HaModal from './fmc-config/HaModal'
import TemplateModal from './fmc-config/TemplateModal'

type ConfigTab = 'device' | 'chassis' | 'vpn'

export default function FmcConfigPage() {
  const [haModalOpen, setHaModalOpen] = useState(false)
  const [templateOpen, setTemplateOpen] = useState(false)
  const [templateMode, setTemplateMode] = useState<'chassis' | 'device'>('chassis')
  const [activeTab, setActiveTab] = useState<ConfigTab>('device')
  const debugEnabled = useFmcConfigStore(s => s.debugEnabled)
  const setDebugEnabled = useFmcConfigStore(s => s.setDebugEnabled)

  const openTemplate = (mode: 'chassis' | 'device') => {
    setTemplateMode(mode)
    setTemplateOpen(true)
  }

  const tabs: { id: ConfigTab; label: string; icon: typeof Monitor }[] = [
    { id: 'device', label: 'Device Configuration', icon: Monitor },
    { id: 'chassis', label: 'Chassis Configuration', icon: HardDrive },
    { id: 'vpn', label: 'VPN', icon: ShieldCheck },
  ]

  return (
    <div className="space-y-5 animate-[fadeIn_0.3s_ease-out]">
      <div>
        <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 tracking-tight">
          FMC Configuration
        </h1>
        <p className="text-[13px] text-surface-500 mt-0.5">
          Connect to Firepower Management Center, manage devices, and push configuration
        </p>
      </div>

      <FmcConnectionSection />
      <TerminalPanel />
      <DevicesSection onCreateHa={() => setHaModalOpen(true)} />

      {/* Config tabs */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1 p-0.5 bg-surface-100 dark:bg-surface-800/50 rounded-lg border border-surface-200 dark:border-surface-700/60 w-fit">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={cn(
                'flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-[11px] font-medium transition-all',
                activeTab === id
                  ? 'bg-white dark:bg-surface-900 text-surface-900 dark:text-surface-100 shadow-sm border border-surface-200 dark:border-surface-700'
                  : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 border border-transparent',
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          ))}
        </div>
        <label
          className="group relative flex items-center gap-1.5 cursor-pointer select-none"
          title="When enabled, logs the full HTTP method, URL, and request payload for every API call to the terminal panel"
        >
          <input
            type="checkbox"
            checked={debugEnabled}
            onChange={e => setDebugEnabled(e.target.checked)}
            className="rounded border-surface-300 dark:border-surface-600 text-accent-amber focus:ring-accent-amber/30 w-3.5 h-3.5"
          />
          <Bug className={cn('w-3.5 h-3.5 transition-colors', debugEnabled ? 'text-accent-amber' : 'text-surface-400')} />
          <span className={cn('text-[11px] font-medium transition-colors', debugEnabled ? 'text-accent-amber' : 'text-surface-500')}>Debug</span>
        </label>
      </div>

      {activeTab === 'device' && <DeviceConfigSection onTemplate={() => openTemplate('device')} />}
      {activeTab === 'chassis' && <ChassisConfigSection onTemplate={() => openTemplate('chassis')} />}
      {activeTab === 'vpn' && <VpnSection />}

      {/* Modals */}
      <ConfigViewerModal />
      <HaModal open={haModalOpen} onClose={() => setHaModalOpen(false)} />
      <TemplateModal open={templateOpen} onClose={() => setTemplateOpen(false)} mode={templateMode} />
    </div>
  )
}
