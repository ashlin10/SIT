import { useState } from 'react'
import FmcConnectionSection from './fmc-config/FmcConnectionSection'
import TerminalPanel from './fmc-config/TerminalPanel'
import DevicesSection from './fmc-config/DevicesSection'
import DeviceConfigSection from './fmc-config/DeviceConfigSection'
import ChassisConfigSection from './fmc-config/ChassisConfigSection'
import VpnSection from './fmc-config/VpnSection'
import ConfigViewerModal from './fmc-config/ConfigViewerModal'
import HaModal from './fmc-config/HaModal'
import TemplateModal from './fmc-config/TemplateModal'

export default function FmcConfigPage() {
  const [haModalOpen, setHaModalOpen] = useState(false)
  const [templateOpen, setTemplateOpen] = useState(false)
  const [templateMode, setTemplateMode] = useState<'chassis' | 'device'>('chassis')

  const openTemplate = (mode: 'chassis' | 'device') => {
    setTemplateMode(mode)
    setTemplateOpen(true)
  }

  return (
    <div className="space-y-5 animate-in fade-in duration-300">
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
      <ChassisConfigSection onTemplate={() => openTemplate('chassis')} />
      <DeviceConfigSection onTemplate={() => openTemplate('device')} />
      <VpnSection />

      {/* Modals */}
      <ConfigViewerModal />
      <HaModal open={haModalOpen} onClose={() => setHaModalOpen(false)} />
      <TemplateModal open={templateOpen} onClose={() => setTemplateOpen(false)} mode={templateMode} />
    </div>
  )
}
