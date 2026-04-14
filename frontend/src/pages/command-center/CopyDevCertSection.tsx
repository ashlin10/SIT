import { useCommandCenterStore } from '@/stores/commandCenterStore'
import { runStream } from './useStream'
import SectionCard from './SectionCard'
import { ActionBtn } from './HttpProxySection'
import { Play } from 'lucide-react'

export default function CopyDevCertSection() {
  const selectedIds = useCommandCenterStore((s) => s.selectedIds)
  const isExecuting = useCommandCenterStore((s) => s.isExecuting)

  const execute = async () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) { alert('Select at least one device'); return }
    await runStream('/api/command-center/execute-copy-dev-crt/stream', { device_ids: ids })
  }

  return (
    <SectionCard
      title="Copy Dev Certificate"
      badge="FTD and FMC"
      badgeColor="yellow"
      actions={
        <ActionBtn icon={<Play className="w-3.5 h-3.5" />} label="Execute" onClick={execute} primary disabled={isExecuting} />
      }
    >
      <p className="text-[12px] text-surface-500">
        Copies development certificate to selected FTD and FMC devices.
      </p>
    </SectionCard>
  )
}
