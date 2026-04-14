import { useState } from 'react'
import { useCommandCenterStore } from '@/stores/commandCenterStore'
import { runStream } from './useStream'
import SectionCard from './SectionCard'
import { InputField, ActionBtn } from './HttpProxySection'
import { Play } from 'lucide-react'
import CustomSelect from '@/components/CustomSelect'

const MODELS = ['1000', '1200', '3100', '4100', '4200', 'FMC']

export default function DownloadUpgradeSection() {
  const selectedIds = useCommandCenterStore((s) => s.selectedIds)
  const isExecuting = useCommandCenterStore((s) => s.isExecuting)

  const [branch, setBranch] = useState('Release')
  const [version, setVersion] = useState('')
  const [selectedModels, setSelectedModels] = useState<Set<string>>(new Set())

  const toggleModel = (m: string) => {
    setSelectedModels((prev) => {
      const next = new Set(prev)
      if (next.has(m)) next.delete(m)
      else next.add(m)
      return next
    })
  }

  const execute = async () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) { alert('Select at least one device (FMC)'); return }
    if (!version.trim()) { alert('Enter Version'); return }
    const models = Array.from(selectedModels)
    if (models.length === 0) { alert('Select at least one Model'); return }
    await runStream('/api/command-center/download-upgrade/stream', {
      device_ids: ids,
      branch,
      version: version.trim(),
      models,
    })
  }

  return (
    <SectionCard
      title="Download Upgrade Package"
      badge="FMC Only"
      badgeColor="blue"
      actions={
        <ActionBtn icon={<Play className="w-3.5 h-3.5" />} label="Execute" onClick={execute} primary disabled={isExecuting} />
      }
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="block text-[11px] font-medium text-surface-500 mb-1">Branch</label>
          <CustomSelect
            value={branch}
            onChange={setBranch}
            options={[
              { value: 'Release', label: 'Release' },
              { value: 'Development', label: 'Development' },
            ]}
          />
        </div>
        <InputField label="Version" value={version} onChange={setVersion} placeholder="e.g. 7.6.1-291" />
        <div>
          <label className="block text-[11px] font-medium text-surface-500 mb-1">Models</label>
          <div className="grid grid-cols-3 gap-1.5">
            {MODELS.map((m) => (
              <label key={m} className="flex items-center gap-1.5 text-[12px] text-surface-600 dark:text-surface-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={selectedModels.has(m)}
                  onChange={() => toggleModel(m)}
                  className="rounded border-surface-300 dark:border-surface-600 text-vyper-500 focus:ring-vyper-500/30 w-3.5 h-3.5"
                />
                {m}
              </label>
            ))}
          </div>
        </div>
      </div>
      <p className="text-[11px] text-surface-400 mt-2">
        This action runs only on selected FMC devices.
      </p>
    </SectionCard>
  )
}
