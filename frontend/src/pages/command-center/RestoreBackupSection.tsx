import { useState } from 'react'
import { useCommandCenterStore } from '@/stores/commandCenterStore'
import { runStream } from './useStream'
import SectionCard from './SectionCard'
import { InputField, ActionBtn } from './HttpProxySection'
import { Play } from 'lucide-react'

export default function RestoreBackupSection() {
  const selectedIds = useCommandCenterStore((s) => s.selectedIds)
  const isExecuting = useCommandCenterStore((s) => s.isExecuting)

  const [baseUrl, setBaseUrl] = useState('')
  const [doRestore, setDoRestore] = useState(true)

  const execute = async () => {
    if (!baseUrl || !/^https?:\/\//i.test(baseUrl)) {
      alert('Enter a valid Base URL starting with http:// or https://')
      return
    }
    const ids = Array.from(selectedIds)
    if (ids.length === 0) { alert('Select at least one device'); return }
    await runStream('/api/command-center/restore-backup/stream', {
      device_ids: ids,
      base_url: baseUrl,
      do_restore: doRestore,
    })
  }

  return (
    <SectionCard
      title="Restore Device Backup"
      badge="FTD Only"
      badgeColor="green"
      actions={
        <ActionBtn icon={<Play className="w-3.5 h-3.5" />} label="Execute" onClick={execute} primary disabled={isExecuting} />
      }
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="md:col-span-2">
          <InputField label="Base URL for backups" value={baseUrl} onChange={setBaseUrl} placeholder="http://server/path/to/remote-backups/" />
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-[12px] text-surface-600 dark:text-surface-400 cursor-pointer select-none pb-1">
            <input type="checkbox" checked={doRestore} onChange={(e) => setDoRestore(e.target.checked)} className="rounded border-surface-300 dark:border-surface-600 text-vyper-500 focus:ring-vyper-500/30 w-3.5 h-3.5" />
            Also trigger restore after download
          </label>
        </div>
      </div>
      <p className="text-[11px] text-surface-400 mt-2">
        Connects to selected FTD devices, downloads the matching .tar backup from the Base URL, and optionally runs the restore command.
      </p>
    </SectionCard>
  )
}
