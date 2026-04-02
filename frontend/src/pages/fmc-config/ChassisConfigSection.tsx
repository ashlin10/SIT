import { useRef, useState, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { uploadChassisConfig, getChassisConfig, applyChassisConfig } from './api'
import {
  Upload, Download, FileCode, Send, Layers,
  ChevronDown, ChevronUp,
} from 'lucide-react'

// Chassis config groups
interface ChassisItem { key: string; label: string; dataPath?: string }
interface ChassisGroup { id: string; label: string; items: ChassisItem[] }

const CHASSIS_GROUPS: ChassisGroup[] = [
  {
    id: 'chassis-interfaces',
    label: 'Chassis Interfaces',
    items: [
      { key: 'chassis_interfaces.physicalinterfaces', label: 'Physical Interfaces', dataPath: 'chassis_interfaces.physicalinterfaces' },
      { key: 'chassis_interfaces.etherchannelinterfaces', label: 'EtherChannel Interfaces', dataPath: 'chassis_interfaces.etherchannelinterfaces' },
      { key: 'chassis_interfaces.subinterfaces', label: 'Subinterfaces', dataPath: 'chassis_interfaces.subinterfaces' },
    ],
  },
  {
    id: 'chassis-logicaldevices',
    label: 'Logical Devices',
    items: [], // dynamically populated from config
  },
]

// ── Hover card helpers ──

function tryGetChassis(obj: unknown, path: string): unknown {
  try {
    const segs = path.split('.')
    let cur: unknown = obj
    for (const s of segs) { if (cur == null || typeof cur !== 'object') return undefined; cur = (cur as Record<string, unknown>)[s] }
    return cur
  } catch { return undefined }
}

function chassisNamesFromConfig(config: Record<string, unknown> | null, dataPath: string): string[] {
  if (!config) return []
  const val = tryGetChassis(config, dataPath)
  if (Array.isArray(val)) {
    let names = val.map((it) => {
      if (typeof it === 'string') return it
      if (!it || typeof it !== 'object') return ''
      const o = it as Record<string, unknown>
      return String(o.name || o.interfaceName || o.ifname || o.id || '')
    }).filter(Boolean)
    if (names.length === 0 && val.length > 0) names = val.slice(0, 50).map((_, i) => `Item ${i + 1}`)
    return names.slice(0, 50)
  }
  // Single object (e.g. a logical device) - show key/value pairs
  if (val && typeof val === 'object') {
    return Object.entries(val as Record<string, unknown>).slice(0, 50).map(([k, v]) => {
      if (Array.isArray(v)) return `${k}: [${v.length} items]`
      if (v && typeof v === 'object') return `${k}: {${Object.keys(v as object).length} keys}`
      return `${k}: ${String(v ?? '')}`
    })
  }
  return []
}

export default function ChassisConfigSection({ onTemplate }: { onTemplate?: () => void }) {
  const {
    chassisConfig, chassisConfigFilename, chassisConfigYaml, chassisCounts, chassisCheckboxes,
    selectedDeviceIds, isOperationRunning,
    setChassisCheckbox, openViewer, setChassisConfigYaml,
  } = useFmcConfigStore()

  const fileRef = useRef<HTMLInputElement>(null)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})
  const [adminPassword, setAdminPassword] = useState('Cisco@12')

  const hasConfig = !!chassisConfig && Object.keys(chassisCounts).length > 0

  const handleUpload = async (file: File) => {
    const result = await uploadChassisConfig(file)
    if (!result.success) alert(result.message || 'Upload failed')
  }

  const handleGetConfig = async () => {
    const ids = Array.from(selectedDeviceIds)
    if (ids.length !== 1) { alert('Select exactly one device for Get Config'); return }
    const result = await getChassisConfig(ids)
    if (!result.success) alert(result.message || 'Get Config failed')
  }

  const handleApply = async () => {
    if (!chassisConfig) { alert('Upload a chassis config first'); return }
    const result = await applyChassisConfig(chassisCheckboxes, adminPassword)
    if (!result.success) alert(result.message || 'Apply failed')
  }

  const toggle = (id: string) => setCollapsed((c) => ({ ...c, [id]: !c[id] }))

  const allKeys = Object.keys(chassisCheckboxes)
  const allChecked = allKeys.length > 0 && allKeys.every((k) => chassisCheckboxes[k])

  const toggleAll = (v: boolean) => allKeys.forEach((k) => setChassisCheckbox(k, v))

  const inputCls = cn(
    'rounded-lg border px-3 py-2 text-sm',
    'border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800/50',
    'text-surface-800 dark:text-surface-200 placeholder:text-surface-400',
    'focus:outline-none focus:ring-2 focus:ring-vyper-500/30 focus:border-vyper-500',
    'transition-colors'
  )

  const btnCls = (variant: 'primary' | 'secondary' = 'secondary') =>
    cn(
      'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
      variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
      variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
    )

  // Build dynamic logical device items from counts
  const dynamicLogicalItems: ChassisItem[] = Object.keys(chassisCounts)
    .filter((k) => k.startsWith('logical_devices.'))
    .map((k) => {
      const ldName = k.replace('logical_devices.', '')
      // Find index of this LD in the config array for dataPath
      const ldArray = (chassisConfig as any)?.logical_devices as any[] | undefined
      const ldIdx = ldArray?.findIndex((ld: any) => (ld?.name || ld?.baseName) === ldName) ?? -1
      return {
        key: k,
        label: ldName.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
        dataPath: ldIdx >= 0 ? `logical_devices.${ldIdx}` : undefined,
      }
    })

  return (
    <div className={cn(
      'rounded-xl border border-surface-200 dark:border-surface-800/60',
      'bg-white dark:bg-surface-900/50 overflow-hidden'
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-medium text-surface-800 dark:text-surface-200">Chassis Configuration</h2>
          {chassisConfigFilename && (
            <button
              onClick={() => openViewer(`Chassis — ${chassisConfigFilename}`, chassisConfigYaml, setChassisConfigYaml)}
              className="text-[10px] font-medium text-accent-violet bg-accent-violet/10 border border-accent-violet/20 rounded-full px-2.5 py-0.5 hover:bg-accent-violet/20 transition-colors cursor-pointer"
            >
              <FileCode className="w-3 h-3 inline mr-1" />
              {chassisConfigFilename}
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => onTemplate?.()} className={btnCls()}>
            <Layers className="w-3.5 h-3.5" /> Template
          </button>
          <button onClick={handleGetConfig} disabled={isOperationRunning} className={cn(btnCls(), isOperationRunning && 'opacity-40 pointer-events-none')}>
            <Download className="w-3.5 h-3.5" /> Get Config
          </button>
          <button onClick={() => fileRef.current?.click()} className={btnCls()}>
            <Upload className="w-3.5 h-3.5" /> Upload
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".yaml,.yml"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) handleUpload(f)
              e.target.value = ''
            }}
          />
        </div>
      </div>

      <div className="px-5 py-4 space-y-4">
        <p className="text-[11px] text-surface-400">
          Upload a chassis YAML to preview configuration types and counts. Then choose which types to apply and click Push Config.
        </p>

        {/* Management Bootstrap */}
        <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3">
          <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300 block mb-2">Management Bootstrap</span>
          <div>
            <label className="block text-[10px] font-medium text-surface-500 mb-1">Admin Password</label>
            <input
              type="text"
              value={adminPassword}
              onChange={(e) => setAdminPassword(e.target.value)}
              placeholder="adminPassword"
              className={cn(inputCls, 'w-48 py-1 text-xs')}
            />
          </div>
        </div>

        {/* Select All */}
        {hasConfig && (
          <label className="flex items-center gap-2 text-[11px] font-medium text-surface-600 dark:text-surface-400">
            <input
              type="checkbox"
              checked={allChecked}
              onChange={(e) => toggleAll(e.target.checked)}
              className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
            />
            Select All
          </label>
        )}

        {/* Groups */}
        {hasConfig && (
          <div className="space-y-3">
            {/* Chassis Interfaces */}
            <ChassisGroupPanel
              group={CHASSIS_GROUPS[0]}
              counts={chassisCounts}
              checkboxes={chassisCheckboxes}
              onCheckbox={setChassisCheckbox}
              isOpen={!collapsed['chassis-interfaces']}
              onToggle={() => toggle('chassis-interfaces')}
              config={chassisConfig}
            />

            {/* Logical Devices */}
            <ChassisGroupPanel
              group={{ ...CHASSIS_GROUPS[1], items: dynamicLogicalItems }}
              counts={chassisCounts}
              checkboxes={chassisCheckboxes}
              onCheckbox={setChassisCheckbox}
              isOpen={!collapsed['chassis-logicaldevices']}
              onToggle={() => toggle('chassis-logicaldevices')}
              config={chassisConfig}
            />

            {/* Push Config button */}
            <div className="pt-2">
              <button onClick={handleApply} disabled={isOperationRunning} className={cn(btnCls('primary'), isOperationRunning && 'opacity-40 pointer-events-none')}>
                <Send className="w-3.5 h-3.5" /> Push Config
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function ChassisGroupPanel({
  group, counts, checkboxes, onCheckbox, isOpen, onToggle, config,
}: {
  group: { id: string; label: string; items: ChassisItem[] }
  counts: Record<string, number>
  checkboxes: Record<string, boolean>
  onCheckbox: (key: string, value: boolean) => void
  isOpen: boolean
  onToggle: () => void
  config: Record<string, unknown> | null
}) {
  const groupAllChecked = group.items.length > 0 && group.items.every((i) => checkboxes[i.key])

  return (
    <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-surface-50 dark:bg-surface-800/50">
        <div className="flex items-center gap-2">
          <button onClick={onToggle} className="p-0.5 text-surface-400 hover:text-surface-600 transition-colors">
            {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          <label className="flex items-center gap-2 text-[11px] font-medium text-surface-700 dark:text-surface-300">
            <input
              type="checkbox"
              checked={groupAllChecked}
              onChange={(e) => group.items.forEach((i) => onCheckbox(i.key, e.target.checked))}
              className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
            />
            {group.label}
          </label>
        </div>
      </div>
      {isOpen && (
        <div className="p-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {group.items.length === 0 ? (
            <p className="text-[10px] text-surface-400">No items loaded</p>
          ) : (
            group.items.map((item) => (
              <ChassisCheckboxItem
                key={item.key}
                item={item}
                count={counts[item.key]}
                checked={!!checkboxes[item.key]}
                onChange={(v) => onCheckbox(item.key, v)}
                config={config}
              />
            ))
          )}
        </div>
      )}
    </div>
  )
}

function ChassisCheckboxItem({
  item, count, checked, onChange, config,
}: {
  item: ChassisItem
  count?: number
  checked: boolean
  onChange: (v: boolean) => void
  config: Record<string, unknown> | null
}) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const names = item.dataPath && config && pos ? chassisNamesFromConfig(config, item.dataPath) : []

  const show = useCallback((e: React.MouseEvent) => {
    if (!item.dataPath) return
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null }
    setPos({ x: e.clientX + 12, y: e.clientY + 12 })
  }, [item.dataPath])
  const scheduleHide = useCallback(() => {
    hideTimer.current = setTimeout(() => setPos(null), 250)
  }, [])
  const cancelHide = useCallback(() => {
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null }
  }, [])

  return (
    <label className="flex items-center gap-2 text-[11px] text-surface-600 dark:text-surface-400 cursor-pointer hover:text-surface-800 dark:hover:text-surface-200 transition-colors">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
      />
      <span
        className={item.dataPath ? 'underline decoration-dotted underline-offset-2 cursor-default' : ''}
        onMouseEnter={show}
        onMouseLeave={scheduleHide}
      >
        {item.label}
      </span>
      {(count ?? 0) > 0 && (
        <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-surface-100 dark:bg-surface-800 text-surface-500">
          {count}
        </span>
      )}
      {pos && (
        <div
          className="fixed min-w-44 max-w-80 bg-gray-900 text-gray-50 rounded-lg shadow-xl px-3 py-2 text-[11px]"
          style={{ zIndex: 9999, left: Math.min(pos.x, window.innerWidth - 320), top: Math.min(pos.y, window.innerHeight - 220) }}
          onMouseEnter={cancelHide}
          onMouseLeave={scheduleHide}
        >
          <div className="text-xs font-semibold text-blue-300 mb-1">{item.label}</div>
          <ul className="list-none m-0 p-0 max-h-48 overflow-y-auto">
            {names.length === 0
              ? <li className="text-gray-400 italic">No items loaded</li>
              : names.map((n, i) => (
                <li key={i} className="py-0.5 border-b border-white/5 last:border-0">{n}</li>
              ))
            }
          </ul>
        </div>
      )}
    </label>
  )
}
