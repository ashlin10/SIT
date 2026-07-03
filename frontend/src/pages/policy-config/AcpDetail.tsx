import { useState } from 'react'
import { cn } from '@/lib/utils'
import { type AcpDetail as AcpDetailType } from '@/stores/policyConfigStore'
import AssignedPolicyMapping from './AssignedPolicyMapping'
import { ListChecks, Layers, Settings2, ChevronRight, Code2 } from 'lucide-react'

const SETTING_LABELS: Record<string, string> = {
  ElephantFlowSettings: 'Elephant Flow',
  ShadowTrafficSetting: 'Shadow Traffic',
  EVESetting: 'Encrypted Visibility Engine (EVE)',
  LoggingSetting: 'Logging',
  AdvancedLoggingSetting: 'Advanced Logging',
  AccessPolicyDefaultAction: 'Default Action',
  AccessPolicyInheritanceSetting: 'Inheritance',
}

function humanLabel(key: string): string {
  return SETTING_LABELS[key] || key.replace(/([A-Z])/g, ' $1').replace(/^ /, '').replace(/Setting$/, '').trim()
}

const META_KEYS = new Set(['type', 'id', 'links', 'metadata', 'version'])

function SettingBody({ value }: { value: unknown }) {
  const [showRaw, setShowRaw] = useState(false)
  if (value == null) return <p className="px-3 py-1 text-[9px] text-surface-400 italic border-t border-surface-100 dark:border-surface-800">Not configured</p>

  const entries = typeof value === 'object' && !Array.isArray(value)
    ? Object.entries(value as Record<string, unknown>).filter(([k]) => !META_KEYS.has(k))
    : null

  return (
    <div className="border-t border-surface-100 dark:border-surface-800">
      {entries && entries.length > 0 ? (
        <div className="px-3 py-1.5 space-y-0.5">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[9px]">
              <span className="font-medium text-surface-600 dark:text-surface-400 min-w-[100px] shrink-0">{humanLabel(k)}</span>
              <span className="text-surface-500 break-all">{renderValue(v)}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="px-3 py-1 text-[9px] text-surface-400 italic">No configurable values</p>
      )}
      <div className="px-3 py-1 border-t border-surface-50 dark:border-surface-800/50">
        <button onClick={() => setShowRaw(!showRaw)} className="text-[8px] text-surface-400 hover:text-surface-600 flex items-center gap-1">
          <Code2 className="w-2.5 h-2.5" /> {showRaw ? 'Hide' : 'Show'} raw JSON
        </button>
        {showRaw && (
          <pre className="mt-1 text-[8px] leading-relaxed text-surface-400 overflow-auto max-h-36">
            {JSON.stringify(value, null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}

function renderValue(v: unknown): string {
  if (v === true) return 'Yes'
  if (v === false) return 'No'
  if (v == null) return '—'
  if (typeof v === 'string' || typeof v === 'number') return String(v)
  if (Array.isArray(v)) return v.length === 0 ? '(empty)' : v.map(i => typeof i === 'object' ? JSON.stringify(i) : String(i)).join(', ')
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    if (o.name) return String(o.name)
    if (o.id) return String(o.id)
    return JSON.stringify(v)
  }
  return String(v)
}

const ASSIGNED_CATS = ['prefilterPolicy', 'decryptionPolicy', 'identityPolicy']
const CATEGORY_LABELS: Record<string, string> = {
  prefilterPolicy: 'Prefilter', decryptionPolicy: 'Decryption',
  identityPolicy: 'Identity',
}

// Distinct, accessible colors per policy type (consistent in light + dark).
const CATEGORY_BADGE: Record<string, string> = {
  prefilterPolicy: 'text-blue-700 dark:text-blue-300 bg-blue-500/10 border-blue-500/30',
  decryptionPolicy: 'text-purple-700 dark:text-purple-300 bg-purple-500/10 border-purple-500/30',
  identityPolicy: 'text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border-emerald-500/30',
}
const CATEGORY_DIVIDER: Record<string, string> = {
  prefilterPolicy: 'bg-blue-500/40',
  decryptionPolicy: 'bg-purple-500/40',
  identityPolicy: 'bg-emerald-500/40',
}

/** Expanded view of a fetched ACP: rule count, assigned policies, settings, mappings. */
export default function AcpDetail({ detail }: { detail: AcpDetailType }) {
  const [openSetting, setOpenSetting] = useState<string | null>(null)

  return (
    <div className="bg-surface-50/60 dark:bg-surface-800/30 px-4 py-3 space-y-3">
      {/* Summary chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1 text-[10px] font-medium text-vyper-600 bg-vyper-500/10 border border-vyper-500/20 rounded-full px-2.5 py-0.5">
          <ListChecks className="w-3 h-3" /> {detail.rule_count} access rule{detail.rule_count === 1 ? '' : 's'}
        </span>
        {detail.unsupported_settings.length > 0 && (
          <span className="inline-flex items-center gap-1 text-[10px] font-medium text-accent-amber bg-accent-amber/10 border border-accent-amber/20 rounded-full px-2.5 py-0.5">
            {detail.unsupported_settings.length} unsupported setting(s)
          </span>
        )}
      </div>

      {/* Assigned policies (names) */}
      <div>
        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-1">
          <Layers className="w-3 h-3" /> Assigned Policies
        </div>
        <div className="flex flex-wrap gap-2">
          {ASSIGNED_CATS.map((cat) => {
            const ap = detail.assigned_policies[cat]
            const present = !!ap && !!(ap.name || ap.source_id)
            return (
              <span
                key={cat}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] max-w-full',
                  present
                    ? CATEGORY_BADGE[cat]
                    : 'text-surface-400 border-dashed border-surface-300 dark:border-surface-700 bg-transparent',
                )}
                title={ap && !ap.supported ? 'Unsupported on target FMC version' : undefined}
              >
                <span className="font-semibold uppercase tracking-wide shrink-0">{CATEGORY_LABELS[cat]}</span>
                <span className={cn('h-3 w-px shrink-0', present ? CATEGORY_DIVIDER[cat] : 'bg-surface-300 dark:bg-surface-600')} />
                <span className="font-medium truncate">
                  {present ? ap!.name || '(assigned)' : 'none'}
                </span>
                {ap && !ap.supported && <span className="shrink-0" title="Unsupported on target FMC version">⚠</span>}
              </span>
            )
          })}
        </div>
      </div>

      {/* Settings (structured, human-readable) */}
      <div>
        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-1">
          <Settings2 className="w-3 h-3" /> Settings
        </div>
        {detail.settings_keys.length === 0 ? (
          <p className="text-[10px] text-surface-400 italic">No settings present or supported.</p>
        ) : (
          <div className="space-y-1">
            {detail.settings_keys.map((key) => {
              const open = openSetting === key
              const val = (detail.settings as Record<string, unknown>)[key]
              return (
                <div key={key} className="rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900">
                  <button
                    onClick={() => setOpenSetting(open ? null : key)}
                    className="flex items-center gap-1 w-full px-2 py-1 text-[10px] font-medium text-surface-700 dark:text-surface-300"
                    aria-expanded={open}
                  >
                    <ChevronRight className={cn('w-3 h-3 transition-transform', open && 'rotate-90')} />
                    {humanLabel(key)}
                  </button>
                  {open && <SettingBody value={val} />}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Assigned-policy create/override mapping */}
      <div>
        <div className="text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-1">
          Target Mapping
        </div>
        <AssignedPolicyMapping acpName={detail.name} assigned={detail.assigned_policies} />
      </div>
    </div>
  )
}
