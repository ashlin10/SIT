import { useState, useEffect, useCallback, useRef } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'
import {
  usePolicyConfigStore, EMPTY_CERT_REALM,
  type AcpDetail as AcpDetailType, type CertRealmSelections,
  type TargetPolicyOption, type SourceRef,
} from '@/stores/policyConfigStore'
import CustomSelect from '@/components/CustomSelect'
import {
  ListChecks, Layers, Settings2, ChevronRight, Code2, Loader2,
  AlertCircle, KeyRound, Sliders, Lock,
} from 'lucide-react'

const SETTING_LABELS: Record<string, string> = {
  ElephantFlowSettings: 'Elephant Flow',
  ShadowTrafficSetting: 'Shadow Traffic',
  EVESetting: 'Encrypted Visibility Engine (EVE)',
  LoggingSetting: 'Logging',
  LoggingPolicySetting: 'Logging Policy',
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

/** Find the best default target id: same-name match, else first option, else ''. */
function autoDefault(sourceName: string, targetOptions: TargetPolicyOption[]): string {
  if (targetOptions.length === 0) return ''
  const match = targetOptions.find((o) => o.name === sourceName)
  if (match) return match.id
  return targetOptions[0].id
}

/** Expanded view of a fetched ACP: rule count, assigned policies, settings. */
export default function AcpDetail({ detail }: { detail: AcpDetailType }) {
  const [openSetting, setOpenSetting] = useState<string | null>(null)
  const mappings = usePolicyConfigStore((s) => s.mappings)
  const targetPolicies = usePolicyConfigStore((s) => s.targetPolicies)
  const setMapping = usePolicyConfigStore((s) => s.setMapping)
  const tpLoading = usePolicyConfigStore((s) => s.targetPoliciesLoading)
  const tpError = usePolicyConfigStore((s) => s.targetPoliciesError)
  const targetCAs = usePolicyConfigStore((s) => s.targetInternalCAs)
  const targetCerts = usePolicyConfigStore((s) => s.targetInternalCerts)
  const sourceCerts = usePolicyConfigStore((s) => s.sourceCerts)
  const certRealmSel = usePolicyConfigStore((s) => s.certRealmSelections)
  const setCertMapping = usePolicyConfigStore((s) => s.setCertMapping)
  const stripZones = usePolicyConfigStore((s) => s.stripZones)
  const setStripZones = usePolicyConfigStore((s) => s.setStripZones)
  const realmPassword = usePolicyConfigStore((s) => s.realmPassword)
  const setRealmPassword = usePolicyConfigStore((s) => s.setRealmPassword)
  const sel: CertRealmSelections = certRealmSel[detail.name] || { ...EMPTY_CERT_REALM }

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

      {/* Assigned policies — theme styling + inline target replacement dropdown */}
      <div>
        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-1">
          <Layers className="w-3 h-3" /> Assigned Policies
        </div>
        {tpError && (
          <p className="flex items-center gap-1.5 text-[10px] text-accent-rose mb-1">
            <AlertCircle className="w-3 h-3" /> {tpError}
          </p>
        )}
        <div className="space-y-1.5">
          {ASSIGNED_CATS.map((cat) => {
            const ap = detail.assigned_policies[cat]
            const present = !!ap && !!(ap.name || ap.source_id)
            const opts = targetPolicies[cat] || []
            const current = mappings[detail.name]?.[cat] || '__create__'
            return (
              <div key={cat}>
                <div className="flex items-center gap-2 text-[10px] flex-wrap">
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 px-2 py-1 w-[100px] shrink-0">
                    <span className="font-semibold uppercase tracking-wide text-surface-500">{CATEGORY_LABELS[cat]}</span>
                  </span>
                  <span className="font-medium text-surface-700 dark:text-surface-300 truncate max-w-[240px] shrink-0" title={present ? ap!.name || '(assigned)' : 'none'}>
                    {present ? ap!.name || '(assigned)' : 'none'}
                    {ap && !ap.supported && (
                      <span className="ml-1 text-accent-amber" title="Unsupported on target FMC version">⚠</span>
                    )}
                  </span>
                  {present && (
                    <>
                      <span className="text-surface-400 shrink-0">→</span>
                      {tpLoading ? (
                        <span className="inline-flex items-center gap-1 text-surface-400">
                          <Loader2 className="w-3 h-3 animate-spin" /> loading…
                        </span>
                      ) : (
                        <CustomSelect
                          value={current}
                          onChange={(v) => setMapping(detail.name, cat, v)}
                          disabled={!!ap && !ap.supported}
                          minWidth="260px"
                          options={[
                            { value: '__create__', label: 'Create new policy' },
                            ...opts.map((o) => ({ value: o.id, label: `Replace with: ${o.name}` })),
                          ]}
                        />
                      )}
                      <span className={cn(
                        'text-[9px] font-semibold uppercase tracking-wider shrink-0',
                        current !== '__create__' ? 'text-accent-amber' : 'text-accent-emerald',
                      )}>
                        {current !== '__create__' ? 'Override' : 'Create'}
                      </span>
                      {/* Cert mapping buttons inline — split by type */}
                      {cat === 'decryptionPolicy' && current === '__create__' && sourceCerts.length > 0 && (() => {
                        const caRefs = sourceCerts.filter((s) => s.type === 'InternalCA')
                        const certRefs = sourceCerts.filter((s) => s.type !== 'InternalCA')
                        return (
                          <>
                            {caRefs.length > 0 && (
                              <MappingPopover
                                icon={<KeyRound className="w-3 h-3" />}
                                label="Internal CAs"
                                sourceRefs={caRefs}
                                targetOptions={targetCAs}
                                mappings={sel.certMappings}
                                onMap={(srcName, tgtId) => setCertMapping(detail.name, srcName, tgtId)}
                                loading={tpLoading}
                              />
                            )}
                            {certRefs.length > 0 && (
                              <MappingPopover
                                icon={<KeyRound className="w-3 h-3" />}
                                label="Internal Certificates"
                                sourceRefs={certRefs}
                                targetOptions={targetCerts}
                                mappings={sel.certMappings}
                                onMap={(srcName, tgtId) => setCertMapping(detail.name, srcName, tgtId)}
                                loading={tpLoading}
                              />
                            )}
                          </>
                        )
                      })()}
                      {/* Identity Policy: Internal Certificates (authCert) + Realm mapping */}
                      {cat === 'identityPolicy' && current === '__create__' && (() => {
                        const idCertRefs = sourceCerts.filter((s) => s.type === 'PKI_InternalCert')
                        return (
                          <>
                            {idCertRefs.length > 0 && (
                              <MappingPopover
                                icon={<KeyRound className="w-3 h-3" />}
                                label="Internal Certificates"
                                sourceRefs={idCertRefs}
                                targetOptions={targetCerts}
                                mappings={sel.certMappings}
                                onMap={(srcName, tgtId) => setCertMapping(detail.name, srcName, tgtId)}
                                loading={tpLoading}
                              />
                            )}
                          </>
                        )
                      })()}
                    </>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Access Control Policy Options */}
      <div>
        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-surface-600 dark:text-surface-400 mb-1">
          <Sliders className="w-3 h-3" /> Access Control Policy Options
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {/* Realm Password for auto-creating realms on target */}
          <div className="inline-flex items-center gap-2">
            <Lock className="w-3 h-3 text-surface-500" />
            <span className="text-[10px] font-medium text-surface-600 dark:text-surface-400">Realm Password</span>
            <input
              type="password"
              value={realmPassword}
              onChange={(e) => setRealmPassword(e.target.value)}
              placeholder="Bglsit@123"
              className="w-32 px-2 py-0.5 text-[10px] rounded border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800 text-surface-700 dark:text-surface-300 focus:outline-none focus:ring-1 focus:ring-vyper-400"
            />
          </div>
          {/* Remove Zones toggle */}
          <label className="inline-flex items-center gap-2 cursor-pointer select-none">
            <span className="text-[10px] font-medium text-surface-600 dark:text-surface-400">Remove Zones</span>
            <button
              type="button"
              role="switch"
              aria-checked={stripZones}
              onClick={() => setStripZones(!stripZones)}
              className={cn(
                'relative inline-flex h-4 w-7 shrink-0 items-center rounded-full transition-colors',
                stripZones ? 'bg-accent-rose' : 'bg-surface-300 dark:bg-surface-600',
              )}
            >
              <span
                className={cn(
                  'inline-block h-3 w-3 rounded-full bg-white shadow-sm transition-transform',
                  stripZones ? 'translate-x-3.5' : 'translate-x-0.5',
                )}
              />
            </button>
          </label>
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
                    className="flex items-center gap-1.5 w-full px-2 py-1 text-[10px] font-medium text-surface-700 dark:text-surface-300"
                    aria-expanded={open}
                  >
                    <ChevronRight className={cn('w-3 h-3 shrink-0 transition-transform', open && 'rotate-90')} />
                    <span className="text-left">{humanLabel(key)}</span>
                  </button>
                  {open && <SettingBody value={val} />}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Reusable fixed-position popover hook ───────────────────────────────────

function usePopover() {
  const [open, setOpen] = useState(false)
  const btnRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ top: 0, left: 0 })

  const reposition = useCallback(() => {
    if (!btnRef.current) return
    const r = btnRef.current.getBoundingClientRect()
    setPos({ top: r.bottom + 4, left: r.left })
  }, [])

  useEffect(() => {
    if (!open) return
    reposition()
    const onClickOutside = (e: MouseEvent) => {
      const t = e.target as Node
      if (btnRef.current?.contains(t) || panelRef.current?.contains(t)) return
      // Don't close if clicking inside a CustomSelect portal dropdown (z-[9999])
      const el = t instanceof Element ? t : t.parentElement
      if (el?.closest('[class*="z-[9999]"]')) return
      setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    window.addEventListener('scroll', reposition, true)
    window.addEventListener('resize', reposition)
    return () => {
      document.removeEventListener('mousedown', onClickOutside)
      window.removeEventListener('scroll', reposition, true)
      window.removeEventListener('resize', reposition)
    }
  }, [open, reposition])

  return { open, setOpen, btnRef, panelRef, pos }
}

// ─── MappingPopover (for certs / realms) ────────────────────────────────────

/** Popover button for per-reference cert or realm mapping. */
function MappingPopover({
  icon, label, sourceRefs, targetOptions, mappings, onMap, loading,
}: {
  icon: React.ReactNode
  label: string
  sourceRefs: SourceRef[]
  targetOptions: TargetPolicyOption[]
  mappings: Record<string, string>
  onMap: (sourceName: string, targetId: string) => void
  loading: boolean
}) {
  const { open, setOpen, btnRef, panelRef, pos } = usePopover()
  const defaultsApplied = useRef(false)

  // Auto-select defaults: same-name match → first non-skip option → none
  useEffect(() => {
    if (defaultsApplied.current || loading || targetOptions.length === 0) return
    let changed = false
    for (const src of sourceRefs) {
      if (!mappings[src.name]) {
        const def = autoDefault(src.name, targetOptions)
        if (def) { onMap(src.name, def); changed = true }
      }
    }
    if (changed || sourceRefs.every((s) => !!mappings[s.name])) {
      defaultsApplied.current = true
    }
  }, [sourceRefs, targetOptions, mappings, onMap, loading])

  const mapped = sourceRefs.filter((s) => mappings[s.name]).length
  const total = sourceRefs.length

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={() => setOpen(!open)}
        className={cn(
          'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-medium transition-colors',
          open
            ? 'border-vyper-400 bg-vyper-500/10 text-vyper-600'
            : 'border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:border-vyper-400 bg-white dark:bg-surface-800',
        )}
      >
        {icon}
        <span>{label}</span>
        <span className={cn(
          'text-[9px] rounded-full px-1.5 py-0.5 font-semibold',
          mapped === total && total > 0
            ? 'bg-accent-emerald/15 text-accent-emerald'
            : mapped > 0 ? 'bg-accent-amber/15 text-accent-amber'
            : 'bg-surface-100 dark:bg-surface-700 text-surface-500',
        )}>
          {mapped}/{total}
        </span>
      </button>
      {open && createPortal(
        <div
          ref={panelRef}
          className="fixed z-[9998] bg-white dark:bg-surface-900 border border-surface-200 dark:border-surface-700 rounded-xl shadow-xl ring-1 ring-black/5 dark:ring-white/5 py-2 px-3 min-w-[400px] max-w-[520px] max-h-[60vh] overflow-auto"
          style={{ top: pos.top, left: pos.left }}
        >
          <p className="text-[9px] text-surface-400 mb-2">Map each source reference to a target equivalent:</p>
          {loading ? (
            <span className="inline-flex items-center gap-1 text-[10px] text-surface-400">
              <Loader2 className="w-3 h-3 animate-spin" /> loading…
            </span>
          ) : (
            <div className="space-y-2">
              {sourceRefs.map((src) => (
                <div key={src.name} className="flex items-center gap-2">
                  <div className="min-w-[140px] shrink-0">
                    <span className="text-[10px] font-medium text-surface-700 dark:text-surface-300 truncate block" title={src.name}>
                      {src.name}
                    </span>
                    <span className="text-[8px] text-surface-400">{src.type}</span>
                  </div>
                  <span className="text-surface-400 text-[10px] shrink-0">→</span>
                  {targetOptions.length > 0 ? (
                    <CustomSelect
                      value={mappings[src.name] || ''}
                      onChange={(v) => onMap(src.name, v)}
                      minWidth="200px"
                      keepOpen
                      placeholder="Select target…"
                      options={[
                        { value: '', label: '— none —' },
                        ...targetOptions.map((o) => ({ value: o.id, label: `${o.name} (${o.type})` })),
                      ]}
                    />
                  ) : (
                    <span className="text-[10px] text-surface-400 italic">none available</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>,
        document.body,
      )}
    </>
  )
}

