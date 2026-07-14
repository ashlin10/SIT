import { cn } from '@/lib/utils'
import { usePolicyConfigStore } from '@/stores/policyConfigStore'
import { pushPolicies, sanitizePolicyConfig, previewPush } from './api'
import {
  ShieldCheck, AlertTriangle, ArrowRight, Check,
  ChevronDown, ChevronUp, X, FileText, Package, Wrench, Loader2,
} from 'lucide-react'
import { useState, useMemo } from 'react'

interface WarnGroup {
  key: string
  schema: string
  field: string
  message: string
  count: number
  scopes: string[]
}

const _CAT_LABELS: Record<string, string> = {
  prefilterPolicy: 'Prefilter Policy',
  decryptionPolicy: 'Decryption Policy',
  identityPolicy: 'Identity Policy',
  securityIntelligencePolicy: 'Security Intelligence Policy',
}

/** Inline pre-push review panel: shows the resolution plan, validation results,
 * and assigned-policy mappings, requiring confirmation before mutating the target.
 * Replaces the former modal with an inline collapsible panel consistent with
 * the Device Configuration's ValidationReviewPanel. */
export default function PushSummaryModal() {
  const open = usePolicyConfigStore((s) => s.previewOpen)
  const preview = usePolicyConfigStore((s) => s.preview)
  const setOpen = usePolicyConfigStore((s) => s.setPreviewOpen)
  const acps = usePolicyConfigStore((s) => s.acps)
  const perRuleFallback = usePolicyConfigStore((s) => s.perRuleFallback)
  const rejectedSanitizeKeys = usePolicyConfigStore((s) => s.rejectedSanitizeKeys)
  const toggleSanitizeKey = usePolicyConfigStore((s) => s.toggleSanitizeKey)
  const setSanitizeKeysRejected = usePolicyConfigStore((s) => s.setSanitizeKeysRejected)
  const [confirmOverride, setConfirmOverride] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [fixing, setFixing] = useState(false)

  // Build policy summary rows: ACP + each assigned dependent policy with rule counts.
  // Must be called before early return to satisfy React hooks rules.
  const policySummary = useMemo(() => {
    if (!preview) return []
    try {
      const sel = new Set(preview.selected_acps || [])
      const selAcps = acps.filter((a) => sel.has(a.name))
      const rows: { label: string; name: string; rules: number | null }[] = []
      for (const a of selAcps) {
        rows.push({ label: 'Access Control Policy', name: a.name, rules: a.detail?.rule_count ?? 0 })
        if (a.detail?.assigned_policies) {
          for (const [cat, ap] of Object.entries(a.detail.assigned_policies)) {
            if (!ap?.name) continue
            rows.push({ label: _CAT_LABELS[cat] || cat, name: ap.name, rules: null })
          }
        }
      }
      return rows
    } catch {
      return []
    }
  }, [preview, acps])

  if (!open || !preview) return null

  const plan = (preview.plan || {}) as Record<string, unknown[]>
  const validations = preview.validations || []
  const overrides = (preview.assigned_policy_mappings || []).filter((m) => (m as Record<string, unknown>).behavior === 'override')
  const hasOverrides = overrides.length > 0
  const conflicts = (Array.isArray(plan.conflicts) ? plan.conflicts : []) as Record<string, unknown>[]
  const cycles = (Array.isArray(plan.cycles) ? plan.cycles : []) as string[][]
  const unresolved = (Array.isArray(plan.unresolved) ? plan.unresolved : []) as Record<string, unknown>[]
  const blocking = conflicts.length > 0 || cycles.length > 0
  const validationErrors = validations.flatMap((v) => ((v as Record<string, unknown[]>).errors || []))
  const validationWarnings = validations.flatMap((v) => ((v as Record<string, unknown[]>).warnings || []))
  const canPush = !blocking && validationErrors.length === 0 && (!hasOverrides || confirmOverride)

  // Group sanitizable field warnings by "<Schema>:<field>" so identical
  // mismatches across many rules collapse into a single entry with a count
  // (consistent with Device Configuration's validation review).
  const groupMap = new Map<string, WarnGroup>()
  const otherWarnings: { scope: string; message: string }[] = []
  for (const w of validationWarnings) {
    const rec = w as Record<string, unknown>
    if (rec.sanitizable && rec.group_key) {
      const key = String(rec.group_key)
      const g = groupMap.get(key) || {
        key, schema: String(rec.schema || ''), field: String(rec.field || ''),
        message: String(rec.message || ''), count: 0, scopes: [],
      }
      g.count += 1
      if (rec.scope) g.scopes.push(String(rec.scope))
      groupMap.set(key, g)
    } else {
      otherWarnings.push({ scope: String(rec.scope || ''), message: String(rec.message || '') })
    }
  }
  const warnGroups = Array.from(groupMap.values()).sort((a, b) => a.key.localeCompare(b.key))
  const acceptedKeys = warnGroups.map((g) => g.key).filter((k) => !rejectedSanitizeKeys.has(k))
  const allAccepted = warnGroups.length > 0 && warnGroups.every((g) => !rejectedSanitizeKeys.has(g.key))

  const handleFix = async () => {
    if (acceptedKeys.length === 0) return
    setFixing(true)
    try {
      const r = await sanitizePolicyConfig(acceptedKeys)
      if (!r.success) { alert(r.message || 'Sanitize failed'); return }
      // Re-run preview so the panel refreshes with the reduced warning set.
      await previewPush({ preserveLogs: true })
    } finally {
      setFixing(false)
    }
  }

  // Total access rules across the selected ACPs (human-friendly summary).
  const selected = new Set(preview.selected_acps)
  const selectedAcps = acps.filter((a) => selected.has(a.name))
  const ruleTotal = selectedAcps.reduce((sum, a) => sum + (a.detail?.rule_count ?? 0), 0)

  const handlePush = async () => {
    setOpen(false)
    const r = await pushPolicies(confirmOverride, perRuleFallback)
    if (!r.success) alert(r.message || 'Push failed')
  }

  const count = (k: string) => (plan[k]?.length ?? 0)

  const blockingCount = conflicts.length + cycles.length + validationErrors.length
  const warningCount = unresolved.length + overrides.length + validationWarnings.length
  const noIssues = blockingCount === 0 && warningCount === 0

  return (
    <div className="rounded-xl border border-vyper-300/50 dark:border-vyper-700/40 bg-white dark:bg-surface-900/50 overflow-hidden shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <ShieldCheck className="w-4 h-4 text-vyper-600" />
          <span className="text-[13px] font-semibold text-surface-800 dark:text-surface-200">
            Push Review
          </span>
          <div className="flex items-center gap-1.5">
            <Badge n={blockingCount} tone="rose" label="blocking" />
            <Badge n={warningCount} tone="amber" label="warning" />
          </div>
          <span className="text-[10px] text-surface-500">
            {preview.selected_acps.length} ACP{preview.selected_acps.length === 1 ? '' : 's'}
            {ruleTotal > 0 && ` · ${ruleTotal} rule${ruleTotal === 1 ? '' : 's'}`}
          </span>
        </div>
        <button
          onClick={() => setCollapsed((c) => !c)}
          className="p-1 text-surface-400 hover:text-surface-600 transition-colors"
          title={collapsed ? 'Expand' : 'Collapse'}
        >
          {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
        </button>
      </div>

      {!collapsed && <>
      <div className="px-5 py-4 space-y-4 text-[11px] max-h-[45vh] overflow-y-auto">
        {noIssues && (
          <div className="flex items-center gap-2 text-[11px] text-accent-emerald">
            <Check className="w-4 h-4" /> No conflicts detected. Ready to push.
          </div>
        )}

        {/* ACP chips */}
        <div className="flex flex-wrap gap-1.5">
          {preview.selected_acps.map((n) => (
            <span key={n} className="rounded-full bg-vyper-500/10 text-vyper-600 border border-vyper-500/20 px-2 py-0.5 text-[10px]">{n}</span>
          ))}
        </div>

        {/* Schema validation warnings (fixed above Policies/Objects) */}
        {warnGroups.length > 0 && (
          <div className="rounded-lg border border-accent-amber/30 overflow-hidden">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-accent-amber/5 border-b border-accent-amber/20">
              <AlertTriangle className="w-3.5 h-3.5 text-accent-amber" />
              <span className="font-semibold text-accent-amber">
                Unsupported fields on target ({warnGroups.length})
              </span>
              <span className="text-[10px] text-surface-400 font-normal">— select fields to remove, then Fix</span>
              <div className="ml-auto flex items-center gap-2">
                <label className="flex items-center gap-1 text-[10px] text-surface-500 cursor-pointer select-none"
                  title="Select / deselect all fields">
                  <input
                    type="checkbox"
                    checked={allAccepted}
                    onChange={() => setSanitizeKeysRejected(warnGroups.map((g) => g.key), allAccepted)}
                    className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
                  />
                  All ({acceptedKeys.length}/{warnGroups.length})
                </label>
                <button
                  onClick={handleFix}
                  disabled={fixing || acceptedKeys.length === 0}
                  className={cn(
                    'flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-semibold transition-colors',
                    'bg-vyper-600 text-white hover:bg-vyper-700',
                    (fixing || acceptedKeys.length === 0) && 'opacity-40 pointer-events-none',
                  )}
                  title="Remove the selected unsupported fields from the loaded config, then re-validate"
                >
                  {fixing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Wrench className="w-3 h-3" />}
                  Fix
                </button>
              </div>
            </div>
            <div className="divide-y divide-surface-100 dark:divide-surface-800/50 max-h-52 overflow-auto">
              {warnGroups.map((g) => {
                const accepted = !rejectedSanitizeKeys.has(g.key)
                return (
                  <label
                    key={g.key}
                    className="flex items-start gap-2 px-3 py-1.5 cursor-pointer hover:bg-surface-50 dark:hover:bg-surface-800/30"
                    title={g.scopes.slice(0, 20).join('\n')}
                  >
                    <input
                      type="checkbox"
                      checked={accepted}
                      onChange={() => toggleSanitizeKey(g.key)}
                      className="mt-0.5 rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-surface-700 dark:text-surface-300">{g.schema}</span>
                        <span className="text-surface-400">·</span>
                        <span className="font-mono px-1 rounded bg-surface-100 dark:bg-surface-800 text-surface-700 dark:text-surface-300">{g.field}</span>
                      </div>
                      <div className="text-[10px] text-surface-500 mt-0.5">{g.message}</div>
                    </div>
                    {g.count > 1 && (
                      <span className="text-[11px] font-semibold text-surface-500 shrink-0 tabular-nums">×{g.count}</span>
                    )}
                  </label>
                )
              })}
            </div>
          </div>
        )}

        {otherWarnings.length > 0 && (
          <div className="text-[10px] text-surface-400 space-y-0.5">
            {otherWarnings.slice(0, 10).map((w, i) => (
              <div key={i}>{w.scope}: {w.message}</div>
            ))}
            {otherWarnings.length > 10 && <div>+{otherWarnings.length - 10} more…</div>}
          </div>
        )}

        {/* Policies */}
        {policySummary.length > 0 && (
          <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-50 dark:bg-surface-800/50 border-b border-surface-200 dark:border-surface-700">
              <FileText className="w-3.5 h-3.5 text-vyper-600" />
              <span className="font-semibold text-surface-700 dark:text-surface-300">Policies ({policySummary.length})</span>
            </div>
            <div className="divide-y divide-surface-100 dark:divide-surface-800/50">
              {policySummary.map((p, i) => (
                <div key={i} className="flex items-center justify-between px-3 py-1.5">
                  <div>
                    <span className="text-[10px] text-surface-400">{p.label}</span>
                    <span className="ml-1.5 font-medium text-surface-700 dark:text-surface-300">{p.name}</span>
                  </div>
                  {p.rules !== null && (
                    <span className="text-[10px] text-surface-500">{p.rules} rule{p.rules === 1 ? '' : 's'}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Objects */}
        <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
          <div className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-50 dark:bg-surface-800/50 border-b border-surface-200 dark:border-surface-700">
            <Package className="w-3.5 h-3.5 text-vyper-600" />
            <span className="font-semibold text-surface-700 dark:text-surface-300">Objects</span>
          </div>
          <div className="grid grid-cols-3 gap-2 p-2">
            <Stat label="To create" value={count('to_create')} tone="emerald" />
            <Stat label="Reused" value={count('to_reuse')} tone="surface" />
            <Stat label="Unresolved" value={count('unresolved')} tone={unresolved.length ? 'amber' : 'surface'} />
          </div>
        </div>

        {(overrides.length > 0) && (
          <Section title={`Policies to override (${overrides.length})`} tone="amber">
            {overrides.map((o, i) => {
              const m = o as Record<string, unknown>
              return (
                <div key={i} className="text-surface-600 dark:text-surface-400">
                  <span className="font-medium">{String(m.acp)}</span> — {String(m.category)}: "{String(m.source_name)}"
                </div>
              )
            })}
          </Section>
        )}

        {unresolved.length > 0 && (
          <Section title={`Objects that won't transfer (${unresolved.length})`} tone="amber">
            <div className="text-surface-500 dark:text-surface-400 mb-1">
              Not found on the target FMC. Rules keep working when the id is globally consistent; otherwise the reference is dropped from the rule.
            </div>
            {unresolved.slice(0, 30).map((u, i) => (
              <div key={i} className="text-surface-600 dark:text-surface-400">
                <span className="font-medium">{String(u.type)}</span> "{String(u.name)}"
              </div>
            ))}
            {unresolved.length > 30 && <div className="text-surface-400">+{unresolved.length - 30} more…</div>}
          </Section>
        )}

        {conflicts.length > 0 && (
          <Section title="Blocking: name collisions on target" tone="rose">
            <div className="text-surface-500 dark:text-surface-400 mb-1">
              An object with the same name already exists on the target FMC but with different settings. Rename or remove it, then push again.
            </div>
            {conflicts.map((c, i) => (
              <div key={i} className="text-surface-600 dark:text-surface-400">
                <span className="font-medium">{String(c.type)} "{String(c.name)}"</span>
              </div>
            ))}
          </Section>
        )}

        {cycles.length > 0 && (
          <Section title="Blocking: objects reference each other in a loop" tone="rose">
            <div className="text-surface-600 dark:text-surface-400">
              {cycles.length} group{cycles.length === 1 ? '' : 's'} of objects depend on each other and can't be ordered for creation. Review these object groups on the source FMC.
            </div>
          </Section>
        )}

        {validationErrors.length > 0 && (
          <Section title={`Validation errors (${validationErrors.length})`} tone="rose">
            {validationErrors.slice(0, 20).map((e, i) => (
              <div key={i} className="text-surface-600 dark:text-surface-400">
                {String((e as Record<string, unknown>).scope || '')}: {String((e as Record<string, unknown>).message || '')}
              </div>
            ))}
          </Section>
        )}

        {hasOverrides && (
          <label className="flex items-start gap-2 rounded-lg border border-accent-amber/30 bg-accent-amber/10 px-3 py-2">
            <input type="checkbox" checked={confirmOverride} onChange={(e) => setConfirmOverride(e.target.checked)}
              className="mt-0.5 rounded border-surface-300 text-accent-amber focus:ring-accent-amber/30" />
            <span className="text-[10px] text-surface-700 dark:text-surface-300">
              <span className="inline-flex items-center gap-1 font-semibold text-accent-amber"><AlertTriangle className="w-3 h-3" /> Confirm override</span>
              {' '}— I understand that {overrides.length} existing target policy(ies) will be overridden.
            </span>
          </label>
        )}
      </div>

      {/* Footer actions */}
      <div className="flex flex-wrap items-center gap-2.5 px-5 py-3 border-t border-surface-100 dark:border-surface-800/50">
        <div className="flex-1" />
        <button onClick={() => setOpen(false)}
          className={btnCls('secondary', false)}>
          <X className="w-3.5 h-3.5" /> Cancel
        </button>
        <button onClick={handlePush} disabled={!canPush}
          className={btnCls('primary', !canPush)}>
          <ArrowRight className="w-3.5 h-3.5" />
          Confirm & Push
        </button>
      </div>
      </>}
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone: 'emerald' | 'amber' | 'rose' | 'surface' }) {
  const toneCls = {
    emerald: 'text-accent-emerald', amber: 'text-accent-amber', rose: 'text-accent-rose', surface: 'text-surface-600 dark:text-surface-300',
  }[tone]
  return (
    <div className="rounded-lg border border-surface-200 dark:border-surface-700 px-3 py-2">
      <div className={cn('text-lg font-semibold', toneCls)}>{value}</div>
      <div className="text-[10px] text-surface-400">{label}</div>
    </div>
  )
}

function Section({ title, tone, children }: { title: string; tone: 'rose' | 'amber'; children: React.ReactNode }) {
  const border = tone === 'rose' ? 'border-accent-rose/30' : 'border-accent-amber/30'
  return (
    <div className={cn('rounded-lg border px-3 py-2 space-y-1', border)}>
      <h4 className={cn('font-semibold', tone === 'rose' ? 'text-accent-rose' : 'text-accent-amber')}>{title}</h4>
      <div className="max-h-40 overflow-auto space-y-0.5">{children}</div>
    </div>
  )
}

function Badge({ n, tone, label }: { n: number; tone: 'rose' | 'amber'; label: string }) {
  if (!n) return null
  return (
    <span className={cn('text-[10px] font-medium px-1.5 py-0.5 rounded-full border',
      tone === 'rose' && 'text-accent-rose border-accent-rose/30 bg-accent-rose/10',
      tone === 'amber' && 'text-accent-amber border-accent-amber/30 bg-accent-amber/10',
    )}>
      {n} {label}
    </span>
  )
}

function btnCls(variant: 'primary' | 'secondary', disabled: boolean) {
  return cn(
    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
    variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
    variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
    disabled && 'opacity-40 pointer-events-none',
  )
}
