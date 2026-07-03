import { Loader2, AlertCircle } from 'lucide-react'
import CustomSelect from '@/components/CustomSelect'
import { usePolicyConfigStore, type AssignedPolicyInfo } from '@/stores/policyConfigStore'

const CATEGORY_LABELS: Record<string, string> = {
  prefilterPolicy: 'Prefilter Policy',
  decryptionPolicy: 'Decryption Policy',
  identityPolicy: 'Identity Policy',
}

/**
 * Mapping controls for an ACP's assigned policies. For each assigned policy the
 * user chooses to either create a new policy on the target (default) or
 * override an existing target policy of the same category.
 */
export default function AssignedPolicyMapping({ acpName, assigned }: {
  acpName: string
  assigned: Record<string, AssignedPolicyInfo>
}) {
  const mappings = usePolicyConfigStore((s) => s.mappings)
  const targetPolicies = usePolicyConfigStore((s) => s.targetPolicies)
  const setMapping = usePolicyConfigStore((s) => s.setMapping)
  const loading = usePolicyConfigStore((s) => s.targetPoliciesLoading)
  const loaded = usePolicyConfigStore((s) => s.targetPoliciesLoaded)
  const loadError = usePolicyConfigStore((s) => s.targetPoliciesError)

  const categories = Object.keys(assigned).filter((c) => c in CATEGORY_LABELS)
  if (categories.length === 0) {
    return <p className="text-[10px] text-surface-400 italic">No assigned policies on this ACP.</p>
  }

  if (loading) {
    return (
      <p className="flex items-center gap-1.5 text-[10px] text-surface-400">
        <Loader2 className="w-3 h-3 animate-spin" /> Loading target policies…
      </p>
    )
  }
  if (loadError) {
    return (
      <p className="flex items-center gap-1.5 text-[10px] text-accent-rose">
        <AlertCircle className="w-3 h-3" /> {loadError}
      </p>
    )
  }

  return (
    <div className="space-y-2">
      {categories.map((cat) => {
        const ap = assigned[cat]
        const opts = targetPolicies[cat] || []
        const current = mappings[acpName]?.[cat] || '__create__'
        const isOverride = current !== '__create__'
        return (
          <div key={cat} className="grid grid-cols-12 items-center gap-2">
            <div className="col-span-4 text-[10px]">
              <div className="font-medium text-surface-600 dark:text-surface-400">{CATEGORY_LABELS[cat] || cat}</div>
              <div className="text-surface-400 truncate" title={ap.name}>
                source: {ap.name || '—'}{!ap.supported && ' (unsupported on target)'}
              </div>
            </div>
            <div className="col-span-6">
              <CustomSelect
                value={current}
                onChange={(v) => setMapping(acpName, cat, v)}
                disabled={!ap.supported}
                options={[
                  { value: '__create__', label: 'Create new policy' },
                  ...opts.map((o) => ({ value: o.id, label: `Override: ${o.name}` })),
                ]}
              />
              {loaded && opts.length === 0 && (
                <div className="text-[9px] text-surface-400 mt-0.5">
                  No existing target policies of this type — a new one will be created.
                </div>
              )}
            </div>
            <div className="col-span-2">
              <span className={
                'text-[9px] font-semibold uppercase tracking-wider ' +
                (isOverride ? 'text-accent-amber' : 'text-accent-emerald')
              }>
                {isOverride ? 'Override' : 'Create'}
              </span>
            </div>
          </div>
        )
      })}
      <p className="text-[9px] text-surface-400">
        Overriding an existing target policy requires confirmation before the push runs.
      </p>
    </div>
  )
}
