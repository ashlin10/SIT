import { useState, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import type { ValidationIssue, ValidationReport, DeviceInterface } from '@/stores/fmcConfigStore'
import {
  continueValidatedPush, cancelValidation, sanitizeConfig,
  applyValidationFixes, revalidate,
} from './api'
import {
  ShieldCheck, ShieldAlert, AlertTriangle, AlertCircle, Info, X, Check,
  Loader2, Eye, Send, Wrench, RefreshCw, ChevronDown, ChevronUp,
} from 'lucide-react'

const REMOVE = '__REMOVE__'

/** FMC speed enum ranking: higher index = faster. Used to pick next-highest supported speed. */
const SPEED_RANK: Record<string, number> = {
  TEN: 1,
  HUNDRED: 2,
  THOUSAND: 3,
  TWO_THOUSAND_FIVE_HUNDRED: 4,
  TEN_THOUSAND: 5,
  TWENTY_FIVE_THOUSAND: 6,
  FORTY_THOUSAND: 7,
  HUNDRED_THOUSAND: 8,
  TWO_HUNDRED_THOUSAND: 9,
  FOUR_HUNDRED_THOUSAND: 10,
}

/** Given an unsupported speed and a list of allowed speeds, return the next-highest supported speed. */
function nextHighestSpeed(currentSpeed: string, allowed: string[]): string {
  const ranked = allowed.filter((s) => s !== 'AUTO' && s !== 'DETECT_SFP' && SPEED_RANK[s] != null)
    .sort((a, b) => (SPEED_RANK[b] || 0) - (SPEED_RANK[a] || 0))
  const curRank = SPEED_RANK[currentSpeed] ?? 0
  // Find the highest allowed speed that is <= current speed
  for (const s of ranked) {
    if ((SPEED_RANK[s] || 0) <= curRank) return s
  }
  // If none is lower, pick the lowest available
  return ranked.length > 0 ? ranked[ranked.length - 1] : allowed[0] || ''
}

/** Returns true if the interface is an SFP-type port (has DETECT_SFP in its per-interface speeds). */
function isSfpPort(name: string, perIfaceSpeeds: Map<string, string[]>): boolean {
  const speeds = perIfaceSpeeds.get(name)
  return !!speeds && speeds.includes('DETECT_SFP')
}

const MGMT_RE = /^(management|mgmt)/i
const PHYS_RE = /^(ethernet|gigabitethernet|tengigabitethernet|fortygigabitethernet|hundredgigabitethernet|twentyfivegigabitethernet)/i

function isHardwarePort(name: string): boolean {
  if (!name || typeof name !== 'string') return false
  return PHYS_RE.test(name) || MGMT_RE.test(name) || /^[a-z]+\d+\/\d+$/i.test(name)
}
function isManagementPort(name: string): boolean {
  return typeof name === 'string' && MGMT_RE.test(name)
}

/** Natural sort comparator for interface names: Ethernet1/2 < Ethernet1/10. */
function naturalIfaceCompare(a: string, b: string): number {
  const re = /(\D+)(\d+)/g
  const pa: (string | number)[] = []
  const pb: (string | number)[] = []
  let m: RegExpExecArray | null
  re.lastIndex = 0
  while ((m = re.exec(a))) { pa.push(m[1].toLowerCase(), parseInt(m[2], 10)) }
  re.lastIndex = 0
  while ((m = re.exec(b))) { pb.push(m[1].toLowerCase(), parseInt(m[2], 10)) }
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const va = pa[i] ?? ''
    const vb = pb[i] ?? ''
    if (typeof va === 'number' && typeof vb === 'number') {
      if (va !== vb) return va - vb
    } else {
      const cmp = String(va).localeCompare(String(vb))
      if (cmp !== 0) return cmp
    }
  }
  return 0
}

type IfaceKind = 'physical' | 'management' | 'member'

interface IfaceRow {
  name: string
  contexts: string[]
  speed: string
  allowSpeed: boolean
  onDevice: boolean
  kind: IfaceKind
  parentName?: string
  parentSection?: string
  deviceSpeed?: string  // speed reported by the target device for this interface
}

interface EtherchannelRow {
  name: string
  ecId: number
  speed: string
  parentSection: string
}

interface MemberGroup {
  parentName: string
  parentSection: string
  etherchannel?: EtherchannelRow
  members: IfaceRow[]
}

/** Build the hardware-interface correction rows from the loaded YAML config. */
function buildInterfaceRows(
  config: Record<string, unknown> | null,
  deviceNames: Set<string>,
  deviceIfaceMap: Map<string, DeviceInterface>,
): { standalone: IfaceRow[]; memberGroups: MemberGroup[] } {
  const rows = new Map<string, IfaceRow>()
  // Build a lookup of physical interface speeds from the YAML config
  const physSpeedMap = new Map<string, string>()
  if (config) {
    const physArr = (config as Record<string, unknown>)['physical_interfaces']
    if (Array.isArray(physArr)) {
      for (const it of physArr as Record<string, unknown>[]) {
        const n = String(it.name || '')
        const hw = (it.hardware || {}) as Record<string, unknown>
        if (n && hw.speed) physSpeedMap.set(n, String(hw.speed))
      }
    }
  }
  const add = (name: string, context: string, speed = '', allowSpeed = false, kind: IfaceKind = 'physical', parentName?: string, parentSection?: string) => {
    if (!name || !isHardwarePort(name)) return
    const k = kind === 'member' ? `${parentName}::${name}` : name
    const existing = rows.get(k)
    if (existing) {
      if (!existing.contexts.includes(context)) existing.contexts.push(context)
      if (allowSpeed) existing.allowSpeed = true
      if (!existing.speed && speed) existing.speed = speed
    } else {
      const inferredKind = kind === 'physical' && isManagementPort(name) ? 'management' as IfaceKind : kind
      const devIf = deviceIfaceMap.get(name)
      rows.set(k, { name, contexts: [context], speed, allowSpeed, onDevice: deviceNames.has(name), kind: inferredKind, parentName, parentSection, deviceSpeed: devIf?.speed || '' })
    }
  }
  if (!config) return { standalone: [], memberGroups: [] }
  const arr = (k: string): Record<string, unknown>[] => {
    const v = (config as Record<string, unknown>)[k]
    return Array.isArray(v) ? (v as Record<string, unknown>[]) : []
  }
  arr('physical_interfaces').forEach((it) => {
    const hw = (it.hardware || {}) as Record<string, unknown>
    add(String(it.name || ''), 'Physical', String(hw.speed || ''), true)
  })
  const ecRows: EtherchannelRow[] = []
  arr('etherchannel_interfaces').forEach((it) => {
    const pName = String(it.name || '?')
    const hw = (it.hardware || {}) as Record<string, unknown>
    const ecSpeed = String(hw.speed || '')
    const ecId = typeof it.etherChannelId === 'number' ? it.etherChannelId : parseInt(String(it.etherChannelId || '0'), 10)
    ecRows.push({ name: pName, ecId, speed: ecSpeed, parentSection: 'etherchannel_interfaces' })
    const members = Array.isArray(it.selectedInterfaces) ? it.selectedInterfaces as Record<string, unknown>[] : []
    members.forEach((m) => {
      const mName = String(m.name || '')
      // Member speed: look up from physical_interfaces YAML, else inherit parent EC speed
      const mSpeed = physSpeedMap.get(mName) || ecSpeed
      add(mName, `Port-channel member`, mSpeed, true, 'member', pName, 'etherchannel_interfaces')
    })
  })
  arr('bridge_group_interfaces').forEach((it) => {
    const pName = String(it.name || '?')
    const members = Array.isArray(it.selectedInterfaces) ? it.selectedInterfaces as Record<string, unknown>[] : []
    members.forEach((m) => {
      const mName = String(m.name || '')
      add(mName, `BVI member`, physSpeedMap.get(mName) || '', true, 'member', pName, 'bridge_group_interfaces')
    })
  })
  arr('inline_sets').forEach((it) => {
    const pName = String(it.name || '?')
    const members = Array.isArray(it.selectedInterfaces) ? it.selectedInterfaces as Record<string, unknown>[] : []
    members.forEach((m) => {
      const mName = String(m.name || '')
      add(mName, `Inline-set member`, physSpeedMap.get(mName) || '', true, 'member', pName, 'inline_sets')
    })
  })
  arr('subinterfaces').forEach((it) => {
    const nm = String(it.name || '')
    const parent = String(it.parentName || (nm.includes('.') ? nm.split('.')[0] : ''))
    add(parent, 'Subinterface parent', '', true)
  })
  arr('redundant_interfaces').forEach((it) => {
    const pName = String(it.name || '?')
    const members = Array.isArray(it.selectedInterfaces) ? it.selectedInterfaces as Record<string, unknown>[] : []
    members.forEach((m) => {
      const mName = String(m.name || '')
      add(mName, `Redundant member`, physSpeedMap.get(mName) || '', true, 'member', pName, 'redundant_interfaces')
    })
  })
  const all = Array.from(rows.values()).sort((a, b) => naturalIfaceCompare(a.name, b.name))
  const standalone = all.filter((r) => r.kind !== 'member')
  // Group member rows by parentName, and attach etherchannel header rows
  const groupMap = new Map<string, MemberGroup>()
  all.filter((r) => r.kind === 'member').forEach((r) => {
    const key = `${r.parentSection}::${r.parentName}`
    if (!groupMap.has(key)) {
      const ec = ecRows.find((e) => e.name === r.parentName && r.parentSection === 'etherchannel_interfaces')
      groupMap.set(key, { parentName: r.parentName!, parentSection: r.parentSection!, etherchannel: ec, members: [] })
    }
    groupMap.get(key)!.members.push(r)
  })
  // Also create groups for etherchannels that have no members yet in rows
  ecRows.forEach((ec) => {
    const key = `etherchannel_interfaces::${ec.name}`
    if (!groupMap.has(key)) groupMap.set(key, { parentName: ec.name, parentSection: 'etherchannel_interfaces', etherchannel: ec, members: [] })
  })
  return { standalone, memberGroups: Array.from(groupMap.values()) }
}

const SEVERITY_META: Record<string, { icon: typeof AlertCircle; cls: string; label: string }> = {
  blocking: { icon: ShieldAlert, cls: 'text-accent-rose', label: 'Blocking' },
  warning: { icon: AlertTriangle, cls: 'text-accent-amber', label: 'Warning' },
  info: { icon: Info, cls: 'text-accent-sky', label: 'Info' },
}

export default function ValidationReviewPanel() {
  const {
    validationOpen, validationPhase, validationReports, validationFmcVersion, validationRunId,
    interfaceMappings, speedChanges, interfaceRemovals, memberChanges,
    etherchannelIdChanges, rejectedIssueIds,
    selectedDeviceIds, configCheckboxes, uploadedConfig,
    isOperationRunning, openViewer,
    setInterfaceMapping, setSpeedChange, setInterfaceRemoval, setMemberChange,
    setEtherchannelIdChange, toggleRejectedIssue,
  } = useFmcConfigStore()

  const [busy, setBusy] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const removalsInitRef = useRef<string | null>(null)

  // ── Aggregate counts + conflicts ──
  const totals = { blocking: 0, warning: 0, info: 0 }
  validationReports.forEach((r) => {
    totals.blocking += r.counts?.blocking || 0
    totals.warning += r.counts?.warning || 0
    totals.info += r.counts?.info || 0
  })
  const allConflicts = validationReports.flatMap((r) => r.interfaceConflicts || [])

  // Classify device interfaces by type for filtered dropdowns.
  const deviceNames = new Set<string>()
  const speedSet = new Set<string>()
  const physicalDeviceIfaces: string[] = []
  const managementDeviceIfaces: string[] = []
  const deviceIfaceMap = new Map<string, DeviceInterface>()
  validationReports.forEach((r) => (r.deviceInterfaces || []).forEach((d) => {
    if (!d.name || deviceNames.has(d.name)) return
    deviceNames.add(d.name)
    deviceIfaceMap.set(d.name, d)
    if (d.speed) speedSet.add(d.speed)
    if (d.managementOnly || isManagementPort(d.name)) {
      managementDeviceIfaces.push(d.name)
    } else if (d.type === 'PhysicalInterface' || PHYS_RE.test(d.name)) {
      physicalDeviceIfaces.push(d.name)
    }
  }))
  physicalDeviceIfaces.sort(naturalIfaceCompare)
  managementDeviceIfaces.sort(naturalIfaceCompare)
  const deviceSpeeds = Array.from(speedSet).filter((s) => s !== 'AUTO' && s !== 'DETECT_SFP').sort()

  // Build per-interface supported speeds map from model schema data.
  const perIfaceSpeeds = new Map<string, string[]>()
  validationReports.forEach((r) => {
    const pis = r.perInterfaceSpeeds || {}
    const ms = r.managementSpeeds || {}
    for (const [name, speeds] of Object.entries(pis)) perIfaceSpeeds.set(name, speeds)
    for (const [name, speeds] of Object.entries(ms)) perIfaceSpeeds.set(name, speeds)
  })

  const { standalone, memberGroups } = buildInterfaceRows(uploadedConfig, deviceNames, deviceIfaceMap)
  const allRows = [...standalone, ...memberGroups.flatMap((g) => g.members)]
  const noChanges = totals.blocking === 0 && totals.warning === 0 && allConflicts.length === 0
  // Count speed mismatches for the interface section severity
  const hasSpeedMismatch = allRows.some((r) => r.onDevice && r.speed && r.deviceSpeed && r.speed !== r.deviceSpeed)

  // Auto-initialize removals and speed defaults each time validation results change.
  // Use a fingerprint so re-validation or schema switches get fresh defaults.
  const reportFingerprint = `${validationRunId}`
  useEffect(() => {
    if (validationPhase !== 'review') return
    if (removalsInitRef.current === reportFingerprint) return
    removalsInitRef.current = reportFingerprint
    // Default not-on-device standalone interfaces to removal.
    standalone.forEach((row) => {
      if (!row.onDevice && !interfaceMappings[row.name] && !interfaceRemovals.has(row.name)) {
        setInterfaceRemoval(row.name, true)
      }
    })
    // Default not-on-device member interfaces to removal.
    memberGroups.forEach((g) => g.members.forEach((row) => {
      if (!row.onDevice && !memberChanges[g.parentName]?.[row.name]) {
        setMemberChange(g.parentName, row.name, REMOVE)
      }
    }))
    // Auto-default speed for interfaces with unsupported speed on target.
    allRows.forEach((row) => {
      if (!row.speed) return
      const allowed = perIfaceSpeeds.get(row.name)
      if (allowed && !allowed.includes(row.speed) && !speedChanges[row.name]) {
        const best = nextHighestSpeed(row.speed, allowed)
        if (best) setSpeedChange(row.name, best)
      }
    })
  }) // eslint-disable-line react-hooks/exhaustive-deps

  const deviceIds = Array.from(selectedDeviceIds)

  // Detect duplicate interface assignments (same target selected for multiple sources).
  const assignedTargets = new Map<string, string[]>()
  Object.entries(interfaceMappings).forEach(([src, tgt]) => {
    if (tgt && !interfaceRemovals.has(src)) {
      assignedTargets.set(tgt, [...(assignedTargets.get(tgt) || []), src])
    }
  })
  Object.values(memberChanges).forEach((map) => {
    Object.entries(map).forEach(([src, tgt]) => {
      if (tgt && tgt !== src) assignedTargets.set(tgt, [...(assignedTargets.get(tgt) || []), src])
    })
  })
  const duplicateWarnings: string[] = []
  assignedTargets.forEach((sources, tgt) => {
    if (sources.length > 1) duplicateWarnings.push(`'${tgt}' is assigned to multiple sources: ${sources.join(', ')}`)
  })

  const handlePreview = async () => {
    setBusy(true)
    try {
      const res = await sanitizeConfig()
      if (!res.success) { alert(res.message || 'Preview failed'); return }
      openViewer('Corrected configuration preview', res.sanitizedYaml || 'No changes.')
    } finally { setBusy(false) }
  }

  const handleFix = async () => {
    setBusy(true)
    try {
      const res = await applyValidationFixes()
      if (!res.success) { alert(res.message || 'Fix failed'); return }
      await revalidate(deviceIds, configCheckboxes)
    } finally { setBusy(false) }
  }

  const handleContinue = async () => {
    setBusy(true)
    try {
      const res = await continueValidatedPush(deviceIds, configCheckboxes)
      if (!res.success) alert(res.message || 'Push failed')
    } finally { setBusy(false) }
  }

  const disabled = busy || isOperationRunning

  // Collect all auto-fixable issue IDs across all reports (using groupIds from deduped issues).
  const allAutoFixableIds: string[] = []
  validationReports.forEach((r) => r.issues.forEach((i) => {
    if (i.autoFixable) {
      const ids = i.groupIds && i.groupIds.length ? i.groupIds : [i.id]
      allAutoFixableIds.push(...ids)
    }
  }))
  const acceptedCount = allAutoFixableIds.filter((id) => !rejectedIssueIds.has(id)).length
  const allChecked = allAutoFixableIds.length > 0 && allAutoFixableIds.every((id) => !rejectedIssueIds.has(id))

  /** Dropdown names filtered by row kind. */
  const namesForKind = (kind: IfaceKind) =>
    kind === 'management' ? managementDeviceIfaces : physicalDeviceIfaces

  // Extract EC ID range from the model schema (first report that has it).
  const ecIdRange = validationReports.find((r) => r.ecIdRange)?.ecIdRange || { min: 1, max: 48 }

  // Separate etherchannel-specific issues (EC ID out-of-range) from general config issues.
  // Live-filter: if the user corrected the EC ID to a valid range, suppress the issue.
  const ecIssuesByName = new Map<string, ValidationIssue[]>()
  const configIssues: { report: ValidationReport; issues: ValidationIssue[] }[] = []
  let ecIdIssuesResolved = 0
  validationReports.forEach((report) => {
    const otherIssues: ValidationIssue[] = []
    ;(report.issues || []).forEach((i) => {
      if (i.section === 'etherchannel_interfaces' && i.field === 'etherChannelId') {
        const corrected = etherchannelIdChanges[i.itemName]
        if (corrected != null && corrected >= ecIdRange.min && corrected <= ecIdRange.max) {
          ecIdIssuesResolved++
          return // issue resolved — skip it
        }
        ecIssuesByName.set(i.itemName, [...(ecIssuesByName.get(i.itemName) || []), i])
      } else if (i.field === 'hardware.speed') {
        // Speed issues are handled in the Interfaces section — skip from Configuration.
        return
      } else {
        otherIssues.push(i)
      }
    })
    configIssues.push({ report, issues: otherIssues })
  })

  // Live blocking count: start from backend blocking total, subtract resolved EC IDs,
  // then compute how many not-on-device interfaces (standalone + members) remain unresolved.
  // An interface is resolved if it's either marked for removal OR mapped to a different target.
  const conflictSourceNames = new Set(allConflicts.map((c) => c.sourceName))
  // Count resolved conflicts (subset of allConflicts that user addressed)
  const resolvedConflicts = allConflicts.filter((c) =>
    interfaceRemovals.has(c.sourceName) || (interfaceMappings[c.sourceName] && interfaceMappings[c.sourceName] !== c.sourceName)
  ).length
  // Backend totals.blocking already includes allConflicts.length, so subtract all conflicts
  // then add back only the unresolved ones. Also add not-on-device that aren't in conflicts.
  const nonConflictUnresolved = standalone.filter((r) =>
    !r.onDevice && !interfaceRemovals.has(r.name)
    && !(interfaceMappings[r.name] && interfaceMappings[r.name] !== r.name)
    && !conflictSourceNames.has(r.name)
  ).length
  // Port-channel groups (etherchannel only)
  const portChannelGroups = memberGroups.filter((g) => g.parentSection === 'etherchannel_interfaces')
  const otherMemberGroups = memberGroups.filter((g) => g.parentSection !== 'etherchannel_interfaces')

  // Port-channel member speed validation: all members must share the same effective speed.
  // Also derive the effective EC speed from uniform member speed.
  const ecSpeedWarnings = new Map<string, string>()
  const ecDerivedSpeed = new Map<string, string>()  // parentName → derived speed
  portChannelGroups.forEach((group) => {
    const memberSpeeds = new Set<string>()
    group.members.forEach((row) => {
      const eff = speedChanges[row.name] || row.speed
      if (eff) memberSpeeds.add(eff)
    })
    if (memberSpeeds.size > 1) {
      ecSpeedWarnings.set(group.parentName, `Members have mixed speeds: ${Array.from(memberSpeeds).join(', ')}`)
    } else if (memberSpeeds.size === 1) {
      ecDerivedSpeed.set(group.parentName, Array.from(memberSpeeds)[0])
    }
  })

  // Sync derived EC speed into the store so it's sent with interfaceCorrections.
  useEffect(() => {
    ecDerivedSpeed.forEach((speed, parentName) => {
      const ecKey = `__ec__${parentName}`
      if (speed && speedChanges[ecKey] !== speed) {
        setSpeedChange(ecKey, speed)
      }
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(Array.from(ecDerivedSpeed.entries()))])

  // ── Early returns (after all hooks) ──
  if (!validationOpen) return null
  if (validationPhase === 'validating') {
    return (
      <Panel>
        <div className="flex items-center gap-3 px-6 py-10 justify-center text-surface-500">
          <Loader2 className="w-5 h-5 animate-spin text-vyper-600" />
          <span className="text-xs">Validating configuration against target device(s)…</span>
        </div>
      </Panel>
    )
  }

  // Build a map of all selected target interface names for duplicate detection.
  // A target is "selected" if the user has explicitly mapped to it (not removed, not the original name).
  const targetCounts = new Map<string, string[]>()  // target name → list of source names
  standalone.forEach((row) => {
    const target = interfaceRemovals.has(row.name) ? '' : (interfaceMappings[row.name] || '')
    if (target && target !== REMOVE && target !== row.name) {
      targetCounts.set(target, [...(targetCounts.get(target) || []), row.name])
    }
  })
  memberGroups.forEach((group) => {
    group.members.forEach((row) => {
      const target = memberChanges[group.parentName]?.[row.name] || ''
      if (target && target !== REMOVE && target !== row.name) {
        targetCounts.set(target, [...(targetCounts.get(target) || []), row.name])
      }
    })
  })
  const duplicateTargets = new Map<string, string[]>()  // target → sources that map to it
  targetCounts.forEach((sources, target) => {
    if (sources.length > 1) duplicateTargets.set(target, sources)
  })
  const duplicateCount = duplicateTargets.size

  const liveBlocking = Math.max(0,
    (totals.blocking - ecIdIssuesResolved)
    - resolvedConflicts
    + nonConflictUnresolved
  ) + duplicateCount

  // First report target for header metadata display
  const firstTarget = validationReports[0]?.target
  const schemaLabel = firstTarget ? (firstTarget.resolvedFtlBranch || validationFmcVersion || firstTarget.fmcVersion || '?') : '?'

  return (
    <Panel>
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3.5 border-b border-surface-100 dark:border-surface-800/50">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <ShieldCheck className="w-4.5 h-4.5 text-vyper-600" />
          <span className="text-[13px] font-semibold text-surface-800 dark:text-surface-200">
            Validate Config review
          </span>
          <div className="flex items-center gap-1.5">
            <Badge n={liveBlocking} sev="blocking" />
            <Badge n={totals.warning} sev="warning" />
            <Badge n={totals.info} sev="info" />
          </div>
          {firstTarget && (
            <div className="flex items-center gap-x-2 text-[10px] text-surface-500">
              <span className="font-semibold text-surface-700 dark:text-surface-300">{firstTarget.deviceName || firstTarget.deviceId}</span>
              <Meta label="Model" value={`${firstTarget.rawModel || '?'}${firstTarget.resolvedSku ? ` → ${firstTarget.resolvedSku}` : ''}`} ok={firstTarget.modelSchemaFound} />
              <Meta label="FTD" value={firstTarget.rawVersion || '?'} />
              <Meta label="FMC Schema" value={schemaLabel} ok={firstTarget.fmcSchemaFound} />
            </div>
          )}
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
      <div className="px-6 py-5 space-y-5 max-h-[45vh] overflow-y-auto">
        {noChanges && liveBlocking === 0 && allRows.every((r) => r.onDevice) && !hasSpeedMismatch && duplicateWarnings.length === 0 && (
          <div className="flex items-center gap-2 text-[11px] text-accent-emerald">
            <Check className="w-4.5 h-4.5" /> No conflicts or unsupported fields detected. You can continue safely.
          </div>
        )}

        {/* Duplicate assignment warnings */}
        {duplicateWarnings.length > 0 && (
          <div className="space-y-1">
            {duplicateWarnings.map((w, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px] text-accent-amber">
                <AlertTriangle className="w-4 h-4 shrink-0" /> {w}
              </div>
            ))}
          </div>
        )}

        {/* ═══ INTERFACES SECTION ═══ */}
        {(standalone.length > 0 || portChannelGroups.length > 0 || otherMemberGroups.length > 0) && (
          <div className="space-y-3">
            <div className="text-[12px] font-semibold text-surface-800 dark:text-surface-200 border-b border-surface-200 dark:border-surface-700 pb-1.5">
              Interfaces
            </div>

            {/* Column headers */}
            <div className="flex items-center gap-2 text-[10px] font-semibold text-surface-500 dark:text-surface-400 px-0.5">
              <span className="w-36">Source</span>
              <span className="flex-1" />
              <span className="mr-[10.5rem]">Target</span>
            </div>

            {/* Physical Interfaces subsection */}
            {standalone.length > 0 && (
              <div>
                <div className="text-[10px] font-semibold text-surface-500 dark:text-surface-400 mb-1">Physical Interfaces</div>
                <div className="space-y-0">
                  {standalone.map((row) => (
                    <InterfaceCorrectionRow
                      key={row.name}
                      row={row}
                      deviceNames={namesForKind(row.kind)}
                      deviceSpeeds={deviceSpeeds}
                      perIfaceSpeeds={perIfaceSpeeds}
                      mapping={interfaceRemovals.has(row.name) ? REMOVE : (interfaceMappings[row.name] || '')}
                      speed={speedChanges[row.name] ?? ''}
                      duplicateTargets={duplicateTargets}
                      onName={(val) => {
                        if (val === REMOVE) { setInterfaceRemoval(row.name, true) }
                        else { setInterfaceRemoval(row.name, false); setInterfaceMapping(row.name, val) }
                      }}
                      onSpeed={(val) => setSpeedChange(row.name, val)}
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Port-channel Interfaces subsection */}
            {portChannelGroups.length > 0 && (
              <div className="space-y-2">
                <div className="text-[10px] font-semibold text-surface-500 dark:text-surface-400">Port-channel Interfaces</div>
                {portChannelGroups.map((group) => {
                  const groupEcIssues = ecIssuesByName.get(group.parentName) || []
                  const speedWarn = ecSpeedWarnings.get(group.parentName)
                  return (
                    <div
                      key={`${group.parentSection}::${group.parentName}`}
                      className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden"
                    >
                      {group.etherchannel && (
                        <EtherchannelHeaderRow
                          ec={group.etherchannel}
                          deviceSpeeds={deviceSpeeds}
                          ecIdRange={ecIdRange}
                          ecIdChange={etherchannelIdChanges[group.parentName]}
                          speedChange={speedChanges[`__ec__${group.parentName}`] ?? ''}
                          derivedSpeed={ecDerivedSpeed.get(group.parentName)}
                          onEcIdChange={(v) => setEtherchannelIdChange(group.parentName, v)}
                          onSpeedChange={(v) => setSpeedChange(`__ec__${group.parentName}`, v)}
                          ecIssues={groupEcIssues}
                          speedWarning={speedWarn}
                        />
                      )}
                      <div className="px-3 py-2 space-y-0">
                        {group.members.map((row) => (
                          <InterfaceCorrectionRow
                            key={`${group.parentName}::${row.name}`}
                            row={row}
                            deviceNames={physicalDeviceIfaces}
                            deviceSpeeds={deviceSpeeds}
                            perIfaceSpeeds={perIfaceSpeeds}
                            mapping={memberChanges[group.parentName]?.[row.name] || ''}
                            speed={speedChanges[row.name] ?? ''}
                            duplicateTargets={duplicateTargets}
                            onName={(val) => setMemberChange(group.parentName, row.name, val)}
                            onSpeed={(val) => setSpeedChange(row.name, val)}
                          />
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Other member groups (BVI, Inline-set, Redundant) */}
            {otherMemberGroups.map((group) => {
              const sectionLabel = group.parentSection === 'bridge_group_interfaces' ? 'BVI'
                : group.parentSection === 'inline_sets' ? 'Inline Set'
                : 'Redundant'
              return (
                <Section
                  key={`${group.parentSection}::${group.parentName}`}
                  title={`${sectionLabel}: ${group.parentName} — members (${group.members.length})`}
                  sev={group.members.some((m) => !m.onDevice && !memberChanges[group.parentName]?.[m.name]) ? 'blocking' : 'info'}
                >
                  <div className="space-y-0">
                    {group.members.map((row) => (
                      <InterfaceCorrectionRow
                        key={`${group.parentName}::${row.name}`}
                        row={row}
                        deviceNames={physicalDeviceIfaces}
                        deviceSpeeds={deviceSpeeds}
                        perIfaceSpeeds={perIfaceSpeeds}
                        mapping={memberChanges[group.parentName]?.[row.name] || ''}
                        speed={speedChanges[row.name] ?? ''}
                        duplicateTargets={duplicateTargets}
                        onName={(val) => setMemberChange(group.parentName, row.name, val)}
                        onSpeed={(val) => setSpeedChange(row.name, val)}
                      />
                    ))}
                  </div>
                </Section>
              )
            })}
          </div>
        )}

        {/* ═══ CONFIGURATION SECTION ═══ */}
        {configIssues.some((ci) => ci.issues.length > 0) && (
          <div className="space-y-3">
            <div className="text-[12px] font-semibold text-surface-800 dark:text-surface-200 border-b border-surface-200 dark:border-surface-700 pb-1.5">
              Configuration
            </div>
            {configIssues.map(({ report, issues }) => {
              if (issues.length === 0) return null
              return (
                <div key={report.target.deviceId || report.target.deviceName} className="space-y-2">
                  {issues.map((i) => {
                    const ids = i.groupIds && i.groupIds.length ? i.groupIds : [i.id]
                    const allAccepted = i.autoFixable && ids.every((id) => !rejectedIssueIds.has(id))
                    return (
                      <IssueRow
                        key={i.id}
                        issue={i}
                        accepted={allAccepted}
                        onToggle={() => ids.forEach((id) => toggleRejectedIssue(id))}
                      />
                    )
                  })}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Footer actions */}
      <div className="flex flex-wrap items-center gap-2.5 px-6 py-3.5 border-t border-surface-100 dark:border-surface-800/50">
        <button
          onClick={handlePreview}
          disabled={disabled}
          className={btn('secondary', disabled)}
          title="Preview the full corrected YAML as if fixes were applied"
        >
          <Eye className="w-4 h-4" /> Preview
        </button>
        {allAutoFixableIds.length > 0 && (
          <label className="flex items-center gap-1.5 text-[10px] text-surface-500 cursor-pointer select-none ml-2" title="Select / deselect all fixable issues">
            <input
              type="checkbox"
              checked={allChecked}
              onChange={() => {
                const rejectAll = allChecked
                allAutoFixableIds.forEach((id) => {
                  if (rejectAll && !rejectedIssueIds.has(id)) toggleRejectedIssue(id)
                  else if (!rejectAll && rejectedIssueIds.has(id)) toggleRejectedIssue(id)
                })
              }}
              className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
            />
            All ({acceptedCount}/{allAutoFixableIds.length})
          </label>
        )}
        <div className="flex-1" />
        <button
          onClick={handleFix}
          disabled={disabled}
          className={btn('primary', disabled)}
          title="Apply the accepted fixes + interface corrections to the loaded YAML, then re-validate"
        >
          <Wrench className="w-4 h-4" /> Fix
        </button>
        <button
          onClick={() => { setBusy(true); revalidate(deviceIds, configCheckboxes).finally(() => setBusy(false)) }}
          disabled={disabled}
          className={btn('secondary', disabled)}
          title="Re-run validation against the currently loaded YAML"
        >
          <RefreshCw className="w-4 h-4" /> Revalidate
        </button>
        <button
          onClick={handleContinue}
          disabled={disabled}
          className={btn('primary', disabled)}
          title="Proceed and push the currently loaded configuration"
        >
          <Send className="w-4 h-4" /> Continue
        </button>
        <button
          onClick={cancelValidation}
          disabled={disabled}
          className={btn('danger', disabled)}
        >
          <X className="w-4 h-4" /> Cancel
        </button>
      </div>
      </>}
    </Panel>
  )
}

// ── Interface correction row ──

/** Etherchannel header row: displays above members with EC ID + speed editing + EC issues */
function EtherchannelHeaderRow({
  ec, deviceSpeeds, ecIdRange, ecIdChange, speedChange, derivedSpeed, onEcIdChange, onSpeedChange,
  ecIssues, speedWarning,
}: {
  ec: EtherchannelRow
  deviceSpeeds: string[]
  ecIdRange: { min: number; max: number }
  ecIdChange: number | undefined
  speedChange: string
  derivedSpeed?: string
  onEcIdChange: (v: number | null) => void
  onSpeedChange: (v: string) => void
  ecIssues: ValidationIssue[]
  speedWarning?: string
}) {
  const speedOptions = Array.from(new Set([...(ec.speed ? [ec.speed] : []), ...deviceSpeeds])).filter((s) => s !== 'AUTO' && s !== 'DETECT_SFP')
  const selCls = 'w-40 truncate rounded border border-surface-300 dark:border-surface-600 bg-white dark:bg-surface-800 px-1.5 py-1 text-[11px] text-surface-700 dark:text-surface-300 focus:outline-none focus:ring-1 focus:ring-vyper-500 disabled:opacity-50'
  const ecIdVal = ecIdChange ?? ec.ecId
  const ecIdValid = ecIdVal >= ecIdRange.min && ecIdVal <= ecIdRange.max
  const hasEcError = ecIssues.length > 0 && !ecIdValid

  return (
    <div className={cn(
      'flex flex-col gap-1.5 text-[11px] py-2 px-3 bg-surface-50 dark:bg-surface-800/40 border-b border-surface-200 dark:border-surface-700',
    )}>
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="font-mono font-semibold text-surface-700 dark:text-surface-300">{ec.name}</span>
        <span className="text-[9px] text-surface-500 dark:text-surface-400">members</span>
        <label className="flex items-center gap-1.5 text-[10px] text-surface-500 dark:text-surface-400">
          EtherChannel ID
          <input
            type="number"
            min={ecIdRange.min}
            max={ecIdRange.max}
            value={ecIdVal}
            onChange={(e) => {
              const v = e.target.value.trim()
              onEcIdChange(v ? parseInt(v, 10) : null)
            }}
            className={cn(
              'w-16 rounded border bg-white dark:bg-surface-800 px-1.5 py-1 text-[11px] text-surface-700 dark:text-surface-300 focus:outline-none focus:ring-1 focus:ring-vyper-500',
              hasEcError ? 'border-accent-rose/60' : ecIdValid && ecIssues.length > 0 ? 'border-accent-emerald/60' : 'border-surface-300 dark:border-surface-600',
            )}
          />
          {ecIdValid && ecIssues.length > 0 && (
            <Check className="w-3.5 h-3.5 text-accent-emerald" />
          )}
        </label>
        <label className="flex items-center gap-1.5 text-[10px] text-surface-500 dark:text-surface-400">
          Speed
          {derivedSpeed ? (
            <>
              <span
                className={cn(selCls, 'inline-block opacity-70')}
                title={`Derived from member interfaces (${derivedSpeed})`}
              >{derivedSpeed}</span>
              <span className="text-[9px] text-accent-sky" title="Speed derived from member interfaces">synced</span>
            </>
          ) : (
            <select
              value={speedChange}
              onChange={(e) => onSpeedChange(e.target.value)}
              className={selCls}
            >
              <option value="">{ec.speed || 'not set'}</option>
              {speedOptions.filter((s) => s !== ec.speed).map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          )}
        </label>
      </div>
      {hasEcError && ecIssues.map((issue) => (
        <div key={issue.id} className="flex items-start gap-1.5 text-[10px] text-accent-rose">
          <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <div className="flex-1">
            <span>{issue.message}</span>
            {issue.proposedAction && <span className="ml-1.5 text-vyper-600 dark:text-vyper-400">{issue.proposedAction}</span>}
          </div>
        </div>
      ))}
      {speedWarning && (
        <div className="flex items-start gap-1.5 text-[10px] text-accent-amber">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span>{speedWarning}</span>
        </div>
      )}
    </div>
  )
}

function InterfaceCorrectionRow({
  row, deviceNames, deviceSpeeds, perIfaceSpeeds, mapping, speed, duplicateTargets, onName, onSpeed,
}: {
  row: IfaceRow
  deviceNames: string[]
  deviceSpeeds: string[]
  perIfaceSpeeds: Map<string, string[]>
  mapping: string
  speed: string
  duplicateTargets: Map<string, string[]>
  onName: (val: string) => void
  onSpeed: (val: string) => void
}) {
  const effectiveMapping = !row.onDevice && !mapping ? REMOVE : mapping
  const removed = effectiveMapping === REMOVE
  // Use per-interface speeds from model schema if available, else fallback to global device speeds.
  // Filter out AUTO always; filter DETECT_SFP unless this is an SFP port.
  const ifaceSpeeds = perIfaceSpeeds.get(row.name)
  const sfp = isSfpPort(row.name, perIfaceSpeeds)
  const rawSpeedOptions = ifaceSpeeds
    ? Array.from(new Set([...(row.speed ? [row.speed] : []), ...ifaceSpeeds]))
    : Array.from(new Set([...(row.speed ? [row.speed] : []), ...deviceSpeeds]))
  const speedOptions = rawSpeedOptions.filter((s) => s !== 'AUTO' && (sfp || s !== 'DETECT_SFP'))
  const selCls = 'w-40 truncate rounded border border-surface-300 dark:border-surface-600 bg-white dark:bg-surface-800 px-1.5 py-1 text-[11px] text-surface-700 dark:text-surface-300 focus:outline-none focus:ring-1 focus:ring-vyper-500 disabled:opacity-50'
  const speedMismatch = row.onDevice && row.speed && row.deviceSpeed && row.speed !== row.deviceSpeed

  // Only show device-present interfaces in the name dropdown (exclude the source name if not on device).
  const nameOptions = deviceNames.filter((n) => n !== row.name)

  // Check if the effective target is a duplicate.
  const effectiveTarget = effectiveMapping && effectiveMapping !== REMOVE ? effectiveMapping : ''
  const isDuplicate = effectiveTarget && effectiveTarget !== row.name && duplicateTargets.has(effectiveTarget)
  const dupSources = isDuplicate ? duplicateTargets.get(effectiveTarget)! : []

  return (
    <div className={cn(
      'flex flex-wrap items-center gap-2 text-[11px] py-1 border-b border-surface-100 dark:border-surface-800/40 last:border-0',
      removed && 'opacity-60',
    )}>
      <span className={cn(
        'font-mono px-1.5 py-0.5 rounded w-36 truncate inline-block text-[10px]',
        row.onDevice ? 'bg-accent-emerald/10 text-accent-emerald' : 'bg-accent-rose/10 text-accent-rose',
      )}>
        {row.name}
      </span>
      {!row.onDevice && <span className="text-[9px] text-accent-rose">not on device</span>}
      {speedMismatch && (
        <span className="text-[9px] text-accent-amber" title={`YAML speed '${row.speed}' differs from device speed '${row.deviceSpeed}'`}>
          speed mismatch
        </span>
      )}
      {isDuplicate && (
        <span className="text-[9px] text-accent-rose font-medium" title={`${effectiveTarget} is also mapped from: ${dupSources.filter((s) => s !== row.name).join(', ')}`}>
          duplicate target
        </span>
      )}
      <span className="text-[9px] text-surface-400">{row.contexts.join(', ')}</span>

      <label className="ml-auto flex items-center gap-1 text-[10px] text-surface-500">
        Name
        <select value={effectiveMapping} onChange={(e) => onName(e.target.value)} className={cn(selCls, isDuplicate && 'border-accent-rose/60')}>
          {row.onDevice
            ? <option value="">{row.name}</option>
            : <option value="" disabled>{row.name} (not on device)</option>
          }
          {nameOptions.map((n) => <option key={n} value={n}>{n}</option>)}
          <option value={REMOVE}>None (remove)</option>
        </select>
      </label>

      {row.allowSpeed && (
        <label className="flex items-center gap-1 text-[10px] text-surface-500">
          Speed
          <select
            value={speed}
            onChange={(e) => onSpeed(e.target.value)}
            disabled={removed}
            className={cn(selCls, speedMismatch && !speed && 'border-accent-amber/60')}
          >
            <option value="">{row.speed || 'not set'}</option>
            {speedOptions.filter((s) => s !== row.speed).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      )}
    </div>
  )
}

// ── Issue row ──

function IssueRow({ issue, accepted, onToggle }: {
  issue: ValidationIssue
  accepted: boolean
  onToggle: () => void
}) {
  const meta = SEVERITY_META[issue.severity] || SEVERITY_META.info
  const Icon = meta.icon
  const count = issue.count || 1

  return (
    <div
      className={cn(
        'flex items-start gap-2 text-[11px] py-1 border-b border-surface-100 dark:border-surface-800/40 last:border-0',
        issue.autoFixable && 'cursor-pointer hover:bg-surface-50 dark:hover:bg-surface-800/30',
      )}
      onClick={issue.autoFixable ? onToggle : undefined}
    >
      <Icon className={cn('w-3.5 h-3.5 mt-0.5 shrink-0', meta.cls)} />
      <div className="flex-1 min-w-0">
        <div className="text-surface-700 dark:text-surface-300">{issue.message}</div>
        <div className="flex flex-wrap items-center gap-2 mt-0.5 text-[10px] text-surface-500">
          {issue.section && <span className="font-mono">{issue.section}</span>}
          {issue.field && <span className="font-mono px-1 rounded bg-surface-100 dark:bg-surface-800">{issue.field}</span>}
          {issue.proposedAction && <span className="text-vyper-600 dark:text-vyper-400">{issue.proposedAction}</span>}
        </div>
      </div>
      {count > 1 && (
        <span
          className="text-[11px] font-semibold text-surface-500 dark:text-surface-400 shrink-0 tabular-nums cursor-help mr-2"
          title={issue.groupFields?.join('\n') || `${count} identical occurrences`}
        >
          ×{count}
        </span>
      )}
      {issue.autoFixable ? (
        <label className="flex items-center gap-1 text-[10px] text-surface-500 shrink-0 cursor-pointer" title="Include this fix when applying" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={accepted}
            onChange={onToggle}
            className="rounded border-surface-300 text-vyper-600 focus:ring-vyper-500/30"
          />
        </label>
      ) : (
        <span className="text-[10px] text-surface-400 shrink-0">manual</span>
      )}
    </div>
  )
}

// ── Small UI helpers ──

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div id="validation-review-panel" className="rounded-xl border border-vyper-300/50 dark:border-vyper-700/40 bg-white dark:bg-surface-900/50 overflow-hidden shadow-sm">
      {children}
    </div>
  )
}

function Section({ title, sev, children }: { title: string; sev: keyof typeof SEVERITY_META; children: React.ReactNode }) {
  const meta = SEVERITY_META[sev]
  const Icon = meta.icon
  return (
    <div>
      <div className={cn('flex items-center gap-1.5 text-[11px] font-medium mb-2', meta.cls)}>
        <Icon className="w-4 h-4" /> {title}
      </div>
      {children}
    </div>
  )
}

function Badge({ n, sev }: { n: number; sev: keyof typeof SEVERITY_META }) {
  const meta = SEVERITY_META[sev]
  if (!n) return null
  return (
    <span className={cn('text-[10px] font-medium px-1.5 py-0.5 rounded-full border', meta.cls,
      sev === 'blocking' && 'border-accent-rose/30 bg-accent-rose/10',
      sev === 'warning' && 'border-accent-amber/30 bg-accent-amber/10',
      sev === 'info' && 'border-accent-sky/30 bg-accent-sky/10',
    )}>
      {n} {meta.label.toLowerCase()}
    </span>
  )
}

function Meta({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <span className="text-[10px] text-surface-500">
      {label}: <span className={cn('font-mono', ok === false ? 'text-accent-amber' : 'text-surface-700 dark:text-surface-300')}>{value}</span>
    </span>
  )
}

function btn(variant: 'primary' | 'secondary' | 'danger' | 'warning', disabled: boolean) {
  return cn(
    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
    variant === 'primary' && 'bg-vyper-600 hover:bg-vyper-700 text-white',
    variant === 'secondary' && 'border border-surface-200 dark:border-surface-700 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800',
    variant === 'danger' && 'border border-accent-rose/30 text-accent-rose/80 hover:bg-accent-rose/10',
    variant === 'warning' && 'border border-accent-amber/30 text-accent-amber hover:bg-accent-amber/10',
    disabled && 'opacity-40 pointer-events-none',
  )
}
