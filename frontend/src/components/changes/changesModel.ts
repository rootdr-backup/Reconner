import { diffWordsWithSpace } from 'diff'
import type { ChangeCategory, ChangeEntry, MonitoringChange } from '../../types'

export type ChangeFilter = ChangeCategory | 'all'

export const CHANGE_FILTERS: { id: ChangeFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'security', label: 'Security' },
  { id: 'scripts', label: 'Scripts' },
  { id: 'http', label: 'HTTP' },
  { id: 'tech', label: 'Tech' },
  { id: 'headers', label: 'Headers' },
  { id: 'assets', label: 'Assets & scope' },
  { id: 'alerts', label: 'Alerts' },
]

export const CATEGORY_BY_TYPE: Record<string, ChangeCategory> = {
  status_change: 'http',
  http_change: 'http',
  http_service_removed: 'http',
  new_http_service: 'http',
  page_change: 'http',
  js_change: 'scripts',
  css_change: 'scripts',
  tech_change: 'tech',
  new_subdomain: 'assets',
  subdomain_removed: 'assets',
  host_status_change: 'assets',
  scope_landed: 'assets',
  scope_re_eligible: 'assets',
  security_header_removed: 'headers',
  watch_failed: 'alerts',
  watch_kind_conflict: 'alerts',
  monitor_failed: 'alerts',
  monitor_escalation_started: 'alerts',
  scan_auto_paused: 'alerts',
}

export function categoryForChangeType(changeType: string): ChangeCategory {
  if (!changeType) return 'http'
  const exact = CATEGORY_BY_TYPE[changeType]
  if (exact) return exact
  if (changeType === 'js_change' || changeType.includes('script') || changeType.includes('stylesheet')) return 'scripts'
  if (changeType.includes('header')) return 'headers'
  if (changeType.startsWith('security')) return 'security'
  return 'http'
}

// changeHosts returns the new-host names stored on a new_subdomain ChangeEntry.
// Returns null for any other change type, missing metadata, or a non-string
// hosts value so callers can keep the prior count-only rendering.
export function changeHosts(item: Pick<ChangeEntry, 'change_type' | 'metadata'>): string[] | null {
  if (item.change_type !== 'new_subdomain') return null
  const hosts = item.metadata?.hosts
  if (!Array.isArray(hosts)) return null
  const out = hosts.filter((h): h is string => typeof h === 'string' && h.length > 0)
  return out.length > 0 ? out : null
}

// Bucket order follows the API taxonomy: stylesheet/script markers win before
// the generic "security:" prefix, and any header change lands in Headers.
export const monitorRowKind = (c: { change_type?: string }): ChangeFilter => {
  const ct = typeof c?.change_type === 'string' ? c.change_type : ''
  return categoryForChangeType(ct)
}

export type ChangeBadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const changeBadgeVariant = (c: { severity?: string; change_type?: string }): ChangeBadgeVariant => {
  const sev = (c.severity || '').toLowerCase()
  if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'info') {
    return sev as ChangeBadgeVariant
  }
  const ct = typeof c.change_type === 'string' ? c.change_type : ''
  return ct === 'js_change' ? 'medium'
    : ct.startsWith('security') || ct.includes('header') ? 'high'
      : ct === 'tech_change' ? 'low'
        : 'info'
}

export interface ChangeLike {
  change_type?: string
  old_value?: string
  new_value?: string
  url?: string
}

export interface MonitorChangeGroup<T extends ChangeLike = MonitoringChange> {
  key: string
  rep: T
  items: T[]
  urls: string[]
}

export const OCCURRENCE_PAGE_SIZE = 200

export type GroupIdentity<T> = string | ((row: T) => string)

export function groupMonitorChanges<T extends ChangeLike>(rows: T[], identity: GroupIdentity<T> = ''): MonitorChangeGroup<T>[] {
  const groups = new Map<string, MonitorChangeGroup<T>>()
  for (const c of rows) {
    const id = typeof identity === 'function' ? identity(c) : identity
    const prefix = id ? `${id}\u0000` : ''
    const key = `${prefix}${c.change_type || ''}\u0000${c.old_value || ''}\u0000${c.new_value || ''}`
    const g = groups.get(key)
    if (g) g.items.push(c)
    else groups.set(key, { key, rep: c, items: [c], urls: [] })
  }
  for (const g of groups.values()) {
    g.urls = [...new Set(g.items.map(i => i.url || ''))]
  }
  return [...groups.values()]
}

export function parseStatusTransition(oldValue: string, newValue: string): { oldCode?: number; newCode?: number } {
  const pick = (value: string) => {
    const text = value || ''
    const explicit = /(?:^|[\s,])status=(\d{3})(?!\d)/.exec(text)
    const match = explicit || /\b([1-5]\d{2})\b/.exec(text)
    if (!match) return undefined
    const code = Number(match[1])
    return Number.isFinite(code) ? code : undefined
  }
  return { oldCode: pick(oldValue), newCode: pick(newValue) }
}

export interface InlineDiffPiece {
  kind: 'same' | 'added' | 'removed'
  text: string
}

export function inlineDiffPieces(oldValue: string, newValue: string): InlineDiffPiece[] {
  return diffWordsWithSpace(oldValue || '', newValue || '').map(part => ({
    kind: part.added ? 'added' : part.removed ? 'removed' : 'same',
    text: part.value,
  }))
}
