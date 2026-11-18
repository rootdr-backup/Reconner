import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { changes, targets as targetsApi, watchApi } from '../../lib/api'
import type { ChangeEntry, Target, WatchRound } from '../../types'
import { Badge, Button, CopyButton, Empty, SkeletonRows } from '../ui'
import { cn, timeAgo } from '../../lib/utils'
import { ws } from '../../lib/websocket'
import {
  CHANGE_FILTERS, changeBadgeVariant, type ChangeFilter,
} from './changesModel'
import InlineChangeDiff from './InlineChangeDiff'
import { ChangeDiffViewer } from '../targets/ChangeDiffViewer'

type DiffView = { targetId: string; url: string; kind: 'css' | 'js' }

const PAGE = 200

const TIME_FILTERS = [
  { id: '0', label: 'All time' },
  { id: '12', label: '12h' },
  { id: '24', label: '24h' },
  { id: '168', label: '7d' },
  { id: '720', label: '1mo' },
  { id: '1440', label: '2mo' },
  { id: '2160', label: '3mo' },
  { id: '-1', label: 'Custom' },
]

const FIELD_LABELS: Record<string, string> = {
  status_change: 'Status code',
  http_change: 'HTTP / page',
  http_service_removed: 'Service removed',
  new_http_service: 'New service',
  page_change: 'Page',
  js_change: 'JavaScript',
  css_change: 'Stylesheet',
  tech_change: 'Technologies',
  new_subdomain: 'New host',
  subdomain_removed: 'Host removed',
  host_status_change: 'Host status',
  scope_landed: 'Scope landed',
  scope_re_eligible: 'Scope re-eligible',
  security_header_removed: 'Security header',
  watch_failed: 'Watch failed',
  watch_kind_conflict: 'Watch conflict',
  monitor_failed: 'Monitor failed',
  monitor_escalation_started: 'Escalation',
  scan_auto_paused: 'Auto paused',
}

const ROUND_DOT: Record<string, string> = {
  running: 'bg-severity-medium',
  finished: 'bg-severity-low',
  completed: 'bg-severity-low',
  failed: 'bg-severity-critical',
  cancelled: 'bg-text-muted',
  interrupted: 'bg-text-muted',
}

function fieldLabel(changeType: string): string {
  if (!changeType) return 'CHANGE'
  if (FIELD_LABELS[changeType]) return FIELD_LABELS[changeType].toUpperCase()
  if (changeType.startsWith('security:')) {
    return changeType.slice('security:'.length).replace(/_/g, ' ').toUpperCase()
  }
  return changeType.replace(/_/g, ' ').toUpperCase()
}

function sinceFor(hours: string, custom: string): string {
  if (hours === '-1') return custom ? new Date(custom).toISOString() : ''
  if (hours === '0' || !hours) return ''
  const ms = Number(hours) * 3600_000
  if (!Number.isFinite(ms)) return ''
  return new Date(Date.now() - ms).toISOString()
}

function fmtDate(value: string): string {
  if (!value) return '—'
  const iso = value.includes('T') ? value : value.replace(' ', 'T') + 'Z'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

interface ChangeCard {
  key: string
  target_id: string
  target_name: string
  url: string
  task_id: string
  source: string
  seen: boolean
  detected_at: string
  items: ChangeEntry[]
}

// One card per host per scan. task_id identifies a watch round; rows without
// one use the exact timestamp, which groups rows written by the same pass.
function groupIntoCards(rows: ChangeEntry[]): ChangeCard[] {
  const map = new Map<string, ChangeCard>()
  for (const r of rows) {
    const key = `${r.target_id}\u0000${r.url}\u0000${r.task_id || r.detected_at}`
    let card = map.get(key)
    if (!card) {
      card = {
        key, target_id: r.target_id, target_name: r.target_name, url: r.url,
        task_id: r.task_id || '', source: r.source, seen: false,
        detected_at: r.detected_at, items: [],
      }
      map.set(key, card)
    }
    card.items.push(r)
    if (r.detected_at > card.detected_at) card.detected_at = r.detected_at
  }
  for (const card of map.values()) card.seen = card.items.every(i => i.seen)
  return [...map.values()].sort((a, b) => b.detected_at.localeCompare(a.detected_at))
}

function SourceBadge({ source }: { source: string }) {
  const map: Record<string, { label: string; className: string }> = {
    watch: { label: 'Watch', className: 'border-accent/50 bg-accent/10 text-accent' },
    monitor: { label: 'Deep', className: 'border-border text-text-muted' },
    scope: { label: 'Scope', className: 'border-severity-medium/40 bg-severity-medium/10 text-severity-medium' },
    notification: { label: 'Bell', className: 'border-severity-low/40 bg-severity-low/10 text-severity-low' },
  }
  const s = map[source] || { label: source, className: 'border-border text-text-muted' }
  return (
    <span className={cn('rounded-full border px-1.5 py-0.5 text-[10px]', s.className)}>
      {s.label}
    </span>
  )
}

interface Props {
  targetId?: string
  compact?: boolean
}

export default function ChangeLog({ targetId, compact }: Props) {
  const [hours, setHours] = useState('0')
  const [customSince, setCustomSince] = useState('')
  const [category, setCategory] = useState<ChangeFilter>('all')
  const [source, setSource] = useState('')
  const [severity, setSeverity] = useState('')
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [selectedTaskId, setSelectedTaskId] = useState('')
  const [hideSeen, setHideSeen] = useState(false)
  const [rows, setRows] = useState<ChangeEntry[]>([])
  const [rounds, setRounds] = useState<WatchRound[]>([])
  const [targetList, setTargetList] = useState<Target[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [serverTotal, setServerTotal] = useState(0)
  const [detail, setDetail] = useState<ChangeCard | null>(null)
  const [diffView, setDiffView] = useState<DiffView | null>(null)

  const requestSeq = useRef(0)
  const pageCount = useRef(1)
  const reloadTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (targetId) return
    let alive = true
    targetsApi.list().then(list => { if (alive) setTargetList(list || []) }).catch(() => {})
    return () => { alive = false }
  }, [targetId])

  const params = useCallback((): Record<string, string> => {
    const p: Record<string, string> = {}
    const since = sinceFor(hours, customSince)
    if (since) p.since = since
    if (category !== 'all') p.category = category
    if (source) p.source = source
    if (severity) p.severity = severity
    if (selectedTaskId) p.task_id = selectedTaskId
    const t = targetId || selectedTargetId
    if (t) p.target_id = t
    return p
  }, [hours, customSince, category, source, severity, selectedTaskId, targetId, selectedTargetId])

  const load = useCallback(async (reset = false) => {
    const seq = ++requestSeq.current
    setLoading(true)
    setError('')
    if (reset) pageCount.current = 1
    const p = params()
    const roundTarget = targetId || selectedTargetId
    try {
      const [changeRows, roundRows] = await Promise.all([
        targetId
          ? changes.forTarget(targetId, p)
          : Promise.all(
            Array.from({ length: pageCount.current }, (_, i) =>
              changes.listPage({ ...p, page: String(i + 1), limit: String(PAGE) })),
          ).then(pages => {
            const merged: ChangeEntry[] = []
            const ids = new Set<string>()
            for (const page of pages) {
              setServerTotal(page.total)
              for (const row of page.data) {
                if (!ids.has(row.id)) { ids.add(row.id); merged.push(row) }
              }
            }
            return merged
          }),
        watchApi.rounds(roundTarget ? { target_id: roundTarget } : {}),
      ])
      if (seq !== requestSeq.current) return
      setRows(changeRows)
      setRounds(roundRows)
    } catch (e) {
      if (seq === requestSeq.current) setError(e instanceof Error ? e.message : 'Failed to load changes')
    } finally {
      if (seq === requestSeq.current) setLoading(false)
    }
  }, [params, targetId, selectedTargetId])

  useEffect(() => { void load(true) }, [load])

  useEffect(() => {
    const schedule = () => {
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
      reloadTimer.current = setTimeout(() => { void load() }, 2500)
    }
    const offs = [
      ws.on('task_progress', schedule),
      ws.on('task_finished', schedule),
      ws.on('scope_landed', schedule),
      ws.on('notification_created', schedule),
    ]
    const poll = setInterval(() => { void load() }, 30000)
    return () => {
      offs.forEach(off => off())
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
      clearInterval(poll)
    }
  }, [load])

  const loadMore = async () => {
    const next = pageCount.current + 1
    const seq = ++requestSeq.current
    setLoading(true)
    try {
      const res = await changes.listPage({ ...params(), page: String(next), limit: String(PAGE) })
      if (seq !== requestSeq.current) return
      pageCount.current = next
      setServerTotal(res.total)
      setRows(prev => {
        const ids = new Set(prev.map(r => r.id))
        const added = res.data.filter(r => !ids.has(r.id))
        return added.length ? [...prev, ...added] : prev
      })
    } catch (e) {
      if (seq === requestSeq.current) setError(e instanceof Error ? e.message : 'Failed to load more changes')
    } finally {
      if (seq === requestSeq.current) setLoading(false)
    }
  }

  const applySeen = (ids: string[], seen: boolean) => {
    const idSet = new Set(ids)
    setRows(prev => prev.map(r => idSet.has(r.id) ? { ...r, seen } : r))
    setDetail(prev => {
      if (!prev) return prev
      const items = prev.items.map(i => idSet.has(i.id) ? { ...i, seen } : i)
      return { ...prev, items, seen: items.every(i => i.seen) }
    })
  }

  const toggleCardSeen = async (card: ChangeCard) => {
    const seen = !card.seen
    const ids = card.items.map(i => i.id)
    try {
      await changes.setSeen(ids, seen)
      applySeen(ids, seen)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update read state')
    }
  }

  const markAllRead = async () => {
    try {
      const res = await changes.markAllSeen(params())
      if (res.updated > 0) await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to mark all read')
    }
  }

  const visibleRows = useMemo(() => hideSeen ? rows.filter(r => !r.seen) : rows, [rows, hideSeen])
  const cards = useMemo(() => groupIntoCards(visibleRows), [visibleRows])

  return (
    <div className={cn('space-y-3', compact && 'space-y-2')}>
      {/* Time filter */}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-[10px] uppercase tracking-wide text-text-muted">Since</span>
        {TIME_FILTERS.map(f => (
          <button
            key={f.id}
            type="button"
            onClick={() => setHours(f.id)}
            className={cn(
              'rounded-full border px-2.5 py-1 text-[11px] transition',
              hours === f.id
                ? 'border-accent bg-accent/15 text-accent'
                : 'border-border text-text-muted hover:text-text-primary',
            )}
          >
            {f.label}
          </button>
        ))}
        {hours === '-1' && (
          <input
            className="input w-auto py-1 text-xs"
            type="datetime-local"
            value={customSince}
            onChange={e => setCustomSince(e.target.value)}
          />
        )}
      </div>

      {/* Category and source filters */}
      <div className="flex flex-wrap items-center gap-1.5">
        {CHANGE_FILTERS.map(chip => (
          <button
            key={chip.id}
            type="button"
            onClick={() => setCategory(chip.id)}
            className={cn(
              'rounded-full border px-2.5 py-1 text-[11px] transition',
              category === chip.id
                ? 'border-accent bg-accent/15 text-accent'
                : 'border-border text-text-muted hover:text-text-primary',
            )}
          >
            {chip.label}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-y border-white/[.06] py-2">
        <select className="input w-auto py-1 text-xs" value={source} onChange={e => setSource(e.target.value)}>
          <option value="">All sources</option>
          {['monitor', 'watch', 'scope', 'notification'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input w-auto py-1 text-xs" value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {!targetId && (
          <select className="input w-auto py-1 text-xs" value={selectedTargetId} onChange={e => setSelectedTargetId(e.target.value)}>
            <option value="">All targets</option>
            {targetList.map(t => (
              <option key={t.id} value={t.id}>{t.name || t.domain}</option>
            ))}
          </select>
        )}
        <label className="flex items-center gap-1 text-[11px] text-text-muted">
          <input type="checkbox" checked={hideSeen} onChange={e => setHideSeen(e.target.checked)} />
          Hide seen
        </label>
        <button
          type="button"
          onClick={() => void markAllRead()}
          className="text-[11px] text-accent hover:underline"
        >
          Mark all read
        </button>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading}
          className="ml-auto text-[11px] text-text-muted hover:text-text-primary disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {/* Slim watch round strip. Status word stays visible, not just the dot. */}
      {rounds.length > 0 && (
        <div className="flex items-center gap-1.5 overflow-x-auto py-1.5">
          <span className="shrink-0 mr-1 text-[10px] uppercase tracking-wide text-text-muted">Rounds</span>
          {rounds.slice(0, 20).map(r => (
            <button
              key={r.id}
              type="button"
              onClick={() => setSelectedTaskId(prev => prev === r.id ? '' : r.id)}
              className={cn(
                'shrink-0 rounded-full border px-2.5 py-1 text-[11px] transition',
                selectedTaskId === r.id
                  ? 'border-accent bg-accent/15 text-accent'
                  : 'border-border text-text-muted hover:text-text-primary',
              )}
              title={`${r.target_name} · ${r.status} · ${r.change_count} change(s)`}
            >
              <span className={cn('mr-1 inline-block h-1.5 w-1.5 rounded-full', ROUND_DOT[r.status] || 'bg-text-muted')} />
              {r.target_name || r.target_id} · {timeAgo(r.finished_at || r.started_at)} · {r.change_count}
              <span className="ml-1 opacity-70">{r.status}</span>
            </button>
          ))}
          {selectedTaskId && (
            <button type="button" onClick={() => setSelectedTaskId('')} className="shrink-0 text-[10px] text-accent hover:underline">
              Clear
            </button>
          )}
        </div>
      )}

      {error && <p className="rounded-lg border border-severity-medium/30 bg-severity-medium/10 px-3 py-2 text-xs text-severity-medium">{error}</p>}

      {/* The change log feed */}
      <div className="overflow-hidden rounded-xl border border-white/[.06] bg-white/[.02]">
        {loading ? (
          <div className="py-2"><SkeletonRows rows={8} cols={3} /></div>
        ) : cards.length === 0 ? (
          <Empty message={hideSeen ? 'All changes are marked as seen.' : 'No changes recorded yet.'} />
        ) : (
          cards.map(card => {
            const first = card.items[0]
            const canDiff = first.source === 'monitor' &&
              (first.change_type === 'css_change' || first.change_type === 'js_change') && !!first.url
            return (
              <div
                key={card.key}
                className={cn('border-b border-white/[.05] px-3 py-3 last:border-0', card.seen && 'opacity-40')}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="shrink-0 text-[10px] tabular-nums text-text-muted">{fmtDate(card.detected_at)}</span>
                  <SourceBadge source={card.source} />
                  {!targetId && (
                    <span className="max-w-[160px] shrink-0 truncate text-xs text-text-primary" title={card.target_name || card.target_id}>
                      {card.target_name || card.target_id || '—'}
                    </span>
                  )}
                  {card.url && (
                    <a
                      href={card.url}
                      target="_blank"
                      rel="noreferrer"
                      className="max-w-[420px] min-w-0 truncate text-xs text-accent hover:underline"
                      title={card.url}
                    >
                      {card.url}
                    </a>
                  )}
                  <button
                    type="button"
                    onClick={() => void toggleCardSeen(card)}
                    className="ml-auto shrink-0 rounded border border-border px-2 py-0.5 text-[10px] text-text-muted hover:text-text-primary"
                  >
                    {card.seen ? 'unmark' : 'mark'}
                  </button>
                </div>

                <div className="mt-2 space-y-1.5 pl-1">
                  {card.items.map((item, i) => (
                    <div key={`${item.id}-${i}`} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
                      <span className="w-32 shrink-0 text-[10px] font-semibold uppercase tracking-wide text-text-muted">
                        {fieldLabel(item.change_type)}
                      </span>
                      <InlineChangeDiff oldValue={item.old_value} newValue={item.new_value} changeType={item.change_type} />
                      <Badge variant={changeBadgeVariant(item)}>{item.severity}</Badge>
                    </div>
                  ))}
                </div>

                <div className="mt-2 flex items-center gap-3 pl-1 text-[10px] text-text-muted">
                  <button type="button" onClick={() => setDetail(card)} className="text-accent hover:underline">
                    Details
                  </button>
                  {canDiff && (
                    <button
                      type="button"
                      onClick={() => setDiffView({
                        targetId: card.target_id,
                        url: card.url,
                        kind: first.change_type === 'css_change' ? 'css' : 'js',
                      })}
                      className="text-accent hover:underline"
                    >
                      Diff
                    </button>
                  )}
                  <span className="tabular-nums">{card.items.length} change(s)</span>
                </div>
              </div>
            )
          })
        )}
      </div>

      {!targetId && rows.length < serverTotal && (
        <div className="flex justify-center">
          <Button size="sm" variant="ghost" onClick={() => void loadMore()} disabled={loading}>
            Load {Math.min(PAGE, serverTotal - rows.length)} more
          </Button>
        </div>
      )}

      {/* Detail drawer */}
      {detail && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/60"
          onClick={() => setDetail(null)}
        >
          <div
            className="h-full w-full max-w-lg overflow-y-auto border-l border-border bg-surface-1 p-5"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="text-sm font-semibold">{fieldLabel(detail.items[0]?.change_type || '')}</h3>
                <p className="mt-1 break-all text-xs text-text-muted">{detail.url || detail.target_name}</p>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setDetail(null)}>Close</Button>
            </div>

            <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Target</dt>
                <dd className="truncate">{detail.target_name || detail.target_id}</dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Detected</dt>
                <dd className="tabular-nums">{fmtDate(detail.detected_at)}</dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Source</dt>
                <dd><SourceBadge source={detail.source} /></dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-text-muted">Round</dt>
                <dd className="font-mono text-[10px]">{detail.task_id ? detail.task_id.slice(0, 12) : '—'}</dd>
              </div>
            </dl>

            <div className="mt-4 space-y-3">
              {detail.items.map((item, i) => (
                <div key={`${item.id}-${i}`} className="rounded-lg border border-white/[.06] bg-white/[.02] p-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">
                    {fieldLabel(item.change_type)} · {item.severity}
                  </p>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <p className="text-[10px] text-text-muted">Before</p>
                      <p className="mt-0.5 break-all whitespace-pre-wrap font-mono text-severity-medium">{item.old_value || '∅'}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-text-muted">After</p>
                      <p className="mt-0.5 break-all whitespace-pre-wrap font-mono text-severity-low">{item.new_value || '∅'}</p>
                    </div>
                  </div>
                  {item.url && (
                    <p className="mt-2 flex items-center gap-1 text-[10px] text-text-muted">
                      <span className="max-w-[260px] truncate" title={item.url}>{item.url}</span>
                      <CopyButton text={item.url} />
                    </p>
                  )}
                  {item.metadata && Object.keys(item.metadata).length > 0 && (
                    <pre className="mt-2 max-h-32 overflow-auto rounded bg-black/30 p-2 text-[10px] text-text-muted">
                      {JSON.stringify(item.metadata, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
            </div>

            <div className="mt-5 flex items-center gap-3">
              {(targetId || selectedTargetId) && (
                <Link
                  to={`/targets/${targetId || selectedTargetId}`}
                  className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent hover:bg-accent/20"
                >
                  Open target →
                </Link>
              )}
              <button
                type="button"
                onClick={() => void toggleCardSeen(detail)}
                className="text-xs text-text-muted hover:text-text-primary"
              >
                {detail.seen ? 'Mark unread' : 'Mark read'}
              </button>
            </div>
          </div>
        </div>
      )}

      {diffView && (
        <ChangeDiffViewer
          targetId={diffView.targetId}
          url={diffView.url}
          kind={diffView.kind}
          onClose={() => setDiffView(null)}
        />
      )}
    </div>
  )
}
