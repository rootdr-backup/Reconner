import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { changes, targets as targetsApi, watchApi } from '../../lib/api'
import type { ChangeEntry, Target, WatchRound } from '../../types'
import { Badge, Button, CopyButton, Empty, SkeletonRows } from '../ui'
import { cn, timeAgo } from '../../lib/utils'
import { ws } from '../../lib/websocket'
import {
  CHANGE_FILTERS, OCCURRENCE_PAGE_SIZE, changeBadgeVariant, groupMonitorChanges,
  type ChangeFilter, type MonitorChangeGroup,
} from './changesModel'
import InlineChangeDiff from './InlineChangeDiff'
import RoundTimeline from './RoundTimeline'
import ScopeEventsPanel from './ScopeEventsPanel'
import ChangesNotificationsPanel from './ChangesNotificationsPanel'
import { ChangeDiffViewer } from '../targets/ChangeDiffViewer'

type Subtab = 'overview' | 'http' | 'scripts' | 'assets' | 'alerts'
type ScriptKind = 'all' | 'js' | 'css'
type DiffView = { targetId: string; url: string; kind: 'css' | 'js' }

const PAGE = 200

const SUBTABS: { id: Subtab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'http', label: 'HTTP & status' },
  { id: 'scripts', label: 'Scripts' },
  { id: 'assets', label: 'Assets & scope' },
  { id: 'alerts', label: 'Alerts' },
]

const EMPTY_BY_TAB: Record<Subtab, string> = {
  overview: 'No changes recorded yet.',
  http: 'No HTTP or status changes detected.',
  scripts: 'No script diffs. Watch rounds do not fetch JavaScript; run a deep scan to track script drift.',
  assets: 'No new hosts or scope landings.',
  alerts: 'No alert-category changes detected.',
}

function SourceBadge({ source }: { source: string }) {
  const map: Record<string, { label: string; className: string }> = {
    watch: { label: 'Watch', className: 'border-accent/50 bg-accent/10 text-accent' },
    monitor: { label: 'Deep', className: 'border-border text-text-muted' },
    scope: { label: 'Scope', className: 'border-severity-medium/40 bg-severity-medium/10 text-severity-medium' },
    notification: { label: 'Bell', className: 'border-severity-low/40 bg-severity-low/10 text-severity-low' },
  }
  const s = map[source] || { label: source, className: 'border-border text-text-muted' }
  return <span className={cn('rounded-full border px-1.5 py-0.5 text-[10px]', s.className)}>{s.label}</span>
}

function Kpi({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg border border-white/[.06] bg-white/[.02] px-3 py-2">
      <p className="text-[10px] uppercase tracking-wider text-text-muted">{label}</p>
      <p className={cn('mt-0.5 text-base font-semibold tabular-nums', tone || 'text-text-primary')}>{value}</p>
    </div>
  )
}

interface TableProps {
  groups: MonitorChangeGroup<ChangeEntry>[]
  showTarget: boolean
  visibleCount: number
  expanded: Map<string, number>
  onToggle: (key: string) => void
  onMore: (key: string) => void
  onDiff: (row: ChangeEntry) => void
}

function ChangeTable({ groups, showTarget, visibleCount, expanded, onToggle, onMore, onDiff }: TableProps) {
  const pageGroups = groups.slice(0, visibleCount)
  const colSpan = showTarget ? 6 : 5
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-xs">
        <thead className="table-header">
          <tr>
            {showTarget && <th className="table-cell">Target</th>}
            <th className="table-cell">When</th>
            <th className="table-cell">Source</th>
            <th className="table-cell">Change</th>
            <th className="table-cell">Before → After</th>
            <th className="table-cell">Round</th>
          </tr>
        </thead>
        <tbody>
          {pageGroups.map(group => {
            const rep = group.rep
            const shown = expanded.get(group.key) || 1
            const extra = group.items.length - 1
            const canDiff = rep.source === 'monitor' && (rep.change_type === 'css_change' || rep.change_type === 'js_change') && !!rep.url
            return (
              <Fragment key={group.key}>
                <tr className="table-row align-top">
                  {showTarget && (
                    <td className="table-cell max-w-[160px] truncate" title={rep.target_name || rep.target_id}>
                      {rep.target_name || rep.target_id || '—'}
                    </td>
                  )}
                  <td className="table-cell whitespace-nowrap text-text-muted">{timeAgo(rep.detected_at)}</td>
                  <td className="table-cell"><SourceBadge source={rep.source} /></td>
                  <td className="table-cell">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant={changeBadgeVariant(rep)}>{rep.change_type}</Badge>
                      {canDiff && (
                        <Button size="sm" variant="ghost" onClick={() => onDiff(rep)}>Diff</Button>
                      )}
                    </div>
                  </td>
                  <td className="table-cell max-w-[360px]">
                    <InlineChangeDiff oldValue={rep.old_value} newValue={rep.new_value} changeType={rep.change_type} />
                    {extra > 0 && (
                      <button
                        type="button"
                        onClick={() => onToggle(group.key)}
                        className="mt-1 block text-[10px] text-accent hover:underline"
                        title={group.urls.join('\n')}
                      >
                        {shown > 1 ? 'Hide' : `+${extra} more change(s) · ${group.urls.length} URL(s)`}
                      </button>
                    )}
                    {rep.url && (
                      <div className="mt-1 flex items-center gap-1 text-[10px] text-text-muted">
                        <span className="max-w-[220px] truncate" title={rep.url}>{rep.url}</span>
                        <CopyButton text={rep.url} />
                      </div>
                    )}
                  </td>
                  <td className="table-cell whitespace-nowrap font-mono text-[10px] text-text-muted">
                    {rep.task_id ? rep.task_id.slice(0, 8) : '—'}
                  </td>
                </tr>
                {extra > 0 && shown > 1 && group.items.slice(1, shown).map((item, i) => (
                  <tr key={`${group.key}-${i}`} className="table-row bg-white/[.01]">
                    <td colSpan={colSpan} className="table-cell">
                      <div className="flex flex-wrap items-center gap-2 text-[11px]">
                        <span className="font-mono text-text-muted">{item.old_value || '∅'}</span>
                        <span className="text-text-muted">→</span>
                        <span className="font-mono text-severity-medium">{item.new_value || '∅'}</span>
                        {item.url && <span className="max-w-[240px] truncate text-text-muted" title={item.url}>{item.url}</span>}
                        <span className="text-text-muted">{timeAgo(item.detected_at)}</span>
                        {item.task_id && <span className="font-mono text-[10px] text-text-muted">{item.task_id.slice(0, 8)}</span>}
                      </div>
                    </td>
                  </tr>
                ))}
                {extra > 0 && shown > 1 && shown < group.items.length && (
                  <tr className="table-row">
                    <td colSpan={colSpan} className="table-cell">
                      <button type="button" onClick={() => onMore(group.key)} className="text-[10px] text-accent hover:underline">
                        Show {Math.min(OCCURRENCE_PAGE_SIZE, group.items.length - shown)} more
                      </button>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

interface Props {
  targetId?: string
  compact?: boolean
}

export default function ChangesExplorer({ targetId, compact }: Props) {
  const [subtab, setSubtab] = useState<Subtab>('overview')
  const [category, setCategory] = useState<ChangeFilter>('all')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [since, setSince] = useState('')
  const [selectedTargetId, setSelectedTargetId] = useState('')
  const [selectedTaskId, setSelectedTaskId] = useState('')
  const [scriptKind, setScriptKind] = useState<ScriptKind>('all')
  const [rows, setRows] = useState<ChangeEntry[]>([])
  const [rounds, setRounds] = useState<WatchRound[]>([])
  const [targetList, setTargetList] = useState<Target[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [visibleCount, setVisibleCount] = useState(PAGE)
  const [expanded, setExpanded] = useState<Map<string, number>>(new Map())
  const [diffView, setDiffView] = useState<DiffView | null>(null)
  const reloadTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const requestSeq = useRef(0)

  useEffect(() => {
    if (targetId) return
    let alive = true
    targetsApi.list().then(list => { if (alive) setTargetList(list || []) }).catch(() => {})
    return () => { alive = false }
  }, [targetId])

  const load = useCallback(async (resetView = false) => {
    const seq = ++requestSeq.current
    setLoading(true)
    setError('')
    if (resetView) {
      setVisibleCount(PAGE)
      setExpanded(new Map())
    }
    const params: Record<string, string> = {}
    if (category !== 'all') params.category = category
    if (severity) params.severity = severity
    if (source) params.source = source
    if (since) params.since = since
    if (selectedTaskId) params.task_id = selectedTaskId
    const globalTarget = !targetId ? selectedTargetId : ''
    if (globalTarget) params.target_id = globalTarget
    try {
      const [changeRows, roundRows] = await Promise.all([
        targetId ? changes.forTarget(targetId, params) : changes.list(params),
        watchApi.rounds(globalTarget ? { target_id: globalTarget } : targetId ? { target_id: targetId } : {}),
      ])
      if (seq !== requestSeq.current) return
      setRows(changeRows)
      setRounds(roundRows)
    } catch (e) {
      if (seq !== requestSeq.current) return
      setError(e instanceof Error ? e.message : 'Failed to load changes')
    } finally {
      if (seq === requestSeq.current) setLoading(false)
    }
  }, [targetId, category, severity, source, since, selectedTaskId, selectedTargetId])

  useEffect(() => { void load(true) }, [load])

  useEffect(() => {
    const schedule = () => {
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
      reloadTimer.current = setTimeout(() => { void load() }, 3000)
    }
    const immediate = () => { void load() }
    const offs = [
      ws.on('task_progress', schedule),
      ws.on('task_finished', immediate),
      ws.on('scope_landed', schedule),
      ws.on('notification_created', schedule),
    ]
    const poll = targetId ? null : setInterval(immediate, 30000)
    return () => {
      offs.forEach(off => off())
      if (poll) clearInterval(poll)
      if (reloadTimer.current) clearTimeout(reloadTimer.current)
    }
  }, [load, targetId])

  const switchSubtab = (next: Subtab) => {
    setSubtab(next)
    setCategory('all')
    setScriptKind('all')
  }

  const allowedCategories = useMemo(() => {
    switch (subtab) {
      case 'http': return ['http', 'headers']
      case 'scripts': return ['scripts']
      case 'assets': return ['assets']
      case 'alerts': return ['alerts']
      default: return CHANGE_FILTERS.filter(f => f.id !== 'all').map(f => f.id)
    }
  }, [subtab])

  const chips = useMemo(
    () => CHANGE_FILTERS.filter(f => f.id === 'all' || allowedCategories.includes(f.id)),
    [allowedCategories],
  )

  const scopedRows = useMemo(
    () => rows.filter(r => allowedCategories.includes(r.category)),
    [rows, allowedCategories],
  )

  const visibleRows = useMemo(() => {
    if (subtab !== 'scripts' || scriptKind === 'all') return scopedRows
    return scopedRows.filter(r =>
      scriptKind === 'js'
        ? /js_change|script/i.test(r.change_type)
        : /css_change|stylesheet/i.test(r.change_type))
  }, [scopedRows, subtab, scriptKind])

  const groups = useMemo(
    () => groupMonitorChanges<ChangeEntry>(
      visibleRows,
      targetId ? '' : (row: ChangeEntry) => `${row.target_id}:${row.task_id || ''}`,
    ),
    [visibleRows, targetId],
  )

  const flipCount = rows.filter(r => r.change_type === 'status_change').length
  const hostCount = rows.filter(r => r.change_type === 'new_subdomain' || r.change_type === 'scope_landed').length
  const failedRounds = rounds.filter(r => r.status === 'failed').length
  const lastSeen = rows.length ? timeAgo(rows[0].detected_at) : '—'

  const toggleGroup = (key: string) => {
    setExpanded(prev => {
      const next = new Map(prev)
      next.set(key, next.get(key) ? 1 : 2)
      return next
    })
  }
  const moreGroup = (key: string) => {
    setExpanded(prev => {
      const next = new Map(prev)
      next.set(key, (next.get(key) || 1) + OCCURRENCE_PAGE_SIZE)
      return next
    })
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        <Kpi label="Changes" value={rows.length} />
        <Kpi label="Status flips" value={flipCount} tone="text-severity-medium" />
        <Kpi label="New hosts" value={hostCount} tone="text-severity-low" />
        <Kpi label="Failed rounds" value={failedRounds} tone={failedRounds ? 'text-severity-critical' : undefined} />
        <Kpi label="Last detection" value={lastSeen} />
      </div>

      {!compact && (
        <section className="rounded-xl border border-white/[.06] bg-white/[.02]">
          <h3 className="panel-heading">Watch rounds</h3>
          <RoundTimeline
            rounds={rounds}
            selectedTaskId={selectedTaskId}
            onSelect={id => { setSelectedTaskId(id); setVisibleCount(PAGE) }}
            compact={compact}
          />
        </section>
      )}

      <section className="rounded-xl border border-white/[.06] bg-white/[.02]">
        <div className="border-b border-white/[.06] px-3 py-2">
          <div className="segmented-control inline-flex">
            {SUBTABS.map(s => (
              <button
                key={s.id}
                type="button"
                onClick={() => switchSubtab(s.id)}
                className={cn('px-3 py-1 text-xs', subtab === s.id && 'active')}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap gap-1 border-b border-white/[.06] px-3 py-2">
          {chips.map(chip => (
            <button
              key={chip.id}
              type="button"
              onClick={() => setCategory(chip.id)}
              className={cn(
                'rounded-full border px-2.5 py-1 text-xs transition',
                category === chip.id
                  ? 'border-accent bg-accent/15 text-accent'
                  : 'border-border text-text-muted hover:text-text-primary',
              )}
            >
              {chip.label}
            </button>
          ))}
        </div>

        {subtab === 'scripts' && (
          <div className="flex gap-1 border-b border-white/[.06] px-3 py-2">
            {(['all', 'js', 'css'] as ScriptKind[]).map(kind => (
              <button
                key={kind}
                type="button"
                onClick={() => setScriptKind(kind)}
                className={cn(
                  'rounded-full border px-2.5 py-1 text-xs transition',
                  scriptKind === kind
                    ? 'border-accent bg-accent/15 text-accent'
                    : 'border-border text-text-muted hover:text-text-primary',
                )}
              >
                {kind === 'all' ? 'All scripts' : kind === 'js' ? 'JavaScript' : 'Stylesheets'}
              </button>
            ))}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2 border-b border-white/[.06] px-3 py-2">
          <select className="input w-auto py-1 text-xs" value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="input w-auto py-1 text-xs" value={source} onChange={e => setSource(e.target.value)}>
            <option value="">All sources</option>
            {['monitor', 'watch', 'scope', 'notification'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className="input w-auto py-1 text-xs" type="date" value={since} onChange={e => setSince(e.target.value)} />
          {!targetId && (
            <select className="input w-auto py-1 text-xs" value={selectedTargetId} onChange={e => setSelectedTargetId(e.target.value)}>
              <option value="">All targets</option>
              {targetList.map(t => (
                <option key={t.id} value={t.id}>{t.name || t.domain}</option>
              ))}
            </select>
          )}
          {selectedTaskId && (
            <Button size="sm" variant="ghost" onClick={() => setSelectedTaskId('')}>Clear round</Button>
          )}
        </div>

        {subtab === 'assets' && <ScopeEventsPanel targetId={targetId || selectedTargetId || undefined} />}
        {subtab === 'alerts' && <ChangesNotificationsPanel />}

        {error ? (
          <p className="px-3 py-6 text-center text-sm text-severity-medium">{error}</p>
        ) : loading ? (
          <SkeletonRows rows={8} cols={targetId ? 5 : 6} />
        ) : groups.length === 0 ? (
          <Empty message={EMPTY_BY_TAB[subtab]} />
        ) : (
          <ChangeTable
            groups={groups}
            showTarget={!targetId}
            visibleCount={visibleCount}
            expanded={expanded}
            onToggle={toggleGroup}
            onMore={moreGroup}
            onDiff={row => {
              if (!row.target_id || !row.url) return
              setDiffView({
                targetId: row.target_id,
                url: row.url,
                kind: row.change_type === 'css_change' ? 'css' : 'js',
              })
            }}
          />
        )}

        {groups.length > 0 && (
          <div className="flex items-center justify-between border-t border-white/[.06] px-3 py-2 text-[11px] text-text-muted">
            <span className="tabular-nums">
              {groups.length} distinct change group(s) · {visibleRows.length} change(s)
            </span>
            {visibleCount < groups.length && (
              <Button size="sm" variant="ghost" onClick={() => setVisibleCount(v => v + PAGE)}>
                Load {Math.min(PAGE, groups.length - visibleCount)} more
              </Button>
            )}
          </div>
        )}
      </section>

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
