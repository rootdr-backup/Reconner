import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { findings as findingsApi, type AllFinding } from '../lib/api'
import { timeAgo, truncate, cn } from '../lib/utils'

const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const
type Sev = typeof SEVS[number]

const sevText: Record<string, string> = {
  critical: 'text-severity-critical', high: 'text-severity-high',
  medium: 'text-severity-medium', low: 'text-severity-low', info: 'text-text-muted',
}
const sevBadge: Record<string, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
  info: 'bg-white/5 text-text-muted border-border',
}

export default function Findings() {
  const nav = useNavigate()
  const [rows, setRows] = useState<AllFinding[]>([])
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState<'finding' | 'candidate'>('finding')
  const [sevFilter, setSevFilter] = useState<Sev | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let cancelled = false
    setLoading(true); setErr('')
    findingsApi.all({ status })
      .then(r => { if (!cancelled) setRows(r || []) })
      .catch(e => { if (!cancelled) setErr(e?.message || 'Failed to load findings') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [status])

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of rows) c[f.severity?.toLowerCase()] = (c[f.severity?.toLowerCase()] || 0) + 1
    return c
  }, [rows])

  const shown = useMemo(
    () => sevFilter ? rows.filter(f => f.severity?.toLowerCase() === sevFilter) : rows,
    [rows, sevFilter])

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">Findings</h1>
        <span className="text-xs text-text-muted">across all targets</span>
        <div className="ml-auto flex items-center gap-1 text-xs">
          <button onClick={() => { setStatus('finding'); setSevFilter(null) }}
            className={cn('px-3 py-1.5 rounded border', status === 'finding' ? 'border-accent text-accent' : 'border-border text-text-muted')}>
            Confirmed
          </button>
          <button onClick={() => { setStatus('candidate'); setSevFilter(null) }}
            className={cn('px-3 py-1.5 rounded border', status === 'candidate' ? 'border-accent text-accent' : 'border-border text-text-muted')}>
            Needs Review
          </button>
        </div>
      </div>

      {/* severity summary — click to filter */}
      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setSevFilter(null)}
          className={cn('px-3 py-2 rounded-lg border text-xs font-medium', !sevFilter ? 'border-accent text-accent' : 'border-border text-text-muted')}>
          All <span className="tabular-nums">{rows.length}</span>
        </button>
        {SEVS.map(s => (
          <button key={s} onClick={() => setSevFilter(sevFilter === s ? null : s)}
            disabled={!counts[s]}
            className={cn('px-3 py-2 rounded-lg border text-xs font-medium capitalize disabled:opacity-40',
              sevFilter === s ? 'border-accent' : 'border-border', sevText[s])}>
            {s} <span className="tabular-nums">{counts[s] || 0}</span>
          </button>
        ))}
      </div>

      {err && <div className="card p-4 text-sm text-severity-high">{err}</div>}

      <div className="card overflow-hidden" style={{ padding: 0 }}>
        {loading ? (
          <p className="text-sm text-text-muted p-8 text-center">Loading findings…</p>
        ) : shown.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-text-secondary text-sm mb-1">
              {status === 'finding' ? 'No confirmed findings yet.' : 'Nothing awaiting review.'}
            </p>
            <p className="text-text-muted text-xs">
              Findings appear here as scans confirm them. Start a scan from a target to populate this view.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  {['Severity', 'Type', 'Target', 'URL', 'Parameter', 'Conf.', 'Found'].map(h => (
                    <th key={h} className="table-header text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map(f => (
                  <tr key={f.id} onClick={() => nav(`/targets/${f.target_id}`)}
                    className="border-b border-border/50 last:border-0 hover:bg-surface-3/50 transition-colors cursor-pointer">
                    <td className="table-cell">
                      <span className={cn('px-2 py-0.5 rounded border text-[10px] font-semibold uppercase', sevBadge[f.severity?.toLowerCase()] || sevBadge.info)}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="table-cell font-mono text-xs">{f.type}</td>
                    <td className="table-cell text-xs text-text-secondary">{f.domain}</td>
                    <td className="table-cell font-mono text-xs text-text-muted" title={f.url}>{truncate(f.url, 60)}</td>
                    <td className="table-cell font-mono text-xs">{f.parameter || '—'}</td>
                    <td className="table-cell text-xs tabular-nums">{f.confidence || '—'}</td>
                    <td className="table-cell text-xs text-text-muted whitespace-nowrap">{timeAgo(f.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
