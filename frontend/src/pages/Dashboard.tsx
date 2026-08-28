import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { dashboard, tasks as tasksApi, type DashboardCharts } from '../lib/api'
import { Spinner } from '../components/ui'
import { cn, timeAgo } from '../lib/utils'
import type { DashboardStats, Task } from '../types'

// Severity swatches — aligned to the committed design tokens (see tailwind.config).
const SEV_COLOR: Record<string, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#0ea5e9',
}

// Donut chart (pure SVG) for the severity split — no chart library.
function SeverityDonut({ data }: { data: { severity: string; count: number }[] }) {
  const total = data.reduce((s, d) => s + d.count, 0)
  const R = 54, C = 2 * Math.PI * R
  let offset = 0
  return (
    <div className="flex items-center gap-5">
      <svg viewBox="0 0 140 140" className="w-36 h-36 shrink-0 -rotate-90">
        <circle cx="70" cy="70" r={R} fill="none" stroke="currentColor" className="text-white/[.06]" strokeWidth="16" />
        {total > 0 && data.filter(d => d.count > 0).map(d => {
          const frac = d.count / total
          const dash = frac * C
          const el = (
            <circle key={d.severity} cx="70" cy="70" r={R} fill="none" stroke={SEV_COLOR[d.severity] || '#5a6a7e'}
              strokeWidth="16" strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-offset} strokeLinecap="butt" />
          )
          offset += dash
          return el
        })}
        <text x="70" y="66" textAnchor="middle" className="fill-text-primary rotate-90" fontSize="22" fontWeight="700" transform="rotate(90 70 70)">{total}</text>
        <text x="70" y="84" textAnchor="middle" className="fill-text-muted" fontSize="9" transform="rotate(90 70 70)">FINDINGS</text>
      </svg>
      <div className="space-y-1.5 flex-1 min-w-0">
        {data.map(d => (
          <div key={d.severity} className="flex items-center gap-2 text-xs">
            <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: SEV_COLOR[d.severity] }} />
            <span className="capitalize text-text-secondary flex-1">{d.severity}</span>
            <span className="font-semibold tabular-nums">{d.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Horizontal bar list (vuln by type).
function BarList({ data, colorClass }: { data: { label: string; value: number }[]; colorClass: string }) {
  const max = Math.max(1, ...data.map(d => d.value))
  return (
    <div className="space-y-2">
      {data.map(d => (
        <div key={d.label} className="flex items-center gap-2 text-xs">
          <span className="w-28 shrink-0 truncate font-mono text-text-secondary" title={d.label}>{d.label}</span>
          <div className="flex-1 h-2.5 rounded-full bg-white/[.05] overflow-hidden">
            <div className={cn('h-full rounded-full', colorClass)} style={{ width: `${(d.value / max) * 100}%` }} />
          </div>
          <span className="w-8 text-right font-semibold tabular-nums">{d.value}</span>
        </div>
      ))}
    </div>
  )
}

// Sparkline (scans over time).
function Sparkline({ data }: { data: { date: string; scans: number }[] }) {
  if (data.length === 0) return <p className="text-xs text-text-muted">No scans in the last 30 days.</p>
  const max = Math.max(1, ...data.map(d => d.scans))
  const W = 100, H = 28
  const pts = data.map((d, i) => `${(i / Math.max(1, data.length - 1)) * W},${H - (d.scans / max) * H}`).join(' ')
  const total = data.reduce((s, d) => s + d.scans, 0)
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="w-full h-12">
        <polyline points={pts} fill="none" stroke="currentColor" className="text-accent" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      </svg>
      <p className="text-[10px] text-text-muted mt-1">{total} scans · last {data.length} active day(s)</p>
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="card p-3.5">
      <p className="text-[11px] text-text-muted mb-1">{label}</p>
      <p className={cn('text-2xl font-semibold tabular-nums', tone)}>{value}</p>
    </div>
  )
}

const KIND_CHIP: Record<string, string> = {
  web: 'bg-accent-muted text-accent-hover', network: 'bg-series-3/15 text-series-3', mixed: 'bg-severity-low/15 text-severity-low',
}

const TASK_STATUS_DOT: Record<string, string> = {
  running: 'dot-running', completed: 'dot-online', failed: 'dot-error',
  paused: 'dot-offline', pending: 'dot-offline', queued: 'dot-offline', cancelled: 'dot-offline',
}

// Recent activity — the last handful of scan tasks, newest first. Gives the
// dashboard a live pulse of "what has the platform been doing lately".
function RecentActivity() {
  const nav = useNavigate()
  const [rows, setRows] = useState<Task[] | null>(null)
  useEffect(() => {
    let alive = true
    const load = () => tasksApi.list().then(r => {
      if (!alive) return
      const sorted = [...r].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, 8)
      setRows(sorted)
    }).catch(() => { if (alive) setRows([]) })
    load()
    const i = setInterval(load, 30000)
    return () => { alive = false; clearInterval(i) }
  }, [])
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Recent activity</p>
        <button onClick={() => nav('/tasks')} className="text-[11px] text-accent hover:underline">View all →</button>
      </div>
      {rows === null ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="skeleton h-8 rounded" />)}</div>
      ) : rows.length === 0 ? (
        <p className="text-xs text-text-muted py-6 text-center">No scans have run yet.</p>
      ) : (
        <div className="space-y-0.5">
          {rows.map(t => (
            <button key={t.id} onClick={() => t.target_id && nav(`/targets/${t.target_id}`)}
              className="w-full flex items-center gap-3 text-left px-2 py-2 rounded-lg hover:bg-white/[.04] transition-colors">
              <span className={cn('shrink-0', TASK_STATUS_DOT[t.status] || 'dot-offline')} />
              <span className="min-w-0 flex-1">
                <span className="block text-sm text-text-primary truncate">{t.name || t.type || 'Scan'}</span>
                <span className="block text-[11px] text-text-muted truncate">{t.target_domain || '—'}{t.current_module ? ` · ${t.current_module}` : ''}</span>
              </span>
              <span className="text-[11px] text-text-muted tabular-nums shrink-0">{timeAgo(t.created_at)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const nav = useNavigate()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [charts, setCharts] = useState<DashboardCharts | null>(null)
  const [topSort, setTopSort] = useState<'findings' | 'subdomains' | 'alive_hosts'>('findings')
  const [loading, setLoading] = useState(true)
  const load = async () => {
    try {
      const [s, c] = await Promise.all([dashboard.stats(), dashboard.charts().catch(() => ({}))])
      setStats(s); setCharts(c)
    } catch { /**/ } finally { setLoading(false) }
  }
  useEffect(() => { load(); const i = setInterval(load, 30000); return () => clearInterval(i) }, [])
  if (loading) return <div className="flex items-center justify-center h-64"><Spinner/></div>
  if (!stats) return null

  const sev = charts?.severity_breakdown || []
  const totalVulns = sev.reduce((s, d) => s + d.count, 0)
  const critHigh = sev.filter(d => d.severity === 'critical' || d.severity === 'high').reduce((s, d) => s + d.count, 0)
  const byType = (charts?.vuln_by_type || []).map(d => ({ label: String(d.type).replace(/_/g, ' '), value: d.count }))
  const topTargets = [...(charts?.top_targets || [])].sort((a, b) => (b[topSort] || 0) - (a[topSort] || 0))
  const maxBar = Math.max(1, ...topTargets.map(t => t[topSort] || 0))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold">Dashboard</h1>
          <p className="text-xs text-text-muted">{stats.targets} target(s) · {totalVulns} finding(s) · {critHigh} critical/high</p>
        </div>
        {/* Quick actions */}
        <div className="flex items-center gap-2">
          <button onClick={() => nav('/targets')} className="btn-primary text-xs">+ New Target</button>
          <button onClick={() => nav('/findings')} className="btn-secondary text-xs">View Findings</button>
          <button onClick={() => nav('/tasks')} className="btn-secondary text-xs">Scans</button>
          <button onClick={load} className="btn-ghost text-xs" title="Refresh">↻</button>
        </div>
      </div>

      {/* Hero KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Targets" value={stats.targets} />
        <Stat label="Alive hosts" value={stats.alive_hosts.toLocaleString()} tone="text-severity-low" />
        <Stat label="Findings" value={totalVulns} tone={totalVulns > 0 ? 'text-severity-high' : undefined} />
        <Stat label="Critical / High" value={critHigh} tone={critHigh > 0 ? 'text-severity-critical' : undefined} />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-3">Findings by severity</p>
          {totalVulns > 0 ? <SeverityDonut data={sev} /> : <p className="text-xs text-text-muted py-8 text-center">No findings yet.</p>}
        </div>
        <div className="card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-3">Vulnerabilities by type</p>
          {byType.length > 0 ? <BarList data={byType} colorClass="bg-severity-high" /> : <p className="text-xs text-text-muted py-8 text-center">No typed vulns yet.</p>}
        </div>
        <div className="card p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-3">Scan activity (30d)</p>
          <Sparkline data={charts?.scans_over_time || []} />
          <div className="grid grid-cols-2 gap-2 mt-4">
            <Stat label="Running" value={stats.running_tasks} tone={stats.running_tasks > 0 ? 'text-accent' : undefined} />
            <Stat label="Failed" value={stats.failed_tasks} tone={stats.failed_tasks > 0 ? 'text-severity-critical' : undefined} />
          </div>
        </div>
      </div>

      {/* Top targets + recent activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div className="card p-4 lg:col-span-2">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Top targets</p>
          <select value={topSort} onChange={e => setTopSort(e.target.value as typeof topSort)}
            className="bg-surface-alt border border-border rounded px-2 py-1 text-[11px] text-text-primary">
            <option value="findings" className="bg-surface-3">by findings</option>
            <option value="subdomains" className="bg-surface-3">by subdomains</option>
            <option value="alive_hosts" className="bg-surface-3">by alive hosts</option>
          </select>
        </div>
        {topTargets.length === 0 ? (
          <p className="text-xs text-text-muted py-6 text-center">No targets yet — add one to get started.</p>
        ) : (
          <div className="space-y-2">
            {topTargets.map(t => (
              <button key={t.id} onClick={() => nav(`/targets/${t.id}`)}
                className="w-full flex items-center gap-3 text-left px-2 py-1.5 rounded-lg hover:bg-white/[.04] transition-colors">
                <span className={cn('text-[9px] px-1.5 py-0.5 rounded font-semibold uppercase shrink-0', KIND_CHIP[t.kind] || KIND_CHIP.web)}>{t.kind}</span>
                <span className="text-sm truncate flex-1 min-w-0" title={t.domain}>{t.name || t.domain}</span>
                <div className="w-40 h-2 rounded-full bg-white/[.05] overflow-hidden shrink-0 hidden sm:block">
                  <div className="h-full rounded-full bg-severity-high" style={{ width: `${((t[topSort] || 0) / maxBar) * 100}%` }} />
                </div>
                <span className="text-xs text-text-muted tabular-nums w-16 text-right shrink-0">{t.subdomains} subs</span>
                <span className="text-sm font-semibold tabular-nums w-10 text-right shrink-0">{t[topSort]}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      <RecentActivity />
      </div>

      {/* Recon detail */}
      <div>
        <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-3">Recon surface</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Subdomains" value={stats.subdomains.toLocaleString()} />
          <Stat label="HTTP services" value={stats.http_services.toLocaleString()} />
          <Stat label="JS files" value={stats.js_files.toLocaleString()} />
          <Stat label="Parameters" value={stats.parameters.toLocaleString()} />
          <Stat label="Reflected params" value={stats.reflected_parameters} tone={stats.reflected_parameters > 0 ? 'text-severity-high' : undefined} />
          <Stat label="Nuclei" value={stats.nuclei_findings} />
          <Stat label="Backup files" value={stats.backup_findings} tone={stats.backup_findings > 0 ? 'text-severity-high' : undefined} />
          <Stat label="Open redirects" value={stats.open_redirect_findings} tone={stats.open_redirect_findings > 0 ? 'text-severity-medium' : undefined} />
        </div>
      </div>
    </div>
  )
}
