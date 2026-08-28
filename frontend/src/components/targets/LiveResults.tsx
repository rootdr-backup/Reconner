import { useEffect, useState } from 'react'
import { ws } from '../../lib/websocket'
import { tasks as tasksApi } from '../../lib/api'
import { cn } from '../../lib/utils'

interface LiveEvent {
  id: number
  type: string
  data: Record<string, string>
  ts: number
}

const typeLabel: Record<string, { label: string; color: string }> = {
  new_subdomain:      { label: 'Subdomain',    color: 'text-severity-low' },
  new_js_finding:     { label: 'JS Secret',    color: 'text-severity-high' },
  new_reflected_param:{ label: 'Reflected',    color: 'text-severity-medium' },
}

let counter = 0

// fmtETA renders a seconds count as a compact "~5m 20s" / "~45s" / "<1m".
function fmtETA(sec: number): string {
  if (sec <= 0) return 'almost done'
  if (sec < 60) return `~${sec}s`
  const m = Math.floor(sec / 60), s = sec % 60
  if (m < 60) return s > 0 ? `~${m}m ${s}s` : `~${m}m`
  const h = Math.floor(m / 60)
  return `~${h}h ${m % 60}m`
}

interface Prog { module: string; eta: number; moduleEta: number; progress: number; total: number; at: number }

export const LiveResults = ({ targetId, active }: { targetId: string; active: boolean }) => {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [prog, setProg] = useState<Prog | null>(null)
  const [, setTick] = useState(0) // 1s ticker so the countdown ticks between module updates

  // Live countdown between server updates.
  useEffect(() => {
    if (!active) return
    const iv = setInterval(() => setTick(t => t + 1), 1000)
    return () => clearInterval(iv)
  }, [active])

  useEffect(() => {
    if (!active) return
    const un = ws.on('task_progress', (payload) => {
      const p = payload as { target_id: string; current_module: string; eta_seconds?: number; module_eta_seconds?: number; progress?: number; total?: number }
      if (p.target_id !== targetId) return
      setProg({ module: p.current_module, eta: p.eta_seconds || 0, moduleEta: p.module_eta_seconds || 0, progress: p.progress || 0, total: p.total || 0, at: Date.now() })
    })
    return un
  }, [targetId, active])

  // Seed the ETA from the running task on mount. task_progress is broadcast only
  // when a module STARTS, so a user opening the target mid-module would otherwise
  // see no ETA until the next module begins (possibly minutes). The tasks table
  // already persists the live eta_seconds/module_eta_seconds/current_module, so
  // fetch them once immediately; WS ticks then keep the banner fresh.
  useEffect(() => {
    if (!active) return
    let cancelled = false
    tasksApi.list({ target_id: targetId, status: 'running', limit: '1' })
      .then(list => {
        if (cancelled || !list || list.length === 0) return
        const t = list[0]
        setProg(prev => prev ?? {
          module: t.current_module || '', eta: t.eta_seconds || 0, moduleEta: t.module_eta_seconds || 0,
          progress: t.progress || 0, total: t.total || 0, at: Date.now(),
        })
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [targetId, active])

  // Elapsed since the last server progress update, to decrement the shown ETA.
  const elapsed = prog ? Math.floor((Date.now() - prog.at) / 1000) : 0
  const etaLeft = prog ? Math.max(0, prog.eta - elapsed) : 0
  const modLeft = prog ? Math.max(0, prog.moduleEta - elapsed) : 0

  useEffect(() => {
    if (!active) return

    const unsubs = [
      ws.on('new_subdomain', (payload) => {
        const p = payload as Record<string, string>
        if (p.target_id !== targetId) return
        setEvents(prev => [{ id: counter++, type: 'new_subdomain', data: p, ts: Date.now() }, ...prev.slice(0, 199)])
      }),
      ws.on('new_js_finding', (payload) => {
        const p = payload as Record<string, string>
        if (p.target_id !== targetId) return
        setEvents(prev => [{ id: counter++, type: 'new_js_finding', data: p, ts: Date.now() }, ...prev.slice(0, 199)])
      }),
      ws.on('new_reflected_param', (payload) => {
        const p = payload as Record<string, string>
        if (p.target_id !== targetId) return
        setEvents(prev => [{ id: counter++, type: 'new_reflected_param', data: p, ts: Date.now() }, ...prev.slice(0, 199)])
      }),
    ]

    return () => unsubs.forEach(u => u())
  }, [targetId, active])

  if (!active && events.length === 0) return null

  return (
    <div className="card overflow-hidden" style={{ padding: 0 }}>
      <div className="px-3 py-2 border-b border-border flex items-center gap-2">
        {active && <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />}
        <span className="text-xs font-medium text-text-secondary">Live Results</span>
        <span className="text-xs text-text-muted ml-auto">{events.length} found</span>
      </div>
      {active && prog && (
        <div className="px-3 py-2 border-b border-border bg-white/[.02]">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-text-muted">⏱ Scan ETA</span>
            <span className="font-semibold text-accent-hover tabular-nums">{fmtETA(etaLeft)}</span>
            <span className="text-text-muted ml-auto">
              {prog.total > 0 && <span className="tabular-nums">{prog.progress + 1}/{prog.total} · </span>}
              <span className="font-mono text-text-secondary">{prog.module || '…'}</span>
              <span className="text-text-muted"> {fmtETA(modLeft)}</span>
            </span>
          </div>
          {prog.total > 0 && (
            <div className="mt-1.5 h-1 rounded-full bg-white/[.06] overflow-hidden">
              <div className="h-full rounded-full transition-all duration-500"
                style={{ width: `${Math.round(((prog.progress + 1) / prog.total) * 100)}%`, backgroundImage: 'var(--grad-accent)' }} />
            </div>
          )}
        </div>
      )}
      <div className="max-h-52 overflow-y-auto">
        {events.length === 0
          ? <p className="text-xs text-text-muted p-3">Waiting for results...</p>
          : events.map(ev => {
              const meta = typeLabel[ev.type] || { label: ev.type, color: 'text-text-secondary' }
              return (
                <div key={ev.id} className="flex items-start gap-2 px-3 py-1.5 border-b border-border/50 last:border-0 hover:bg-surface-3/50 transition-colors">
                  <span className={cn('text-xs font-semibold shrink-0 w-20', meta.color)}>{meta.label}</span>
                  <span className="font-mono text-xs text-text-primary truncate">
                    {ev.type === 'new_subdomain' && ev.data.subdomain}
                    {ev.type === 'new_js_finding' && `[${ev.data.type}] ${ev.data.value}`}
                    {ev.type === 'new_reflected_param' && `${ev.data.parameter} in ${ev.data.url}`}
                  </span>
                  <span className="text-xs text-text-muted shrink-0 ml-auto">
                    {new Date(ev.ts).toLocaleTimeString()}
                  </span>
                </div>
              )
            })}
      </div>
    </div>
  )
}
