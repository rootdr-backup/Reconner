import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate, Link } from 'react-router-dom'
import { ws } from '../../lib/websocket'
import { useUIStore } from '../../store/ui'
import { notifications as notifApi, targets as targetsApi, type Notification } from '../../lib/api'
import type { Target } from '../../types'
import { cn, timeAgo, useDebouncedValue } from '../../lib/utils'

const sevDot: Record<string, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-accent',
}

// Static labels for top-level route segments; `/targets/:id` resolves to the
// target name via a tiny in-memory cache so breadcrumbs read like a terminal
// path: "~/targets/example.com" instead of a raw UUID.
const SEGMENT_LABEL: Record<string, string> = {
  targets: 'targets', findings: 'findings', tasks: 'tasks', system: 'system',
}

function useBreadcrumbs(): { label: string; to: string }[] {
  const { pathname } = useLocation()
  const [targetName, setTargetName] = useState<string | null>(null)
  const parts = pathname.split('/').filter(Boolean)

  // Resolve a target name when the path is /targets/:id.
  const targetId = parts[0] === 'targets' && parts[1] ? parts[1] : null
  useEffect(() => {
    if (!targetId) { setTargetName(null); return }
    let alive = true
    targetsApi.get(targetId).then(t => { if (alive) setTargetName(t.name || t.domain) }).catch(() => {})
    return () => { alive = false }
  }, [targetId])

  const crumbs: { label: string; to: string }[] = []
  if (parts[0] && SEGMENT_LABEL[parts[0]]) crumbs.push({ label: SEGMENT_LABEL[parts[0]], to: `/${parts[0]}` })
  if (targetId) crumbs.push({ label: targetName || '…', to: `/targets/${targetId}` })
  return crumbs
}

// Global search — a lightweight command-palette-style target jump. Targets are
// fetched once and filtered client-side (debounced), so typing stays smooth
// even with thousands of targets. Enter jumps to the first match.
function GlobalSearch() {
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [all, setAll] = useState<Target[]>([])
  const boxRef = useRef<HTMLDivElement | null>(null)
  const debounced = useDebouncedValue(q, 200)

  // Lazy-load the target list the first time the box is focused.
  const loadOnce = () => { if (all.length === 0) targetsApi.list().then(setAll).catch(() => {}) }

  useEffect(() => {
    const onDoc = (e: MouseEvent) => { if (open && boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const results = useMemo(() => {
    const term = debounced.trim().toLowerCase()
    if (!term) return []
    return all.filter(t => (t.name || '').toLowerCase().includes(term) || (t.domain || '').toLowerCase().includes(term)).slice(0, 8)
  }, [debounced, all])

  const go = (t: Target) => { setOpen(false); setQ(''); nav(`/targets/${t.id}`) }

  return (
    <div className="relative hidden md:block" ref={boxRef}>
      <div className="flex items-center gap-2 w-56 lg:w-64 px-3 py-1.5 rounded bg-surface-alt border border-border focus-within:border-accent/50 transition-colors">
        <span className="text-accent font-mono text-xs shrink-0">/</span>
        <input value={q} onFocus={() => { loadOnce(); setOpen(true) }} onChange={e => { setQ(e.target.value); setOpen(true) }}
          onKeyDown={e => { if (e.key === 'Enter' && results[0]) go(results[0]); if (e.key === 'Escape') setOpen(false) }}
          placeholder="grep targets…" className="bg-transparent outline-none text-sm text-text-primary placeholder-text-muted w-full font-mono" />
      </div>
      {open && debounced.trim() && (
        <div className="absolute left-0 mt-2 w-80 max-w-[calc(100vw-2rem)] max-h-80 overflow-y-auto rounded border border-border bg-surface-2 shadow-2xl z-50">
          {results.length === 0
            ? <p className="text-xs text-text-muted text-center py-6">No targets match “{debounced.trim()}”.</p>
            : results.map(t => (
              <button key={t.id} onClick={() => go(t)}
                className="w-full text-left px-4 py-2.5 border-b border-border/60 last:border-0 hover:bg-accent/[.06] transition-colors">
                <span className="block text-sm text-text-primary truncate">{t.name || t.domain}</span>
                {t.name && <span className="block text-[11px] text-text-muted truncate font-mono">{t.domain}</span>}
              </button>
            ))}
        </div>
      )}
    </div>
  )
}

export const TopBar = () => {
  const [connected, setConnected] = useState(false)
  const { toasts, removeToast, setSidebarOpen } = useUIStore()
  const navigate = useNavigate()
  const crumbs = useBreadcrumbs()

  const [items, setItems] = useState<Notification[]>([])
  const [unread, setUnread] = useState(0)
  const [open, setOpen] = useState(false)
  const bellRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => { const i = setInterval(() => setConnected(ws.connected), 2000); return () => clearInterval(i) }, [])

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await notifApi.list()
        if (alive) { setItems(r.notifications || []); setUnread(r.unread || 0) }
      } catch { /* ignore */ }
    }
    load()
    const t = setInterval(load, 60 * 1000) // poll every minute
    return () => { alive = false; clearInterval(t) }
  }, [])

  // Close the dropdown on an outside click.
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (open && bellRef.current && !bellRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const markAllRead = async () => {
    try { await notifApi.markRead() } catch { /* ignore */ }
    setItems(items.map(n => ({ ...n, is_read: true })))
    setUnread(0)
  }

  const openNotif = (n: Notification) => {
    setOpen(false)
    if (n.target_id) navigate(`/targets/${n.target_id}`)
  }

  return (
    <>
      <header className="h-16 flex items-center justify-between gap-2 sm:gap-4 px-3 sm:px-6 border-b border-border bg-surface-1/80 backdrop-blur-xl shrink-0">
        {/* Mobile menu button — opens the off-canvas sidebar drawer */}
        <button onClick={() => setSidebarOpen(true)} title="Open menu"
          className="lg:hidden p-2 -ml-1 rounded text-text-secondary hover:text-text-primary hover:bg-white/[.06] transition-colors shrink-0">
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        {/* Terminal-path breadcrumbs: ~/targets/example.com */}
        <nav className="flex items-center gap-0.5 text-[13px] min-w-0 font-mono" aria-label="Breadcrumb">
          <span className="text-text-muted shrink-0">~</span>
          {crumbs.length === 0 && <span className="text-text-muted/60 shrink-0">/</span>}
          {crumbs.map((c, i) => (
            <span key={c.to} className="flex items-center gap-0.5 min-w-0">
              <span className="text-text-muted/50 shrink-0">/</span>
              {i === crumbs.length - 1
                ? <span className="text-accent font-medium truncate">{c.label}</span>
                : <Link to={c.to} className="text-text-secondary hover:text-text-primary transition-colors truncate">{c.label}</Link>}
            </span>
          ))}
        </nav>

        <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
          <GlobalSearch />

          {/* Notifications bell */}
          <div className="relative" ref={bellRef}>
            <button onClick={() => setOpen(o => !o)} title="Notifications"
              className="relative p-2 rounded text-text-muted hover:text-text-primary hover:bg-white/[.06] transition-colors">
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              {unread > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-severity-critical text-white text-[10px] font-bold grid place-items-center">
                  {unread > 99 ? '99+' : unread}
                </span>
              )}
            </button>

            {open && (
              <div className="absolute right-0 mt-2 w-80 max-w-[calc(100vw-1.5rem)] max-h-[70vh] overflow-hidden flex flex-col rounded border border-border bg-surface-2 shadow-2xl z-50">
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
                  <span className="text-sm font-semibold font-mono">// notifications</span>
                  {unread > 0 && (
                    <button onClick={markAllRead} className="text-[11px] text-accent hover:underline">Mark all read</button>
                  )}
                </div>
                <div className="overflow-y-auto">
                  {items.length === 0 ? (
                    <p className="text-xs text-text-muted text-center py-8">No notifications yet.</p>
                  ) : items.map(n => (
                    <button key={n.id} onClick={() => openNotif(n)}
                      className={cn('w-full text-left px-4 py-2.5 border-b border-border/60 hover:bg-white/[.04] transition-colors flex gap-2.5',
                        !n.is_read && 'bg-accent/[.05]')}>
                      <span className={cn('mt-1.5 w-2 h-2 rounded-full shrink-0', sevDot[n.severity] || 'bg-accent')} />
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs font-semibold text-text-primary truncate">{n.title}</span>
                        {n.body && <span className="block text-[11px] text-text-secondary break-words line-clamp-2">{n.body}</span>}
                        <span className="block text-[10px] text-text-muted mt-0.5">{timeAgo(n.created_at)}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className={cn('flex items-center gap-2 text-[11px] font-semibold px-2.5 sm:px-3 py-1.5 rounded-full border font-mono tracking-wider',
            connected
              ? 'text-severity-low border-severity-low/25 bg-severity-low/10'
              : 'text-text-muted border-white/10 bg-white/5')}>
            <span className={connected ? 'dot-online' : 'dot-offline'}/>
            <span>{connected ? 'LIVE' : 'OFFLINE'}</span>
          </div>
        </div>
      </header>

      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none max-w-[calc(100vw-2.5rem)]">
        {toasts.map(t => (
          <div key={t.id} className={cn('flex items-start gap-3 px-4 py-3 rounded border shadow-lg text-sm pointer-events-auto min-w-64 max-w-sm',
            t.type === 'success' && 'bg-surface-3 border-severity-low/30 text-severity-low',
            t.type === 'error' && 'bg-surface-3 border-severity-critical/30 text-severity-critical',
            t.type === 'warning' && 'bg-surface-3 border-severity-medium/30 text-severity-medium',
            t.type === 'info' && 'bg-surface-3 border-accent/30 text-accent',
          )}>
            {/* min-w-0 + break lets a long message wrap/clamp instead of stretching the
                toast across the whole viewport (a pasted 700-IP scope did exactly that). */}
            <span className="flex-1 min-w-0 break-words line-clamp-4 max-h-40 overflow-hidden">{t.message}</span>
            <button onClick={() => removeToast(t.id)} className="opacity-60 hover:opacity-100 shrink-0">✕</button>
          </div>
        ))}
      </div>
    </>
  )
}
