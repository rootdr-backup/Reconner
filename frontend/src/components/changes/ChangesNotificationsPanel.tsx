import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { notifications as notifApi } from '../../lib/api'
import type { Notification } from '../../lib/api'
import { ws } from '../../lib/websocket'
import { openNotification, sevDot } from '../../lib/notifications'
import { Button } from '../ui'
import { timeAgo } from '../../lib/utils'

type Bucket = 'all' | 'deep' | 'watch' | 'findings'
const BUCKETS: { id: Bucket; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'deep', label: 'Deep' },
  { id: 'watch', label: 'Watch' },
  { id: 'findings', label: 'Findings' },
]

export default function ChangesNotificationsPanel() {
  const navigate = useNavigate()
  const [bucket, setBucket] = useState<Bucket>('all')
  const [items, setItems] = useState<Notification[]>([])
  const [unread, setUnread] = useState(0)

  const load = useCallback(async () => {
    try {
      const r = await notifApi.list(bucket)
      setItems(r.notifications || [])
      setUnread(r.unread || 0)
    } catch { /* keep the last good list */ }
  }, [bucket])

  useEffect(() => {
    let alive = true
    const run = () => { if (alive) void load() }
    run()
    const timer = setInterval(run, 60 * 1000)
    const offs = [
      ws.on('notification_created', run),
      ws.on('scope_landed', run),
      ws.on('task_finished', run),
    ]
    return () => { alive = false; clearInterval(timer); offs.forEach(off => off()) }
  }, [load])

  const markOne = (n: Notification) => {
    if (!n.is_read) setItems(prev => prev.map(item => item.id === n.id ? { ...item, is_read: true } : item))
    openNotification(n, navigate, notifApi.markRead)
    void load()
  }

  const markAll = async () => {
    try {
      await notifApi.markRead([])
      setItems(prev => prev.map(n => ({ ...n, is_read: true })))
      setUnread(0)
    } catch { /* ignore */ }
  }

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
        <div className="flex gap-1">
          {BUCKETS.map(b => (
            <button
              key={b.id}
              type="button"
              onClick={() => setBucket(b.id)}
              className={`rounded-full border px-2.5 py-1 text-xs transition ${bucket === b.id
                ? 'border-accent bg-accent/15 text-accent'
                : 'border-border text-text-muted hover:text-text-primary'}`}
            >
              {b.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs tabular-nums text-text-muted">{unread} unread</span>
          <Button size="sm" variant="ghost" onClick={() => void markAll()} disabled={unread === 0}>Mark all read</Button>
        </div>
      </div>
      {items.length === 0 ? (
        <p className="px-3 py-6 text-center text-sm text-text-muted">No notifications in this bucket.</p>
      ) : (
        <div className="divide-y divide-white/[.05]">
          {items.map(n => (
            <button
              key={n.id}
              type="button"
              onClick={() => markOne(n)}
              className={`flex w-full gap-3 px-3 py-2 text-left transition hover:bg-white/[.03] ${n.is_read ? '' : 'bg-accent/[.05]'}`}
            >
              <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${sevDot[n.severity] || sevDot.info}`} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-text-primary">{n.title}</span>
                <span className="block text-xs text-text-muted line-clamp-2">{n.body}</span>
              </span>
              <span className="shrink-0 text-[10px] text-text-muted">{timeAgo(n.created_at)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
