import { useCallback, useEffect, useState } from 'react'
import { bounty, targets as targetsApi } from '../../lib/api'
import type { WatchScopeEvent } from '../../lib/api'
import type { BountyScopeEvent } from '../../types'
import { Button, Badge } from '../ui'
import { timeAgo } from '../../lib/utils'

interface Props {
  targetId?: string
}

export default function ScopeEventsPanel({ targetId }: Props) {
  const [events, setEvents] = useState<WatchScopeEvent[]>([])
  const [scopeEvents, setScopeEvents] = useState<BountyScopeEvent[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    if (!targetId) return
    try {
      const [landed, scope] = await Promise.all([
        targetsApi.watchScopeEvents(targetId),
        bounty.events(targetId),
      ])
      setEvents(landed.events || [])
      setScopeEvents(scope || [])
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load scope events')
    }
  }, [targetId])

  useEffect(() => { void load() }, [load])

  const promote = async (value: string) => {
    if (!targetId) return
    setBusy(value)
    try {
      await targetsApi.promoteWatchScope(targetId, [value.toLowerCase()])
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to promote host')
    } finally {
      setBusy(null)
    }
  }

  const resolve = async (event: BountyScopeEvent, decision: 'approve' | 'reject') => {
    if (!targetId) return
    setBusy(event.id)
    try {
      await bounty.resolveEvent(targetId, event.id, decision)
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to resolve scope change')
    } finally {
      setBusy(null)
    }
  }

  if (!targetId) {
    return <p className="px-3 py-6 text-center text-sm text-text-muted">Select a target to see its scope events.</p>
  }
  if (error) {
    return <p className="px-3 py-6 text-center text-sm text-severity-medium">{error}</p>
  }

  return (
    <div className="space-y-3 p-3">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Landed watch hosts</p>
        <Button size="sm" variant="ghost" onClick={() => void load()} disabled={busy !== null}>Refresh</Button>
      </div>
      {events.length === 0 ? (
        <p className="text-xs text-text-muted">No hosts landed yet. Eligible hosts appear after a watch round finds them alive.</p>
      ) : (
        <div className="space-y-1.5">
          {events.map(ev => (
            <div key={ev.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[.05] bg-white/[.02] px-2 py-1.5">
              <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-text-primary">{ev.identifier}</code>
              <span className="text-[10px] text-text-muted">{timeAgo(ev.detected_at)}</span>
              <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void promote(ev.identifier)}>
                Promote to Deep seed
              </Button>
            </div>
          ))}
        </div>
      )}

      <div className="pt-2">
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted">Bounty scope changes</p>
        {scopeEvents.length === 0 ? (
          <p className="text-xs text-text-muted">No bounty scope changes recorded.</p>
        ) : (
          <div className="space-y-1.5">
            {scopeEvents.slice(0, 50).map(ev => (
              <div key={ev.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[.05] bg-white/[.02] px-2 py-1.5">
                <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-text-primary">{ev.old_json || ev.new_json}</code>
                <Badge variant={ev.status === 'approved' ? 'low' : ev.status === 'rejected' ? 'medium' : 'info'}>{ev.status}</Badge>
                {ev.status === 'pending' && (
                  <>
                    <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void resolve(ev, 'approve')}>Approve</Button>
                    <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void resolve(ev, 'reject')}>Reject</Button>
                  </>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
