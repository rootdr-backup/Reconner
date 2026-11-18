import { cn, timeAgo } from '../../lib/utils'
import type { WatchRound } from '../../types'

const TASK_STATUS_DOT: Record<string, string> = {
  running: 'dot-running', completed: 'dot-online', finished: 'dot-online', failed: 'dot-error',
  paused: 'dot-offline', pending: 'dot-offline', queued: 'dot-offline', cancelled: 'dot-offline',
}

interface Props {
  rounds: WatchRound[]
  selectedTaskId: string
  onSelect: (taskId: string) => void
  compact?: boolean
}

function duration(round: WatchRound): string {
  if (!round.started_at || !round.finished_at) return '—'
  const ms = new Date(round.finished_at).getTime() - new Date(round.started_at).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const sec = Math.round(ms / 1000)
  if (sec < 60) return `${sec}s`
  return `${Math.floor(sec / 60)}m ${sec % 60}s`
}

export default function RoundTimeline({ rounds, selectedTaskId, onSelect, compact }: Props) {
  if (rounds.length === 0) {
    return <p className="px-3 py-6 text-center text-sm text-text-muted">No watch rounds yet.</p>
  }
  return (
    <div className={cn('divide-y divide-white/[.05]', compact && 'max-h-64 overflow-y-auto')}>
      {rounds.map(round => (
        <button
          key={round.id}
          type="button"
          onClick={() => onSelect(selectedTaskId === round.id ? '' : round.id)}
          className={cn(
            'flex w-full items-center gap-3 px-3 py-2 text-left text-sm transition hover:bg-white/[.03]',
            selectedTaskId === round.id && 'bg-accent/10',
          )}
        >
          <span className={cn(TASK_STATUS_DOT[round.status] || 'dot-offline')} />
          <span className="min-w-0 flex-1">
            <span className="block truncate font-medium text-text-primary">{round.target_name || round.target_id}</span>
            <span className="block text-xs text-text-muted">{timeAgo(round.started_at)} · {duration(round)}</span>
          </span>
          <span className="shrink-0 tabular-nums text-xs text-accent">{round.change_count} changes</span>
          {round.error && <span className="shrink-0 text-xs text-severity-medium" title={round.error}>error</span>}
        </button>
      ))}
    </div>
  )
}
