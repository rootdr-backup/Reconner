import { cn } from '../../lib/utils'
import { statusCodeColor } from '../../lib/utils'
import { inlineDiffPieces, parseStatusTransition } from './changesModel'

interface Props {
  oldValue: string
  newValue: string
  changeType: string
}

function StatusPill({ code }: { code?: number }) {
  if (!code) return <span className="text-text-muted">—</span>
  return (
    <span className={cn('rounded border border-border px-1.5 py-0.5 font-mono text-xs tabular-nums', statusCodeColor(code))}>
      {code}
    </span>
  )
}

export default function InlineChangeDiff({ oldValue, newValue, changeType }: Props) {
  const { oldCode, newCode } = parseStatusTransition(oldValue, newValue)
  if (changeType === 'status_change' && (oldCode || newCode)) {
    return (
      <span className="inline-flex items-center gap-1.5" title={`${oldValue} → ${newValue}`}>
        <StatusPill code={oldCode} />
        <span className="text-text-muted">→</span>
        <StatusPill code={newCode} />
      </span>
    )
  }

  const pieces = inlineDiffPieces(oldValue, newValue)
  return (
    <span
      className="font-mono text-xs break-all whitespace-pre-wrap"
      title={`Old: ${oldValue}\nNew: ${newValue}`}
    >
      {pieces.map((piece, i) => (
        <span
          key={i}
          className={cn(
            piece.kind === 'removed' && 'bg-severity-medium/10 text-severity-medium line-through',
            piece.kind === 'added' && 'bg-severity-low/10 text-severity-low',
            piece.kind === 'same' && 'text-text-muted',
          )}
        >
          {piece.kind === 'removed' ? '−' : piece.kind === 'added' ? '+' : ''}{piece.text}
        </span>
      ))}
    </span>
  )
}
