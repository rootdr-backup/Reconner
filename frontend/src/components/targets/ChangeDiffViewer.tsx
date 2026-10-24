import { useEffect, useMemo, useState } from 'react'
import { Modal, CopyButton } from '../ui'
import { findings as findingsApi } from '../../lib/api'
import { diffLines } from 'diff'
import { cn, truncate } from '../../lib/utils'
import type { FileBodyResponse } from '../../types'

type Props = {
  targetId: string
  url: string
  kind: 'css' | 'js'
  onClose: () => void
}

// Line-level diff for a monitored stylesheet/script change (css_change /
// js_change rows). Both sides are read from the body captured at detection time
// (monitor.go's css_files/js_files) — never a live re-fetch: a live fetch would
// show today's bytes on both sides and pull a possibly third-party URL through
// a fresh GET on every drawer open.
export function ChangeDiffViewer({ targetId, url, kind, onClose }: Props) {
  const [current, setCurrent] = useState<FileBodyResponse | null>(null)
  const [previous, setPrevious] = useState<FileBodyResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError('')
    setCurrent(null)
    setPrevious(null)
    Promise.all([
      findingsApi.fileBody(targetId, kind, url, 'current'),
      findingsApi.fileBody(targetId, kind, url, 'old'),
    ])
      .then(([cur, prev]) => {
        if (!alive) return
        setCurrent(cur)
        setPrevious(prev)
        setLoading(false)
      })
      .catch(e => {
        if (!alive) return
        setError(e instanceof Error ? e.message : 'Failed to load stored file bodies')
        setLoading(false)
      })
    return () => { alive = false }
  }, [targetId, kind, url])

  const hunks = useMemo(() => {
    if (!current || !previous) return null
    return diffLines(previous.content || '', current.content || '')
  }, [current, previous])

  const added = (hunks || []).reduce((n, h) => n + (h.added ? (h.count || 0) : 0), 0)
  const removed = (hunks || []).reduce((n, h) => n + (h.removed ? (h.count || 0) : 0), 0)
  // Identical bytes on both sides but different recorded hashes ⇒ the 256 KB
  // capture cap cut the tail: the change is real, it just sits past the stored
  // content.
  const truncated = !!previous?.captured && !!current?.captured && added === 0 && removed === 0 && previous.hash !== current.hash

  return (
    <Modal open onClose={onClose} width="xl"
      title={`${kind === 'css' ? 'Stylesheet' : 'JavaScript'} diff — ${truncate(url, 80)}`}
      footer={<span className="text-xs text-text-muted"><span className="text-severity-low">+{added.toLocaleString()}</span>{' / '}<span className="text-severity-medium">−{removed.toLocaleString()}</span> lines</span>}>
      <p className="font-mono text-[11px] text-text-muted break-all mb-3">{url}</p>
      {loading && <p className="text-xs text-text-muted py-8 text-center">Loading stored snapshots…</p>}
      {!loading && error && <p className="text-xs text-severity-medium py-8 text-center">{error}</p>}
      {!loading && !error && (
        <div className="rounded-lg border border-border overflow-hidden">
          {!previous?.captured || !current?.captured ? (
            <p className="px-3 py-2 text-[11px] text-text-muted bg-surface-3 border-b border-border">
              {!previous?.captured && !current?.captured
                ? 'Neither side was captured — this row predates content tracking. Recorded hashes only.'
                : !previous?.captured
                ? 'Original content was not captured — this row predates content tracking. Current capture shown read-only.'
                : 'Current content was not captured. Stored original shown read-only.'}
            </p>
          ) : truncated ? (
            <p className="px-3 py-2 text-[11px] text-severity-medium bg-surface-3 border-b border-border">
              Both snapshots hold identical bytes but the recorded hashes differ — the change sits past the 256 KB capture cap.
            </p>
          ) : null}
          {previous?.captured && current?.captured ? (
            <div className="max-h-[55vh] overflow-y-auto">
              {(hunks || []).length === 0 && (
                <p className="px-3 py-2 text-[11px] text-text-muted">No stored content on either side.</p>
              )}
              {(hunks || []).map((h, i) => (
                <div key={i} className={cn(h.added && 'bg-severity-low/10', h.removed && 'bg-severity-medium/10')}>
                  {h.value.replace(/\n$/, '').split('\n').map((line, j) => (
                    <div key={j} className={cn('px-3 py-px font-mono text-[11px] whitespace-pre-wrap break-all', h.added ? 'text-severity-low' : h.removed ? 'text-severity-medium' : 'text-text-muted')}>
                      <span className="select-none opacity-60 mr-2">{h.added ? '+' : h.removed ? '−' : ' '}</span>{line}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          ) : (
            <div className="max-h-[55vh] overflow-y-auto">
              {((current?.captured ? current.content : previous?.content) || 'Not captured.').split('\n').map((line, j) => (
                <div key={j} className="px-3 py-px font-mono text-[11px] whitespace-pre-wrap break-all text-text-muted">{line}</div>
              ))}
            </div>
          )}
          <div className="flex items-center justify-between gap-3 px-3 py-2 border-t border-border bg-surface-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-[10px] uppercase tracking-wider text-text-muted shrink-0">Old ({previous?.hash ? previous.hash.slice(0, 12) : '—'})</span>
              {previous?.captured ? <CopyButton text={previous.content} /> : <span className="text-[10px] text-text-muted">not captured</span>}
            </div>
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-[10px] uppercase tracking-wider text-text-muted shrink-0">Current ({current?.hash ? current.hash.slice(0, 12) : '—'})</span>
              {current?.captured ? <CopyButton text={current.content} /> : <span className="text-[10px] text-text-muted">not captured</span>}
            </div>
          </div>
        </div>
      )}
    </Modal>
  )
}
