import { useEffect, useState } from 'react'
import { Modal } from '../ui'
import { targets as targetsApi } from '../../lib/api'

type Ev = { identity_label: string; request: string; response: string; comparison: string; note: string; image?: string }
type Replay = { identity_label: string; status: number; content_type: string; length: number; body: string; verdict: string; timing_ms: number }

const verdictClass: Record<string, string> = {
  authorized: 'badge-critical', denied: 'badge-low', ambiguous: 'badge-medium', error: 'badge-neutral',
}

// EvidenceViewer shows the structured, redacted per-identity request/response
// evidence behind a finding, and lets the researcher replay the request across
// identities (Phase 6 + 7). Credentials are already redacted server-side.
export const EvidenceViewer = ({ targetId, findingId, url, type, open, onClose }:
  { targetId: string; findingId: string; url: string; type: string; open: boolean; onClose: () => void }) => {
  const [ev, setEv] = useState<Ev[]>([])
  const [replays, setReplays] = useState<Replay[]>([])
  const [comparison, setComparison] = useState('')
  const [loading, setLoading] = useState(false)
  const [replaying, setReplaying] = useState(false)

  useEffect(() => {
    if (!open) return
    setLoading(true)
    targetsApi.evidence(targetId, findingId).then(setEv).catch(() => setEv([])).finally(() => setLoading(false))
    setReplays([]); setComparison('')
  }, [open, targetId, findingId])

  const replay = async () => {
    setReplaying(true)
    try {
      const r = await targetsApi.replay(targetId, { method: 'GET', url, identity_id: 'all' })
      setReplays(r.results || []); setComparison(r.comparison || '')
    } catch { /* ignore */ } finally { setReplaying(false) }
  }

  return (
    <Modal open={open} onClose={onClose} title={`Evidence — ${type.replace(/_/g, ' ')}`} width="xl">
      <div className="space-y-4">
        <div className="text-xs font-mono text-text-muted break-all">{url}</div>

        {loading && <p className="text-xs text-text-muted">Loading evidence…</p>}
        {!loading && ev.length === 0 && (
          <p className="text-xs text-text-muted">No structured evidence stored for this finding (older finding, or a scanner that hasn't been migrated to the evidence engine yet).</p>
        )}

        {ev.map((e, i) => (
          <div key={i} className="card p-3 space-y-2">
            <div className="flex items-center gap-2">
              <span className="badge-info">{e.identity_label || 'identity'}</span>
              {e.comparison && <span className="text-xs text-text-secondary">{e.comparison}</span>}
            </div>
            {e.image && (
              <a href={e.image} target="_blank" rel="noreferrer" className="block">
                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Live snapshot</div>
                <img src={e.image} alt="device snapshot" loading="lazy"
                  className="max-h-64 rounded border border-white/[.08] object-contain bg-black/40" />
              </a>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Request</div>
                <pre className="text-[11px] font-mono whitespace-pre-wrap bg-black/30 rounded p-2 max-h-40 overflow-auto">{e.request}</pre>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Response</div>
                <pre className="text-[11px] font-mono whitespace-pre-wrap bg-black/30 rounded p-2 max-h-40 overflow-auto">{e.response}</pre>
              </div>
            </div>
            {e.note && <div className="text-xs text-text-secondary border-t border-white/[.06] pt-2">{e.note}</div>}
          </div>
        ))}

        {/* Replay */}
        <div className="card p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Replay across identities</span>
            <button onClick={replay} disabled={replaying} className="btn-secondary text-xs">
              {replaying ? 'Replaying…' : 'Replay GET as unauth + all identities'}
            </button>
          </div>
          {comparison && <div className="text-xs text-text-muted">{comparison}</div>}
          {replays.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-text-muted text-left">
                  <th className="py-1 pr-3">Identity</th><th className="py-1 pr-3">Verdict</th>
                  <th className="py-1 pr-3">Status</th><th className="py-1 pr-3">Bytes</th><th className="py-1 pr-3">ms</th>
                </tr></thead>
                <tbody>
                  {replays.map((r, i) => (
                    <tr key={i} className="border-t border-white/[.06]">
                      <td className="py-1 pr-3 font-medium">{r.identity_label}</td>
                      <td className="py-1 pr-3"><span className={verdictClass[r.verdict] || 'badge-neutral'}>{r.verdict}</span></td>
                      <td className="py-1 pr-3 font-mono">{r.status}</td>
                      <td className="py-1 pr-3 font-mono">{r.length}</td>
                      <td className="py-1 pr-3 font-mono">{r.timing_ms}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="text-[10px] text-text-muted">Researcher-triggered, authorized testing only. Bodies are redacted server-side.</p>
        </div>
      </div>
    </Modal>
  )
}
