import { useEffect, useState } from 'react'
import { targets as targetsApi } from '../../lib/api'

type Hyp = { kind: string; identity: string; object_type: string; object_id: string; action: string; endpoint: string; expected: string; observed: string; status: string; confidence: number; test_plan: string; reason: string; finding_id: string }
type Rel = { object_type: string; object_id: string; endpoint: string; identity: string; role: string; provenance: string }

const statusStyle: Record<string, string> = {
  VERIFIED: 'badge-critical', HYPOTHESIS: 'badge-info', TESTED: 'badge-medium', REJECTED: 'badge-neutral',
}
const roleStyle: Record<string, string> = {
  CREATOR: 'badge-critical', OWNER: 'badge-high', ADMIN: 'badge-high', EDITOR: 'badge-medium',
  MEMBER: 'badge-low', VIEWER: 'badge-low', ACCESSOR: 'badge-neutral',
}

// AuthorizationPanel is the analyst view over the P1 authorization pipeline:
// object ownership relationships + ranked hypotheses (what's worth testing / what
// was verified). Not a decorative dashboard — it answers "who owns what" and
// "where does someone have access without a relationship".
export const AuthorizationPanel = ({ targetId }: { targetId: string }) => {
  const [hyps, setHyps] = useState<Hyp[]>([])
  const [rels, setRels] = useState<Rel[]>([])
  const [groups, setGroups] = useState<{ key: string; type: string; severity: string; affected_count: number; confidence: number }[]>([])
  const [graph, setGraph] = useState<{ nodes: { id: string; type: string; label: string }[]; edges: { from: string; to: string; label: string; kind: string }[] }>({ nodes: [], edges: [] })
  const [tab, setTab] = useState<'hypotheses' | 'ownership' | 'groups' | 'workflow' | 'runner'>('hypotheses')
  const [wfJson, setWfJson] = useState('[\n  {"identity_label":"user-a","method":"POST","url":"https://app/api/projects","extract":{"project.id":"id"}},\n  {"identity_label":"user-b","method":"GET","url":"https://app/api/projects/${project.id}","expect_denied":true}\n]')
  const [wfOut, setWfOut] = useState<string>('')
  const [verifyRow, setVerifyRow] = useState<number | null>(null)
  const [vf, setVf] = useState({ owner: '', read_url: '', write_method: 'PATCH', write_url: '', write_body: '' })
  const [vres, setVres] = useState<string>('')

  const load = () => {
    targetsApi.hypotheses(targetId).then(setHyps).catch(() => setHyps([]))
    targetsApi.relationships(targetId).then(setRels).catch(() => setRels([]))
    targetsApi.findingGroups(targetId).then(setGroups).catch(() => setGroups([]))
    targetsApi.workflowGraph(targetId).then(setGraph).catch(() => setGraph({ nodes: [], edges: [] }))
  }
  useEffect(load, [targetId])

  const runVerify = async (h: Hyp) => {
    setVres('running…')
    try {
      const r = await targetsApi.verifyWrite(targetId, {
        owner_label: vf.owner, attacker_label: h.identity,
        object_type: h.object_type, object_id: h.object_id,
        read_url: vf.read_url, write_method: vf.write_method, write_url: vf.write_url,
        write_body: vf.write_body,
      })
      setVres(r.side_effect
        ? `⚠ SIDE EFFECT CONFIRMED — ${r.summary} (finding created)`
        : `no side effect — authorization appears intact (before=${r.before_status} after=${r.after_status} write=${r.write_status})`)
      load()
    } catch (e) { setVres(e instanceof Error ? e.message : 'failed') }
  }

  return (
    <details className="card p-4">
      <summary className="text-sm font-medium cursor-pointer select-none flex items-center gap-2">
        Authorization Analysis
        {hyps.some(h => h.status === 'VERIFIED') && <span className="badge-critical">{hyps.filter(h => h.status === 'VERIFIED').length} verified</span>}
        <span className="text-text-muted text-xs">({hyps.length} hypotheses · {rels.length} relationships)</span>
      </summary>

      <div className="mt-3 space-y-3">
        <div className="flex gap-2 text-xs">
          {(['hypotheses', 'ownership', 'groups', 'workflow', 'runner'] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-2.5 py-1 rounded-md ${tab === t ? 'bg-accent/15 text-accent-hover' : 'bg-white/5 text-text-muted'}`}>
              {t === 'hypotheses' ? 'Hypotheses & findings' : t === 'ownership' ? 'Object ownership' : t === 'groups' ? 'Root issues' : t === 'workflow' ? 'Workflow graph' : 'Workflow runner'}
            </button>
          ))}
          <button onClick={load} className="ml-auto px-2.5 py-1 rounded-md bg-white/5 text-text-muted">↻ refresh</button>
        </div>

        {tab === 'hypotheses' && (
          hyps.length === 0
            ? <p className="text-xs text-text-muted">No authorization hypotheses yet. Capture authenticated traffic for ≥2 identities, then run the <code className="code">authz</code> module — it turns ownership + actions into ranked cross-identity tests and auto-verifies READ BOLA.</p>
            : <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="text-text-muted text-left">
                    <th className="py-1 pr-3">Status</th><th className="py-1 pr-3">Kind</th><th className="py-1 pr-3">Plan</th>
                    <th className="py-1 pr-3">Identity</th><th className="py-1 pr-3">Object</th>
                    <th className="py-1 pr-3">Exp→Obs</th><th className="py-1 pr-3">Conf</th><th className="py-1 pr-3">Why</th>
                  </tr></thead>
                  <tbody>
                    {hyps.map((h, i) => (
                      <tr key={i} className="border-t border-white/[.06] align-top">
                        <td className="py-1 pr-3"><span className={statusStyle[h.status] || 'badge-neutral'}>{h.status}</span></td>
                        <td className="py-1 pr-3 font-mono">{h.kind}</td>
                        <td className="py-1 pr-3 font-mono text-text-muted">{h.test_plan}</td>
                        <td className="py-1 pr-3 font-medium">{h.identity}</td>
                        <td className="py-1 pr-3 font-mono">{h.object_type}#{h.object_id}</td>
                        <td className="py-1 pr-3 font-mono">{h.expected}→{h.observed}</td>
                        <td className="py-1 pr-3 font-mono">{h.confidence}</td>
                        <td className="py-1 pr-3 text-text-secondary max-w-md">
                          {h.reason}
                          {h.action !== 'READ' && h.status !== 'VERIFIED' && (
                            <button onClick={() => { setVerifyRow(verifyRow === i ? null : i); setVres('') }}
                              className="ml-2 text-accent-hover hover:underline">verify write ▾</button>
                          )}
                          {verifyRow === i && (
                            <div className="mt-2 p-2 rounded-lg bg-black/30 space-y-1.5">
                              <p className="text-[10px] text-severity-medium">⚠ Destructive: performs the write as {h.identity} on an AUTHORIZED target. Owner's before/after view proves any side effect.</p>
                              <input className="input text-[11px] font-mono" placeholder="owner identity label (e.g. user-a)" value={vf.owner} onChange={e => setVf({ ...vf, owner: e.target.value })} />
                              <input className="input text-[11px] font-mono" placeholder="owner READ url for this object" value={vf.read_url} onChange={e => setVf({ ...vf, read_url: e.target.value })} />
                              <div className="flex gap-1.5">
                                <input className="input text-[11px] font-mono w-24" placeholder="PATCH" value={vf.write_method} onChange={e => setVf({ ...vf, write_method: e.target.value })} />
                                <input className="input text-[11px] font-mono flex-1" placeholder="write url" value={vf.write_url} onChange={e => setVf({ ...vf, write_url: e.target.value })} />
                              </div>
                              <input className="input text-[11px] font-mono" placeholder='write body e.g. {"role":"admin"}' value={vf.write_body} onChange={e => setVf({ ...vf, write_body: e.target.value })} />
                              <button onClick={() => runVerify(h)} className="btn-secondary text-[11px]">Run before/after verification</button>
                              {vres && <div className="text-[11px] text-text-secondary">{vres}</div>}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
        )}

        {tab === 'ownership' && (
          rels.length === 0
            ? <p className="text-xs text-text-muted">No object relationships yet. They're derived from authenticated traffic (CREATE ⇒ creator/owner; response ownership fields ⇒ owner; access ⇒ accessor).</p>
            : <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="text-text-muted text-left">
                    <th className="py-1 pr-3">Object</th><th className="py-1 pr-3">Identity</th>
                    <th className="py-1 pr-3">Role</th><th className="py-1 pr-3">Provenance</th>
                  </tr></thead>
                  <tbody>
                    {rels.map((r, i) => (
                      <tr key={i} className="border-t border-white/[.06]">
                        <td className="py-1 pr-3 font-mono">{r.object_type}#{r.object_id}</td>
                        <td className="py-1 pr-3 font-medium">{r.identity}</td>
                        <td className="py-1 pr-3"><span className={roleStyle[r.role] || 'badge-neutral'}>{r.role}</span></td>
                        <td className="py-1 pr-3 text-text-muted">{r.provenance}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
        )}

        {tab === 'groups' && (
          groups.length === 0
            ? <p className="text-xs text-text-muted">No correlated findings yet. After a scan, findings sharing a root cause (same type + endpoint template) are grouped here — one issue, N affected resources.</p>
            : <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="text-text-muted text-left">
                    <th className="py-1 pr-3">Severity</th><th className="py-1 pr-3">Type</th>
                    <th className="py-1 pr-3">Root cause (endpoint)</th><th className="py-1 pr-3">Affected</th><th className="py-1 pr-3">Conf</th>
                  </tr></thead>
                  <tbody>
                    {groups.map((g, i) => (
                      <tr key={i} className="border-t border-white/[.06]">
                        <td className="py-1 pr-3"><span className={`badge-${g.severity || 'neutral'}`}>{g.severity}</span></td>
                        <td className="py-1 pr-3 font-mono">{g.type}</td>
                        <td className="py-1 pr-3 font-mono text-text-muted break-all">{g.key.split('|')[1]}</td>
                        <td className="py-1 pr-3 font-mono">{g.affected_count} resource(s)</td>
                        <td className="py-1 pr-3 font-mono">{g.confidence}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
        )}

        {tab === 'workflow' && (
          graph.nodes.length === 0
            ? <p className="text-xs text-text-muted">No workflow graph yet. It's built from captured actions + ownership: who created/owns each object and which actions were applied. Capture authenticated traffic first.</p>
            : <div className="space-y-2 text-xs">
                <p className="text-text-muted">{graph.nodes.filter(n => n.type === 'identity').length} identities · {graph.nodes.filter(n => n.type === 'object').length} objects · {graph.edges.length} edges</p>
                {graph.nodes.filter(n => n.type === 'identity').map(idn => {
                  const owns = graph.edges.filter(e => e.from === idn.id && e.kind === 'ownership')
                  const acts = graph.edges.filter(e => e.from === idn.id && e.kind === 'action')
                  return (
                    <div key={idn.id} className="card p-2">
                      <div className="font-medium">{idn.label}</div>
                      {owns.length > 0 && <div className="text-text-secondary">owns: {owns.map(e => `${e.to.replace('obj:', '')} (${e.label})`).join(', ')}</div>}
                      {acts.length > 0 && <div className="text-text-muted">actions: {acts.map(e => `${e.label}→${e.to.replace('obj:', '')}`).join(', ')}</div>}
                      {owns.length === 0 && acts.length === 0 && <div className="text-text-muted">no recorded activity</div>}
                    </div>
                  )
                })}
              </div>
        )}

        {tab === 'runner' && (
          <div className="space-y-2 text-xs">
            <p className="text-text-muted">Define a multi-step workflow (JSON). Steps run in order as the chosen identity;
              use <code className="code">{'${var}'}</code> to reference values extracted by earlier steps
              (<code className="code">extract</code>). Mark a step <code className="code">"expect_denied":true</code> — if it
              still succeeds, a workflow authorization-bypass finding is created. Runs on an AUTHORIZED target only.</p>
            <textarea value={wfJson} onChange={e => setWfJson(e.target.value)} rows={8} className="input font-mono text-[11px]" />
            <button className="btn-secondary text-xs" onClick={async () => {
              setWfOut('running…')
              try {
                const steps = JSON.parse(wfJson)
                const r = await targetsApi.runWorkflow(targetId, steps)
                const lines = r.steps.map(s => `#${s.index} ${s.identity || 'unauth'} ${s.method} ${s.url} → ${s.status} ${s.verdict}${s.flagged ? '  ⚠ FLAGGED (bypass)' : ''}${Object.keys(s.extracted).length ? '  extracted: ' + JSON.stringify(s.extracted) : ''}`)
                if (r.aborted) lines.push('ABORTED: ' + r.abort_reason)
                if (r.flagged_step >= 0) lines.push(`\n⚠ Workflow authorization bypass at step ${r.flagged_step} — finding created.`)
                setWfOut(lines.join('\n')); load()
              } catch (e) { setWfOut(e instanceof Error ? e.message : 'failed') }
            }}>▶ Run workflow</button>
            {wfOut && <pre className="text-[11px] font-mono whitespace-pre-wrap bg-black/30 rounded p-2 max-h-64 overflow-auto">{wfOut}</pre>}
          </div>
        )}
      </div>
    </details>
  )
}
