import { useCallback, useEffect, useMemo, useState } from 'react'
import { captures, targets as targetsApi, type CapturePreview } from '../lib/api'
import type { Target } from '../types'
import { Badge, Button } from '../components/ui'
import { useUIStore } from '../store/ui'
import GuidedCorpus from '../components/GuidedCorpus'

const sourceFor = async (file: File) => {
  const prefix = (await file.slice(0, 4096).text()).trimStart()
  if (prefix.startsWith('<')) return 'burp_xml'
  if (prefix.startsWith('{')) return 'reconner_json'
  throw new Error('Unsupported capture file. Choose Burp XML or Reconner capture JSON.')
}

const previewTestLabel: Record<string, string> = {
  idor_bola: 'IDOR', sqli: 'SQLi', xss: 'XSS', nosqli: 'NoSQLi', ssrf: 'SSRF', open_redirect: 'Redirect',
}

export default function GuidedAnalyze() {
  const [targets, setTargets] = useState<Target[]>([])
  const [targetId, setTargetId] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [identity, setIdentity] = useState('User A')
  const [label, setLabel] = useState('')
  const [preview, setPreview] = useState<CapturePreview | null>(null)
  const [busy, setBusy] = useState<'preview'|'import'|null>(null)
  const [captureId, setCaptureId] = useState('')
  const [workspaceReady, setWorkspaceReady] = useState(false)
  const [captureOpen, setCaptureOpen] = useState(true)
  const [reviewOpen, setReviewOpen] = useState(true)
  const { addToast } = useUIStore()

  useEffect(() => {
    targetsApi.list().then(value => {
      const web = value.filter(target => target.kind !== 'network')
      setTargets(web)
      if (web[0]) setTargetId(web[0].id)
    }).catch(() => addToast('error', 'Could not load projects'))
  }, [])

  const summary = useMemo(() => {
    const tests = new Set<string>()
    const hosts = new Set<string>()
    let automatic = 0
    for (const item of preview?.items || []) {
      if (!item.accepted) continue
      if (item.auto_eligible) automatic++
      for (const test of item.suggested_tests || []) tests.add(previewTestLabel[test] || test)
      try { hosts.add(new URL(item.route).host) } catch { /* invalid routes are already rejected by admission */ }
    }
    return { tests: [...tests], hosts: [...hosts], automatic }
  }, [preview])

  const submit = async (commit: boolean) => {
    if (!file || !targetId) { addToast('error', 'Choose a project and capture file'); return }
    setBusy(commit ? 'import' : 'preview')
    try {
      const source = await sourceFor(file)
      if (commit) {
        const result = await captures.import(targetId, file, source, identity.trim(), label.trim())
        setPreview(result.preview)
        setCaptureId(result.capture_id)
        setCaptureOpen(false)
        setReviewOpen(false)
        addToast('success', `${result.templates_stored} encrypted request templates imported; no traffic was sent`)
      } else {
        const result = await captures.preview(targetId, file, source, identity.trim(), label.trim())
        setPreview(result.preview)
        addToast('success', `Passive preview ready: ${result.preview.accepted} in-scope requests`)
      }
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Capture import failed') }
    finally { setBusy(null) }
  }

  useEffect(() => { if (file && targetId) void submit(false) }, [file, targetId])
  useEffect(() => { if (workspaceReady && !file) setCaptureOpen(false) }, [workspaceReady, file])
  const handleCaptureChange = useCallback((id: string) => setWorkspaceReady(Boolean(id)), [])

  const phase = captureId ? 2 : preview ? 1 : workspaceReady ? 2 : 0
  const steps = [
    ['Capture', 'Choose traffic'],
    ['Review', 'Approve scope'],
    ['Automate', 'Validate & test'],
  ]

  return <div className="space-y-4 max-w-[1500px] mx-auto">
    <header className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-3">
      <div><p className="page-kicker">Traffic workbench</p><h1 className="mt-1 text-3xl font-semibold tracking-[-.04em]">Guided Analyze</h1><p className="page-lede mt-1">Turn real browser or Burp traffic into a focused, automated security test plan.</p></div>
      <div className="flex items-center gap-1 rounded-xl border border-border bg-surface-2 p-1">
        {steps.map(([title, detail], index) => <div key={title} className={`flex items-center gap-2 rounded-lg px-3 py-2 ${index === phase ? 'bg-accent/10 text-text-primary' : index < phase ? 'text-severity-low' : 'text-text-muted'}`}>
          <span className={`grid h-5 w-5 place-items-center rounded-full text-[10px] font-bold ${index <= phase ? 'bg-accent text-surface-1' : 'bg-surface-3 border border-border'}`}>{index < phase ? '✓' : index + 1}</span>
          <span className="hidden sm:block"><span className="block text-[11px] font-semibold leading-none">{title}</span><span className="block text-[9px] mt-1 opacity-70">{detail}</span></span>
        </div>)}
      </div>
    </header>

    <section className="card overflow-hidden">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 border-b border-border px-4 py-3">
        <div><p className="text-sm font-semibold">1 · Add captured traffic</p><p className="text-[11px] text-text-muted mt-0.5">Preview and import are local and passive. No target request is sent.</p></div>
        <div className="flex items-center gap-2"><Badge variant="success">PASSIVE</Badge><Button size="sm" variant="ghost" onClick={() => setCaptureOpen(value => !value)}>{captureOpen ? 'Hide' : 'Add another'}</Button></div>
      </div>
      {captureOpen && <div className="p-4 space-y-3">
        <div className="grid lg:grid-cols-[minmax(220px,.7fr)_minmax(320px,1.3fr)] gap-3">
          <label><span className="label">Project</span><select className="input" disabled={!!busy} value={targetId} onChange={event => { setTargetId(event.target.value); setPreview(null); setCaptureId(''); setWorkspaceReady(false); setReviewOpen(true) }}><option value="">Choose project…</option>{targets.map(target => <option key={target.id} value={target.id}>{target.name || target.domain}</option>)}</select></label>
          <label><span className="label">Burp XML or Reconner capture JSON</span><input className="input file:mr-3 file:text-xs file:bg-transparent file:border-0 file:text-accent" type="file" disabled={!!busy} onChange={event => { setFile(event.target.files?.[0] || null); setPreview(null); setCaptureId(''); setReviewOpen(true) }}/></label>
        </div>
        <details className="rounded-lg border border-border/70 bg-surface-3/20">
          <summary className="cursor-pointer px-3 py-2 text-xs text-text-secondary">Capture identity & label <span className="text-text-muted">— optional metadata</span></summary>
          <div className="grid md:grid-cols-2 gap-3 border-t border-border/70 p-3">
            <label><span className="label">Identity</span><input className="input" disabled={!!busy} value={identity} maxLength={80} onChange={event => setIdentity(event.target.value)} placeholder="User A / User B / Admin"/></label>
            <label><span className="label">Capture label</span><input className="input" disabled={!!busy} value={label} maxLength={120} onChange={event => setLabel(event.target.value)} placeholder="Checkout → invoice flow"/></label>
          </div>
        </details>
        {file && <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-lg border border-border bg-surface-3/30 px-3 py-2.5">
          <div className="min-w-0"><p className="truncate text-xs font-medium">{file.name}</p><p className="text-[10px] text-text-muted mt-0.5">{(file.size / 1048576).toFixed(1)} MiB · {busy === 'preview' ? 'Inspecting scope and request shapes…' : preview ? `${preview.accepted} in scope and ready to import` : 'Waiting for preview'}</p></div>
          <div className="flex shrink-0 gap-2"><Button size="sm" variant="ghost" loading={busy === 'preview'} disabled={!!busy} onClick={() => submit(false)}>Refresh preview</Button>{preview && !captureId && <Button size="sm" variant="primary" loading={busy === 'import'} disabled={!!busy || preview.accepted === 0} onClick={() => submit(true)}>Import {preview.accepted} requests →</Button>}{captureId && <Badge variant="success">Imported</Badge>}</div>
        </div>}
      </div>}
    </section>

    {preview && <section className="card overflow-hidden">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-border px-4 py-3">
        <div><p className="text-sm font-semibold">2 · Scope review</p><p className="text-[11px] text-text-muted mt-0.5">Reconner found {preview.accepted} usable requests across {summary.hosts.length} host{summary.hosts.length === 1 ? '' : 's'}.</p></div>
        <div className="flex items-center gap-2">{!captureId ? <Button variant="primary" loading={busy === 'import'} disabled={!!busy || preview.accepted === 0} onClick={() => submit(true)}>Import and build test plan</Button> : <Badge variant="success">TEST PLAN READY</Badge>}<Button size="sm" variant="ghost" onClick={() => setReviewOpen(value => !value)}>{reviewOpen ? 'Hide' : 'Review'}</Button></div>
      </div>
      {reviewOpen && <>
      <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-border border-b border-border">
        {[['In scope', preview.accepted], ['Auto-safe', summary.automatic], ['Sensitive', preview.sensitive], ['Writes', preview.state_changing]].map(([title, value]) => <div className="px-4 py-3" key={String(title)}><p className="text-[10px] uppercase tracking-wide text-text-muted">{title}</p><p className="text-xl font-bold mt-0.5">{value}</p></div>)}
      </div>
      <div className="flex flex-wrap items-center gap-2 px-4 py-3">
        <span className="text-[10px] uppercase tracking-wide text-text-muted mr-1">Likely surfaces</span>
        {summary.tests.map(test => <Badge key={test}>{test}</Badge>)}
        {preview.rejected > 0 && <Badge variant="warning">{preview.rejected} rejected</Badge>}
      </div>
      <details className="border-t border-border">
        <summary className="cursor-pointer px-4 py-3 text-xs font-medium hover:bg-white/[.02]">Review all {preview.total} captured exchanges <span className="text-text-muted font-normal">— values stay hidden</span></summary>
        <div className="max-h-[360px] overflow-auto border-t border-border"><table className="w-full"><thead><tr>{['Request','Type','Suggested','Admission'].map(title => <th className="table-header" key={title}>{title}</th>)}</tr></thead><tbody>{preview.items.map(item => <tr key={item.sequence} className="border-b border-border/60"><td className="table-cell max-w-xl"><span className="text-[10px] font-bold mr-2">{item.method}</span><code className="text-[11px] break-all">{item.route}</code></td><td className="table-cell"><Badge variant={item.operation_kind === 'state_changing' ? 'warning' : 'neutral'}>{item.operation_kind}</Badge></td><td className="table-cell"><div className="flex flex-wrap gap-1">{(item.suggested_tests || []).map(test => <span className="text-[10px] text-accent" key={test}>{previewTestLabel[test] || test}</span>)}</div></td><td className="table-cell"><Badge variant={item.auto_eligible ? 'success' : item.accepted ? 'neutral' : 'warning'}>{item.auto_eligible ? 'auto-safe' : item.accepted ? 'manual' : 'rejected'}</Badge></td></tr>)}</tbody></table></div>
      </details>
      </>}
    </section>}

    {targetId && <GuidedCorpus key={targetId} targetId={targetId} importedId={captureId} onCaptureChange={handleCaptureChange}/>}
  </div>
}
