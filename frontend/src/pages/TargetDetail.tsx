import { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { targets as targetsApi, findings as findingsApi, tasks as tasksApi } from '../lib/api'
import { useUIStore } from '../store/ui'
import { Badge, Button, Spinner, Empty, CopyButton, ErrorBoundary, SkeletonRows } from '../components/ui'
import { ScanModal } from '../components/targets/ScanModal'
import { EvidenceViewer } from '../components/targets/EvidenceViewer'
import { LiveResults } from '../components/targets/LiveResults'
import { ws } from '../lib/websocket'
import { timeAgo, statusCodeColor, truncate, cn } from '../lib/utils'
import type {
  Target, Subdomain, HTTPService, JSFile, JSFinding, Parameter,
  DirectoryFinding, BackupFinding, OpenRedirectFinding, NucleiFinding, VulnFinding, MonitoringChange, AttackPath, Task, IngramCamera, Asset
} from '../types'

// Findings information architecture — a logical hierarchy instead of a flat row
// of unrelated siblings. Assets = the discovered surface; Vulnerabilities = the
// working area (Confirmed vs Needs-Review first, then by check type); Activity =
// change monitoring.
const TAB_GROUPS = [
  { group: 'Assets', tabs: [
    { id: 'subdomains', label: 'Hosts' },
    { id: 'http', label: 'URLs' },
    { id: 'js', label: 'Scripts' },
    { id: 'params', label: 'Parameters' },
    { id: 'dirs', label: 'Directories' },
  ] },
  { group: 'Vulnerabilities', tabs: [
    { id: 'vulns', label: 'Confirmed' },
    { id: 'candidates', label: 'Needs Review' },
    { id: 'redirects', label: 'Open Redirects' },
    { id: 'nuclei', label: 'Nuclei' },
    { id: 'js-findings', label: 'JS / Secrets' },
    { id: 'backups', label: 'Exposed Files' },
  ] },
  { group: 'Activity', tabs: [
    { id: 'monitor', label: 'Changes' },
  ] },
]

// Rows rendered per page-window before the operator asks for more (item 3:
// keeps deep-range result sets from mounting tens of thousands of DOM nodes).
const PAGE = 200

const severityColor: Record<string, string> = {
  critical: 'text-severity-critical',
  high: 'text-severity-high',
  medium: 'text-severity-medium',
  low: 'text-severity-low',
  info: 'text-text-muted',
}

const LIFECYCLE_STYLE: Record<string, string> = {
  CONFIRMED: 'text-severity-low border-severity-low/30 bg-severity-low/10',
  VERIFIED: 'text-severity-low border-severity-low/30 bg-severity-low/10',
  INCONCLUSIVE: 'text-severity-medium border-severity-medium/30 bg-severity-medium/10',
  REJECTED: 'text-severity-critical border-severity-critical/30 bg-severity-critical/10',
  DUPLICATE: 'text-text-muted border-white/10 bg-white/5',
  DETECTED: 'text-text-secondary border-white/10 bg-white/5',
  LEGACY: 'text-text-muted border-white/10 bg-white/5',
}
function LifecycleChip({ lifecycle }: { lifecycle: string }) {
  const cls = LIFECYCLE_STYLE[lifecycle] || LIFECYCLE_STYLE.LEGACY
  const label = lifecycle === 'LEGACY' ? 'unverified' : lifecycle.toLowerCase()
  return (
    <span className={cn('inline-block mt-0.5 px-1.5 py-0.5 rounded border text-[9px] font-semibold uppercase tracking-wide', cls)}
      title="Lifecycle state (authoritative candidate state)">{label}</span>
  )
}

// TriageBar — the per-finding False-Positive management control (section 3).
// Records the operator's decision (Confirmed / False Positive / Accepted Risk);
// a finding marked FP drops out of the working list on the next load.
const TRIAGE_OPTS: { key: string; label: string; cls: string }[] = [
  { key: 'confirmed', label: 'Confirm', cls: 'text-severity-low border-severity-low/40 bg-severity-low/10' },
  { key: 'false_positive', label: 'False Positive', cls: 'text-severity-critical border-severity-critical/40 bg-severity-critical/10' },
  { key: 'accepted_risk', label: 'Accept Risk', cls: 'text-severity-medium border-severity-medium/40 bg-severity-medium/10' },
]
function TriageBar({ targetId, finding, onDone }: { targetId: string; finding: VulnFinding; onDone: () => void }) {
  const [busy, setBusy] = useState('')
  const cur = finding.triage || ''
  const set = async (t: string) => {
    setBusy(t)
    try { await findingsApi.setTriage(targetId, finding.id, t); onDone() } catch { /* toast handled globally */ } finally { setBusy('') }
  }
  return (
    <div className="flex flex-wrap gap-1 mt-1.5" title="False-Positive triage">
      {TRIAGE_OPTS.map(o => (
        <button key={o.key} disabled={!!busy} onClick={() => set(o.key)}
          className={cn('px-1.5 py-0.5 rounded border text-[10px] font-semibold transition-colors disabled:opacity-50',
            cur === o.key ? o.cls : 'border-border text-text-muted hover:text-text-secondary')}>
          {busy === o.key ? '…' : o.label}
        </button>
      ))}
    </div>
  )
}

// Remediation guidance shown on every finding (section 4). Keyed by vuln type;
// falls back to a generic message so no confirmed finding is left without advice.
const REMEDIATION: Record<string, string> = {
  xss: 'Contextually output-encode all user-controlled data at the sink (HTML/attribute/JS/URL). Prefer framework auto-escaping, add a strict Content-Security-Policy, and set HttpOnly on session cookies.',
  dom_xss: 'Treat URL, window.name and postMessage data as untrusted. Avoid innerHTML/outerHTML/document.write/eval sinks; use textContent or a proven HTML sanitizer, validate message origins, and enforce a strict Content-Security-Policy.',
  sqli: 'Use parameterized queries / prepared statements everywhere; never concatenate input into SQL. Apply least-privilege DB accounts and validate input types server-side.',
  nosqli: 'Reject operator objects ($where/$ne/$regex) from user input; cast query values to the expected scalar type; use an allowlist for query fields.',
  idor: 'Enforce a server-side authorization (ownership/ACL) check on EVERY object access, keyed to the authenticated principal — never trust the client-supplied object id. Prefer unguessable identifiers.',
  bola: 'Enforce per-object ownership checks on every read and write; do not rely on the object id being unguessable alone.',
  bfla: 'Enforce function-level authorization on every state-changing endpoint (roles/permissions), not just on the UI. Deny by default.',
  ssrf: 'Validate and allowlist outbound destinations; resolve + pin the target IP and block private/link-local/metadata ranges; disable unused URL schemes and follow-redirects to internal hosts.',
  open_redirect: 'Do not redirect to user-controlled absolute URLs; use a server-side allowlist of paths, or sign/validate the redirect target and force it same-origin.',
  redirect: 'Use a server-side allowlist for redirect destinations and force same-origin; never reflect a raw user-supplied URL into Location.',
  lfi: 'Never pass user input to filesystem APIs; use a fixed allowlist of files/ids, canonicalize + confine paths to a base directory, and reject traversal sequences.',
  ssti: 'Never render user input as a template. Use logic-less templates or a sandboxed engine and pass data as bound variables, not template source.',
  cmdi: 'Avoid shelling out with user input; use native APIs or an argument array with no shell, and validate against a strict allowlist.',
  xxe: 'Disable external entity + DTD processing in the XML parser (FEATURE_SECURE_PROCESSING / disallow-doctype-decl).',
  jwt: 'Pin the accepted algorithm server-side (reject "none"/alg confusion), verify the signature with a strong secret/key, and validate iss/aud/exp.',
  crlf: 'Strip/encode CR and LF from any user input that reaches HTTP headers; use the framework header API rather than raw string concatenation.',
  cache_poison: 'Do not reflect unkeyed request inputs into cacheable responses; include all response-affecting inputs in the cache key or mark responses no-store.',
  takeover: 'Remove the dangling DNS record or reclaim the referenced third-party resource; monitor for dangling CNAMEs.',
}
function remediationFor(t: string): string {
  return REMEDIATION[String(t || '').toLowerCase()] ||
    'Validate and authorize this request server-side, encode/parameterize untrusted input at every sink, and re-test after the fix.'
}

// Vuln classes whose vector is a single GET query-parameter — for these we can
// assemble a one-click reproduction URL (parameter's value replaced by the
// payload). XSS especially: clicking the link fires the payload in the browser.
const GET_PARAM_VULNS = new Set([
  'xss', 'sqli', 'lfi', 'ssti', 'cmdi', 'ssrf', 'open_redirect', 'redirect',
  'nosqli', 'idor', 'path_traversal', 'crlf', 'rfi', 'xxe',
])

// buildPocUrl injects the payload into `param` on top of the finding's URL and
// returns the fully-encoded reproduction URL — the exact request that triggered
// the finding, ready to paste in a browser or curl. Returns null when the finding
// isn't a GET-param class or the pieces needed to rebuild the request are missing.
function buildPocUrl(type: string, rawUrl: string, param?: string, payload?: string): string | null {
  if (!rawUrl || !param || !payload) return null
  const normalizedType = String(type || '').toLowerCase()
  if (normalizedType === 'dom_xss') {
    if (param === 'dom:hash') return `${rawUrl.split('#', 1)[0]}#${payload}`
    if (param.startsWith('dom:') || param.startsWith('path:')) return null
  } else if (!GET_PARAM_VULNS.has(normalizedType)) return null
  try {
    const u = new URL(rawUrl)
    u.searchParams.set(param, payload)
    return u.toString()
  } catch {
    return null
  }
}

// pocCurl returns a copy-paste curl one-liner that reproduces the finding.
function pocCurl(url: string): string {
  return `curl -sk '${String(url).replace(/'/g, `'\\''`)}'`
}

// NucleiAffected expands a collapsed nuclei finding into EVERY URL that template
// matched, each with its own PoC (curl + raw request/response) — so the other
// hits behind an "×N" badge are visible in the UI with proof, not only in the log.
type AffectedRow = { matched_url: string; curl_command: string; request: string; response: string; created_at: string }
function NucleiAffected({ targetId, templateId, count }: { targetId: string; templateId: string; count: number }) {
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState<AffectedRow[] | null>(null)
  const [loading, setLoading] = useState(false)
  const toggle = () => {
    const next = !open
    setOpen(next)
    if (next && rows === null) {
      setLoading(true)
      findingsApi.nucleiAffected(targetId, templateId).then(setRows).catch(() => setRows([])).finally(() => setLoading(false))
    }
  }
  return (
    <div className="mt-0.5">
      <button onClick={toggle} className="text-[10px] text-accent hover:underline select-none">
        {open ? '▾' : '▸'} {count} matched URL(s) — show all with PoC
      </button>
      {open && (
        <div className="mt-1 space-y-1.5 max-h-80 overflow-auto pr-1">
          {loading && <p className="text-[10px] text-text-muted">Loading…</p>}
          {rows?.map((a, i) => (
            <div key={i} className="border-l border-white/10 pl-2">
              <div className="flex items-start gap-1">
                <a href={a.matched_url} target="_blank" rel="noreferrer"
                  className="flex-1 font-mono text-[10px] text-accent break-all hover:underline">{a.matched_url}</a>
                <CopyButton text={a.matched_url} />
              </div>
              {a.curl_command && (
                <details className="mt-0.5">
                  <summary className="cursor-pointer text-[10px] text-text-muted hover:text-text-secondary select-none">PoC</summary>
                  <div className="flex items-start gap-1 mt-0.5">
                    <pre className="flex-1 font-mono text-[10px] text-severity-medium whitespace-pre-wrap break-all bg-bg-secondary/50 p-1 rounded max-h-32 overflow-auto">{a.curl_command}</pre>
                    <CopyButton text={a.curl_command} />
                  </div>
                  {(a.request || a.response) && (
                    <details className="mt-0.5">
                      <summary className="cursor-pointer text-[10px] text-text-muted select-none">Raw request/response</summary>
                      {a.request && <pre className="mt-0.5 font-mono text-[10px] text-text-secondary whitespace-pre-wrap break-all bg-bg-secondary/50 p-1 rounded max-h-40 overflow-auto">{a.request}</pre>}
                      {a.response && <pre className="mt-0.5 font-mono text-[10px] text-text-muted whitespace-pre-wrap break-all bg-bg-secondary/50 p-1 rounded max-h-40 overflow-auto">{a.response}</pre>}
                    </details>
                  )}
                </details>
              )}
            </div>
          ))}
          {rows && rows.length === 0 && !loading && <p className="text-[10px] text-text-muted">No details stored.</p>}
        </div>
      )}
    </div>
  )
}

// ReportMenu — the single report entry point. The primary click opens the full
// HTML report; the caret reveals the other export formats (Markdown, PDF) so the
// action bar carries one button instead of three competing ones.
function ReportMenu({ targetId }: { targetId: string }) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const close = () => setOpen(false)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [open])
  const base = `/api/targets/${targetId}`
  const item = 'block px-3 py-2 text-xs text-text-secondary hover:text-text-primary hover:bg-white/5 transition-colors'
  return (
    <div className="relative" onClick={e => e.stopPropagation()}>
      <div className="flex items-stretch">
        <a href={`${base}/report.html`} target="_blank" rel="noreferrer"
          className="btn-secondary text-sm rounded-r-none">Report</a>
        <button onClick={() => setOpen(o => !o)} aria-label="Report export formats" title="Export formats"
          className="btn-secondary text-sm px-2 rounded-l-none border-l border-black/30">▾</button>
      </div>
      {open && (
        <div className="absolute right-0 mt-1 z-30 w-48 rounded-lg border border-border bg-surface-3 shadow-2xl overflow-hidden animate-fade-in">
          <a href={`${base}/report.html`} target="_blank" rel="noreferrer" className={item}>Full report — HTML</a>
          <a href={`${base}/report`} target="_blank" rel="noreferrer" className={item}>Export — Markdown</a>
          <a href={`${base}/report.pdf`} target="_blank" rel="noreferrer" className={item}>Export — PDF</a>
        </div>
      )}
    </div>
  )
}

export default function TargetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { addToast } = useUIStore()
  const [target, setTarget] = useState<Target | null>(null)
  const [tab, setTab] = useState('subdomains')
  const [fpView, setFpView] = useState(false)
  const [loading, setLoading] = useState(true)
  const [tabLoading, setTabLoading] = useState(false)
  const [data, setData] = useState<unknown[]>([])
  // Deep IP-range scans can write thousands of rows to a single tab. Mounting
  // every <tr> at once froze the page and blew out the layout, so we render an
  // incremental window (PAGE at a time) and let the operator pull more on demand.
  const [visibleCount, setVisibleCount] = useState(PAGE)
  const [sort, setSort] = useState<{ key: 'size' | 'status' | 'severity' | null; dir: 'asc' | 'desc' }>({ key: null, dir: 'desc' })
  // Status-class filter for the URLs tab: 'all' | '2' | '3' | '4' | '5' (2xx…5xx).
  const [statusClass, setStatusClass] = useState<'all' | '2' | '3' | '4' | '5'>('all')
  const [scanOpen, setScanOpen] = useState(false)
  const [assets, setAssets] = useState<Asset[]>([])
  const [scanAsset, setScanAsset] = useState<Asset | null>(null)
  const [newAsset, setNewAsset] = useState('')
  const [assetBusy, setAssetBusy] = useState(false)
  const [evidence, setEvidence] = useState<{ id: string; url: string; type: string } | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [monitorSaving, setMonitorSaving] = useState(false)
  const [paths, setPaths] = useState<AttackPath[]>([])
  const [lastFailedTask, setLastFailedTask] = useState<Task | null>(null)
  const [resuming, setResuming] = useState(false)
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!id) return
    targetsApi.get(id).then(t => {
      setTarget(t)
      setIsScanning(t.scan_status === 'running')
      // Network targets never populate the default 'subdomains' tab — land on
      // the tab that actually carries their results.
    }).catch(() => navigate('/targets')).finally(() => setLoading(false))
    targetsApi.graph(id).then(g => setPaths(g.attack_paths || [])).catch(() => {})
    loadAssets()
  }, [id])

  const loadAssets = () => { if (id) targetsApi.assets(id).then(a => setAssets(a || [])).catch(() => {}) }
  const addAsset = async () => {
    const v = newAsset.trim()
    if (!v || !id) return
    setAssetBusy(true)
    try { await targetsApi.addAsset(id, v, ''); setNewAsset(''); loadAssets(); addToast('success', 'Asset added') }
    catch (e) { addToast('error', e instanceof Error ? e.message : 'Failed to add asset') }
    finally { setAssetBusy(false) }
  }
  const removeAsset = async (a: Asset) => {
    if (!id) return
    try { await targetsApi.deleteAsset(id, a.id); loadAssets() } catch { addToast('error', 'Failed to delete asset') }
  }
  const renameAsset = async (a: Asset) => {
    if (!id) return
    const name = window.prompt('Asset name', a.name || '')
    if (name === null) return
    try { await targetsApi.updateAsset(id, a.id, { name }); loadAssets() } catch { addToast('error', 'Failed to rename') }
  }

  // A "failed" scan_status alone doesn't say WHY — the reason (e.g. a
  // watchdog timeout on a large target) lives on the task row, not the
  // target, and was previously never surfaced here at all.
  useEffect(() => {
    if (!id || target?.scan_status !== 'failed') { setLastFailedTask(null); return }
    tasksApi.list({ target_id: id, limit: '1' })
      .then(rows => setLastFailedTask(rows?.[0] || null))
      .catch(() => {})
  }, [id, target?.scan_status])

  const canResumeLastTask = lastFailedTask &&
    (lastFailedTask.status === 'failed' || lastFailedTask.status === 'cancelled') &&
    (lastFailedTask.modules?.length || 0) > (lastFailedTask.completed_modules?.length || 0)

  const resumeLastTask = async () => {
    if (!lastFailedTask) return
    setResuming(true)
    try {
      const newTask = await tasksApi.resume(lastFailedTask.id)
      addToast('success', `Resumed — ${newTask.modules.length} module(s) remaining`)
      setIsScanning(true)
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to resume')
    } finally {
      setResuming(false)
    }
  }

  // Auto-refresh tab data when a module finishes during a scan
  useEffect(() => {
    return ws.on('task_progress', (payload) => {
      const p = payload as { target_id: string; current_module: string }
      if (p.target_id !== id) return
      // Reload the tab that just had data written to it
      const moduleToTab: Record<string, string> = {
        subdomain_enum: 'subdomains',
        http_probe: 'http',
        js_analysis: 'js',
        param_discovery: 'params',
        param_reflection: 'params',
        dir_discovery: 'dirs',
        backup_discovery: 'backups',
        open_redirect: 'redirects',
        nuclei: 'nuclei',
        vuln_scan: 'vulns',
        monitor: 'monitor',
      }
      const targetTab = moduleToTab[p.current_module]
      if (targetTab && targetTab === tab) {
        // Only refresh current tab if it matches the module that just ran
        if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
        refreshTimerRef.current = setTimeout(() => {
          loadTab(tab)
          targetsApi.get(id!).then(t => { setTarget(t); setIsScanning(t.scan_status === 'running') }).catch(() => {})
        }, 3000)
      }
    })
  }, [id, tab])

  // Detect scan start/finish
  useEffect(() => {
    const unsubs = [
      ws.on('task_started', (p) => { const ev = p as { target_id: string }; if (ev.target_id === id) setIsScanning(true) }),
      ws.on('task_finished', (p) => {
        const ev = p as { target_id: string }
        if (ev.target_id !== id) return
        setIsScanning(false)
        loadTab(tab)
        targetsApi.get(id!).then(setTarget).catch(() => {})
      }),
      ws.on('task_cancelled', () => setIsScanning(false)),
    ]
    return () => unsubs.forEach(u => u())
  }, [id, tab])

  useEffect(() => { if (id) loadTab(tab) }, [tab, id, fpView])

  // Client-side sort of the loaded rows by response size or status code. Works
  // on any tab: reads the first present numeric field, so tabs without size/
  // status are simply unaffected. Lets you manage high-volume result sets.
  const numOf = (item: unknown, keys: string[]): number => {
    const o = item as Record<string, unknown>
    for (const k of keys) if (typeof o?.[k] === 'number') return o[k] as number
    return 0
  }
  // critical → high → medium → low → info, so "desc" reads as most-severe-first
  // (the usual triage order) and "asc" flips to low→high per your request.
  const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  const applySort = (key: 'size' | 'status' | 'severity') => {
    const dir: 'asc' | 'desc' = sort.key === key && sort.dir === 'desc' ? 'asc' : 'desc'
    setSort({ key, dir })
    const get = key === 'size'
      ? (i: unknown) => numOf(i, ['content_length', 'size', 'contentLength'])
      : key === 'status'
      ? (i: unknown) => numOf(i, ['status_code', 'status', 'statusCode'])
      : (i: unknown) => severityRank[String((i as Record<string, unknown>)?.severity || '').toLowerCase()] ?? -1
    setData(prev => [...prev].sort((a, b) => dir === 'desc' ? get(b) - get(a) : get(a) - get(b)))
  }
  const isSeverityTab = tab === 'nuclei' || tab === 'vulns' || tab === 'candidates'

  const loadTab = async (t: string) => {
    if (!id) return
    setTabLoading(true)
    try {
      let r: unknown[] = []
      if (t === 'subdomains') r = await findingsApi.subdomains(id)
      else if (t === 'http') r = await findingsApi.httpServices(id)
      else if (t === 'js') r = await findingsApi.jsFiles(id)
      else if (t === 'js-findings') r = await findingsApi.jsFindings(id)
      else if (t === 'params') r = await findingsApi.parameters(id, false)
      else if (t === 'dirs') r = await findingsApi.directoryFindings(id)
      else if (t === 'backups') r = await findingsApi.backupFindings(id)
      else if (t === 'redirects') r = await findingsApi.openRedirects(id)
      else if (t === 'nuclei') r = await findingsApi.nucleiFindings(id)
      else if (t === 'vulns') r = fpView ? await findingsApi.vulnFindings(id, 'all', 'false_positive') : await findingsApi.vulnFindings(id, 'finding')
      else if (t === 'candidates') r = await findingsApi.vulnFindings(id, 'candidate')
      else if (t === 'cameras') r = await findingsApi.ingram(id)
      else if (t === 'monitor') r = await findingsApi.monitoringChanges(id)
      setData(r || [])
      setVisibleCount(PAGE)
    } catch { setData([]) }
    setTabLoading(false)
  }

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner /></div>
  if (!target) return null

  const dot: Record<string, string> = {
    idle: 'bg-text-muted',
    running: 'bg-accent animate-pulse',
    paused: 'bg-severity-medium',
    finished: 'bg-severity-low',
    failed: 'bg-severity-critical',
  }

  const pauseScan = async () => {
    if (!id) return
    try {
      await targetsApi.pauseScan(id)
      setTarget(t => t ? { ...t, scan_status: 'paused' } : t)
    } catch (e) { console.error(e) }
  }
  const resumeScan = async () => {
    if (!id) return
    try {
      await targetsApi.resumeScan(id)
      setTarget(t => t ? { ...t, scan_status: 'running' } : t)
    } catch (e) { console.error(e) }
  }
  const skipPhase = async () => {
    if (!id) return
    try {
      await targetsApi.skipPhase(id)
      addToast('success', 'Skipping current phase — continuing to the next.')
    } catch (e: any) { addToast('error', e?.message || 'Nothing to skip right now') }
  }
  const cancelScan = async () => {
    if (!id) return
    if (!confirm('Cancel the entire scan? All remaining phases stop. Findings already saved are kept.')) return
    try {
      await targetsApi.cancelScan(id)
      setTarget(t => t ? { ...t, scan_status: 'idle' } : t)
      addToast('success', 'Scan cancelled.')
    } catch (e: any) { addToast('error', e?.message || 'Could not cancel') }
  }

  const saveMonitor = async (enabled: boolean, hours: number) => {
    if (!id) return
    setMonitorSaving(true)
    try {
      await targetsApi.updateMonitor(id, enabled, hours)
      setTarget(prev => prev ? { ...prev, monitor_enabled: enabled, monitor_interval_hours: hours } : prev)
    } catch { /* ignore */ } finally { setMonitorSaving(false) }
  }

  // Network targets' actual results (Nuclei/Vulns/Candidates) used to sit
  // BELOW monitoring settings, attack paths, the auth-header form and the
  // identities/authorization panels — none of which are commonly used for a
  // network scope, so reaching results meant scrolling past all of it every
  // time. CSS order (not a JSX reshuffle, to keep this low-risk) puts the
  // results block right after Network Services for network targets only; web
  // targets keep their original order untouched.
  const isNetwork = target.kind === 'network'

  // URLs (http) tab: optional filter by HTTP status class (2xx…5xx) before windowing.
  const filteredData = (tab === 'http' && statusClass !== 'all')
    ? data.filter(row => {
        const code = Number((row as { status_code?: number })?.status_code || 0)
        return Math.floor(code / 100) === Number(statusClass)
      })
    : data
  // Windowed view of the loaded rows — only the first `visibleCount` are mounted.
  const pageData = filteredData.slice(0, visibleCount)
  const hasMore = filteredData.length > visibleCount

  return (
    <ErrorBoundary>
    <div className={cn('space-y-5', isNetwork && 'flex flex-col')}>
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <button onClick={() => navigate('/targets')} className="text-text-muted hover:text-text-primary text-sm shrink-0">← Back</button>
          <span className={cn('w-2.5 h-2.5 rounded-full shrink-0', dot[target.scan_status] || 'bg-text-muted')} />
          {/* A network target's "domain" is its whole scope — up to 65k IPs. Without
              truncation the h1 renders the entire list and shoves the action buttons
              (Scan/Report/Pause/Skip/Cancel) off-screen. Cap it; full value on hover. */}
          <h1 className="text-xl font-semibold truncate min-w-0 max-w-[36ch] md:max-w-[52ch]" title={target.domain}>
            {target.name || target.domain}
          </h1>
          {target.priority !== 'medium' && (
            <Badge variant={target.priority === 'critical' ? 'critical' : target.priority === 'high' ? 'high' : 'low'}>
              {target.priority}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
          <ReportMenu targetId={id!} />
          {target.scan_status === 'running' && (
            <button onClick={pauseScan} className="btn-secondary text-sm">Pause</button>
          )}
          {target.scan_status === 'running' && (
            <button onClick={skipPhase} className="btn-secondary text-sm" title="Abort just the current phase and continue to the next">Skip phase</button>
          )}
          {(target.scan_status === 'running' || target.scan_status === 'paused') && (
            <button onClick={cancelScan} className="btn-secondary text-sm text-severity-high" title="Stop the entire scan (all remaining phases)">Cancel</button>
          )}
          {target.scan_status === 'paused' && (
            <button onClick={resumeScan} className="btn-secondary text-sm text-severity-medium">Resume</button>
          )}
          <button onClick={() => setScanOpen(true)} className="btn-primary text-sm">Scan</button>
        </div>
      </div>

      {target.scan_status === 'failed' && lastFailedTask?.error && (
        <div className="px-4 py-2.5 rounded-lg bg-severity-critical/10 border border-severity-critical/30 text-xs text-severity-critical flex items-center gap-3">
          <span><span className="font-semibold">Last scan failed: </span>{lastFailedTask.error}</span>
          {canResumeLastTask && (
            <button onClick={resumeLastTask} disabled={resuming}
              className="ml-auto shrink-0 btn-secondary text-[11px] whitespace-nowrap disabled:opacity-50">
              {resuming ? 'Resuming…' : 'Resume remaining'}
            </button>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
        {[
          { label: 'Subdomains', value: target.subdomain_count },
          { label: 'Alive', value: target.alive_host_count, color: 'text-severity-low' },
          { label: 'Findings', value: target.finding_count, color: target.finding_count > 0 ? 'text-severity-high' : undefined },
          { label: 'Priority', value: target.priority },
          { label: 'Status', value: target.scan_status },
          { label: 'Last Scan', value: target.last_scan_at ? timeAgo(target.last_scan_at) : 'Never' },
        ].map(s => (
          <div key={s.label} className="card p-3 text-center">
            <p className={cn('text-base font-semibold', s.color || 'text-text-primary')}>{s.value}</p>
            <p className="text-xs text-text-muted">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Assets — scan each one individually, add / remove / name them. */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
            Assets <span className="normal-case text-text-muted/70">— scanned individually</span>
          </p>
          <span className="text-[10px] text-text-muted">{assets.length}</span>
        </div>
        <div className="flex flex-col sm:flex-row gap-2 mb-3">
          <input value={newAsset} onChange={e => setNewAsset(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addAsset() }}
            placeholder="add asset — domain, IP, CIDR, range, or a mix (space/comma separated)"
            className="flex-1 bg-surface-alt border border-border rounded px-2 py-1.5 text-xs font-mono" />
          <Button size="sm" variant="secondary" loading={assetBusy} onClick={addAsset}>Add</Button>
        </div>
        {assets.length === 0 ? (
          <p className="text-xs text-text-muted py-2">No assets yet — add one above, or they’re seeded from the target’s scope on creation.</p>
        ) : (
          <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
            {assets.map(a => (
              <div key={a.id} className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-white/[.02] border border-white/[.05] flex-wrap sm:flex-nowrap">
                <span className={cn('text-[9px] px-1.5 py-0.5 rounded font-semibold uppercase shrink-0',
                  a.kind === 'network' ? 'bg-series-3/15 text-series-3' : a.kind === 'mixed' ? 'bg-severity-low/15 text-severity-low' : 'bg-accent-muted text-accent-hover')}>{a.kind}</span>
                <div className="min-w-0 flex-1">
                  {a.name && <p className="text-xs font-medium truncate">{a.name}</p>}
                  <p className="text-[11px] font-mono text-text-secondary truncate" title={a.value}>{a.value}</p>
                </div>
                <Button size="sm" variant="primary" onClick={() => setScanAsset(a)}>Scan</Button>
                <button onClick={() => renameAsset(a)} title="Rename" className="p-1 rounded text-text-muted hover:text-accent hover:bg-accent/10">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                </button>
                <button onClick={() => removeAsset(a)} title="Delete" className="p-1 rounded text-text-muted hover:text-severity-critical hover:bg-severity-critical/10">
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className={cn('space-y-5', isNetwork && 'order-2')}>
      {/* Monitoring settings */}
      <div className="card p-4 flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <div
              onClick={() => saveMonitor(!target.monitor_enabled, target.monitor_interval_hours || 12)}
              className={cn(
                'w-10 h-5 rounded-full transition-colors relative cursor-pointer',
                target.monitor_enabled ? 'bg-accent' : 'bg-surface-alt'
              )}
            >
              <span className={cn(
                'absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform',
                target.monitor_enabled ? 'translate-x-5' : 'translate-x-0.5'
              )} />
            </div>
            <span className="text-sm font-medium">
              {target.monitor_enabled ? 'Monitoring On' : 'Monitoring Off'}
            </span>
          </label>
          {monitorSaving && <span className="text-xs text-text-muted">Saving…</span>}
        </div>
        {target.monitor_enabled && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-text-muted">Every</span>
            <select
              value={target.monitor_interval_hours || 12}
              onChange={e => saveMonitor(true, parseInt(e.target.value))}
              className="bg-surface-alt border border-border rounded px-2 py-1 text-sm"
            >
              {[1, 3, 6, 12, 24, 48, 72, 168].map(h => (
                <option key={h} value={h}>{h < 24 ? `${h}h` : `${h/24}d`}</option>
              ))}
            </select>
            <span className="text-sm text-text-muted">
              {target.monitor_last_run ? `· Last: ${timeAgo(target.monitor_last_run)}` : '· Never run'}
            </span>
          </div>
        )}
        {target.monitor_enabled && (
          <p className="w-full text-[11px] text-text-muted mt-1">
            Each cycle re-enumerates subdomains, re-probes hosts, and runs takeover + backup/config-file discovery.
            If a new subdomain/asset or change is found, you're notified and <b>nuclei + backup discovery</b> auto-run over the new surface.
          </p>
        )}
      </div>

      {/* Attack paths (correlation / intelligence layer) */}
      {paths.length > 0 && (
        <div className="card p-4">
          <p className="text-sm font-semibold mb-2">Attack Paths <span className="text-text-muted font-normal">({paths.length} correlated)</span></p>
          <div className="space-y-2">
            {paths.slice(0, 8).map((p, i) => (
              <div key={i} className="border border-border rounded p-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={p.severity}>{p.severity}</Badge>
                  <span className="text-xs font-mono text-text-primary">{p.host}</span>
                  {p.confidence > 0 && <span className="text-[10px] text-text-muted">{p.confidence}% conf</span>}
                  {p.tech && p.tech.length > 0 && <span className="text-[10px] text-accent">{p.tech.join(' · ')}</span>}
                </div>
                <ul className="mt-1.5 space-y-0.5">
                  {p.steps.map((s, j) => (
                    <li key={j} className="text-xs text-text-secondary">↳ {s}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      </div>

      <div className={cn('space-y-5', isNetwork && 'order-1')}>
      {isScanning && <LiveResults targetId={id!} active={isScanning} />}

      <div className="border-b border-border flex items-stretch overflow-x-auto">
        {TAB_GROUPS.map((g, gi) => (
          <div key={g.group} className="flex items-center">
            {gi > 0 && <span className="mx-1.5 my-2 w-px bg-border" />}
            <span className="pl-2 pr-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted/60 self-center select-none">{g.group}</span>
            {g.tabs.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={cn(
                  'px-3 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-all',
                  tab === t.id ? 'border-accent text-accent' : 'border-transparent text-text-muted hover:text-text-secondary'
                )}>
                {t.label}
              </button>
            ))}
          </div>
        ))}
      </div>

      {tab !== 'cameras' && (
      <div className="flex gap-2 items-center px-1 py-2 text-xs text-text-muted flex-wrap">
        {tab === 'vulns' && (
          <button onClick={() => setFpView(v => !v)}
            className={cn('px-2 py-1 rounded border font-semibold mr-1',
              fpView ? 'border-severity-critical text-severity-critical bg-severity-critical/10' : 'border-border text-text-muted hover:text-text-secondary')}>
            {fpView ? '← Back to findings' : 'False Positives'}
          </button>
        )}
        <span>Sort by:</span>
        {isSeverityTab && (
          <button onClick={() => applySort('severity')}
            className={cn('px-2 py-1 rounded border', sort.key === 'severity' ? 'border-accent text-accent' : 'border-border')}>
            Severity {sort.key === 'severity' ? (sort.dir === 'asc' ? '↑ low→high' : '↓ high→low') : ''}
          </button>
        )}
        <button onClick={() => applySort('size')}
          className={cn('px-2 py-1 rounded border', sort.key === 'size' ? 'border-accent text-accent' : 'border-border')}>
          File size {sort.key === 'size' ? (sort.dir === 'desc' ? '↓' : '↑') : ''}
        </button>
        <button onClick={() => applySort('status')}
          className={cn('px-2 py-1 rounded border', sort.key === 'status' ? 'border-accent text-accent' : 'border-border')}>
          Response {sort.key === 'status' ? (sort.dir === 'desc' ? '↓' : '↑') : ''}
        </button>
        {tab === 'http' && (
          <span className="flex items-center gap-1 ml-2 pl-2 border-l border-border">
            <span className="text-text-muted">Status:</span>
            {(['all', '2', '3', '4', '5'] as const).map(c => (
              <button key={c} onClick={() => { setStatusClass(c); setVisibleCount(PAGE) }}
                className={cn('px-2 py-1 rounded border',
                  statusClass === c ? 'border-accent text-accent' : 'border-border',
                  c === '2' ? 'text-severity-low' : c === '4' ? 'text-severity-medium' : c === '5' ? 'text-severity-critical' : '')}>
                {c === 'all' ? 'All' : `${c}xx`}
              </button>
            ))}
          </span>
        )}
      </div>
      )}

      <ErrorBoundary>
      <div className="card overflow-hidden" style={{ padding: 0 }}>
        {tabLoading
          ? <div className="py-2"><SkeletonRows rows={8} cols={5} /></div>
          : data.length === 0
            ? <Empty message={tab === 'cameras' ? 'No cameras/DVRs found by Ingram yet. Run a scan with the Ingram (camera) option enabled.' : 'No data found'} />
            : tab === 'cameras'
            ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4 p-4">
                {(pageData as IngramCamera[]).map(cam => (
                  <div key={cam.id} className="border border-border rounded-lg overflow-hidden bg-bg-secondary/40 flex flex-col">
                    {cam.image
                      ? <a href={cam.image} target="_blank" rel="noreferrer" className="block bg-black">
                          <img src={cam.image} alt={cam.address} loading="lazy"
                            className="w-full h-52 object-contain bg-black hover:opacity-90 transition-opacity" />
                        </a>
                      : <div className="w-full h-52 flex items-center justify-center bg-bg-secondary text-text-muted text-xs gap-2">
                          no snapshot
                        </div>}
                    <div className="p-3 space-y-1.5 flex-1 flex flex-col">
                      <div className="flex items-center justify-between gap-2">
                        <a href={`http://${cam.address}/`} target="_blank" rel="noreferrer"
                          className="text-accent hover:underline font-mono text-sm font-semibold break-all">{cam.address}</a>
                        <Badge variant={cam.severity || 'info'}>{cam.severity}</Badge>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs font-semibold text-text-primary capitalize">{cam.product}</span>
                        {cam.poc && <span className="px-1.5 py-0.5 rounded bg-accent/15 text-accent text-[10px] font-mono">{cam.poc}</span>}
                      </div>
                      {cam.description && <p className="text-xs text-text-secondary break-words">{cam.description}</p>}
                      {cam.impact && <p className="text-[11px] text-text-muted break-words"><span className="font-semibold">Impact:</span> {cam.impact}</p>}
                      <div className="mt-auto pt-1 text-[10px] text-text-muted">{timeAgo(cam.created_at)}</div>
                    </div>
                  </div>
                ))}
              </div>
            )
            : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border">
                      {tab === 'subdomains' && ['Subdomain', 'IP', 'Status', 'Title', 'Server', 'Last Seen'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'http' && ['URL', 'Status', 'Title', 'Size', 'Time'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'js' && ['URL', 'Size', 'Hash', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'js-findings' && ['Severity', 'Type', 'Value', 'JS File Source', 'Context', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'params' && ['Full URL', 'Parameter', 'Source', 'Reflected', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'dirs' && ['URL', 'Status', 'Size', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'backups' && ['URL', 'Status', 'Size', 'Type', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'redirects' && ['URL', 'Redirects To', 'Verified', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'nuclei' && ['Severity', 'Template', 'URL', 'Description', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {(tab === 'vulns' || tab === 'candidates') && ['Severity', 'Type', 'URL', 'Parameter', 'Evidence / Provenance', 'Found'].map(h => <th key={h} className="table-header">{h}</th>)}
                      {tab === 'monitor' && ['URL', 'Change Type', 'Old Value', 'New Value', 'Detected'].map(h => <th key={h} className="table-header">{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {tab === 'subdomains' && (pageData as Subdomain[]).map(s => (
                      <tr key={s.id} className="table-row">
                        <td className="table-cell">
                          <div className="flex items-center gap-2">
                            <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', s.is_alive ? 'bg-severity-low' : 'bg-text-muted')} />
                            <span className="font-mono text-xs">{s.subdomain}</span>
                            {s.source === 'vhost' && (
                              <span title="Discovered via virtual-host scan (not in DNS)" className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent/20 text-accent-hover shrink-0">vhost</span>
                            )}
                            <CopyButton text={s.subdomain} />
                          </div>
                        </td>
                        <td className="table-cell font-mono text-xs">{s.ip || '—'}</td>
                        <td className="table-cell"><span className={cn('font-mono text-xs', statusCodeColor(s.status_code))}>{s.status_code || '—'}</span></td>
                        <td className="table-cell text-xs">{truncate(s.page_title || '', 40) || '—'}</td>
                        <td className="table-cell text-xs">{truncate(s.server || '', 30) || '—'}</td>
                        <td className="table-cell text-xs">{timeAgo(s.last_seen)}</td>
                      </tr>
                    ))}
                    {tab === 'http' && (pageData as HTTPService[]).map(s => (
                      <tr key={s.id} className="table-row">
                        <td className="table-cell max-w-xs">
                          <div className="flex items-center gap-1.5">
                            <a href={s.url} target="_blank" rel="noreferrer" className="text-accent hover:underline text-xs font-mono truncate">{truncate(s.url, 60)}</a>
                            <CopyButton text={s.url} />
                            {s.waf && (
                              <span title={`Behind WAF: ${s.waf}`}
                                className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-severity-medium/15 text-severity-medium whitespace-nowrap">
                                WAF · {s.waf}
                              </span>
                            )}
                            {s.cms && (
                              <span title={`CMS: ${s.cms} — stock WP/Joomla/Drupal skip active injection scans`}
                                className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent/15 text-accent whitespace-nowrap capitalize">
                                {s.cms}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="table-cell"><span className={cn('font-mono text-xs', statusCodeColor(s.status_code))}>{s.status_code}</span></td>
                        <td className="table-cell text-xs">{truncate(s.title || '', 40) || '—'}</td>
                        <td className="table-cell text-xs">{s.content_length > 0 ? `${(s.content_length / 1024).toFixed(1)}KB` : '—'}</td>
                        <td className="table-cell text-xs">{s.response_time_ms > 0 ? `${s.response_time_ms}ms` : '—'}</td>
                      </tr>
                    ))}
                    {tab === 'js' && (pageData as JSFile[]).map(f => (
                      <tr key={f.id} className="table-row">
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={f.url} target="_blank" rel="noreferrer" className="text-accent hover:underline text-xs font-mono truncate">{truncate(f.url, 70)}</a>
                            <CopyButton text={f.url} />
                          </div>
                        </td>
                        <td className="table-cell text-xs">{f.size > 0 ? `${(f.size / 1024).toFixed(1)}KB` : '—'}</td>
                        <td className="table-cell font-mono text-xs">{f.hash ? f.hash.slice(0, 8) : '—'}</td>
                        <td className="table-cell text-xs">{timeAgo(f.created_at)}</td>
                      </tr>
                    ))}
                    {tab === 'js-findings' && (pageData as JSFinding[]).map(f => (
                      <tr key={f.id} className="table-row">
                        <td className="table-cell whitespace-nowrap">
                          <span className={cn('text-xs font-bold uppercase', severityColor[f.severity])}>{f.severity}</span>
                          {f.verified && <span className="ml-1 text-[10px] font-bold text-severity-critical" title="Verified live credential">VERIFIED</span>}
                        </td>
                        <td className="table-cell text-xs font-mono whitespace-nowrap">{f.type}</td>
                        <td className="table-cell max-w-xs">
                          <div className="flex items-center gap-1">
                            <span className="font-mono text-xs text-text-primary break-all">{truncate(f.value, 80)}</span>
                            <CopyButton text={f.value} />
                          </div>
                        </td>
                        <td className="table-cell max-w-xs">
                          {f.js_file_url ? (
                            <div className="flex items-center gap-1">
                              <a href={f.js_file_url} target="_blank" rel="noreferrer"
                                className="text-accent hover:underline text-xs font-mono truncate block max-w-xs"
                                title={f.js_file_url}>{truncate(f.js_file_url, 60)}</a>
                              <CopyButton text={f.js_file_url} />
                            </div>
                          ) : <span className="text-text-muted text-xs">—</span>}
                        </td>
                        <td className="table-cell text-xs text-text-muted max-w-xs font-mono">{truncate(f.context || '', 100)}</td>
                        <td className="table-cell text-xs whitespace-nowrap">{timeAgo(f.created_at)}</td>
                      </tr>
                    ))}
                    {tab === 'params' && (pageData as Parameter[]).map(p => {
                      const fullUrl = (() => {
                        try {
                          const u = new URL(p.url)
                          u.searchParams.set(p.parameter, p.value || 'FUZZ')
                          return u.toString()
                        } catch { return p.url }
                      })()
                      return (
                        <tr key={p.id} className="table-row">
                          <td className="table-cell max-w-lg">
                            <div className="flex items-center gap-1.5">
                              <a href={fullUrl} target="_blank" rel="noreferrer"
                                className="text-accent hover:underline text-xs font-mono break-all"
                                title={fullUrl}>{fullUrl}</a>
                              <CopyButton text={fullUrl} />
                            </div>
                          </td>
                          <td className="table-cell font-mono text-xs text-text-primary whitespace-nowrap">{p.parameter}</td>
                          <td className="table-cell text-xs">{p.source || '—'}</td>
                          <td className="table-cell">{p.is_reflected ? <Badge variant="high">Reflected</Badge> : <span className="text-xs text-text-muted">No</span>}</td>
                          <td className="table-cell text-xs">{timeAgo(p.created_at)}</td>
                        </tr>
                      )
                    })}
                    {tab === 'dirs' && (pageData as DirectoryFinding[]).map(d => (
                      <tr key={d.id} className="table-row">
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={d.url} target="_blank" rel="noreferrer" className="text-accent hover:underline text-xs font-mono truncate">{truncate(d.url, 70)}</a>
                            <CopyButton text={d.url} />
                          </div>
                        </td>
                        <td className="table-cell"><span className={cn('font-mono text-xs', statusCodeColor(d.status_code))}>{d.status_code}</span></td>
                        <td className="table-cell text-xs">{d.content_length > 0 ? `${(d.content_length / 1024).toFixed(1)}KB` : '—'}</td>
                        <td className="table-cell text-xs">{timeAgo(d.created_at)}</td>
                      </tr>
                    ))}
                    {tab === 'backups' && (pageData as BackupFinding[]).map(b => (
                      <tr key={b.id} className="table-row">
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={b.url} target="_blank" rel="noreferrer" className="text-accent hover:underline text-xs font-mono truncate">{truncate(b.url, 70)}</a>
                            <CopyButton text={b.url} />
                          </div>
                        </td>
                        <td className="table-cell"><span className={cn('font-mono text-xs', statusCodeColor(b.status_code))}>{b.status_code}</span></td>
                        <td className="table-cell text-xs">{b.content_length > 0 ? `${(b.content_length / 1024).toFixed(1)}KB` : '—'}</td>
                        <td className="table-cell text-xs capitalize">{b.backup_type || '—'}</td>
                        <td className="table-cell text-xs">{timeAgo(b.created_at)}</td>
                      </tr>
                    ))}
                    {tab === 'redirects' && (pageData as OpenRedirectFinding[]).map(r => (
                      <tr key={r.id} className="table-row">
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={r.url} target="_blank" rel="noreferrer"
                              className="text-accent hover:underline text-xs font-mono break-all"
                              title={r.url}>{truncate(r.url, 80)}</a>
                            <CopyButton text={r.url} />
                          </div>
                        </td>
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={r.redirect_to} target="_blank" rel="noreferrer"
                              className="text-severity-medium hover:underline text-xs font-mono break-all"
                              title={r.redirect_to}>{truncate(r.redirect_to, 80)}</a>
                            <CopyButton text={r.redirect_to} />
                          </div>
                        </td>
                        <td className="table-cell">{r.verified ? <Badge variant="high">Verified</Badge> : <span className="text-xs text-text-muted">Unverified</span>}</td>
                        <td className="table-cell text-xs">{timeAgo(r.created_at)}</td>
                      </tr>
                    ))}
                    {tab === 'nuclei' && (pageData as NucleiFinding[]).map(n => (
                      <tr key={n.id} className="table-row">
                        <td className="table-cell whitespace-nowrap">
                          <Badge variant={n.severity}>{n.severity}</Badge>
                        </td>
                        <td className="table-cell text-xs">
                          <p className="text-text-primary font-semibold flex items-center gap-1.5">
                            {n.template_name}
                            {(n.affected_count ?? 1) > 1 && (
                              <span className="px-1.5 py-0.5 rounded bg-accent/15 text-accent text-[10px] font-mono shrink-0"
                                title={`This template matched ${n.affected_count} URLs — collapsed into one finding`}>
                                ×{n.affected_count}
                              </span>
                            )}
                          </p>
                          <p className="text-text-muted font-mono text-xs">{n.template_id}</p>
                        </td>
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={n.matched_url || n.url} target="_blank" rel="noreferrer"
                              className="text-accent hover:underline text-xs font-mono break-all"
                              title={n.matched_url || n.url}>{truncate(n.matched_url || n.url, 70)}</a>
                            <CopyButton text={n.matched_url || n.url} />
                          </div>
                          {(n.affected_count ?? 1) > 1 && (
                            <NucleiAffected targetId={id!} templateId={n.template_id} count={n.affected_count ?? 1} />
                          )}
                        </td>
                        <td className="table-cell text-xs text-text-muted max-w-xs">
                          {truncate(n.description || '', 80) || '—'}
                          {n.curl_command && (
                            <details className="mt-1.5">
                              <summary className="cursor-pointer text-accent hover:underline select-none">PoC</summary>
                              <div className="mt-1.5 space-y-1.5">
                                <div className="flex items-start gap-1">
                                  <pre className="flex-1 font-mono text-[10px] text-severity-medium whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded max-h-32 overflow-auto">{n.curl_command}</pre>
                                  <CopyButton text={n.curl_command} />
                                </div>
                                {(n.request || n.response) && (
                                  <details>
                                    <summary className="cursor-pointer text-text-muted hover:text-text-secondary select-none">Raw request/response</summary>
                                    {n.request && <pre className="mt-1 font-mono text-[10px] text-text-secondary whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded max-h-40 overflow-auto">{n.request}</pre>}
                                    {n.response && <pre className="mt-1 font-mono text-[10px] text-text-muted whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded max-h-40 overflow-auto">{n.response}</pre>}
                                  </details>
                                )}
                              </div>
                            </details>
                          )}
                        </td>
                        <td className="table-cell text-xs whitespace-nowrap">{timeAgo(n.created_at)}</td>
                      </tr>
                    ))}
                    {(tab === 'vulns' || tab === 'candidates') && (pageData as VulnFinding[]).map(v => {
                      const pocUrl = buildPocUrl(v.type, v.url, v.parameter, v.payload)
                      const reproUrl = pocUrl || v.url
                      const isXss = ['xss', 'dom_xss'].includes(String(v.type || '').toLowerCase())
                      return (
                      <tr key={v.id} className="table-row">
                        <td className="table-cell whitespace-nowrap">
                          <Badge variant={v.severity}>{v.severity}</Badge>
                          {typeof v.confidence === 'number' && v.confidence > 0 && (
                            <div className={cn('text-[10px] font-bold mt-0.5',
                              v.confidence >= 85 ? 'text-severity-low' : v.confidence >= 60 ? 'text-severity-medium' : 'text-text-muted')}
                              title="Verification confidence">
                              {v.confidence}% conf
                            </div>
                          )}
                        </td>
                        <td className="table-cell text-xs font-mono font-semibold whitespace-nowrap">
                          <div>{String(v.type || '').replace(/_/g, ' ')}</div>
                          {v.lifecycle && <LifecycleChip lifecycle={v.lifecycle} />}
                        </td>
                        <td className="table-cell max-w-sm">
                          <div className="flex items-center gap-1.5">
                            <a href={v.url} target="_blank" rel="noreferrer"
                              className="text-accent hover:underline text-xs font-mono break-all"
                              title={v.url}>{truncate(v.url, 60)}</a>
                            <CopyButton text={v.url} />
                          </div>
                          {pocUrl && (
                            <div className="flex items-center gap-1.5 mt-1">
                              <a href={pocUrl} target="_blank" rel="noreferrer"
                                className="text-severity-high hover:underline text-[11px] font-mono font-semibold whitespace-nowrap"
                                title={pocUrl}>{isXss ? 'Fire PoC ↗' : 'Open PoC ↗'}</a>
                              <CopyButton text={pocUrl} />
                            </div>
                          )}
                        </td>
                        <td className="table-cell font-mono text-xs text-text-primary whitespace-nowrap">{v.parameter || '—'}</td>
                        <td className="table-cell text-xs text-text-muted max-w-md">
                          <span title={v.evidence}>{truncate(v.evidence, 90) || '—'}</span>
                          {v.payload && <div className="font-mono text-xs text-severity-medium mt-0.5" title={v.payload}>payload: {truncate(v.payload, 60)}</div>}
                          <details className="mt-1.5">
                            <summary className="cursor-pointer text-accent hover:underline select-none text-[11px]">
                              PoC &amp; full evidence
                            </summary>
                            <div className="mt-1.5 space-y-2">
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">
                                  {isXss ? 'Reproduction URL — open to fire the payload' : 'Reproduction URL (full path)'}
                                </div>
                                <div className="flex items-start gap-1">
                                  <a href={reproUrl} target="_blank" rel="noreferrer"
                                    className="flex-1 font-mono text-[10px] text-severity-high break-all hover:underline">{reproUrl}</a>
                                  <CopyButton text={reproUrl} />
                                </div>
                              </div>
                              {v.payload && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">Payload</div>
                                  <div className="flex items-start gap-1">
                                    <pre className="flex-1 font-mono text-[10px] text-severity-medium whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded">{v.payload}</pre>
                                    <CopyButton text={v.payload} />
                                  </div>
                                </div>
                              )}
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">curl</div>
                                <div className="flex items-start gap-1">
                                  <pre className="flex-1 font-mono text-[10px] text-text-secondary whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded">{pocCurl(reproUrl)}</pre>
                                  <CopyButton text={pocCurl(reproUrl)} />
                                </div>
                              </div>
                              {v.evidence && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">Evidence</div>
                                  <pre className="font-mono text-[10px] text-text-muted whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded max-h-48 overflow-auto">{v.evidence}</pre>
                                </div>
                              )}
                              {v.provenance && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-wider text-text-muted mb-0.5">Provenance (raw)</div>
                                  <pre className="font-mono text-[10px] text-text-muted whitespace-pre-wrap break-all bg-bg-secondary/50 p-1.5 rounded max-h-48 overflow-auto">{v.provenance}</pre>
                                </div>
                              )}
                              <div>
                                <div className="text-[10px] uppercase tracking-wider text-severity-low mb-0.5">Remediation</div>
                                <p className="text-[11px] text-text-secondary leading-relaxed bg-severity-low/[.06] border border-severity-low/20 rounded p-1.5">{remediationFor(v.type)}</p>
                              </div>
                            </div>
                          </details>
                        </td>
                        <td className="table-cell text-xs whitespace-nowrap align-top">
                          <button onClick={() => setEvidence({ id: v.id, url: v.url, type: v.type })}
                            className="btn-secondary text-[11px] mb-1">Evidence</button>
                          <div className="text-text-muted">{timeAgo(v.created_at)}</div>
                          <TriageBar targetId={id!} finding={v} onDone={() => loadTab(tab)} />
                        </td>
                      </tr>
                      )
                    })}
                    {tab === 'monitor' && (pageData as MonitoringChange[]).map(c => (
                      <tr key={c.id} className="table-row">
                        <td className="table-cell max-w-xs">
                          <div className="flex items-center gap-1.5">
                            <a href={c.url} target="_blank" rel="noreferrer" className="text-accent hover:underline text-xs font-mono truncate">{truncate(c.url, 50)}</a>
                            <CopyButton text={c.url} />
                          </div>
                        </td>
                        <td className="table-cell">
                          <Badge variant={c.change_type === 'js_change' ? 'medium' : 'info'}>{c.change_type}</Badge>
                        </td>
                        <td className="table-cell text-xs text-text-muted max-w-xs font-mono">{truncate(c.old_value, 50)}</td>
                        <td className="table-cell text-xs text-severity-medium max-w-xs font-mono">{truncate(c.new_value, 50)}</td>
                        <td className="table-cell text-xs">{timeAgo(c.detected_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        {!tabLoading && hasMore && (
          <div className="flex items-center justify-center gap-3 py-3 border-t border-border text-xs">
            <span className="text-text-muted">
              Showing {pageData.length.toLocaleString()} of {filteredData.length.toLocaleString()}
            </span>
            <button onClick={() => setVisibleCount(c => c + PAGE)} className="btn-secondary text-xs">
              Load {Math.min(PAGE, data.length - visibleCount).toLocaleString()} more
            </button>
            <button onClick={() => setVisibleCount(data.length)} className="text-accent hover:underline">
              Show all
            </button>
          </div>
        )}
      </div>
      </ErrorBoundary>
      </div>

      {scanOpen && (
        <ScanModal
          target={target}
          open={true}
          onClose={() => setScanOpen(false)}
          onStarted={() => targetsApi.get(id!).then(setTarget)}
        />
      )}
      {scanAsset && (
        <ScanModal
          target={target}
          asset={{ id: scanAsset.id, value: scanAsset.value, kind: scanAsset.kind, name: scanAsset.name }}
          open={true}
          onClose={() => setScanAsset(null)}
          onStarted={() => targetsApi.get(id!).then(setTarget)}
        />
      )}
      {evidence && (
        <EvidenceViewer
          targetId={id!}
          findingId={evidence.id}
          url={evidence.url}
          type={evidence.type}
          open={true}
          onClose={() => setEvidence(null)}
        />
      )}
    </div>
    </ErrorBoundary>
  )
}
