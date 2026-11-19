import { useEffect, useRef, useState } from 'react'
import { system, type ApiKeyState, type ToolCatalogEntry, type ScanConfig } from '../lib/api'
import { Button, Spinner } from '../components/ui'
import { cn } from '../lib/utils'
import { ws } from '../lib/websocket'
import { useUIStore } from '../store/ui'
import { useAuthStore } from '../store/auth'
import { UsersAdmin } from '../components/system/UsersAdmin'
import { TelegramIntegration } from '../components/system/TelegramIntegration'
import { CorpusManager } from '../components/system/CorpusManager'
import { useUpdateCenter } from '../components/layout/UpdateCenter'

interface SystemLogLine { level: string; module: string; message: string; time: string }

// The automatic monitor watch pipeline the operator can retune on the
// System → Scanning page. Order here is display order; server-side the state
// monitor ("monitor") is always hoisted before HTTP/JS refresh when both are
// picked, so the scheduled baseline lands before anything overwrites it.
const DEFAULT_WATCH_MODULES = ['subdomain_enum', 'monitor', 'http_probe', 'takeover', 'cors', 'backup_discovery']

const MONITOR_MODULE_OPTIONS: { value: string; label: string; hint: string }[] = [
  { value: 'subdomain_enum', label: 'Subdomain re-enumeration', hint: 'catches newly-appeared names each cycle' },
  { value: 'monitor', label: 'State monitor / snapshot', hint: 'always runs first — snapshots the baseline' },
  { value: 'http_probe', label: 'HTTP probe', hint: 'refreshes live host titles/statuses' },
  { value: 'takeover', label: 'Takeover checks', hint: 'flags dangling DNS records' },
  { value: 'cors', label: 'CORS re-check', hint: 're-tests permissive CORS on live endpoints' },
  { value: 'backup_discovery', label: 'Backup file discovery', hint: 'looks for leaked .env/backup files' },
]

// The discovery sources a watch round may use. The list matches the server's
// watch-only source ids (internal/scanner/discovery_sources.go). Each source
// runs in its own slot with its own timeout; the sources run in parallel, so
// turning one off makes the round cheaper, never slower.
const WATCH_SOURCE_OPTIONS: { value: string; label: string; hint: string }[] = [
  { value: 'subfinder', label: 'subfinder', hint: 'passive provider APIs — the broad sweep' },
  { value: 'assetfinder', label: 'assetfinder', hint: 'passive — fast, small result set' },
  { value: 'chaos', label: 'chaos', hint: 'projectdiscovery dataset — needs an API key' },
  { value: 'findomain', label: 'findomain', hint: 'active DNS wordlist — fast, but sends queries to the nameserver' },
  { value: 'crtsh', label: 'crt.sh', hint: 'certificate transparency logs' },
  { value: 'certspotter', label: 'certspotter', hint: 'certificate transparency logs' },
  { value: 'hackertarget', label: 'hackertarget', hint: 'passive host list' },
  { value: 'rapiddns', label: 'rapiddns', hint: 'passive DNS index' },
  { value: 'otx', label: 'otx', hint: 'AlienVault passive DNS' },
  { value: 'anubis', label: 'anubis', hint: 'passive subdomain list' },
  { value: 'urlscan', label: 'urlscan', hint: 'public scan index' },
]

// The watch module set is FIXED by design (D1): passive discovery plus one
// HTTP probe. It is shown as a read-only badge list, never as checkboxes.
const WATCH_MODULE_SET = ['subdomain_enum', 'http_probe']

type ScanDraft = {
  resolvers: string; depth: number; enabled: boolean; catchall: boolean;
  excludeIDs: string; repos: string; monitor: string[];
  maxConcurrentScans: number; maxConcurrentDeepScans: number; maxConcurrentWatchScans: number;
  watchHTTPThreads: number; watchHTTPRateLimit: number; watchRoundsMinGap: number;
  watchRoundIntervalHours: number;
  watchSourceTimeoutMinutes: number; watchSources: string[];
  watchRowsRetentionDays: number; watchScopeEventsRetentionDays: number;
  watchNotifyHostCap: number; watchFailLimit: number;
}

// numOr parses a bounded integer input. NaN and out-of-range values fall back
// to a safe default so a half-typed number cannot reach the API.
const numOr = (raw: string, fallback: number, min: number, max: number) => {
  const n = Number.parseInt(raw, 10)
  return Number.isFinite(n) && n >= min && n <= max ? n : fallback
}

// scanDraftFrom maps the wire config into the editable draft. The defaults
// mirror internal/config/config.go.
const scanDraftFrom = (sc: ScanConfig): ScanDraft => ({
  resolvers: (sc.dns_resolvers || []).join('\n'),
  depth: sc.subdomain_recursion_depth || 4,
  enabled: sc.subdomain_recursion_enabled === true,
  catchall: sc.http_catchall_detection === true,
  excludeIDs: (sc.nuclei_exclude_template_ids || []).join('\n'),
  repos: (sc.nuclei_extra_template_repos || []).join('\n'),
  // Empty on the wire ⇒ the built-in default watch set applies.
  monitor: (sc.monitor_modules && sc.monitor_modules.length ? sc.monitor_modules : DEFAULT_WATCH_MODULES),
  maxConcurrentScans: sc.max_concurrent_scans || 2,
  maxConcurrentDeepScans: sc.max_concurrent_deep_scans || 1,
  maxConcurrentWatchScans: sc.max_concurrent_watch_scans ?? 1,
  watchHTTPThreads: sc.watch_http_threads || 10,
  watchHTTPRateLimit: sc.watch_http_rate_limit || 25,
  watchRoundsMinGap: sc.watch_rounds_min_gap || 30,
  watchRoundIntervalHours: sc.watch_round_interval_hours || 12,
  watchSourceTimeoutMinutes: sc.watch_source_timeout_minutes || 5,
  watchSources: (sc.watch_enumeration_sources && sc.watch_enumeration_sources.length
    ? sc.watch_enumeration_sources
    : ['subfinder', 'assetfinder', 'chaos', 'findomain']),
  watchRowsRetentionDays: sc.watch_rows_retention_days || 30,
  watchScopeEventsRetentionDays: sc.watch_scope_events_retention_days || 180,
  watchNotifyHostCap: sc.watch_notify_host_cap || 20,
  watchFailLimit: sc.watch_fail_limit || 3,
})

export default function System() {
  const [activeTab, setActiveTab] = useState<'overview' | 'integrations' | 'corpora' | 'toolchain' | 'team'>('overview')
  const [tools, setTools] = useState<Record<string,boolean>>({})
  const [catalog, setCatalog] = useState<ToolCatalogEntry[]>([])
  const [installing, setInstalling] = useState<Record<string, boolean>>({})
  const [stats, setStats] = useState<Record<string,number>>({})
  const [loading, setLoading] = useState(true)
  const [templateLog, setTemplateLog] = useState<SystemLogLine[]>([])
  const [updatingTemplates, setUpdatingTemplates] = useState(false)
  const [apiKeys, setApiKeys] = useState<ApiKeyState[]>([])
  const [drafts, setDrafts] = useState<Record<string,string>>({})
  const [savingKeys, setSavingKeys] = useState(false)
  const [scanCfg, setScanCfg] = useState<ScanConfig | null>(null)
  const [scanDraft, setScanDraft] = useState<ScanDraft | null>(null)
  const [savingScanCfg, setSavingScanCfg] = useState(false)
  const { addToast } = useUIStore()
  const isAdmin = useAuthStore(s => s.user?.role === 'admin')
  const { info: updateInfo, checking: checkingUpdate, refresh: refreshUpdate, showDetails: showUpdateDetails } = useUpdateCenter()
  const templateTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const load = async () => {
    try {
      const [t, cat, s, ks, sc] = await Promise.all([
        system.tools(),
        system.toolCatalog().catch(() => [] as ToolCatalogEntry[]),
        system.stats(),
        system.getSettings().catch(() => ({ api_keys: [] })),
        system.getScanConfig().catch(() => null),
      ])
      setTools(t||{}); setCatalog(cat||[]); setStats(s||{}); setApiKeys(ks?.api_keys || [])
      if (sc) {
        setScanCfg(sc)
        setScanDraft(scanDraftFrom(sc))
      }
    }
    catch { /**/ } finally { setLoading(false) }
  }

  const installTool = async (name: string) => {
    setInstalling(p => ({ ...p, [name]: true }))
    try {
      const r = await system.installTool(name)
      if (r.installed) {
        addToast('success', `${name} installed`)
        const cat = await system.toolCatalog().catch(() => catalog)
        setCatalog(cat)
        setTools(await system.tools().catch(() => tools))
      } else if (r.manual) {
        addToast('info', `${name}: run manually → ${r.command || r.doc || 'see docs'}`)
      } else {
        addToast('error', `${name}: ${r.message || 'install failed'}`)
      }
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : `Failed to install ${name}`)
    } finally {
      setInstalling(p => ({ ...p, [name]: false }))
    }
  }

  const saveKeys = async () => {
    const patch: Record<string,string> = {}
    for (const [k, v] of Object.entries(drafts)) if (v !== undefined) patch[k] = v
    if (Object.keys(patch).length === 0) { addToast('info', 'No key changes to save'); return }
    setSavingKeys(true)
    try {
      const res = await system.updateSettings(patch)
      setApiKeys(res.api_keys || []); setDrafts({})
      addToast('success', 'API keys saved')
    } catch {
      addToast('error', 'Failed to save API keys')
    } finally { setSavingKeys(false) }
  }
  const splitLines = (s: string) => s.split('\n').map(l => l.trim()).filter(Boolean)
  const saveScanCfg = async () => {
    if (!scanDraft) return
    setSavingScanCfg(true)
    try {
      const res = await system.updateScanConfig({
        dns_resolvers: splitLines(scanDraft.resolvers),
        subdomain_recursion_depth: scanDraft.depth,
        subdomain_recursion_enabled: scanDraft.enabled,
        http_catchall_detection: scanDraft.catchall,
        nuclei_exclude_template_ids: splitLines(scanDraft.excludeIDs),
        nuclei_extra_template_repos: splitLines(scanDraft.repos),
        monitor_modules: scanDraft.monitor,
        max_concurrent_scans: scanDraft.maxConcurrentScans,
        max_concurrent_deep_scans: scanDraft.maxConcurrentDeepScans,
        max_concurrent_watch_scans: scanDraft.maxConcurrentWatchScans,
        watch_http_threads: scanDraft.watchHTTPThreads,
        watch_http_rate_limit: scanDraft.watchHTTPRateLimit,
        watch_rounds_min_gap: scanDraft.watchRoundsMinGap,
        watch_round_interval_hours: scanDraft.watchRoundIntervalHours,
        watch_source_timeout_minutes: scanDraft.watchSourceTimeoutMinutes,
        watch_enumeration_sources: scanDraft.watchSources,
        watch_rows_retention_days: scanDraft.watchRowsRetentionDays,
        watch_scope_events_retention_days: scanDraft.watchScopeEventsRetentionDays,
        watch_notify_host_cap: scanDraft.watchNotifyHostCap,
        watch_fail_limit: scanDraft.watchFailLimit,
      })
      setScanCfg(res)
      setScanDraft(scanDraftFrom(res))
      addToast('success', 'Scan configuration saved — watch modules apply from the next monitor cycle, the rest from the next scan')
    } catch {
      addToast('error', 'Failed to save scan configuration')
    } finally { setSavingScanCfg(false) }
  }

  useEffect(() => {
    load()
    const i = setInterval(() => system.stats().then(s => setStats(s || {})).catch(() => {}), 30000)
    return () => clearInterval(i)
  }, [])

  // nuclei -update-templates + the official/community repo sync (see
  // nuclei.go's syncExtraTemplates) runs in the background on the server;
  // progress streams here as "system_log" events. The backend emits an
  // explicit "Template sync complete." line when it's actually done — that's
  // the real signal the spinner clears on. The timeout below is ONLY a
  // safety net (server restarted mid-sync, missed websocket event, etc.), so
  // it's set comfortably past the backend's own 15-minute cap rather than a
  // guess shorter than the work could actually take.
  useEffect(() => ws.on('system_log', (payload: unknown) => {
    const line = payload as SystemLogLine
    if (line.module !== 'nuclei_templates') return
    setTemplateLog(p => [...p.slice(-49), line])
    if (line.message === 'Template sync complete.') {
      if (templateTimeoutRef.current) { clearTimeout(templateTimeoutRef.current); templateTimeoutRef.current = null }
      setUpdatingTemplates(false)
      addToast('success', 'Nuclei template sync complete')
    }
  }), [])

  const handleUpdateTemplates = async () => {
    setUpdatingTemplates(true)
    setTemplateLog([])
    try {
      const res = await system.updateTemplates()
      addToast('info', res.message)
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to start template update')
      setUpdatingTemplates(false)
      return
    }
    // Safety-net only — the real "done" signal is the system_log completion
    // line above. 18 min > the backend's 15-min sync budget, so this should
    // essentially never fire under normal conditions.
    if (templateTimeoutRef.current) clearTimeout(templateTimeoutRef.current)
    templateTimeoutRef.current = setTimeout(() => setUpdatingTemplates(false), 18 * 60 * 1000)
  }

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner className="w-10 h-10"/></div>

  const tabs: { id: 'overview' | 'integrations' | 'corpora' | 'toolchain' | 'team'; label: string; hidden?: boolean }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'integrations', label: 'Integrations' },
    { id: 'corpora', label: 'Wordlists & payloads', hidden: !isAdmin },
    { id: 'toolchain', label: 'Toolchain' },
    { id: 'team', label: 'Team', hidden: !isAdmin },
  ]
  const formatDate = (value?: string) => value && value !== 'unknown'
    ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : 'Unknown'

  return (
    <div className="space-y-5">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <p className="page-kicker">Platform control</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-[-.04em]">System &amp; updates</h1>
          <p className="page-lede mt-1">Release health, integrations, scanner tools and team access.</p>
        </div>
        <div className="flex items-center gap-2">
          {activeTab === 'toolchain' && (
            <Button size="sm" variant="secondary" loading={updatingTemplates} onClick={handleUpdateTemplates}>↻ Update templates</Button>
          )}
          <Button size="sm" variant="ghost" onClick={load}>↻ Refresh</Button>
        </div>
      </header>

      <div className="flex gap-1 overflow-x-auto no-scrollbar border-b border-border" role="tablist">
        {tabs.filter(t => !t.hidden).map(t => (
          <button key={t.id} type="button" role="tab" aria-selected={activeTab === t.id}
            onClick={() => setActiveTab(t.id)}
            className={cn('relative shrink-0 px-4 py-2.5 text-xs font-medium transition-colors',
              activeTab === t.id ? 'text-text-primary' : 'text-text-muted hover:text-text-secondary')}>
            {t.label}
            {activeTab === t.id && <span className="absolute left-3 right-3 bottom-0 h-0.5 rounded-full bg-accent" />}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-6 animate-fade-in">
          <section className="card overflow-hidden">
            <div className="grid lg:grid-cols-[1.35fr_.65fr]">
              <div className="p-5 sm:p-6 bg-gradient-to-br from-accent/[.10] via-transparent to-transparent">
                <div className="flex items-center gap-2 text-xs">
                  <span className={cn('w-2.5 h-2.5 rounded-full', updateInfo?.update_available ? 'bg-accent animate-pulse' : updateInfo?.error ? 'bg-severity-medium' : 'bg-severity-low')} />
                  <span className="font-semibold text-text-primary">
                    {!updateInfo ? 'Loading release status…' : !updateInfo.enabled ? 'Automatic checks disabled' : updateInfo.update_available ? `Reconner v${updateInfo.latest} is ready` : 'Reconner is up to date'}
                  </span>
                </div>
                <h2 className="mt-4 text-3xl sm:text-4xl font-semibold tracking-tight">v{updateInfo?.current || '—'}</h2>
                <p className="mt-2 text-sm text-text-secondary max-w-xl">
                  Reconner checks the latest stable GitHub release every six hours using a cached conditional request. It never interrupts scans or updates itself automatically.
                </p>
                <div className="mt-5 flex flex-wrap gap-2">
                  {updateInfo?.update_available && <Button variant="primary" onClick={showUpdateDetails}>Review update</Button>}
                  <Button variant="secondary" loading={checkingUpdate} onClick={refreshUpdate}>Check now</Button>
                  {updateInfo?.url && <a href={updateInfo.url} target="_blank" rel="noreferrer" className="btn-ghost">GitHub release ↗</a>}
                </div>
              </div>
              <dl className="grid grid-cols-2 lg:grid-cols-1 border-t lg:border-t-0 lg:border-l border-border bg-black/[.10]">
                {[
                  ['Channel', updateInfo?.channel || 'stable'],
                  ['Commit', updateInfo?.current_commit && updateInfo.current_commit !== 'unknown' ? updateInfo.current_commit.slice(0, 12) : 'unknown'],
                  ['Built', formatDate(updateInfo?.build_date)],
                  ['Next check', formatDate(updateInfo?.next_check_at)],
                ].map(([label, value]) => (
                  <div key={label} className="p-4 border-b border-r lg:border-r-0 border-border last:border-b-0">
                    <dt className="text-[10px] uppercase tracking-wider text-text-muted">{label}</dt>
                    <dd className="mt-1 text-xs font-mono text-text-secondary break-all">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>
            {updateInfo?.error && <div className="px-5 py-2.5 text-[11px] text-severity-medium border-t border-severity-medium/20 bg-severity-medium/[.05]">GitHub check: {updateInfo.error}{updateInfo.stale ? ' · showing the last successful result' : ''}</div>}
          </section>

          {Object.keys(stats).length > 0 && (
            <section>
              <p className="section-title">Runtime health</p>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {Object.entries(stats).map(([k,v]) => (
                  <div key={k} className="card p-4">
                    <p className="text-[10px] uppercase tracking-wider text-text-muted">{k.replace(/_/g,' ')}</p>
                    <p className="mt-2 text-xl font-semibold tabular-nums">{typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(1)) : v}</p>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {activeTab === 'integrations' && (
        <section className="animate-fade-in">
          {isAdmin && <TelegramIntegration />}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
            <div>
              <h2 className="text-sm font-semibold">Passive intelligence providers</h2>
              <p className="text-xs text-text-muted mt-1">Optional credentials are persisted server-side and are never returned in full.</p>
            </div>
            <Button size="sm" variant="primary" loading={savingKeys} onClick={saveKeys}>Save changes</Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {apiKeys.map(k => (
              <div key={k.name} className="card p-4">
                <div className="flex items-center justify-between gap-3 mb-2">
                  <span className="text-sm font-medium">{k.label}</span>
                  <span className={cn('text-[10px]', k.set ? 'text-severity-low' : 'text-text-muted')}>{k.set ? `● connected ${k.masked ? `(${k.masked})` : ''}` : '○ not configured'}</span>
                </div>
                <input type="password" autoComplete="off" placeholder={k.set ? 'Enter a new value to replace' : k.hint}
                  value={drafts[k.name] ?? ''} onChange={e => setDrafts(d => ({ ...d, [k.name]: e.target.value }))}
                  className="input font-mono" />
                <p className="text-[10px] text-text-muted mt-2">Expected format: <span className="font-mono">{k.hint}</span></p>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'corpora' && <CorpusManager />}

      {activeTab === 'toolchain' && (
        <section className="space-y-5 animate-fade-in">
          {templateLog.length > 0 && (
            <div className="card p-4">
              <p className="section-title">Template sync</p>
              <div className="space-y-1 max-h-44 overflow-y-auto font-mono text-xs">
                {templateLog.map((l, i) => <p key={i} className={l.level === 'error' ? 'text-severity-critical' : l.level === 'warn' ? 'text-severity-medium' : 'text-text-secondary'}>{l.message}</p>)}
              </div>
            </div>
          )}
          {isAdmin && scanDraft && (
            <div className="card p-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-3">
                <div>
                  <h2 className="text-sm font-semibold">Scanning configuration</h2>
                  <p className="text-xs text-text-muted mt-1">Controls DNS resolution, recursive subdomain depth, and which nuclei templates run. Applies to the next scan.</p>
                </div>
                <Button size="sm" variant="primary" loading={savingScanCfg} onClick={saveScanCfg}>Save configuration</Button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium">DNS resolvers <span className="text-text-muted">(one per line)</span></label>
                  <textarea rows={5} value={scanDraft.resolvers}
                    onChange={e => setScanDraft(d => d && ({ ...d, resolvers: e.target.value }))}
                    placeholder={(scanCfg?.default_dns_resolvers || []).join('\n')}
                    className="input font-mono text-xs mt-1" />
                  <p className="text-[10px] text-text-muted mt-1">Empty ⇒ built-in public resolvers (Cloudflare/Google/Quad9/OpenDNS). Pointing at fast resolvers is the biggest subdomain-enum speedup.</p>
                </div>
                <div>
                  <label className="text-xs font-medium">Recursive subdomain depth</label>
                  <div className="flex items-center gap-3 mt-1">
                    <input type="number" min={1} max={10} value={scanDraft.depth} disabled={!scanDraft.enabled}
                      onChange={e => setScanDraft(d => d && ({ ...d, depth: parseInt(e.target.value, 10) || 1 }))}
                      className="input font-mono text-xs w-28" />
                    <label className="flex items-center gap-1.5 text-xs font-medium whitespace-nowrap">
                      <input type="checkbox" className="accent-accent" checked={scanDraft.enabled}
                        onChange={e => setScanDraft(d => d && ({ ...d, enabled: e.target.checked }))} />
                      Enable recursive enumeration
                    </label>
                  </div>
                  <p className="text-[10px] text-text-muted mt-1">After the apex, each resolving subdomain is itself enumerated, down to this many levels (default 4). Off or depth 1 ⇒ apex only. This is the deployment default; the scan dialog can opt in per scan.</p>
                  <label className="flex items-center gap-1.5 text-xs font-medium mt-2">
                    <input type="checkbox" className="accent-accent" checked={scanDraft.catchall}
                      onChange={e => setScanDraft(d => d && ({ ...d, catchall: e.target.checked }))} />
                    Mark HTTP catch-all subdomains
                  </label>
                  <p className="text-[10px] text-text-muted mt-1">Optional, off by default. After HTTP probing, groups 2xx hosts that all serve one wildcard page — redirect-to-apex fleets or homepage clones (the "junk.git.target" catch-all case) — and hides them from the Hosts tab, reports, graph and web modules. Reads stored responses only, no extra requests. Seeds and vhosts are never touched.</p>
                </div>
                <div>
                  <label className="text-xs font-medium">Nuclei — exclude template IDs <span className="text-text-muted">(one per line)</span></label>
                  <textarea rows={4} value={scanDraft.excludeIDs}
                    onChange={e => setScanDraft(d => d && ({ ...d, excludeIDs: e.target.value }))}
                    placeholder={'e.g.\nCVE-2019-5544\noptions-method'}
                    className="input font-mono text-xs mt-1" />
                  <p className="text-[10px] text-text-muted mt-1">Added on top of the built-in curated blocklist. Use a template's exact <span className="font-mono">id</span>.</p>
                </div>
                <div>
                  <label className="text-xs font-medium">Nuclei — extra template repos <span className="text-text-muted">(git URLs, one per line)</span></label>
                  <textarea rows={4} value={scanDraft.repos}
                    onChange={e => setScanDraft(d => d && ({ ...d, repos: e.target.value }))}
                    placeholder={(scanCfg?.default_nuclei_repos || []).join('\n')}
                    className="input font-mono text-xs mt-1" />
                  <p className="text-[10px] text-text-muted mt-1">Cloned on top of the official set. Empty ⇒ the two official ProjectDiscovery repos only. Community repos are a known false-positive source — add deliberately.</p>
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs font-medium">Default monitor modules</label>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 mt-2">
                    {MONITOR_MODULE_OPTIONS.map(m => (
                      <label key={m.value} className="flex items-start gap-2 text-xs font-medium">
                        <input type="checkbox" className="accent-accent mt-0.5"
                          checked={scanDraft.monitor.includes(m.value)}
                          onChange={e => setScanDraft(d => d && ({ ...d, monitor: e.target.checked ? [...d.monitor, m.value] : d.monitor.filter(v => v !== m.value) }))} />
                        <span>{m.label} <span className="font-normal text-text-muted">— {m.hint}</span></span>
                      </label>
                    ))}
                  </div>
                  <p className="text-[10px] text-text-muted mt-1">Modules the automatic monitor schedule runs; applies from its next cycle. The state monitor always snapshots first, before HTTP/JS refresh. Uncheck everything ⇒ the built-in set above applies.</p>
                </div>
                <div className="md:col-span-2 border-t border-border-subtle pt-4">
                  <div className="flex items-center justify-between gap-3">
                    <label className="text-xs font-medium">Watch scanning <span className="text-text-muted">(breadth tier)</span></label>
                    <div className="flex flex-wrap gap-1">
                      {WATCH_MODULE_SET.map(m => (
                        <span key={m} className="px-1.5 py-0.5 rounded bg-bg-tertiary text-[10px] font-mono text-text-secondary">{m}</span>
                      ))}
                    </div>
                  </div>
                  <p className="text-[10px] text-text-muted mt-1 mb-3">
                    A watch round runs passive discovery plus one HTTP probe. The module set is fixed, so it is shown as a badge list.
                    The source toggles below pick which discovery tools it may use — they run in parallel, each with its own timeout.
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {WATCH_SOURCE_OPTIONS.map(s => (
                      <label key={s.value} className="flex items-start gap-2 text-xs font-medium">
                        <input type="checkbox" className="accent-accent mt-0.5"
                          checked={scanDraft.watchSources.includes(s.value)}
                          onChange={e => setScanDraft(d => d && ({ ...d, watchSources: e.target.checked ? [...d.watchSources, s.value] : d.watchSources.filter(v => v !== s.value) }))} />
                        <span>{s.label} <span className="font-normal text-text-muted">— {s.hint}</span></span>
                      </label>
                    ))}
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                    <div>
                      <label className="text-xs font-medium">Round interval (hours)</label>
                      <input type="number" min={1} max={168} value={scanDraft.watchRoundIntervalHours}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchRoundIntervalHours: parseInt(e.target.value, 10) || 12 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Normal wait between finished rounds of one project.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Retry gap (min)</label>
                      <input type="number" min={5} max={1440} value={scanDraft.watchRoundsMinGap}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchRoundsMinGap: parseInt(e.target.value, 10) || 30 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Wait after a failed or interrupted round before retrying.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Source timeout (min)</label>
                      <input type="number" min={1} max={30} value={scanDraft.watchSourceTimeoutMinutes}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchSourceTimeoutMinutes: parseInt(e.target.value, 10) || 5 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Per source. There is no round-wide timeout: the round always finishes.</p>
                    </div>
                    <div>
                      <label htmlFor="maxConcurrentWatchScans" className="text-xs font-medium">Watch rounds in parallel</label>
                      <input id="maxConcurrentWatchScans" type="number" min={0} max={16} value={scanDraft.maxConcurrentWatchScans}
                        onChange={e => setScanDraft(d => d && ({ ...d, maxConcurrentWatchScans: numOr(e.target.value, 0, 0, 16) }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Watch rounds that may run at the same time. 0 disables them.</p>
                    </div>
                    <div>
                      <label htmlFor="maxConcurrentDeepScans" className="text-xs font-medium">Deep scans in parallel</label>
                      <input id="maxConcurrentDeepScans" type="number" min={1} max={8} value={scanDraft.maxConcurrentDeepScans}
                        onChange={e => setScanDraft(d => d && ({ ...d, maxConcurrentDeepScans: numOr(e.target.value, 1, 1, 8) }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Heavy full-pipeline scans. Deep keeps its slots; watch uses the rest.</p>
                    </div>
                    <div>
                      <label htmlFor="maxConcurrentScans" className="text-xs font-medium">Total scans in parallel</label>
                      <input id="maxConcurrentScans" type="number" min={1} max={32} value={scanDraft.maxConcurrentScans}
                        onChange={e => setScanDraft(d => d && ({ ...d, maxConcurrentScans: numOr(e.target.value, 1, 1, 32) }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Ceiling for deep plus watch rounds together.</p>
                    </div>
                    <div className="col-span-2 rounded-lg border border-white/[.06] bg-white/[.02] px-3 py-2">
                      <p className="text-[11px] font-medium text-text-primary">Safe range for this box</p>
                      <p className="text-[10px] text-text-muted mt-0.5">
                        Total {scanCfg?.envelope_total ?? '—'} · deep {scanCfg?.envelope_deep ?? '—'} · watch {scanCfg?.envelope_watch ?? '—'}
                      </p>
                      <p className="text-[10px] text-text-muted mt-1">
                        Values apply while the box is healthy. Live memory/CPU pressure may briefly throttle new scans.
                        A deep scan and a watch round never run on the same project.
                      </p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Watch HTTP threads</label>
                      <input type="number" min={1} max={40} value={scanDraft.watchHTTPThreads}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchHTTPThreads: parseInt(e.target.value, 10) || 10 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">httpx threads per watch round. Deep scans keep their own.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Watch HTTP rate (rps)</label>
                      <input type="number" min={1} max={150} value={scanDraft.watchHTTPRateLimit}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchHTTPRateLimit: parseInt(e.target.value, 10) || 25 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Requests per second per watch round.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Rows kept (days)</label>
                      <input type="number" min={1} max={365} value={scanDraft.watchRowsRetentionDays}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchRowsRetentionDays: parseInt(e.target.value, 10) || 30 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Prunes raw watch rows. Landed scope and notifications survive.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Scope history (days)</label>
                      <input type="number" min={1} max={3650} value={scanDraft.watchScopeEventsRetentionDays}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchScopeEventsRetentionDays: parseInt(e.target.value, 10) || 180 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">How long the landed-scope audit trail is kept.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Hosts per alert</label>
                      <input type="number" min={1} max={100} value={scanDraft.watchNotifyHostCap}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchNotifyHostCap: parseInt(e.target.value, 10) || 20 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Names listed per grouped scope alert. The count is always shown.</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium">Failed rounds before pause</label>
                      <input type="number" min={1} max={10} value={scanDraft.watchFailLimit}
                        onChange={e => setScanDraft(d => d && ({ ...d, watchFailLimit: parseInt(e.target.value, 10) || 3 }))}
                        className="input font-mono text-xs w-full mt-1" />
                      <p className="text-[10px] text-text-muted mt-1">Consecutive failures that stop the chain for one project.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
          <div>
            <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-2 mb-4">
              <div>
                <h2 className="text-sm font-semibold">Scanner toolchain</h2>
                <p className="text-xs text-text-muted mt-1">{(catalog.length ? catalog.filter(t => t.installed).length : Object.values(tools).filter(Boolean).length)}/{catalog.length || Object.keys(tools).length} tools available</p>
              </div>
              <p className="text-[11px] text-text-muted">The official Docker image bundles and verifies the complete toolchain.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
              {(catalog.length ? catalog : Object.entries(tools).map(([name, installed]) => ({ name, installed, method: '', command: '', doc: '', notes: '', one_click: false }))).map(t => (
                <div key={t.name} className="card p-3 flex items-center gap-3">
                  <span className={cn('w-2 h-2 rounded-full shrink-0', t.installed ? 'bg-severity-low' : 'bg-severity-critical')} />
                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-mono">{t.name}</span>
                    {!t.installed && <span className="block text-[10px] text-text-muted truncate" title={t.command || t.doc}>{t.notes || t.command || 'Unavailable'}</span>}
                  </div>
                  {t.installed ? <span className="text-xs text-severity-low">✓</span> : t.one_click ? (
                    <Button size="sm" variant="secondary" disabled={!!installing[t.name]} onClick={() => installTool(t.name)}>{installing[t.name] ? <Spinner /> : 'Install'}</Button>
                  ) : (
                    <div className="flex gap-1">
                      {t.command && <button onClick={() => { navigator.clipboard?.writeText(t.command); addToast('success', 'Command copied') }} className="btn-ghost !px-2 !py-1 text-xs">Copy</button>}
                      {t.doc && <a href={t.doc} target="_blank" rel="noreferrer" className="btn-ghost !px-2 !py-1 text-xs">Docs</a>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {activeTab === 'team' && isAdmin && <div className="animate-fade-in"><UsersAdmin /></div>}
    </div>
  )
}
