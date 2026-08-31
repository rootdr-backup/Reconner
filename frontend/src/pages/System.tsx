import { useEffect, useRef, useState } from 'react'
import { system, type ApiKeyState, type ToolCatalogEntry } from '../lib/api'
import { Button, Spinner } from '../components/ui'
import { cn } from '../lib/utils'
import { ws } from '../lib/websocket'
import { useUIStore } from '../store/ui'
import { useAuthStore } from '../store/auth'
import { UsersAdmin } from '../components/system/UsersAdmin'
import { useUpdateCenter } from '../components/layout/UpdateCenter'

interface SystemLogLine { level: string; module: string; message: string; time: string }

export default function System() {
  const [activeTab, setActiveTab] = useState<'overview' | 'integrations' | 'toolchain' | 'team'>('overview')
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
  const { addToast } = useUIStore()
  const isAdmin = useAuthStore(s => s.user?.role === 'admin')
  const { info: updateInfo, checking: checkingUpdate, refresh: refreshUpdate, showDetails: showUpdateDetails } = useUpdateCenter()
  const templateTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const load = async () => {
    try {
      const [t, cat, s, ks] = await Promise.all([
        system.tools(),
        system.toolCatalog().catch(() => [] as ToolCatalogEntry[]),
        system.stats(),
        system.getSettings().catch(() => ({ api_keys: [] })),
      ])
      setTools(t||{}); setCatalog(cat||[]); setStats(s||{}); setApiKeys(ks?.api_keys || [])
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

  const tabs: { id: 'overview' | 'integrations' | 'toolchain' | 'team'; label: string; hidden?: boolean }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'integrations', label: 'Integrations' },
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
          <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-accent">Platform control</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">System &amp; updates</h1>
          <p className="mt-1 text-xs text-text-muted">Release health, integrations, scanner tools and team access.</p>
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
