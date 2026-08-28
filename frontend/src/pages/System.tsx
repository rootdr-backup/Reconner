import { useEffect, useRef, useState } from 'react'
import { system, type ApiKeyState, type ToolCatalogEntry } from '../lib/api'
import { Button, Spinner } from '../components/ui'
import { cn } from '../lib/utils'
import { ws } from '../lib/websocket'
import { useUIStore } from '../store/ui'
import { useAuthStore } from '../store/auth'
import { UsersAdmin } from '../components/system/UsersAdmin'

interface SystemLogLine { level: string; module: string; message: string; time: string }

export default function System() {
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
  useEffect(() => { load(); const i = setInterval(load, 10000); return () => clearInterval(i) }, [])

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

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner/></div>
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">System</h1>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" loading={updatingTemplates} onClick={handleUpdateTemplates}>
            ↻ Update Nuclei Templates
          </Button>
          <Button size="sm" variant="ghost" onClick={load}>↻ Refresh</Button>
        </div>
      </div>
      {templateLog.length > 0 && (
        <div className="card p-3">
          <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">Template Sync</p>
          <div className="space-y-1 max-h-40 overflow-y-auto font-mono text-xs">
            {templateLog.map((l, i) => (
              <p key={i} className={l.level === 'error' ? 'text-severity-critical' : l.level === 'warn' ? 'text-severity-medium' : 'text-text-secondary'}>{l.message}</p>
            ))}
          </div>
        </div>
      )}
      {isAdmin && <UsersAdmin />}

      {Object.keys(stats).length > 0 && (
        <div>
          <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-3">Stats</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(stats).map(([k,v]) => (
              <div key={k} className="card p-3"><p className="text-xs text-text-muted mb-1">{k.replace(/_/g,' ')}</p>
                <p className="text-lg font-semibold">{typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(1)) : v}</p></div>
            ))}
          </div>
        </div>
      )}
      {apiKeys.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs font-medium text-text-muted uppercase tracking-wider">
              Passive-Intel API Keys <span className="normal-case text-text-muted/70">— optional, stored in config.json, never shown back in full</span>
            </p>
            <Button size="sm" variant="secondary" loading={savingKeys} onClick={saveKeys}>Save keys</Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {apiKeys.map(k => (
              <div key={k.name} className="card p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{k.label}</span>
                  {k.set
                    ? <span className="text-[10px] text-severity-low">✓ set {k.masked && `(${k.masked})`}</span>
                    : <span className="text-[10px] text-text-muted">not set</span>}
                </div>
                <input
                  type="password"
                  autoComplete="off"
                  placeholder={k.set ? 'enter a new value to replace' : k.hint}
                  value={drafts[k.name] ?? ''}
                  onChange={e => setDrafts(d => ({ ...d, [k.name]: e.target.value }))}
                  className="w-full bg-surface-alt border border-border rounded px-2 py-1 text-sm font-mono" />
                <p className="text-[10px] text-text-muted mt-1">format: <span className="font-mono">{k.hint}</span>{k.set && ' · leave blank to keep, clear + save to remove'}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      <div>
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <p className="text-xs font-medium text-text-muted uppercase tracking-wider">
            Tools — {(catalog.length ? catalog.filter(t => t.installed).length : Object.values(tools).filter(Boolean).length)}/
            {(catalog.length || Object.keys(tools).length)} installed
          </p>
          <span className="text-[11px] text-text-muted">
            Missing a tool? Install it here (Go/pip — no root), or copy the command to run manually. Everything degrades gracefully without it.
          </span>
        </div>
        {catalog.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            {catalog.map(t => (
              <div key={t.name} className="card p-3 flex items-center gap-3">
                <span className={cn('w-2 h-2 rounded-full shrink-0', t.installed ? 'bg-severity-low' : 'bg-severity-critical')} />
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-mono">{t.name}</span>
                  {!t.installed && (
                    <span className="block text-[10px] text-text-muted truncate" title={t.command || t.doc}>
                      {t.method === 'apt' ? 'needs root: ' : t.method === 'manual' ? 'manual: ' : ''}{t.command || t.doc}
                      {t.notes ? ` — ${t.notes}` : ''}
                    </span>
                  )}
                </div>
                {t.installed ? (
                  <span className="text-xs text-severity-low shrink-0">✓</span>
                ) : t.one_click ? (
                  <Button size="sm" variant="secondary" disabled={!!installing[t.name]}
                    onClick={() => installTool(t.name)} className="shrink-0">
                    {installing[t.name] ? <Spinner /> : 'Install'}
                  </Button>
                ) : (
                  <div className="flex items-center gap-1 shrink-0">
                    {t.command && (
                      <button title="Copy install command"
                        onClick={() => { navigator.clipboard?.writeText(t.command); addToast('success', 'Command copied') }}
                        className="text-xs px-2 py-1 rounded border border-border text-text-muted hover:text-text-secondary">Copy</button>
                    )}
                    {t.doc && (
                      <a href={t.doc} target="_blank" rel="noopener noreferrer"
                        className="text-xs px-2 py-1 rounded border border-border text-text-muted hover:text-accent">Docs</a>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            {Object.entries(tools).map(([name, ok]) => (
              <div key={name} className="card p-3 flex items-center gap-3">
                <span className={cn('w-2 h-2 rounded-full shrink-0', ok ? 'bg-severity-low' : 'bg-severity-critical')}/>
                <span className="text-sm font-mono flex-1">{name}</span>
                <span className={cn('text-xs', ok ? 'text-severity-low' : 'text-severity-critical')}>{ok ? '✓' : '✗'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
