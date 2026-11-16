import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { targets as targetsApi } from '../lib/api'
import { useUIStore } from '../store/ui'
import { Button, Spinner, Badge, EmptyState, cn } from '../components/ui'
import { Icons } from '../components/layout/Sidebar'
import type { Target } from '../types'

// The WP Scanner is a dedicated surface for WordPress targets: WordPress is heavy
// enough (its own fingerprint gate, enumerators, backup/config exposure, CVE
// coverage) to warrant its own project list and module picker, separate from the
// generic web scanner. Projects created here are tagged WP_TAG and the page lists
// only those.
const WP_TAG = 'wp-scanner'

// The individually-selectable WordPress modules, mirroring the backend scheduler
// tokens. wp_detect is the mandatory gate (always on); wp_credaudit is the
// dual-use opt-in and is OFF by default with a clear warning.
type WPModule = { id: string; label: string; desc: string; required?: boolean; danger?: boolean; defaultOn: boolean }
const WP_MODULES: WPModule[] = [
  { id: 'wp_detect', label: 'Detection gate', required: true, defaultOn: true,
    desc: 'Deep multi-signal verification (REST wp/v2, wp-login form, generator, author redirect). Only hosts confirmed here enter the WordPress pipeline.' },
  { id: 'wp_enum', label: 'Core · plugins · themes', defaultOn: true,
    desc: 'Core version + plugins (asset refs + readme.txt) + themes (style.css) — every item confirmed, not guessed.' },
  { id: 'wp_users', label: 'User enumeration', defaultOn: true,
    desc: 'Usernames WordPress itself returns via the REST users route, author-archive redirect and oembed.' },
  { id: 'wp_config', label: 'wp-config & sensitive files', defaultOn: true,
    desc: 'wp-config backups/swaps and debug.log — reported only when the body carries the real config source / error log.' },
  { id: 'wp_backups', label: 'Public / plugin backups', defaultOn: true,
    desc: 'UpdraftPlus / All-in-One / Duplicator / BackupBuddy … archives and installers — magic-byte confirmed, severity critical.' },
  { id: 'wp_endpoints', label: 'Login · XML-RPC · REST', defaultOn: true,
    desc: 'Login panel + XML-RPC capabilities (system.multicall amplification, pingback SSRF) read from the server itself.' },
  { id: 'wp_misconfig', label: 'Misconfiguration audit', defaultOn: true,
    desc: 'Reinstallable site (install.php/setup-config wizard), open registration, WP_DEBUG display — each content-confirmed.' },
  { id: 'wp_vulns', label: 'Known vulnerabilities (nuclei)', defaultOn: true,
    desc: 'WordPress-tagged nuclei corpus (embedded FP-safe pack + official templates) against confirmed hosts only.' },
  { id: 'wp_credaudit', label: 'Weak-credential audit (brute force)', danger: true, defaultOn: false,
    desc: 'OPT-IN. Sprays the top-1000 WordPress passwords against the ENUMERATED usernames, rate-limited and confirmed only by a definitive XML-RPC login success (no lockout). Ticking it authorizes active credential testing for this scan — use only against targets you are authorized to test.' },
]

const defaultSelection = () => new Set(WP_MODULES.filter(m => m.defaultOn).map(m => m.id))

const isWPProject = (t: Target) => (t.tags || []).includes(WP_TAG)

const scanBadge = (status?: string): { text: string; variant: string } => {
  switch ((status || 'idle').toLowerCase()) {
    case 'running': case 'scanning': return { text: 'scanning', variant: 'info' }
    case 'queued': case 'pending': return { text: 'queued', variant: 'warning' }
    case 'completed': case 'done': return { text: 'done', variant: 'success' }
    case 'failed': case 'error': return { text: 'failed', variant: 'critical' }
    default: return { text: status || 'idle', variant: 'neutral' }
  }
}

export default function WPScanner() {
  const navigate = useNavigate()
  const { addToast } = useUIStore()
  const [projects, setProjects] = useState<Target[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [domainsText, setDomainsText] = useState('')
  const [selected, setSelected] = useState<Set<string>>(defaultSelection())
  const [launching, setLaunching] = useState(false)
  const [sites, setSites] = useState<Record<string, Awaited<ReturnType<typeof targetsApi.wpSites>> | 'loading'>>({})

  const domains = useMemo(
    () => domainsText.split(/[\s,;]+/).map(d => d.trim()).filter(Boolean),
    [domainsText],
  )

  const load = () => targetsApi.list()
    .then(all => setProjects(all.filter(isWPProject)))
    .catch(() => {})
    .finally(() => setLoading(false))

  useEffect(() => {
    load()
    const i = setInterval(load, 10000)
    return () => clearInterval(i)
  }, [])

  const toggle = (id: string) => {
    const m = WP_MODULES.find(x => x.id === id)
    if (m?.required) return
    setSelected(prev => {
      const n = new Set(prev)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
  }

  const selectedModules = () => {
    // wp_detect always first (the gate), then the chosen modules in catalog order.
    const picked = WP_MODULES.filter(m => m.id === 'wp_detect' || selected.has(m.id)).map(m => m.id)
    // The weak-credential audit is dual-use: ticking it sends the per-scan
    // authorization token so the backend will actually submit passwords.
    if (selected.has('wp_credaudit')) picked.push('wp_cred_authorized')
    return Array.from(new Set(picked))
  }

  // Confirm active credential testing before launching when it is selected.
  const confirmCredAudit = () => {
    if (!selected.has('wp_credaudit')) return true
    return window.confirm(
      'Weak-credential audit is selected. This actively sprays the top-1000 WordPress passwords ' +
      'against enumerated usernames. Only proceed if you are explicitly authorized to test these targets.\n\nStart the audit?')
  }

  const createProject = async () => {
    if (domains.length === 0) {
      addToast('error', 'Enter at least one domain.')
      return
    }
    if (!confirmCredAudit()) return
    setLaunching(true)
    try {
      const mods = selectedModules()
      const t = await targetsApi.create({
        domain: domains.join('\n'),
        name: name.trim() || domains[0],
        tags: [WP_TAG],
        description: 'WordPress project',
      })
      await targetsApi.startScan(t.id, mods)
      addToast('success', `WordPress scan started for ${domains.length} domain(s). The detection gate runs first; only verified WordPress hosts continue.`)
      setName(''); setDomainsText(''); setSelected(defaultSelection())
      load()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to create WordPress project')
    } finally {
      setLaunching(false)
    }
  }

  const rescan = async (t: Target) => {
    try {
      await targetsApi.startScan(t.id, selectedModules())
      addToast('success', `Re-scan started for ${t.name || t.domain}`)
      load()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to start re-scan')
    }
  }

  const toggleSites = async (t: Target) => {
    if (sites[t.id]) {
      setSites(s => { const n = { ...s }; delete n[t.id]; return n })
      return
    }
    setSites(s => ({ ...s, [t.id]: 'loading' }))
    try {
      const rows = await targetsApi.wpSites(t.id)
      setSites(s => ({ ...s, [t.id]: rows }))
    } catch {
      setSites(s => ({ ...s, [t.id]: [] }))
    }
  }

  const credOn = selected.has('wp_credaudit')

  return (
    <div className="mx-auto max-w-6xl px-4 py-6 space-y-6">
      <header className="flex items-center gap-3">
        <div className="grid place-items-center w-10 h-10 rounded-xl text-white font-bold" style={{ backgroundImage: 'var(--grad-accent)' }}>W</div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">WP Scanner</h1>
          <p className="text-xs text-text-muted">Dedicated WordPress pipeline — verify first, then run only the modules you pick. Zero false positives.</p>
        </div>
      </header>

      {/* New project */}
      <section className="rounded-2xl border border-white/[.07] bg-white/[.02] p-5 space-y-4">
        <h2 className="text-sm font-semibold text-text-primary">New WordPress project</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1">Project name <span className="font-normal normal-case text-text-muted/70">(optional)</span></label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Acme blogs"
              className="w-full bg-surface-alt border border-border rounded-lg px-3 py-2 text-sm" />
          </div>
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1">Domains <span className="font-normal normal-case text-text-muted/70">(one or many — space, comma or newline separated)</span></label>
            <textarea value={domainsText} onChange={e => setDomainsText(e.target.value)} rows={3}
              placeholder={'blog.example.com\nshop.example.com\nexample.org'}
              className="w-full bg-surface-alt border border-border rounded-lg px-3 py-2 text-sm font-mono resize-y" />
            <p className="mt-1 text-[10px] text-text-muted">{domains.length} domain(s). The detection gate crawls each and only the ones confirmed WordPress enter the pipeline.</p>
          </div>
        </div>

        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">Modules</p>
          <div className="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
            {WP_MODULES.map(m => {
              const on = m.required || selected.has(m.id)
              return (
                <button key={m.id} type="button" onClick={() => toggle(m.id)} title={m.desc} disabled={m.required}
                  className={cn('flex items-start gap-2.5 rounded-xl border p-3 text-left transition-all',
                    on
                      ? m.danger ? 'border-severity-high/50 bg-severity-high/[.08]' : 'border-accent/40 bg-accent/[.1]'
                      : 'border-white/[.07] bg-white/[.02] hover:border-white/20',
                    m.required && 'cursor-default')}>
                  <span className={cn('mt-0.5 w-4 h-4 rounded grid place-items-center text-[9px] shrink-0',
                    on ? (m.danger ? 'bg-severity-high text-white' : 'bg-accent text-white') : 'border border-white/20')}>
                    {on ? '✓' : ''}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-xs font-semibold text-text-primary">
                      {m.label}
                      {m.required && <span className="ml-1 text-[9px] uppercase text-accent-hover">gate</span>}
                      {m.danger && <span className="ml-1 text-[9px] uppercase text-severity-high">opt-in</span>}
                    </span>
                    <span className="block mt-0.5 text-[10px] leading-4 text-text-muted">{m.desc}</span>
                  </span>
                </button>
              )
            })}
          </div>
          {credOn && (
            <div className="mt-2 rounded-lg border border-severity-high/40 bg-severity-high/[.07] p-3 text-[11px] leading-5 text-text-secondary">
              <b className="text-severity-high">Brute force selected.</b> On launch you'll confirm authorization, then Reconner sprays the
              top-1000 WordPress passwords against the enumerated usernames (rate-limited, XML-RPC-confirmed, stops on first hit per user).
              Use exclusively against targets you are explicitly authorized to test.
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3">
          <span className="text-[11px] text-text-muted">{selectedModules().length} module(s) · {domains.length} domain(s)</span>
          <Button variant="primary" loading={launching} disabled={domains.length === 0} onClick={createProject}>
            ▶ Verify &amp; Scan
          </Button>
        </div>
      </section>

      {/* Projects */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-text-primary">WordPress projects</h2>
        {loading ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : projects.length === 0 ? (
          <EmptyState icon={<Icons.wordpress className="w-6 h-6" />} title="No WordPress projects yet" description="Create one above — enter one or several domains and pick the modules to run." />
        ) : (
          <div className="space-y-2">
            {projects.map(t => {
              const b = scanBadge(t.scan_status)
              const site = sites[t.id]
              return (
                <div key={t.id} className="rounded-xl border border-white/[.07] bg-white/[.02] p-4">
                  <div className="flex items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-text-primary truncate">{t.name || t.domain}</span>
                        <Badge variant={b.variant}>{b.text}</Badge>
                        {t.finding_count > 0 && <Badge variant="critical">{t.finding_count} findings</Badge>}
                      </div>
                      <div className="mt-0.5 text-[11px] text-text-muted font-mono truncate">{t.domain.split(/\s+/).join(' · ')}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={() => toggleSites(t)} className="px-2.5 py-1.5 rounded-lg text-xs border border-white/[.08] text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors">
                        {site ? 'Hide hosts' : 'WordPress hosts'}
                      </button>
                      <button onClick={() => rescan(t)} className="px-2.5 py-1.5 rounded-lg text-xs border border-white/[.08] text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors">Re-scan</button>
                      <Button variant="ghost" onClick={() => navigate(`/targets/${t.id}`)}>Open</Button>
                    </div>
                  </div>

                  {site && (
                    <div className="mt-3 rounded-lg border border-white/[.06] bg-black/20 p-3">
                      {site === 'loading' ? (
                        <div className="flex items-center gap-2 text-xs text-text-muted"><Spinner className="w-4 h-4" /> Loading detection results…</div>
                      ) : site.length === 0 ? (
                        <p className="text-[11px] text-text-muted">No detection results yet — the detection gate runs at the start of the scan.</p>
                      ) : (
                        <div className="space-y-1.5">
                          {site.map(s => (
                            <div key={s.url} className="flex items-center gap-2 text-[11px]">
                              <span className={cn('w-2 h-2 rounded-full shrink-0', s.is_wordpress ? 'bg-severity-low' : 'bg-text-muted/40')} />
                              <span className="font-mono text-text-secondary truncate">{s.url}</span>
                              {s.is_wordpress
                                ? <Badge variant="success">WordPress{s.version ? ` ${s.version}` : ''}</Badge>
                                : <Badge variant="neutral">not WordPress</Badge>}
                              {s.is_wordpress && s.signals && <span className="text-[10px] text-text-muted truncate">[{s.signals}]</span>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}
