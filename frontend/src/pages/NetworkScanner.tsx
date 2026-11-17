import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { targets as targetsApi } from '../lib/api'
import { useUIStore } from '../store/ui'
import { Button, Spinner, Badge, EmptyState, cn } from '../components/ui'
import { Icons } from '../components/layout/Sidebar'
import type { Target, NetworkService } from '../types'

// The Network Scanner is a dedicated surface for IP/CIDR/range (or domain)
// targets, mirroring the WP Scanner: port/service discovery is heavy enough
// (naabu + nmap fingerprinting, per-service nuclei, per-protocol credential
// audits) to warrant its own project list and module picker, separate from the
// web scanner. A domain entry is resolved to its address(es) at scan time
// (scanner.ExpandNetworkScope) — the operator's asset is very often a domain,
// not its IP — and every resolved/pasted address still goes through the normal
// CDN/WAF exclusion before anything is probed, so scanning never lands on a
// third-party edge instead of the real origin.
const NET_TAG = 'network-scanner'

type NetModule = { id: string; label: string; desc: string; required?: boolean; danger?: boolean; defaultOn: boolean }
const NET_MODULES: NetModule[] = [
  { id: 'network', label: 'Port, service & OS discovery', required: true, defaultOn: true,
    desc: 'TCP discovery (naabu, falling back to a bounded native connect scan) over a curated important-ports set, then nmap -sV fingerprinting + opportunistic OS detection on every open port. Always verifies — never reports a bare open port as a service.' },
  { id: 'network_nuclei_only', label: 'Service-aware nuclei', defaultOn: true,
    desc: 'Runs the official + embedded nuclei corpus with tags chosen from what was ACTUALLY detected (ssh/ftp/mysql/redis/rdp/smb/…), not a fixed generic tag — so protocol-specific templates actually get exercised.' },
  { id: 'network_initial_access', label: '401/403 verification', defaultOn: true,
    desc: 'The same proof-gated authorization-bypass checks the web scanner uses, against discovered network web services.' },
  { id: 'network_brute', label: 'HTTP Basic credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. Top-1000 passwords against verified HTTP Basic-auth challenges. Rate-limited, stops on lockout.' },
  { id: 'network_brute_ssh', label: 'SSH credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. Top-1000 passwords against verified SSH services, confirmed only by a completed password handshake.' },
  { id: 'network_brute_ftp', label: 'FTP credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. Top-1000 passwords against verified FTP services, confirmed only by the server’s own 230 reply.' },
  { id: 'network_brute_mysql', label: 'MySQL credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. Top-1000 passwords against verified MySQL services, confirmed only by a successful connection.' },
  { id: 'network_brute_postgres', label: 'PostgreSQL credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. Top-1000 passwords against verified PostgreSQL services, confirmed only by a successful (or post-auth) connection.' },
  { id: 'network_brute_redis', label: 'Redis credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. Top-1000 passwords against verified Redis services, confirmed only by the server’s own +OK reply.' },
  { id: 'network_brute_rdp', label: 'RDP credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. ncrack-backed, bounded password subset, against verified RDP services — confirmed only by ncrack’s own discovered-credential report.' },
  { id: 'network_brute_vnc', label: 'VNC credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. ncrack-backed against verified VNC services — confirmed only by ncrack’s own discovered-credential report.' },
  { id: 'network_brute_telnet', label: 'Telnet credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. ncrack-backed against verified Telnet services — confirmed only by ncrack’s own discovered-credential report.' },
  { id: 'network_brute_smb', label: 'SMB credential audit', danger: true, defaultOn: false,
    desc: 'OPT-IN. hydra-backed against verified SMB services — confirmed only by hydra’s own discovered-credential report.' },
]

const PROFILES: { id: 'fast' | 'normal' | 'deep'; label: string; desc: string }[] = [
  { id: 'fast', label: 'Fast', desc: 'Curated important-ports set — quickest, still high-signal.' },
  { id: 'normal', label: 'Normal', desc: 'Top 1000 ports + nmap verification.' },
  { id: 'deep', label: 'Deep', desc: 'All 65535 TCP ports + nmap verification. Slowest.' },
]

const defaultSelection = () => new Set(NET_MODULES.filter(m => m.defaultOn).map(m => m.id))

const isNetProject = (t: Target) => (t.tags || []).includes(NET_TAG)

const scanBadge = (status?: string): { text: string; variant: string } => {
  switch ((status || 'idle').toLowerCase()) {
    case 'running': case 'scanning': return { text: 'scanning', variant: 'info' }
    case 'queued': case 'pending': return { text: 'queued', variant: 'warning' }
    case 'completed': case 'done': return { text: 'done', variant: 'success' }
    case 'failed': case 'error': return { text: 'failed', variant: 'critical' }
    default: return { text: status || 'idle', variant: 'neutral' }
  }
}

export default function NetworkScanner() {
  const navigate = useNavigate()
  const { addToast } = useUIStore()
  const [projects, setProjects] = useState<Target[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [scopeText, setScopeText] = useState('')
  const [selected, setSelected] = useState<Set<string>>(defaultSelection())
  const [profile, setProfile] = useState<'fast' | 'normal' | 'deep'>('fast')
  const [launching, setLaunching] = useState(false)
  const [services, setServices] = useState<Record<string, NetworkService[] | 'loading'>>({})

  const scopeTokens = useMemo(
    () => scopeText.split(/[\s,;]+/).map(d => d.trim()).filter(Boolean),
    [scopeText],
  )

  const load = () => targetsApi.list()
    .then(all => setProjects(all.filter(isNetProject)))
    .catch(() => {})
    .finally(() => setLoading(false))

  useEffect(() => {
    load()
    const i = setInterval(load, 10000)
    return () => clearInterval(i)
  }, [])

  const toggle = (id: string) => {
    const m = NET_MODULES.find(x => x.id === id)
    if (m?.required) return
    setSelected(prev => {
      const n = new Set(prev)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
  }

  const bruteSelected = NET_MODULES.filter(m => m.danger && selected.has(m.id))

  const selectedModules = () => {
    // "network" always first (the discovery gate), then the chosen modules in
    // catalog order.
    const picked = NET_MODULES.filter(m => m.id === 'network' || selected.has(m.id)).map(m => m.id)
    // Any per-protocol brute tick sends the shared per-scan authorization token
    // so the backend will actually submit passwords for THOSE protocols only.
    if (bruteSelected.length > 0) picked.push('net_cred_authorized')
    picked.push(`network_${profile}`)
    return Array.from(new Set(picked))
  }

  // Confirm active credential testing before launching when any is selected.
  const confirmCredAudit = () => {
    if (bruteSelected.length === 0) return true
    const names = bruteSelected.map(m => m.label).join(', ')
    return window.confirm(
      `The following credential audits are selected: ${names}.\n\n` +
      'Each actively sprays the top-1000 passwords against its own verified service(s). ' +
      'Only proceed if you are explicitly authorized to test these targets.\n\nStart the audit?')
  }

  const createProject = async () => {
    if (scopeTokens.length === 0) {
      addToast('error', 'Enter at least one IP, CIDR, inclusive range (e.g. 192.168.1.1-192.168.1.10), or domain.')
      return
    }
    if (!confirmCredAudit()) return
    setLaunching(true)
    try {
      const mods = selectedModules()
      const t = await targetsApi.create({
        domain: scopeTokens.join('\n'),
        name: name.trim() || scopeTokens[0],
        tags: [NET_TAG],
        description: 'Network project',
      })
      await targetsApi.startScan(t.id, mods)
      addToast('success', `Network scan started for ${scopeTokens.length} scope entr${scopeTokens.length === 1 ? 'y' : 'ies'}.`)
      setName(''); setScopeText(''); setSelected(defaultSelection())
      load()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to create network project')
    } finally {
      setLaunching(false)
    }
  }

  const rescan = async (t: Target) => {
    if (!confirmCredAudit()) return
    try {
      await targetsApi.startScan(t.id, selectedModules())
      addToast('success', `Re-scan started for ${t.name || t.domain}`)
      load()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to start re-scan')
    }
  }

  const toggleServices = async (t: Target) => {
    if (services[t.id]) {
      setServices(s => { const n = { ...s }; delete n[t.id]; return n })
      return
    }
    setServices(s => ({ ...s, [t.id]: 'loading' }))
    try {
      const rows = await targetsApi.networkServices(t.id)
      setServices(s => ({ ...s, [t.id]: rows }))
    } catch {
      setServices(s => ({ ...s, [t.id]: [] }))
    }
  }

  return (
    <div className="mx-auto max-w-6xl px-4 py-6 space-y-6">
      <header className="flex items-center gap-3">
        <div className="grid place-items-center w-10 h-10 rounded-xl text-white font-bold" style={{ backgroundImage: 'var(--grad-accent)' }}>N</div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">Network Scanner</h1>
          <p className="text-xs text-text-muted">Dedicated port/service pipeline — verify every service, then run only the modules you pick. Zero false positives.</p>
        </div>
      </header>

      {/* New project */}
      <section className="rounded-2xl border border-white/[.07] bg-white/[.02] p-5 space-y-4">
        <h2 className="text-sm font-semibold text-text-primary">New network project</h2>
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1">Project name <span className="font-normal normal-case text-text-muted/70">(optional)</span></label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Acme VPC"
              className="w-full bg-surface-alt border border-border rounded-lg px-3 py-2 text-sm" />
          </div>
          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1">Scope <span className="font-normal normal-case text-text-muted/70">(one or many — IP, CIDR, inclusive range, or domain)</span></label>
            <textarea value={scopeText} onChange={e => setScopeText(e.target.value)} rows={3}
              placeholder={'203.0.113.10\n10.0.0.0/24\n192.168.1.1-192.168.1.50\nexample.com'}
              className="w-full bg-surface-alt border border-border rounded-lg px-3 py-2 text-sm font-mono resize-y" />
            <p className="mt-1 text-[10px] text-text-muted">{scopeTokens.length} scope entr{scopeTokens.length === 1 ? 'y' : 'ies'}. A domain is resolved to its IP at scan time. Recognised CDN/WAF edge addresses are excluded before probing.</p>
          </div>
        </div>

        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">Port-scan profile</p>
          <div className="grid grid-cols-3 gap-1.5">
            {PROFILES.map(p => (
              <button key={p.id} type="button" onClick={() => setProfile(p.id)}
                className={cn('rounded-lg border px-3 py-2 text-left', profile === p.id ? 'border-accent bg-accent-muted text-accent' : 'border-border text-text-secondary')}>
                <span className="block text-xs font-semibold">{p.label}</span>
                <span className="block text-[10px] text-text-muted">{p.desc}</span>
              </button>
            ))}
          </div>
        </div>

        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">Modules</p>
          <div className="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
            {NET_MODULES.map(m => {
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
          {bruteSelected.length > 0 && (
            <div className="mt-2 rounded-lg border border-severity-high/40 bg-severity-high/[.07] p-3 text-[11px] leading-5 text-text-secondary">
              <b className="text-severity-high">Credential audit selected ({bruteSelected.length}).</b> On launch you'll confirm authorization, then Reconner sprays the
              top-1000 passwords against each protocol's verified service(s) only (rate-limited, stops on first hit per target, confirmed only by a definitive protocol-level signal — never a guess).
              Use exclusively against targets you are explicitly authorized to test. SSH/FTP/MySQL/PostgreSQL/Redis are proven natively; RDP/VNC/Telnet are ncrack-backed and SMB is hydra-backed — all five share the same bounded, stop-on-first-hit discipline.
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3">
          <span className="text-[11px] text-text-muted">{selectedModules().length} module(s) · {scopeTokens.length} scope entr{scopeTokens.length === 1 ? 'y' : 'ies'}</span>
          <Button variant="primary" loading={launching} disabled={scopeTokens.length === 0} onClick={createProject}>
            ▶ Discover &amp; Scan
          </Button>
        </div>
      </section>

      {/* Projects */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-text-primary">Network projects</h2>
        {loading ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : projects.length === 0 ? (
          <EmptyState icon={<Icons.network className="w-6 h-6" />} title="No network projects yet" description="Create one above — enter one or several IP/CIDR/range scopes and pick the modules to run." />
        ) : (
          <div className="space-y-2">
            {projects.map(t => {
              const b = scanBadge(t.scan_status)
              const svc = services[t.id]
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
                      <button onClick={() => toggleServices(t)} className="px-2.5 py-1.5 rounded-lg text-xs border border-white/[.08] text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors">
                        {svc ? 'Hide services' : 'Services'}
                      </button>
                      <button onClick={() => rescan(t)} className="px-2.5 py-1.5 rounded-lg text-xs border border-white/[.08] text-text-secondary hover:text-text-primary hover:border-border-strong transition-colors">Re-scan</button>
                      <Button variant="ghost" onClick={() => navigate(`/targets/${t.id}`)}>Open</Button>
                    </div>
                  </div>

                  {svc && (
                    <div className="mt-3 rounded-lg border border-white/[.06] bg-black/20 p-3">
                      {svc === 'loading' ? (
                        <div className="flex items-center gap-2 text-xs text-text-muted"><Spinner className="w-4 h-4" /> Loading discovered services…</div>
                      ) : svc.length === 0 ? (
                        <p className="text-[11px] text-text-muted">No verified services yet — the discovery module runs at the start of the scan.</p>
                      ) : (
                        <div className="space-y-1.5">
                          {svc.map(s => (
                            <div key={`${s.ip}:${s.port}`} className="flex items-center gap-2 text-[11px]">
                              <span className="w-2 h-2 rounded-full shrink-0 bg-severity-low" />
                              <span className="font-mono text-text-secondary truncate">{s.ip}:{s.port}</span>
                              <Badge variant="neutral">{s.service || 'unknown'}</Badge>
                              {s.tls && <Badge variant="info">TLS</Badge>}
                              {(s.product || s.version) && <span className="text-[10px] text-text-muted truncate">{[s.product, s.version].filter(Boolean).join(' ')}</span>}
                              {s.is_web && s.web_title && <span className="text-[10px] text-text-muted truncate">· {s.web_title}</span>}
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
