import { useEffect, useState } from 'react'
import { Modal, Button } from '../ui'
import { ModuleIcon } from '../ui/ModuleIcon'
import { targets as targetsApi } from '../../lib/api'
import { useUIStore } from '../../store/ui'
import { cn } from '../../lib/utils'
import type { Target } from '../../types'

// Scan profiles (Acunetix/Burp-style) — one click presets the module selection.
// Quick = fast high-signal; Standard = balanced full audit; Deep = everything
// (adds race/smuggling/xxe/ato + full recon); Custom = leave the operator's picks.
const PROFILE_MODULES: Record<string, string[] | 'all'> = {
  quick: ['http_probe', 'js_analysis', 'param_discovery', 'param_reflection', 'open_redirect', 'xss', 'dast', 'sqli', 'nuclei', 'exposure', 'verify'],
  standard: ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery', 'param_reflection', 'paramfuzz', 'dir_discovery', 'backup_discovery', 'open_redirect', 'nuclei', 'xss', 'dast', 'vuln_scan', 'sqli', 'nosqli', 'ssrf', 'idor', 'jwt', 'lfi', 'ssti', 'cmdi', 'xxe', 'oast', 'cache_poison', 'passive', 'takeover', 'exposure', 'intel', 'verify', 'monitor'],
  deep: 'all',
}
const SCAN_PROFILES: { id: string; label: string; sub: string }[] = [
  { id: 'quick', label: 'Quick', sub: 'Fast, high-signal' },
  { id: 'standard', label: 'Standard', sub: 'Balanced audit' },
  { id: 'deep', label: 'Deep', sub: 'Exhaustive' },
  { id: 'custom', label: 'Custom', sub: 'Your picks' },
]

type ModDef = { id: string; label: string; desc: string; default: boolean; group: string }
const MODULES: ModDef[] = [
  { id: 'subdomain_enum',   label: 'Subdomain Enum',      desc: 'Passive + active subdomain discovery — OFF by default; the scan stays on the target host(s) you gave unless you turn this on', default: false, group: 'Recon' },
  { id: 'http_probe',       label: 'HTTP Probe',           desc: 'Probe alive hosts & fingerprint services',      default: true,  group: 'Recon' },
  { id: 'js_analysis',      label: 'JS Analysis',          desc: 'Extract secrets, endpoints, API keys from JS', default: true,  group: 'Recon' },
  { id: 'js_endpoints',     label: 'JS Endpoint Probing',  desc: 'Resolve & scan endpoints found inside JS',     default: true,  group: 'Recon' },
  { id: 'param_discovery',  label: 'Param Discovery',      desc: 'Find URL parameters via crawl & Wayback',      default: true,  group: 'Recon' },
  { id: 'headless_crawl',   label: 'Headless Crawl (SPA)', desc: 'Render pages in a real browser to harvest DOM-injected links, forms & params a raw crawler misses (heavy) — feeds the XSS engine the real rendered surface', default: false, group: 'Recon' },
  { id: 'timemachine',      label: 'TimeMachine (Wayback)',desc: 'Mine archived URLs & bucket params by vuln-class', default: true, group: 'Recon' },
  { id: 'param_reflection', label: 'Reflected Params',     desc: 'Active probe for reflected parameters',         default: true,  group: 'Recon' },
  { id: 'paramfuzz',        label: 'Hidden Param Mining',  desc: 'Discover undocumented params (Arjun-style)',    default: true,  group: 'Recon' },
  { id: 'dir_discovery',    label: 'Directory Scan',       desc: 'Discover hidden paths & admin panels',         default: false, group: 'Recon' },
  { id: 'backup_discovery', label: 'Backup Files',         desc: 'Find backups, configs, .env, .git leaks',      default: false, group: 'Recon' },
  { id: 'open_redirect',    label: 'Open Redirects',       desc: 'Active check for open redirect parameters',    default: true,  group: 'Injection' },
  { id: 'nuclei',           label: 'Nuclei Scan',          desc: 'Nuclei vulnerability templates scan',          default: false, group: 'Injection' },
  { id: 'xss',              label: 'XSS',                  desc: 'Deep context-aware reflected XSS — HTML/attribute (single+double quote)/JS/CSS/URL sinks, multi-reflection, breakout-confirmed', default: true, group: 'Injection' },
  { id: 'dast',             label: 'DAST (XSS+SQLi combo)',desc: 'Combined engine: context-aware XSS differential + error-based SQLi candidate over GET/POST/JSON (redundant when XSS + SQL Injection are on)', default: false, group: 'Injection' },
  { id: 'vuln_scan',        label: 'Vuln Scan',            desc: 'Reflected/stored/blind XSS, CORS, 403 bypass, CRLF', default: true, group: 'Injection' },
  { id: 'sqli',             label: 'SQL Injection',        desc: 'Error / boolean / content-differential + out-of-band, on params & headers',  default: true,  group: 'Injection' },
  { id: 'nosqli',           label: 'NoSQL Injection',      desc: 'MongoDB operator injection ($ne/$eq) + error-based', default: true, group: 'Injection' },
  { id: 'ssrf',             label: 'SSRF',                 desc: 'Cloud metadata / internal via URL params',     default: true,  group: 'Injection' },
  { id: 'idor',             label: 'IDOR / Access Control',desc: 'Enumerable object IDs & missing authorization', default: true,  group: 'Injection' },
  { id: 'jwt',              label: 'JWT / OAuth',          desc: 'alg=none, weak HMAC secret, sensitive claims, OAuth flow', default: true, group: 'Injection' },
  { id: 'race',             label: 'Race Conditions',      desc: 'Parallel-burst TOCTOU / limit-overrun testing', default: false, group: 'Injection' },
  { id: 'smuggling',        label: 'Request Smuggling',    desc: 'Time-based CL.TE / TE.CL desync detection',     default: false, group: 'Injection' },
  { id: 'cache_poison',     label: 'Web Cache Poisoning',  desc: 'Unkeyed-header poisoning of cached responses',  default: true,  group: 'Injection' },
  { id: 'oast',             label: 'Blind SSRF/RCE (OAST)',desc: 'Out-of-band callbacks prove blind SSRF & RCE', default: true,  group: 'Injection' },
  { id: 'lfi',              label: 'LFI / Path Traversal', desc: 'etc/passwd, win.ini, php filter wrappers',     default: true,  group: 'Injection' },
  { id: 'ssti',             label: 'SSTI (Template Inj.)', desc: '{{7*7}} across Jinja/Twig/Freemarker/ERB',     default: true,  group: 'Injection' },
  { id: 'xxe',              label: 'XXE Injection',        desc: 'In-band file read + OAST blind XML entity',    default: true,  group: 'Injection' },
  { id: 'cmdi',             label: 'Command Injection',    desc: 'Reflection-proof echo marker + out-of-band OS command injection (RCE)', default: true, group: 'Injection' },
  { id: 'passive',          label: 'Passive Scan',         desc: 'Headers, cookies, stack traces, leaked secrets', default: true, group: 'Analysis' },
  { id: 'takeover',         label: 'Subdomain Takeover',   desc: 'Detect dangling CNAMEs on unclaimed services — needs subdomain discovery, so turning it on will also enumerate subdomains', default: false,  group: 'Analysis' },
  { id: 'ato',              label: 'Account Takeover Chains', desc: 'Correlates XSS+cookie, open-redirect on auth flows, OAuth+redirect, tokens in URL', default: true, group: 'Analysis' },
  { id: 'origin_ip',        label: 'Origin IP (CDN bypass)',desc: 'Find real IP behind CDN/WAF via DNS history (needs SecurityTrails key)', default: true, group: 'Analysis' },
  { id: 'shodan',           label: 'Shodan Intel',         desc: 'Passive open-port/banner intel via Shodan (needs API key)', default: false, group: 'Analysis' },
  { id: 'exposure',         label: 'Exposure Checks',      desc: 'GraphQL introspection, API specs, open buckets', default: true, group: 'Analysis' },
  { id: 'intel',            label: 'Tech Intelligence',    desc: 'Spring/Laravel/Next/WP/Django specific attacks', default: true, group: 'Analysis' },
  { id: 'verify',           label: 'Verification Engine',  desc: 'Re-confirm findings + confidence/priority score', default: true, group: 'Analysis' },
  { id: 'monitor',          label: 'Change Monitor',       desc: 'Detect changes in HTTP services & JS files',   default: false, group: 'Analysis' },
]
const GROUPS = ['Recon', 'Injection', 'Analysis']

type AssetLite = { id: string; value: string; kind: string; name: string }
interface Props { target: Target; asset?: AssetLite; open: boolean; onClose: () => void; onStarted?: () => void }

export const ScanModal = ({ target, asset, open, onClose, onStarted }: Props) => {
  const [selected, setSelected] = useState<Set<string>>(
    new Set(MODULES.filter(m => m.default).map(m => m.id))
  )
  const [activeProfile, setActiveProfile] = useState('custom')
  const applyProfile = (p: string) => {
    setActiveProfile(p)
    if (p === 'custom') return
    const ids = PROFILE_MODULES[p]
    setSelected(ids === 'all'
      ? new Set(MODULES.map(m => m.id))
      : new Set(ids.filter(id => MODULES.some(m => m.id === id))))
  }
  const [loading, setLoading] = useState(false)
  const { addToast } = useUIStore()
  // When scanning a single asset, the asset's own kind drives the menu; else the

  // A network target's "domain" is its entire scope — up to 65k IPs. Putting it
  // raw into the modal title or a toast blew both out across the screen. Use the
  // friendly name, else a host-count summary, else a short truncation.
  const hostCount = target.domain.split(/[\s,;]+/).filter(Boolean).length
  const label = asset
    ? (asset.name?.trim() || (asset.value.length > 40 ? asset.value.slice(0, 40) + '…' : asset.value))
    : (target.name?.trim()
      || (hostCount > 1 ? `${hostCount} hosts` : (target.domain.length > 40 ? target.domain.slice(0, 40) + '…' : target.domain)))

  // Start a scan against the whole target, or against just this asset when the
  // modal was opened for one.
  const startModules = (mods: string[]) =>
    asset ? targetsApi.scanAsset(target.id, asset.id, mods) : targetsApi.startScan(target.id, mods)

  // Web scan speed/stealth profile — bug-bounty focused: slow keeps the request
  // rate under a target's WAF to avoid bans, fast maximizes throughput.
  const [webSpeed, setWebSpeed] = useState<'slow' | 'normal' | 'fast'>('normal')
  // Slow permutation/brute-force phase of subdomain enum — on by default, but
  // toggleable per scan because it is the longest part of enumeration.
  const [subBrute, setSubBrute] = useState(true)
  // Single-endpoint mode: when the scope is a full URL (has a path and/or query),
  // offer to confine the WHOLE scan to that exact endpoint and the paths under it —
  // param discovery, crawl, JS, and every vuln module (XSS/SQLi/…) run against the
  // given URL (its query AND path params) instead of the whole host.
  const scopeIsURL = /^https?:\/\/[^\s,;]+(\/[^\s,;]*|\?[^\s,;]*)/i.test(target.domain.trim())
    || /^[^\s,;/]+\.[^\s,;/]+\/[^\s,;]/.test(target.domain.trim())
  const [singleEndpoint, setSingleEndpoint] = useState(true)
  // Pre-scan authentication (single-domain web scans only). When subdomain
  // enumeration is NOT selected, the scan targets just this host, so we offer to
  // attach a logged-in session up front. With subdomain enum on, the scan spans
  // many hosts a single cookie wouldn't fit, so this is hidden.
  const [authCookie, setAuthCookie] = useState('')
  const [authBearer, setAuthBearer] = useState('')

  // IDOR/BOLA is only provable with TWO identities (a victim who owns an object
  // and an attacker who tries to read it). When the IDOR module is selected we
  // REQUIRE two sessions — either already configured on the target, or pasted
  // here and created on the fly before the scan starts.
  const [idCount, setIdCount] = useState(0)
  const [idorA, setIdorA] = useState('')
  const [idorB, setIdorB] = useState('')
  useEffect(() => {
    if (!open) return
    setIdorA(''); setIdorB('')
    targetsApi.identities(target.id).then(r => setIdCount(r.length)).catch(() => setIdCount(0))
  }, [open, target.id])
  const idorSelected = selected.has('idor')
  const idorReady = !idorSelected || idCount >= 2 || (idorA.trim() !== '' && idorB.trim() !== '')

  // Every toggle used to persist silently across modal opens (same component
  // instance, `open` only controls visibility) — start each fresh "start
  // scan" attempt from a clean slate instead of whatever was left checked
  // last time (this is what made "nuclei only" silently stick from a
  // previous scan and turn a plain range scan into a no-op).


  const toggle = (id: string) => { setActiveProfile('custom'); return setSelectedToggle(id) }
  const setSelectedToggle = (id: string) => setSelected(p => {
    const n = new Set(p)
    n.has(id) ? n.delete(id) : n.add(id)
    return n
  })

  const selectAll = () => setSelected(new Set(MODULES.map(m => m.id)))
  const selectNone = () => setSelected(new Set())

  // parseCred turns a pasted string into a request-header map. It honours an
  // EXPLICIT "Header-Name: value" — so custom auth headers (auth_token, X-Api-Key,
  // X-Auth-Token, api-key …) work verbatim, not just Cookie/Authorization. Only
  // when no header name is given does it guess: a "Bearer …" or a bare JWT becomes
  // Authorization: Bearer …, and anything else is treated as a Cookie value.
  const parseCred = (s: string): Record<string, string> => {
    s = s.trim()
    if (!s) return {}
    const m = s.match(/^([A-Za-z0-9][A-Za-z0-9_-]*)\s*:\s*([\s\S]+)$/)
    if (m && !/^https?$/i.test(m[1])) {
      const lc = m[1].toLowerCase()
      const name = lc === 'cookie' ? 'Cookie' : lc === 'authorization' ? 'Authorization' : m[1]
      return { [name]: m[2].trim() }
    }
    if (/^bearer\s+/i.test(s)) return { Authorization: s }
    if (/^[\w-]+\.[\w-]+\.[\w-]+$/.test(s)) return { Authorization: `Bearer ${s}` }
    return { Cookie: s }
  }

  const handleStart = async () => {
    if (selected.size === 0) return
    // Enforce the two-identity requirement for IDOR/BOLA BEFORE starting.
    if (idorSelected && idCount < 2 && (!idorA.trim() || !idorB.trim())) {
      addToast('error', 'IDOR/BOLA needs two identities. Paste User A (owner) and User B (attacker) session tokens or cookies below.')
      return
    }
    setLoading(true)
    try {
      // Create the two identities on the fly so the scan has a victim + attacker.
      if (idorSelected && idCount < 2 && idorA.trim() && idorB.trim()) {
        await targetsApi.addIdentity(target.id, { label: 'User A (owner)', role: 'owner', headers: parseCred(idorA), is_baseline: true })
        await targetsApi.addIdentity(target.id, { label: 'User B (attacker)', role: 'attacker', headers: parseCred(idorB), is_baseline: false })
      }
      // Single-domain scan (no subdomain enum): apply the pasted session before
      // the scan starts so authenticated pages are reachable from the first probe.
      if (!selected.has('subdomain_enum') && (authCookie.trim() || authBearer.trim())) {
        const headers: Record<string, string> = {}
        if (authCookie.trim()) Object.assign(headers, parseCred(authCookie.trim()))
        // Flexible: a bare token → Bearer; or an explicit "auth_token: …" / "X-Api-Key: …" custom header.
        if (authBearer.trim()) Object.assign(headers, parseCred(authBearer.trim()))
        try { await targetsApi.setAuth(target.id, headers) } catch { /* non-fatal */ }
      }
      // Preserve module order
      const orderedModules = MODULES.filter(m => selected.has(m.id)).map(m => m.id)
      if (webSpeed === 'slow') orderedModules.push('speed_slow')
      if (webSpeed === 'fast') orderedModules.push('speed_fast')
      if (!subBrute) orderedModules.push('no_subdomain_brute')
      if (scopeIsURL && singleEndpoint) orderedModules.push('single_endpoint')
      await startModules(orderedModules)
      addToast('success', `Scan started for ${label}`)
      onClose()
      onStarted?.()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to start scan')
    } finally { setLoading(false) }
  }

  return (
    <Modal open={open} onClose={onClose} title={`Scan — ${label}`} width="xl">
      <div className="space-y-4">
        {/* Scan profile presets (Acunetix/Burp-style). */}
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1.5">Scan profile</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
            {SCAN_PROFILES.map(p => (
              <button key={p.id} type="button" onClick={() => applyProfile(p.id)}
                className={cn('flex flex-col items-start px-3 py-2 rounded-lg border text-left transition-colors',
                  activeProfile === p.id ? 'border-accent bg-accent-muted text-accent' : 'border-border text-text-secondary hover:text-text-primary hover:border-border-strong')}>
                <span className="text-xs font-semibold">{p.label}</span>
                <span className="text-[10px] text-text-muted">{p.sub}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-between">
          <p className="text-xs text-text-muted">
            <span className="text-accent-hover font-semibold">{selected.size}</span> of {MODULES.length} modules selected
          </p>
          <div className="flex gap-2 text-xs">
            <button onClick={selectAll} className="px-2 py-1 rounded-md bg-accent/10 text-accent-hover hover:bg-accent/20 transition-colors">Select all</button>
            <button onClick={selectNone} className="px-2 py-1 rounded-md bg-white/5 text-text-muted hover:text-text-secondary transition-colors">Clear</button>
          </div>
        </div>

        {/* Scan speed / stealth profile (bug-bounty focused). */}
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1.5">Scan speed</p>
          <div className="grid grid-cols-3 gap-1.5">
            {([
              { id: 'slow', icon: '🐢', label: 'Slow', sub: 'WAF-safe' },
              { id: 'normal', icon: '⚡', label: 'Normal', sub: 'Balanced' },
              { id: 'fast', icon: '🚀', label: 'Fast', sub: 'Max speed' },
            ] as const).map(o => {
              const on = webSpeed === o.id
              return (
                <button key={o.id} onClick={() => setWebSpeed(o.id)}
                  className={`px-3 py-2 rounded-lg border text-center transition-all ${
                    on ? 'bg-accent/[.12] border-accent/40 ring-1 ring-accent/20' : 'bg-white/[.02] border-white/[.06] hover:border-white/20'}`}>
                  <div className="text-sm">{o.icon} <span className="font-medium">{o.label}</span></div>
                  <div className="text-[10px] text-text-muted">{o.sub}</div>
                </button>
              )
            })}
          </div>
          <p className="text-[10px] text-text-muted mt-1">
            {webSpeed === 'slow' && 'Low-and-slow: throttled request rate to stay under a target’s WAF/rate-limits and avoid bans. Slower, stealthier.'}
            {webSpeed === 'normal' && 'Balanced defaults — the standard scan speed.'}
            {webSpeed === 'fast' && 'Maximum request rate and concurrency. Fastest, but louder — likelier to trip WAF/rate-limits.'}
          </p>
        </div>

        {/* Single-endpoint scan — shown only when the scope is a full URL. Confines
            the whole pipeline (param discovery, crawl, JS, XSS/SQLi/all vulns,
            including PATH params) to this exact URL and the paths under it. */}
        {scopeIsURL && (
          <label className="flex items-start gap-3 rounded-lg border border-accent/30 bg-accent/[.06] p-3 cursor-pointer">
            <input type="checkbox" checked={singleEndpoint} onChange={e => setSingleEndpoint(e.target.checked)}
              className="mt-0.5 h-4 w-4 accent-[var(--accent)]" />
            <span>
              <span className="text-xs font-medium text-text-primary">Single endpoint scan <span className="text-text-muted font-normal">(this URL &amp; paths under it)</span></span>
              <span className="block text-[10px] text-text-muted mt-0.5">
                You entered a full URL. Confine the entire scan to it: its query AND path parameters are seeded as
                insertion points, crawling/JS analysis start from this exact endpoint and stay under its path, and every
                vuln module (XSS, SQLi, …) tests it directly. Subdomain enumeration is skipped. Turn OFF to scan the whole host.
              </span>
            </span>
          </label>
        )}

        {/* Subdomain permutation brute-force toggle — the slowest part of enum.
            Only relevant when subdomain enumeration is selected. */}
        {selected.has('subdomain_enum') && (
          <label className="flex items-start gap-3 rounded-lg border border-white/[.08] bg-white/[.02] p-3 cursor-pointer">
            <input type="checkbox" checked={subBrute} onChange={e => setSubBrute(e.target.checked)}
              className="mt-0.5 h-4 w-4 accent-[var(--accent)]" />
            <span>
              <span className="text-xs font-medium text-text-primary">Subdomain permutation brute-force</span>
              <span className="block text-[10px] text-text-muted mt-0.5">
                Wordlist brute-force + name permutations + deep alterx/puredns pass. The longest part of
                enumeration — turn OFF for a fast passive-only map (passive sources, resolution, ASN &amp; vhost still run).
              </span>
            </span>
          </label>
        )}

        {/* Pre-scan authentication — only for single-domain scans (subdomain
            enumeration OFF). Attaches a logged-in session so the scanner reaches
            pages behind auth from the first request. */}
        {!selected.has('subdomain_enum') && (
          <div className="rounded-lg border border-white/[.08] bg-white/[.02] p-3 space-y-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Authentication scan <span className="normal-case font-normal text-text-muted">(optional — single domain)</span></p>
            <p className="text-[10px] text-text-muted">Paste a logged-in session to scan authenticated pages. Applied to every active check on this host. For a custom header use <span className="font-mono">Header-Name: value</span> (e.g. <span className="font-mono">auth_token: eyJ…</span>).</p>
            <input value={authCookie} onChange={e => setAuthCookie(e.target.value)}
              placeholder="Cookie:  session=abc123; other=..."
              className="w-full bg-surface-alt border border-border rounded px-2 py-1.5 text-xs font-mono" />
            <input value={authBearer} onChange={e => setAuthBearer(e.target.value)}
              placeholder="Authorization: Bearer eyJ…   ·   or custom:  auth_token: eyJ…"
              className="w-full bg-surface-alt border border-border rounded px-2 py-1.5 text-xs font-mono" />
          </div>
        )}

        {/* IDOR/BOLA requires two identities — mandatory when the module is on. */}
        {idorSelected && (
          <div className="rounded-lg border border-severity-high/40 bg-severity-high/[.07] p-3 space-y-2">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-severity-high">
              IDOR / BOLA — two identities required
            </p>
            {idCount >= 2 ? (
              <p className="text-[11px] text-severity-low">✓ {idCount} identities configured — cross-user object access will be tested.</p>
            ) : (
              <>
                <p className="text-[10px] text-text-muted">
                  Cross-user testing needs a victim <b>and</b> an attacker session. Paste each one's credential.
                  For a <b>custom header</b> write <span className="font-mono text-text-secondary">Header-Name: value</span> —
                  e.g. <span className="font-mono text-text-secondary">auth_token: eyJ…</span>,{' '}
                  <span className="font-mono text-text-secondary">Cookie: session=…</span>, or{' '}
                  <span className="font-mono text-text-secondary">Authorization: Bearer …</span>. A bare token is sent as a Bearer.
                  {idCount === 1 && <> (one identity already saved — add the missing one)</>}
                </p>
                <input value={idorA} onChange={e => setIdorA(e.target.value)}
                  placeholder="User A (owner):  auth_token: eyJ…   ·   Cookie: session=…"
                  className="w-full bg-surface-alt border border-border rounded px-2 py-1.5 text-xs font-mono" />
                <input value={idorB} onChange={e => setIdorB(e.target.value)}
                  placeholder="User B (attacker):  auth_token: eyJ…   ·   Cookie: session=…"
                  className="w-full bg-surface-alt border border-border rounded px-2 py-1.5 text-xs font-mono" />
              </>
            )}
          </div>
        )}

        {/* All modules visible at once: compact grouped responsive grid —
            1 col on phones, 2 on tablets, 3 on wide screens inside the xl modal.
            Every chip truncates its label so nothing can push out of its cell. */}
        <div className="max-h-[52vh] overflow-y-auto pr-1 space-y-4">
          {GROUPS.map(group => {
            const mods = MODULES.filter(m => m.group === group)
            const on = mods.filter(m => selected.has(m.id)).length
            return (
              <div key={group}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[11px] font-semibold uppercase tracking-[.14em] text-text-muted font-mono">// {group}</span>
                  <span className="text-[10px] text-text-muted font-mono">{on}/{mods.length}</span>
                  <span className="flex-1 h-px bg-white/[.05]" />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-1.5">
                  {mods.map(m => {
                    const sel = selected.has(m.id)
                    return (
                      <button
                        key={m.id}
                        onClick={() => toggle(m.id)}
                        title={m.desc}
                        className={`flex items-center gap-2 px-2.5 py-2 rounded-lg border text-left transition-all duration-150 ${
                          sel
                            ? 'bg-accent/[.12] border-accent/40 text-white ring-1 ring-accent/20'
                            : 'bg-white/[.02] border-white/[.06] text-text-secondary hover:border-white/20 hover:bg-white/[.05]'
                        }`}
                      >
                        <ModuleIcon module={m.id} size={20} />
                        <span className="text-xs font-medium truncate flex-1 min-w-0">{m.label}</span>
                        <span className={`w-3.5 h-3.5 rounded-full grid place-items-center shrink-0 text-[9px] ${
                          sel ? 'bg-accent text-[#140b00] font-bold' : 'border border-white/15'
                        }`}>{sel ? '✓' : ''}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>

        <div className="flex flex-wrap justify-end gap-2 pt-3 border-t border-white/[.06]">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={loading} disabled={selected.size === 0 || !idorReady} onClick={handleStart}
            className="w-full sm:w-auto justify-center whitespace-nowrap"
            title={!idorReady ? 'IDOR/BOLA needs two identities — paste User A and User B above' : undefined}>
            ▶ Start Scan ({selected.size})
          </Button>
        </div>
      </div>
    </Modal>
  )
}
