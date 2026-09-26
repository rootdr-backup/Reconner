import { useEffect, useState } from 'react'
import { Modal, Button } from '../ui'
import { ModuleIcon } from '../ui/ModuleIcon'
import { targets as targetsApi } from '../../lib/api'
import { useUIStore } from '../../store/ui'
import { cn } from '../../lib/utils'
import {
  MODULE_BY_ID, SAFE_PROFILE, SCAN_BUNDLES, SCAN_GROUPS, SCAN_MODULES,
  STANDARD_PROFILE, resolveModuleSelection,
} from '../../lib/scanModules'
import type { Target } from '../../types'

// Profiles hold explicit operator choices. resolveModuleSelection adds the
// required discovery/verification pipeline and the backend independently plans
// the same closure, so a stale/custom client cannot bypass dependencies.
const PROFILE_MODULES: Record<string, string[]> = {
  safe: SAFE_PROFILE,
  standard: STANDARD_PROFILE,
  deep: SCAN_MODULES.filter(module => !module.automatic).map(module => module.id),
}
const SCAN_PROFILES: { id: string; label: string; sub: string }[] = [
  { id: 'safe', label: 'Safe', sub: 'Low-impact default' },
  { id: 'standard', label: 'Standard', sub: 'Focused validation' },
  { id: 'deep', label: 'Deep', sub: 'All opt-in checks' },
  { id: 'custom', label: 'Custom', sub: 'Your picks' },
]

type AssetLite = { id: string; value: string; kind: string; name: string }
interface Props { target: Target; asset?: AssetLite; open: boolean; onClose: () => void; onStarted?: () => void }

export const ScanModal = ({ target, asset, open, onClose, onStarted }: Props) => {
	const scopeKind = asset?.kind || target.kind || 'web'
	const networkCapable = scopeKind === 'network' || (scopeKind === 'mixed' && !!asset)
	const networkOnly = scopeKind === 'network'
	const [networkMode, setNetworkMode] = useState(networkOnly)
	const [networkProfile, setNetworkProfile] = useState<'fast' | 'normal' | 'deep'>('fast')
	const [networkModules, setNetworkModules] = useState<Set<string>>(new Set(['network']))
  const [selected, setSelected] = useState<Set<string>>(
    new Set(SAFE_PROFILE)
  )
  const planned = resolveModuleSelection(selected)
  const [activeProfile, setActiveProfile] = useState('safe')
  const applyProfile = (p: string) => {
    setActiveProfile(p)
    if (p === 'custom') return
    setSelected(new Set((PROFILE_MODULES[p] || []).filter(id => MODULE_BY_ID.has(id))))
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
  // ASN ownership and bug-bounty scope are not equivalent. Keep the potentially
  // broad CIDR sweep off until the operator has verified those ranges manually.
  const [asnDiscovery, setASNDiscovery] = useState(false)
  // Single-endpoint mode: when the scope is a full URL (has a path and/or query),
  // offer to confine the WHOLE scan to that exact endpoint and the paths under it —
  // param discovery, crawl, JS, and every vuln module (XSS/SQLi/…) run against the
  // given URL (its query AND path params) instead of the whole host.
  const scanScope = (asset?.value || target.domain).trim()
  const scopeTokens = scanScope.split(/[\s,;]+/).filter(Boolean)
  const scopeIsURL = scopeTokens.length === 1 && /^https?:\/\/[^\s]+(?:\/[^\s]*|\?[^\s]*)/i.test(scanScope)
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
    setSelected(new Set(SAFE_PROFILE))
    setActiveProfile('safe')
    setWebSpeed('normal')
    setSubBrute(true)
    setASNDiscovery(false)
    setSingleEndpoint(true)
    setAuthCookie('')
    setAuthBearer('')
		setNetworkMode(networkOnly)
		setNetworkProfile('fast')
		setNetworkModules(new Set(['network']))
    targetsApi.identities(target.id).then(r => setIdCount(r.length)).catch(() => setIdCount(0))
  }, [open, target.id, networkOnly])
  const idorSelected = planned.has('idor')
  const idorReady = !idorSelected || idCount >= 2 || (idorA.trim() !== '' && idorB.trim() !== '')

	if (scopeKind === 'mixed' && !asset) {
		return <Modal open={open} onClose={onClose} title={`Scan — ${label}`} width="md"><div className="space-y-4"><div className="rounded-xl border border-accent/30 bg-accent/[.06] p-4"><p className="text-sm font-semibold text-text-primary">Choose one asset to scan</p><p className="mt-2 text-xs leading-5 text-text-secondary">This project contains both web and network scope. Start the scan from an individual asset below so Reconner can show exactly the compatible web or network pipeline and never mix them accidentally.</p></div><div className="flex justify-end"><Button variant="ghost" onClick={onClose}>Close</Button></div></div></Modal>
	}

  if (networkMode) {
		const networkDefs = [
			{ id: 'network', label: 'Port, service & OS discovery', desc: 'TCP connect discovery, banner grabbing, nmap service fingerprint and opportunistic OS detection.' },
			{ id: 'network_nuclei_only', label: 'Service-aware nuclei', desc: 'Run network/TCP templates only against verified open services.' },
			{ id: 'network_initial_access', label: '401/403 verification', desc: 'Run the existing proof-gated authorization bypass checks against discovered web services.' },
			{ id: 'network_brute', label: 'HTTP Basic credential audit', desc: 'Explicit, rate-limited top-1000 password check. Stops on lockout/rate limiting.' },
		]
		const applyNetworkProfile = (profile: 'fast' | 'normal' | 'deep') => {
			setNetworkProfile(profile)
			setNetworkModules(new Set(profile === 'fast' ? ['network'] : profile === 'normal'
				? ['network', 'network_nuclei_only', 'network_initial_access']
				: ['network', 'network_nuclei_only', 'network_initial_access', 'network_brute']))
		}
		const startNetwork = async () => {
			setLoading(true)
			try {
				const modules = networkDefs.filter(module => networkModules.has(module.id)).map(module => module.id)
				if (!modules.includes('network')) modules.unshift('network')
				modules.push(`network_${networkProfile}`)
				await startModules(modules)
				addToast('success', `Network scan started for ${label}`)
				onClose(); onStarted?.()
			} catch (e: unknown) {
				addToast('error', e instanceof Error ? e.message : 'Failed to start network scan')
			} finally { setLoading(false) }
		}
    return (
      <Modal open={open} onClose={onClose} title={`Scan — ${label}`} width="xl" footer={
			<div className="flex items-center justify-end gap-2"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={loading} onClick={startNetwork}>▶ Start Network Scan</Button></div>
		}>
			<div className="space-y-5">
				<div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
					{!networkOnly && <button type="button" onClick={() => setNetworkMode(false)} className="rounded-lg border border-border px-3 py-2 text-left"><span className="block text-xs font-semibold">Web scan</span><span className="text-[10px] text-text-muted">Application pipeline</span></button>}
					{(['fast','normal','deep'] as const).map(profile => <button key={profile} type="button" onClick={() => applyNetworkProfile(profile)} className={cn('rounded-lg border px-3 py-2 text-left',networkProfile===profile?'border-accent bg-accent-muted text-accent':'border-border text-text-secondary')}><span className="block text-xs font-semibold capitalize">Network {profile}</span><span className="text-[10px] text-text-muted">{profile==='fast'?'Important ports':profile==='normal'?'Top 1000 + validation':'All TCP ports + validation'}</span></button>)}
				</div>
				<div className="rounded-xl border border-severity-high/25 bg-severity-high/[.05] p-3 text-[11px] leading-5 text-text-secondary">Runs only because Network Scan was explicitly selected. Recognised CDN/WAF edge IPs are excluded before probing. ICMP is recorded only as a hint and never suppresses TCP discovery.</div>
				<div className="grid grid-cols-1 md:grid-cols-2 gap-2">
					{networkDefs.map(module => { const required=module.id==='network'; const on=required||networkModules.has(module.id); return <button key={module.id} type="button" disabled={required} onClick={() => setNetworkModules(previous => { const next=new Set(previous); next.has(module.id)?next.delete(module.id):next.add(module.id); return next })} className={cn('rounded-xl border p-3 text-left',on?'border-accent/40 bg-accent/[.1]':'border-border bg-white/[.02]')}><span className="block text-xs font-semibold text-text-primary">{module.label}{required?' · required':''}</span><span className="mt-1 block text-[10px] leading-4 text-text-muted">{module.desc}</span></button> })}
				</div>
			</div>
      </Modal>
    )
  }

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

  const selectSafe = () => { setActiveProfile('safe'); setSelected(new Set(SAFE_PROFILE)) }
  const selectNone = () => setSelected(new Set())

  const toggleBundle = (modules: string[]) => {
    setActiveProfile('custom')
    setSelected(previous => {
      const next = new Set(previous)
      const allExplicit = modules.every(id => next.has(id))
      modules.forEach(id => allExplicit ? next.delete(id) : next.add(id))
      return next
    })
  }

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
    if (planned.size === 0) return
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
      if (!planned.has('subdomain_enum') && (authCookie.trim() || authBearer.trim())) {
        const headers: Record<string, string> = {}
        if (authCookie.trim()) Object.assign(headers, parseCred(authCookie.trim()))
        // Flexible: a bare token → Bearer; or an explicit "auth_token: …" / "X-Api-Key: …" custom header.
        if (authBearer.trim()) Object.assign(headers, parseCred(authBearer.trim()))
        try { await targetsApi.setAuth(target.id, headers) } catch { /* non-fatal */ }
      }
      // Preserve module order
      const orderedModules = SCAN_MODULES.filter(m => planned.has(m.id)).map(m => m.id)
      if (webSpeed === 'slow') orderedModules.push('speed_slow')
      if (webSpeed === 'fast') orderedModules.push('speed_fast')
      if (!subBrute) orderedModules.push('no_subdomain_brute')
      if (asnDiscovery) orderedModules.push('asn_discovery')
      if (scopeIsURL && singleEndpoint) orderedModules.push('single_endpoint')
      await startModules(orderedModules)
      addToast('success', `Scan started for ${label}`)
      onClose()
      onStarted?.()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to start scan')
    } finally { setLoading(false) }
  }

  const footer = (
    <div className="flex items-center justify-end gap-2">
      <Button variant="ghost" onClick={onClose}>Cancel</Button>
      <Button variant="primary" loading={loading} disabled={planned.size === 0 || !idorReady} onClick={handleStart}
        title={!idorReady ? 'IDOR/BOLA needs two identities — paste User A and User B above' : undefined}>
        ▶ Start Scan ({planned.size} phases)
      </Button>
    </div>
  )

  return (
    <Modal open={open} onClose={onClose} title={`Scan — ${label}`} width="xl" footer={footer}>
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
					{networkCapable && <button type="button" onClick={() => setNetworkMode(true)} className="flex flex-col items-start px-3 py-2 rounded-lg border border-border text-left text-text-secondary hover:text-text-primary hover:border-border-strong"><span className="text-xs font-semibold">Network Scan</span><span className="text-[10px] text-text-muted">Ports, banners &amp; services</span></button>}
          </div>
        </div>

        <div className="flex items-center justify-between">
          <p className="text-xs text-text-muted">
            <span className="text-accent-hover font-semibold">{selected.size}</span> selected
            {planned.size > selected.size && <span> · {planned.size - selected.size} dependency{planned.size - selected.size === 1 ? '' : 'ies'} added automatically</span>}
          </p>
          <div className="flex gap-2 text-xs">
            <button onClick={selectSafe} className="px-2 py-1 rounded-md bg-accent/10 text-accent-hover hover:bg-accent/20 transition-colors">Safe defaults</button>
            <button onClick={selectNone} className="px-2 py-1 rounded-md bg-white/5 text-text-muted hover:text-text-secondary transition-colors">Clear</button>
          </div>
        </div>

        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1.5">Pipeline bundles</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-1.5">
            {SCAN_BUNDLES.map(bundle => {
              const on = bundle.modules.every(id => selected.has(id))
              return (
                <button key={bundle.id} type="button" onClick={() => toggleBundle(bundle.modules)}
                  className={cn('rounded-lg border px-3 py-2 text-left transition-colors',
                    on ? 'border-accent/40 bg-accent/[.1]' : 'border-border bg-white/[.02] hover:border-border-strong')}>
                  <span className="block text-xs font-semibold text-text-primary">{bundle.label}</span>
                  <span className="block mt-0.5 text-[10px] text-text-muted">{bundle.desc}</span>
                </button>
              )
            })}
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
        {planned.has('subdomain_enum') && (
          <div className="space-y-2">
            <label className="flex items-start gap-3 rounded-lg border border-white/[.08] bg-white/[.02] p-3 cursor-pointer">
              <input type="checkbox" checked={subBrute} onChange={e => setSubBrute(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[var(--accent)]" />
              <span>
                <span className="text-xs font-medium text-text-primary">Deep DNS discovery</span>
                <span className="block text-[10px] text-text-muted mt-0.5">
                  Adaptive dev/tool wordlist + target-derived permutations + dnsx/puredns verification. Turn OFF for a fast passive map.
                </span>
              </span>
            </label>
            <label className="flex items-start gap-3 rounded-lg border border-severity-high/30 bg-severity-high/[.05] p-3 cursor-pointer">
              <input type="checkbox" checked={asnDiscovery} onChange={e => setASNDiscovery(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[var(--accent)]" />
              <span>
                <span className="text-xs font-medium text-text-primary">ASN / CIDR discovery <span className="text-severity-high font-normal">(scope-verified only)</span></span>
                <span className="block text-[10px] text-text-muted mt-0.5">
                  Reverse-resolves organisation netblocks. Enable only after WHOIS/program-scope verification; ASN ownership alone does not make every IP in scope.
                </span>
              </span>
            </label>
          </div>
        )}

        {/* Pre-scan authentication — only for single-domain scans (subdomain
            enumeration OFF). Attaches a logged-in session so the scanner reaches
            pages behind auth from the first request. */}
        {!planned.has('subdomain_enum') && (
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

        {/* The resolved pipeline is shown, including locked automatic dependencies.
            Internal legacy/composite dispatchers are intentionally not user-facing. */}
        <div className="space-y-4">
          {SCAN_GROUPS.map(group => {
            const mods = SCAN_MODULES.filter(m => m.group === group.id)
            const on = mods.filter(m => planned.has(m.id)).length
            return (
              <div key={group.id} className="rounded-xl border border-white/[.06] bg-white/[.015] p-2.5">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">{group.label}</span>
                  <span className="text-[10px] text-text-muted">{on}/{mods.length}</span>
                  <span className="flex-1 h-px bg-white/[.06]" />
                </div>
                <p className="text-[10px] text-text-muted mb-2">{group.desc}</p>
                <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-1.5">
                  {mods.map(m => {
                    const explicit = selected.has(m.id)
                    const sel = planned.has(m.id)
                    const auto = sel && !explicit
                    return (
                      <button
                        key={m.id}
                        type="button"
                        onClick={() => !m.automatic && toggle(m.id)}
                        title={m.desc}
                        disabled={!!m.automatic}
                        className={`flex items-center gap-2 px-2.5 py-2 rounded-lg border text-left transition-all duration-150 ${
                          sel
                            ? 'bg-accent/[.12] border-accent/40 text-white ring-1 ring-accent/20'
                            : 'bg-white/[.02] border-white/[.06] text-text-secondary hover:border-white/20 hover:bg-white/[.05]'
                        } ${m.automatic ? 'cursor-default' : ''}`}
                      >
                        <ModuleIcon module={m.id} size={20} />
                        <span className="min-w-0 flex-1">
                          <span className="block text-xs font-medium truncate">{m.label}</span>
                          <span className={`block text-[9px] uppercase tracking-wide ${m.tier === 'advanced' ? 'text-severity-high' : m.tier === 'active' ? 'text-series-3' : 'text-severity-low'}`}>
                            {auto ? 'auto dependency' : m.automatic ? 'automatic' : m.tier}
                          </span>
                        </span>
                        <span className={`w-3.5 h-3.5 rounded-full grid place-items-center shrink-0 text-[9px] ${
                          sel ? 'bg-accent text-white' : 'border border-white/15'
                        }`}>{sel ? (auto ? '·' : '✓') : ''}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>

      </div>
    </Modal>
  )
}
