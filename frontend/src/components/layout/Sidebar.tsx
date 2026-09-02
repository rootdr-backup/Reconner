import { useEffect, useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { cn } from '../../lib/utils'
import { useAuthStore } from '../../store/auth'
import { dashboard } from '../../lib/api'
import { useUIStore } from '../../store/ui'
import { useUpdateCenter } from './UpdateCenter'

// Donation options. Iranian users have a local gateway; everyone else can send
// crypto to these addresses. Nothing here is collected by the app — they're
// static, click-to-copy addresses shown only in the self-hosted dashboard.
const CRYPTO_DONATIONS: { chain: string; address: string }[] = [
  { chain: 'Solana', address: 'BBdEFMnnMFX8ZqeoXbnmYYLE49gNEygdUDy4ctuB9EiT' },
  { chain: 'Bitcoin', address: 'bc1qefw45vhpwy6k0hw4gayu9qmrje9ml34l8ap7ly' },
  { chain: 'EVM (ETH/BSC/Polygon…)', address: '0x58e7c01913D6eA354DEaB1f83AD9A95B4D9EAfCa' },
  { chain: 'Tron (TRC20)', address: 'TYE2DKJZ7nNkBNEJ7uSr374ZVfKfBUYTic' },
]

const I = (p: string) => (props: { className?: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
    strokeLinecap="round" strokeLinejoin="round" className={props.className}>
    <path d={p} />
  </svg>
)
const Icons = {
  dashboard: I('M4 13h6V4H4v9zM14 21h6V11h-6v10zM14 4v4h6V4h-6zM4 21h6v-4H4v4z'),
  targets: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={p.className}>
      <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" fill="currentColor" />
    </svg>
  ),
  web: I('M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.5 3.8 5.7 3.8 9S14.5 18.5 12 21c-2.5-2.5-3.8-5.7-3.8-9S9.5 5.5 12 3z'),
  network: I('M6 4h12M6 4v4M18 4v4M4 8h16v4H4V8zM8 16h8M8 16v4M16 16v4M6 12v4M18 12v4'),
  bounty: I('M8 4h8v3a4 4 0 0 1-8 0V4zM6 5H4v2a4 4 0 0 0 4 4M18 5h2v2a4 4 0 0 1-4 4M12 11v5M8 20h8M9 16h6v4H9z'),
  findings: I('M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z'),
  tasks: I('M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01'),
  system: I('M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z'),
}

type Badge = { text: string; live?: boolean } | null
type NavItem = { to: string; label: string; Icon: (p: { className?: string }) => JSX.Element; badge?: Badge }
type NavGroup = { label: string; items: NavItem[] }

export const Sidebar = () => {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const [donateOpen, setDonateOpen] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)
  const [targetsN, setTargetsN] = useState(0)
  const [runningN, setRunningN] = useState(0)
  const { mobileNavOpen, setMobileNavOpen } = useUIStore()
  const { info, visible: updateAvailable, showDetails } = useUpdateCenter()

  // Light poll for the nav badges (target count + live running-scan count).
  useEffect(() => {
    let alive = true
    const tick = () => dashboard.stats()
      .then(s => { if (alive) { setTargetsN(s.targets || 0); setRunningN(s.running_tasks || 0) } })
      .catch(() => {})
    tick()
    const i = setInterval(tick, 15000)
    return () => { alive = false; clearInterval(i) }
  }, [])

  const groups: NavGroup[] = [
    { label: 'Command center', items: [{ to: '/', label: 'Overview', Icon: Icons.dashboard }] },
    { label: 'Operations', items: [
      { to: '/bounty-programs', label: 'Bounty programs', Icon: Icons.bounty },
      { to: '/targets', label: 'Projects', Icon: Icons.targets, badge: targetsN > 0 ? { text: String(targetsN) } : null },
      { to: '/findings', label: 'Findings', Icon: Icons.findings },
      { to: '/tasks', label: 'Scan activity', Icon: Icons.tasks, badge: runningN > 0 ? { text: String(runningN), live: true } : null },
    ] },
    { label: 'Platform', items: [{ to: '/system', label: 'System & updates', Icon: Icons.system }] },
  ]

  const copyAddress = async (chain: string, address: string) => {
    try {
      await navigator.clipboard.writeText(address)
    } catch {
      // Clipboard API unavailable (non-HTTPS/older browser) — fall back silently.
    }
    setCopied(chain)
    setTimeout(() => setCopied((c) => (c === chain ? null : c)), 1500)
  }
  return (
    <>
      {mobileNavOpen && <button type="button" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"
        className="fixed inset-0 z-30 bg-black/65 backdrop-blur-sm md:hidden" />}
      <aside className={cn('fixed md:relative z-40 md:z-10 flex flex-col w-[17rem] md:w-60 shrink-0 h-[100dvh] top-0 left-0 border-r border-border bg-surface-1/98 backdrop-blur-xl transition-transform duration-200',
        mobileNavOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0')}>
      <div className="flex items-center gap-3 px-5 h-16 border-b border-border">
        <div className="grid place-items-center w-9 h-9 rounded-xl shrink-0 glow-accent"
          style={{ backgroundImage: 'var(--grad-accent)' }}>
          <svg className="w-5 h-5 text-white" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="1.9" />
            <path d="M12 4v4M12 16v4M4 12h4M16 12h4" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
            <circle cx="12" cy="12" r="2" fill="currentColor" />
          </svg>
        </div>
        <div className="leading-tight">
          <div className="text-[15px] font-bold tracking-tight text-gradient">Reconner</div>
          <div className="text-[10px] text-text-muted tracking-[.16em] uppercase">Attack surface intelligence</div>
        </div>
        <button type="button" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"
          className="ml-auto grid place-items-center w-8 h-8 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[.05] md:hidden">✕</button>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-4 overflow-y-auto no-scrollbar">
        {groups.map(group => (
          <div key={group.label}>
            <p className="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-text-muted/80">{group.label}</p>
            <div className="space-y-0.5">
              {group.items.map(({ to, label, Icon, badge }) => (
                <NavLink key={to} to={to} end={to === '/'} onClick={() => setMobileNavOpen(false)}
                  className={({ isActive }) => cn('nav-item group',
                    isActive ? 'text-text-primary' : 'text-text-secondary hover:text-text-primary hover:bg-white/[.04]'
                  )}>
                  {({ isActive }) => (
                    <>
                      {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full"
                        style={{ backgroundImage: 'var(--grad-accent)' }} />}
                      <span className={cn('absolute inset-0 rounded-lg -z-0', isActive && 'bg-accent-muted ring-1 ring-accent/20')} />
                      <Icon className={cn('relative w-[18px] h-[18px] shrink-0 transition-colors',
                        isActive ? 'text-accent-hover' : 'text-text-muted group-hover:text-text-secondary')} />
                      <span className="relative flex-1">{label}</span>
                      {badge && (
                        <span className={cn('relative flex items-center gap-1 px-1.5 py-0.5 rounded-md text-[10px] font-semibold tabular-nums',
                          badge.live ? 'bg-accent-muted text-accent-hover' : 'bg-white/[.06] text-text-secondary')}>
                          {badge.live && <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />}
                          {badge.text}
                        </span>
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {info && (
        <div className="px-3 pb-2">
          <button type="button" onClick={updateAvailable ? showDetails : undefined}
            className={cn('w-full flex items-center gap-2.5 px-3 py-2 rounded-lg border text-left transition-colors',
              updateAvailable ? 'border-accent/30 bg-accent/[.07] hover:bg-accent/[.11]' : 'border-white/[.06] bg-white/[.02]')}>
            <span className={cn('w-2 h-2 rounded-full shrink-0', updateAvailable ? 'bg-accent animate-pulse' : info.error ? 'bg-severity-medium' : 'bg-severity-low')} />
            <span className="min-w-0 flex-1">
              <span className="block text-[10px] uppercase tracking-wider text-text-muted">{updateAvailable ? 'Update ready' : 'Stable channel'}</span>
              <span className="block text-xs font-mono text-text-secondary truncate">v{updateAvailable ? `${info.current} → ${info.latest}` : info.current}</span>
            </span>
            {updateAvailable && <span className="text-accent text-xs">›</span>}
          </button>
        </div>
      )}

      {/* Support / donate — a single quiet row that expands to the Iranian
          gateway plus click-to-copy crypto addresses for everyone else. */}
      <div className="px-3 pt-2">
        <button type="button" onClick={() => setDonateOpen((o) => !o)}
          title="Support RootDR — donate"
          className="flex items-center justify-center gap-2 w-full px-3 py-2 rounded-lg text-xs font-medium
            text-text-secondary border border-white/[.08] hover:border-accent/40 hover:text-accent
            hover:bg-accent/[.06] transition-colors">
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
          </svg>
          Donate
        </button>

        {donateOpen && (
          <div className="mt-2 p-2.5 rounded-lg border border-white/[.08] bg-black/30 space-y-2">
            <a href="https://daramet.com/RootDR" target="_blank" rel="noreferrer"
              className="flex items-center justify-between gap-2 px-2 py-1.5 rounded-md text-[11px]
                text-text-secondary hover:text-accent hover:bg-accent/[.06] transition-colors">
              <span>Iranian gateway</span>
              <span className="text-accent">daramet.com/RootDR ↗</span>
            </a>
            <div className="pt-1 border-t border-white/[.06]">
              <div className="px-2 pt-1 pb-1 text-[10px] uppercase tracking-wide text-text-muted">Crypto (tap to copy)</div>
              {CRYPTO_DONATIONS.map(({ chain, address }) => (
                <button key={chain} type="button" onClick={() => copyAddress(chain, address)}
                  title={address}
                  className="w-full flex flex-col items-start gap-0.5 px-2 py-1.5 rounded-md text-left
                    hover:bg-accent/[.06] transition-colors group">
                  <span className="flex items-center justify-between w-full text-[11px] text-text-secondary">
                    <span>{chain}</span>
                    <span className={cn('text-[10px]', copied === chain ? 'text-severity-low' : 'text-text-muted group-hover:text-accent')}>
                      {copied === chain ? 'Copied' : 'Copy'}
                    </span>
                  </span>
                  <span className="w-full truncate font-mono text-[10px] text-text-muted">{address}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="border-t border-white/[.06] p-3 mt-2">
        <div className="flex items-center gap-3 px-2 py-2 rounded-lg">
          <div className="grid place-items-center w-8 h-8 rounded-full text-xs font-bold text-white shrink-0"
            style={{ backgroundImage: 'var(--grad-accent)' }}>
            {(user?.username || 'A').slice(0, 1).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-xs font-semibold truncate">{user?.username || 'admin'}</div>
            <div className="text-[10px] text-text-muted">signed in</div>
          </div>
          <button onClick={() => logout().then(() => navigate('/login'))}
            title="Logout"
            className="text-text-muted hover:text-severity-critical transition-colors p-1.5 rounded-md hover:bg-white/5">
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
              strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
            </svg>
          </button>
        </div>
      </div>
      </aside>
    </>
  )
}
