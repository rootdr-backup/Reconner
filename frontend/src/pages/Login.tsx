import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'
import { BrandMark } from '../components/brand/BrandMark'

export default function Login() {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const { login, loading } = useAuthStore()
  const navigate = useNavigate()
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault(); setError('')
    try { await login(username, password); navigate('/') }
    catch (err: unknown) { setError(err instanceof Error ? err.message : 'Login failed') }
  }
  return (
    <div className="relative min-h-screen grid lg:grid-cols-[1.15fr_.85fr] overflow-hidden bg-surface">
      <div className="command-grid" aria-hidden />
      <section className="relative hidden lg:flex flex-col justify-between p-12 xl:p-16 border-r border-white/[.07] overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_12%,rgba(139,124,255,.22),transparent_35%),radial-gradient(circle_at_82%_92%,rgba(79,209,197,.12),transparent_34%)]" />
        <div className="relative z-10 flex items-center gap-3.5">
          <BrandMark size="md" />
          <div><p className="text-xl font-bold tracking-[-.04em]">Reconner <span className="text-xs text-accent font-mono">V3</span></p><p className="text-[10px] uppercase tracking-[.22em] text-text-muted">Security operations</p></div>
        </div>
        <div className="relative z-10 max-w-2xl">
          <p className="page-kicker">Verification-first reconnaissance</p>
          <h1 className="mt-4 text-5xl xl:text-6xl font-semibold leading-[1.04] tracking-[-.055em]">Turn attack-surface noise into <span className="text-gradient">clear decisions.</span></h1>
          <p className="mt-6 max-w-xl text-base leading-7 text-text-secondary">One command center for discovery, evidence, validated findings, automation and long-running scans.</p>
          <div className="mt-10 grid grid-cols-3 gap-3 max-w-xl">
            {['42 scan modules', 'Evidence-first', 'Private by design'].map(item => <div key={item} className="rounded-xl border border-white/[.09] bg-white/[.025] px-4 py-3 text-xs text-text-secondary">{item}</div>)}
          </div>
        </div>
        <p className="relative z-10 text-[11px] text-text-muted">Self-hosted · your targets and evidence stay on your infrastructure.</p>
      </section>
      <section className="relative z-10 flex items-center justify-center p-5 sm:p-10">
      <div className="w-full max-w-md animate-[slideUp_.4s_ease-out]">
        <div className="flex lg:hidden items-center gap-3 mb-10">
          <BrandMark size="md" />
          <div><div className="text-xl font-bold">Reconner <span className="text-xs text-accent font-mono">V3</span></div><div className="text-[9px] uppercase tracking-[.2em] text-text-muted">Security operations</div></div>
        </div>
        <div className="mb-8">
          <p className="page-kicker">Protected workspace</p>
          <h2 className="mt-2 text-3xl font-semibold tracking-[-.04em]">Welcome back.</h2>
          <p className="mt-2 text-sm text-text-muted">Sign in to open your command center.</p>
        </div>
        <div className="card p-6 sm:p-8">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div><label className="label" htmlFor="login-username">Username</label>
              <input id="login-username" type="text" value={username} onChange={e => setUsername(e.target.value)} className="input" autoComplete="username" required/></div>
            <div><label className="label" htmlFor="login-password">Password</label>
              <input id="login-password" type="password" value={password} onChange={e => setPassword(e.target.value)} className="input" autoComplete="current-password" placeholder="••••••••" required/></div>
            {error && <p className="text-xs text-severity-critical bg-severity-critical/10 border border-severity-critical/20 rounded-lg px-3 py-2">{error}</p>}
            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5 text-sm">
              {loading ? 'Opening command center…' : 'Sign in to command center'}
            </button>
          </form>
        </div>
        <p className="text-[11px] text-text-muted mt-5">Built for authorized security research · crafted by <span className="text-gradient font-semibold">RootDR</span></p>
      </div>
      </section>
    </div>
  )
}
