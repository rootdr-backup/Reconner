import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'

// Login — a faux terminal window. Black panel, classic window dots, a typed
// banner line and prompt-styled fields. Pure CSS animation (respects
// prefers-reduced-motion via the global kill-switch in index.css).
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
    <div className="relative min-h-screen flex items-center justify-center px-4 overflow-hidden">
      <div className="aurora" aria-hidden />
      <div className="scanlines" aria-hidden />
      <div className="relative z-10 w-full max-w-sm animate-[slideUp_.4s_ease-out]">
        {/* Terminal window */}
        <div className="card overflow-hidden" style={{ padding: 0 }}>
          {/* Title bar */}
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-surface-1/70">
            <span className="w-2.5 h-2.5 rounded-full bg-[#ff5f56]/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]/80" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#27c93f]/80" />
            <span className="ml-2 text-[11px] text-text-muted font-mono truncate">reconner — auth — 80×24</span>
          </div>

          <div className="p-6 sm:p-7">
            <p className="text-xs text-text-muted font-mono mb-5 break-all">
              <span className="text-accent">$</span> <span className="type-line">ssh {username || 'operator'}@reconner</span><span className="term-cursor" />
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="label font-mono" htmlFor="login-user">
                  <span className="text-accent">user@reconner</span>:<span className="text-text-muted">~$</span> whoami
                </label>
                <input id="login-user" type="text" value={username} onChange={e => setUsername(e.target.value)}
                  className="input font-mono" autoComplete="username" required />
              </div>
              <div>
                <label className="label font-mono" htmlFor="login-pass">
                  <span className="text-accent">user@reconner</span>:<span className="text-text-muted">~$</span> pass --key
                </label>
                <input id="login-pass" type="password" value={password} onChange={e => setPassword(e.target.value)}
                  className="input font-mono" placeholder="••••••••" autoComplete="current-password" required />
              </div>
              {error && (
                <p className="text-xs text-severity-critical bg-severity-critical/10 border border-severity-critical/20 rounded px-3 py-2 font-mono">
                  ✗ {error}
                </p>
              )}
              <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5 text-sm font-mono tracking-wider uppercase">
                {loading ? 'Authenticating…' : '> Authenticate'}
              </button>
            </form>
          </div>
        </div>

        <p className="text-[11px] text-text-muted text-center mt-5 font-mono"># reconner · self-hosted · never sleeps</p>
        <p className="text-[11px] text-text-muted text-center mt-1 font-mono">crafted by <span className="text-accent font-semibold">RootDR</span></p>
      </div>
    </div>
  )
}
