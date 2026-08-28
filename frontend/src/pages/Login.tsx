import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'

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
      <div className="relative z-10 w-full max-w-sm animate-[slideUp_.4s_ease-out]">
        <div className="flex flex-col items-center gap-4 mb-8">
          <div className="grid place-items-center w-16 h-16 rounded-2xl glow-accent"
            style={{ backgroundImage: 'var(--grad-accent)' }}>
            <svg className="w-9 h-9 text-white" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="8" stroke="currentColor" strokeWidth="1.9"/>
              <path d="M12 4v4M12 16v4M4 12h4M16 12h4" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round"/>
              <circle cx="12" cy="12" r="2" fill="currentColor"/>
            </svg>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold tracking-tight text-gradient">Reconner</div>
            <div className="text-xs text-text-muted tracking-wider uppercase mt-0.5">Bug-Bounty Watchtower</div>
          </div>
        </div>
        <div className="card p-7">
          <h1 className="text-base font-semibold mb-5">Sign in to continue</h1>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div><label className="label">Username</label>
              <input type="text" value={username} onChange={e => setUsername(e.target.value)} className="input" required/></div>
            <div><label className="label">Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="input" placeholder="••••••••" required/></div>
            {error && <p className="text-xs text-severity-critical bg-severity-critical/10 border border-severity-critical/20 rounded-lg px-3 py-2">{error}</p>}
            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5 text-sm">
              {loading ? 'Signing in…' : 'Sign In'}
            </button>
          </form>
        </div>
        <p className="text-[11px] text-text-muted text-center mt-5">Reconner · self-hosted · never sleeps</p>
        <p className="text-[11px] text-text-muted text-center mt-1">crafted by <span className="text-gradient font-semibold">RootDR</span></p>
      </div>
    </div>
  )
}
