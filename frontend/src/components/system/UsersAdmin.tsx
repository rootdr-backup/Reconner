import { useEffect, useState } from 'react'
import { users as usersApi, type AccountUser } from '../../lib/api'
import { Button, Badge } from '../ui'
import { cn, timeAgo } from '../../lib/utils'
import { useUIStore } from '../../store/ui'
import { useAuthStore } from '../../store/auth'

// UsersAdmin — the admin-only account-management panel embedded in System.
// Add users, change their role, enable/disable them, reset a password, or
// delete them. The server refuses any change that would remove the last active
// administrator, and refuses self-disable / self-delete; this UI mirrors those
// guards so the buttons never sit in an impossible state.
export function UsersAdmin() {
  const { addToast } = useUIStore()
  const me = useAuthStore(s => s.user)
  const [rows, setRows] = useState<AccountUser[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<number | null>(null)
  const [form, setForm] = useState({ username: '', password: '', role: 'member' })
  const [creating, setCreating] = useState(false)

  const activeAdmins = rows.filter(u => u.role === 'admin' && !u.disabled).length

  const load = async () => {
    try { setRows(await usersApi.list() || []) }
    catch { addToast('error', 'Failed to load users') }
    finally { setLoading(false) }
  }
  useEffect(() => { load() }, [])

  const create = async () => {
    const username = form.username.trim()
    if (!username) { addToast('error', 'Username required'); return }
    if (form.password.length < 8) { addToast('error', 'Password must be at least 8 characters'); return }
    setCreating(true)
    try {
      await usersApi.create(username, form.password, form.role)
      addToast('success', `User "${username}" created`)
      setForm({ username: '', password: '', role: 'member' })
      load()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Failed to create user') }
    finally { setCreating(false) }
  }

  const patch = async (u: AccountUser, body: { role?: string; disabled?: boolean; password?: string }, ok: string) => {
    setBusy(u.id)
    try { await usersApi.update(u.id, body); addToast('success', ok); load() }
    catch (e) { addToast('error', e instanceof Error ? e.message : 'Update failed') }
    finally { setBusy(null) }
  }

  const resetPassword = async (u: AccountUser) => {
    const pw = window.prompt(`New password for "${u.username}" (min 8 chars)`)
    if (pw === null) return
    if (pw.length < 8) { addToast('error', 'Password must be at least 8 characters'); return }
    patch(u, { password: pw }, `Password reset for "${u.username}"`)
  }

  const remove = async (u: AccountUser) => {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    setBusy(u.id)
    try { await usersApi.remove(u.id); addToast('success', `User "${u.username}" deleted`); load() }
    catch (e) { addToast('error', e instanceof Error ? e.message : 'Delete failed') }
    finally { setBusy(null) }
  }

  return (
    <div>
      <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-3">
        Users <span className="normal-case text-text-muted/70">— accounts that can sign in ({rows.length})</span>
      </p>

      {/* Add-user row */}
      <div className="card p-3 mb-3">
        <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr_auto_auto] gap-2 items-center">
          <input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })}
            placeholder="username"
            className="bg-surface-alt border border-border rounded px-2 py-1.5 text-sm" />
          <input value={form.password} onChange={e => setForm({ ...form, password: e.target.value })}
            type="password" autoComplete="new-password" placeholder="initial password (min 8)"
            className="bg-surface-alt border border-border rounded px-2 py-1.5 text-sm font-mono" />
          <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}
            className="bg-surface-alt border border-border rounded px-2 py-1.5 text-sm">
            <option value="member" className="bg-surface-3">Member</option>
            <option value="admin" className="bg-surface-3">Admin</option>
          </select>
          <Button size="sm" variant="primary" loading={creating} onClick={create}>Add user</Button>
        </div>
        <p className="text-[10px] text-text-muted mt-1.5">
          Members can run scans and read findings; admins can additionally manage users and settings.
        </p>
      </div>

      {loading ? (
        <p className="text-xs text-text-muted py-2">Loading…</p>
      ) : (
        <div className="space-y-1.5">
          {rows.map(u => {
            const isSelf = me?.id === u.id
            const isLastAdmin = u.role === 'admin' && !u.disabled && activeAdmins <= 1
            return (
              <div key={u.id} className={cn('flex items-center gap-3 px-3 py-2 rounded-lg border',
                u.disabled ? 'border-white/[.06] bg-white/[.01] opacity-70' : 'border-white/[.06] bg-white/[.02]')}>
                <span className={cn('w-2 h-2 rounded-full shrink-0', u.disabled ? 'bg-text-muted' : 'bg-severity-low')} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium truncate">{u.username}</span>
                    {isSelf && <span className="text-[10px] text-accent">you</span>}
                    {u.disabled && <span className="text-[10px] text-text-muted uppercase tracking-wide">disabled</span>}
                  </div>
                  <p className="text-[10px] text-text-muted">added {timeAgo(u.created_at)}</p>
                </div>

                {/* Role selector */}
                <select value={u.role}
                  disabled={busy === u.id || (isLastAdmin)}
                  title={isLastAdmin ? 'The last active administrator cannot be demoted' : 'Change role'}
                  onChange={e => patch(u, { role: e.target.value }, `Role updated for "${u.username}"`)}
                  className="bg-surface-alt border border-border rounded px-2 py-1 text-xs disabled:opacity-50">
                  <option value="member" className="bg-surface-3">Member</option>
                  <option value="admin" className="bg-surface-3">Admin</option>
                </select>

                <Badge variant={u.role === 'admin' ? 'high' : 'neutral'}>{u.role}</Badge>

                {/* Enable / disable */}
                <Button size="sm" variant="secondary" disabled={busy === u.id || isSelf || isLastAdmin}
                  title={isSelf ? 'You cannot disable your own account' : isLastAdmin ? 'The last active administrator cannot be disabled' : ''}
                  onClick={() => patch(u, { disabled: !u.disabled }, `${u.disabled ? 'Enabled' : 'Disabled'} "${u.username}"`)}>
                  {u.disabled ? 'Enable' : 'Disable'}
                </Button>

                {/* Reset password */}
                <Button size="sm" variant="ghost" disabled={busy === u.id} onClick={() => resetPassword(u)}>
                  Reset password
                </Button>

                {/* Delete */}
                <button disabled={busy === u.id || isSelf || isLastAdmin}
                  title={isSelf ? 'You cannot delete your own account' : isLastAdmin ? 'The last active administrator cannot be deleted' : 'Delete user'}
                  onClick={() => remove(u)}
                  className="p-1.5 rounded text-text-muted hover:text-severity-critical hover:bg-severity-critical/10 transition-colors disabled:opacity-30 disabled:hover:bg-transparent">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
