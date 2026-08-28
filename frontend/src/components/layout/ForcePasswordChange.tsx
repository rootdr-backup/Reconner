import { useState } from 'react'
import { auth as authApi } from '../../lib/api'
import { useAuthStore } from '../../store/auth'
import { Button, Input } from '../ui'

// Blocking modal shown when the admin still has the shipped default password
// (must_change_password from /auth/me). It cannot be dismissed — the operator
// must set a real password before using the app. The "current" password is the
// known default, so we only ask for the new one.
const DEFAULT_PASSWORD = 'change_m)_e'

export const ForcePasswordChange = () => {
  const { refreshMe, user } = useAuthStore()
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)

  if (!user?.must_change_password) return null

  const submit = async () => {
    setErr('')
    if (pw.length < 8) { setErr('Password must be at least 8 characters.'); return }
    if (pw === DEFAULT_PASSWORD) { setErr('Choose a password different from the default.'); return }
    if (pw !== confirm) { setErr('Passwords do not match.'); return }
    setSaving(true)
    try {
      await authApi.changePassword(DEFAULT_PASSWORD, pw)
      await refreshMe()
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Failed to change password')
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" />
      <div className="relative bg-surface-2 border border-border rounded-xl shadow-2xl w-full max-w-md p-6 space-y-4">
        <div>
          <h2 className="text-lg font-semibold">Set a new password</h2>
          <p className="text-xs text-text-muted mt-1">
            You're signed in with the default password. Choose a new one to continue — this is required.
          </p>
        </div>
        <div className="space-y-3">
          <Input label="New password" type="password" value={pw} autoFocus
            placeholder="at least 8 characters"
            onChange={e => setPw(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') submit() }} />
          <Input label="Confirm new password" type="password" value={confirm}
            onChange={e => setConfirm(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') submit() }} />
          {err && <p className="text-xs text-severity-critical">{err}</p>}
        </div>
        <div className="flex justify-end pt-2 border-t border-border">
          <Button variant="primary" loading={saving} onClick={submit}>Set password</Button>
        </div>
      </div>
    </div>
  )
}
