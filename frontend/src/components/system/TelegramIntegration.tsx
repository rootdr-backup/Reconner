import { useEffect, useState } from 'react'
import { system, type TelegramChat, type TelegramRole, type TelegramState } from '../../lib/api'
import { Button, Spinner } from '../ui'
import { cn } from '../../lib/utils'
import { useUIStore } from '../../store/ui'

const emptyState: TelegramState = {
  configured: false, enabled: false, masked_token: '', bot_username: '', connected: false,
  last_error: '', last_connected_at: '', pending: 0, failed: 0, chats: [],
}

export function TelegramIntegration() {
  const [state, setState] = useState<TelegramState | null>(null)
  const [token, setToken] = useState('')
  const [enabled, setEnabled] = useState(false)
  const [saving, setSaving] = useState(false)
  const [chatID, setChatID] = useState('')
  const [chatLabel, setChatLabel] = useState('')
  const [chatRole, setChatRole] = useState<TelegramRole>('viewer')
  const [adding, setAdding] = useState(false)
  const [busyChat, setBusyChat] = useState('')
  const { addToast } = useUIStore()

  const load = async () => {
    try {
      const next = await system.telegram()
      setState(next || emptyState)
      setEnabled(!!next?.enabled)
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Could not load Telegram settings')
      setState(emptyState)
    }
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    setSaving(true)
    try {
      const patch: { bot_token?: string; enabled?: boolean } = { enabled }
      if (token.trim()) patch.bot_token = token.trim()
      const next = await system.updateTelegram(patch)
      setState(next); setEnabled(next.enabled); setToken('')
      addToast('success', next.enabled ? 'Telegram bot enabled' : 'Telegram settings saved')
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Could not save Telegram bot')
    } finally { setSaving(false) }
  }

  const clearToken = async () => {
    if (!window.confirm('Disconnect Telegram and remove the stored BotFather token?')) return
    setSaving(true)
    try {
      const next = await system.updateTelegram({ bot_token: '', enabled: false })
      setState(next); setEnabled(false); setToken('')
      addToast('success', 'Telegram bot disconnected')
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not disconnect Telegram') }
    finally { setSaving(false) }
  }

  const addChat = async () => {
    if (!chatID.trim()) { addToast('error', 'Chat ID is required'); return }
    setAdding(true)
    try {
      await system.addTelegramChat({ chat_id: chatID.trim(), label: chatLabel.trim(), role: chatRole })
      setChatID(''); setChatLabel(''); setChatRole('viewer')
      await load()
      addToast('success', 'Telegram chat added')
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not add chat') }
    finally { setAdding(false) }
  }

  const updateChat = async (chat: TelegramChat, patch: Partial<TelegramChat>) => {
    setBusyChat(chat.id)
    try {
      const next = await system.updateTelegramChat(chat.id, patch)
      setState(next); setEnabled(next.enabled)
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not update chat') }
    finally { setBusyChat('') }
  }

  const deleteChat = async (chat: TelegramChat) => {
    if (!window.confirm(`Remove Telegram chat ${chat.label || chat.chat_id}?`)) return
    setBusyChat(chat.id)
    try {
      await system.deleteTelegramChat(chat.id); await load(); addToast('success', 'Chat removed')
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not remove chat') }
    finally { setBusyChat('') }
  }

  const testChat = async (chat: TelegramChat) => {
    setBusyChat(chat.id)
    try { const r = await system.testTelegramChat(chat.id); addToast('success', r.message) }
    catch (e) { addToast('error', e instanceof Error ? e.message : 'Test message failed') }
    finally { setBusyChat('') }
  }

  const retryFailed = async () => {
    try {
      const result = await system.retryTelegram()
      await load()
      addToast('success', result.message)
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not retry Telegram messages') }
  }

  if (!state) return <div className="card p-6 flex items-center justify-center"><Spinner /></div>

  return (
    <section className="card overflow-hidden mb-6">
      <div className="p-5 border-b border-border bg-gradient-to-br from-[#229ED9]/[.10] via-transparent to-transparent">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="grid place-items-center w-8 h-8 rounded-lg bg-[#229ED9]/15 text-lg">✈</span>
              <div>
                <h2 className="text-sm font-semibold">Telegram control bot</h2>
                <p className="text-[11px] text-text-muted">Scan controls, target management and durable finding alerts through one or more chats.</p>
              </div>
              <span className={cn('badge ml-1', state.connected ? 'badge-low' : state.enabled ? 'badge-medium' : 'badge-neutral')}>
                {state.connected ? `connected${state.bot_username ? ` · @${state.bot_username}` : ''}` : state.enabled ? 'connecting' : 'disabled'}
              </span>
            </div>
            {state.last_error && <p className="mt-3 text-[11px] text-severity-medium break-words">Last error: {state.last_error}</p>}
            <p className="mt-3 text-[10px] text-text-muted max-w-3xl">
              Create a bot with BotFather, paste its token below, add the bot to a private chat or group, then send <code>/start</code>. An unapproved chat receives its numeric Chat ID so you can allowlist it here. Long polling works without a public webhook.
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button size="sm" variant="ghost" onClick={load}>↻ Refresh</Button>
            {state.configured && <Button size="sm" variant="danger" disabled={saving} onClick={clearToken}>Disconnect</Button>}
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_auto] gap-3 items-end">
          <label className="block">
            <span className="label">BotFather token</span>
            <input type="password" autoComplete="off" className="input font-mono"
              placeholder={state.configured ? `Configured (${state.masked_token}) — enter only to replace` : '123456789:AA...'}
              value={token} onChange={e => setToken(e.target.value)} />
          </label>
          <div className="flex items-center gap-3 lg:pb-0.5">
            <label className="flex items-center gap-2 text-xs text-text-secondary cursor-pointer">
              <input type="checkbox" className="accent-accent w-4 h-4" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
              Enable bot
            </label>
            <Button variant="primary" loading={saving} onClick={save}>Validate &amp; save</Button>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold">Allowed chats</h3>
            <p className="text-[10px] text-text-muted mt-1">Viewer is read-only; Operator manages scans; Admin also creates, edits and deletes targets. Give Admin only to a private chat or a fully trusted group.</p>
          </div>
          <div className="flex gap-3 text-[10px] text-text-muted">
            <span>{state.pending} pending</span><span>{state.failed} failed</span>
            {state.failed > 0 && <button className="text-accent hover:underline" onClick={retryFailed}>Retry failed</button>}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr_140px_auto] gap-2 items-end rounded-lg border border-border p-3 bg-white/[.015]">
          <label><span className="label">Chat ID</span><input className="input font-mono" placeholder="-1001234567890" value={chatID} onChange={e => setChatID(e.target.value)} /></label>
          <label><span className="label">Label</span><input className="input" placeholder="Bounty team" value={chatLabel} onChange={e => setChatLabel(e.target.value)} /></label>
          <label><span className="label">Role</span><select className="input" value={chatRole} onChange={e => setChatRole(e.target.value as TelegramRole)}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select></label>
          <Button variant="secondary" loading={adding} onClick={addChat}>Add chat</Button>
        </div>

        {state.chats.length === 0 ? (
          <p className="text-xs text-text-muted text-center py-6">No Telegram chats are allowlisted yet.</p>
        ) : (
          <div className="space-y-2">
            {state.chats.map(chat => (
              <div key={chat.id} className={cn('rounded-lg border border-border p-3 transition-opacity', busyChat === chat.id && 'opacity-60')}>
                <div className="flex flex-col xl:flex-row xl:items-center gap-3">
                  <div className="min-w-0 xl:w-60">
                    <input className="input !py-1 !px-2 text-xs font-medium" aria-label="Chat label" defaultValue={chat.label}
                      placeholder="Unnamed chat" disabled={busyChat === chat.id}
                      onBlur={e => { const label = e.currentTarget.value.trim(); if (label !== chat.label) updateChat(chat, { label }) }} />
                    <p className="text-[10px] text-text-muted font-mono break-all">{chat.chat_id}</p>
                  </div>
                  <select className="input !w-auto text-xs" value={chat.role} disabled={busyChat === chat.id}
                    onChange={e => updateChat(chat, { role: e.target.value as TelegramRole })}>
                    <option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option>
                  </select>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-2 flex-1">
                    <ChatToggle label="Enabled" checked={chat.enabled} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { enabled: v })} />
                    <ChatToggle label="Start" checked={chat.notify_scan_started} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_scan_started: v })} />
                    <ChatToggle label="Every phase" checked={chat.notify_phase_finished} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_phase_finished: v })} />
                    <ChatToggle label="Result" checked={chat.notify_scan_finished} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_scan_finished: v })} />
                    <ChatToggle label="Findings" checked={chat.notify_findings} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_findings: v })} />
                    <ChatToggle label="Monitoring" checked={chat.notify_monitoring} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_monitoring: v })} />
                    <ChatToggle label="Watch start" checked={chat.notify_watch_scan_started} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_watch_scan_started: v })} />
                    <ChatToggle label="Watch result" checked={chat.notify_watch_scan_finished} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_watch_scan_finished: v })} />
                    <ChatToggle label="New scope" checked={chat.notify_scope_landed} disabled={busyChat === chat.id} onChange={v => updateChat(chat, { notify_scope_landed: v })} />
                  </div>
                  <div className="flex gap-1 shrink-0">
                    <Button size="sm" variant="ghost" disabled={busyChat === chat.id || !chat.enabled} onClick={() => testChat(chat)}>Test</Button>
                    <Button size="sm" variant="danger" disabled={busyChat === chat.id} onClick={() => deleteChat(chat)}>Remove</Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="rounded-lg bg-white/[.025] border border-border p-3 text-[10px] text-text-muted leading-relaxed">
          Commands: <code>/status</code>, <code>/targets</code>, <code>/target</code>, <code>/scans</code>, <code>/findings</code>, <code>/scan</code>, <code>/pause</code>, <code>/resume</code>, <code>/skip</code>, <code>/cancel</code>, <code>/addtarget</code>, <code>/edittarget</code>, <code>/deletetarget</code>. Target deletion always requires an inline confirmation. Every mutating command is written to the Telegram audit log.
        </div>
      </div>
    </section>
  )
}

function ChatToggle({ label, checked, disabled, onChange }: { label: string; checked: boolean; disabled?: boolean; onChange: (value: boolean) => void }) {
  return <label className="flex items-center gap-1.5 text-[10px] text-text-secondary cursor-pointer whitespace-nowrap">
    <input type="checkbox" className="accent-accent" checked={checked} disabled={disabled} onChange={e => onChange(e.target.checked)} />{label}
  </label>
}
