import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useUIStore } from '../../store/ui'
import { TelegramIntegration } from './TelegramIntegration'

const initialState = {
  configured: true,
  enabled: true,
  masked_token: '12••••xy',
  bot_username: 'reconner_test_bot',
  connected: true,
  last_error: '',
  last_connected_at: '2026-09-13 01:00:00',
  pending: 0,
  failed: 0,
  chats: [],
}

function ok(data: unknown, status = 200) {
  return new Response(JSON.stringify({ success: true, data }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('TelegramIntegration', () => {
  beforeEach(() => {
    useUIStore.setState({ toasts: [] })
  })

  it('persists an allowlisted chat and renders the saved row', async () => {
    const user = userEvent.setup()
    let saved = false
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method || 'GET'
      if (method === 'POST') {
        const body = JSON.parse(String(init?.body))
        expect(body).toEqual({ chat_id: '1340857378', label: 'Javad', role: 'admin' })
        saved = true
        return ok({
          id: 'chat-1',
          ...body,
          enabled: true,
          notify_scan_started: true,
          notify_phase_finished: true,
          notify_scan_finished: true,
          notify_findings: true,
          notify_monitoring: true,
          created_at: '2026-09-13 01:00:00',
          updated_at: '2026-09-13 01:00:00',
        }, 201)
      }
      return ok({
        ...initialState,
        chats: saved ? [{
          id: 'chat-1', chat_id: '1340857378', label: 'Javad', role: 'admin', enabled: true,
          notify_scan_started: true, notify_phase_finished: true,
          notify_scan_finished: true, notify_findings: true, notify_monitoring: true,
          created_at: '2026-09-13 01:00:00', updated_at: '2026-09-13 01:00:00',
        }] : [],
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    render(<TelegramIntegration />)
    await screen.findByText(/connected · @reconner_test_bot/i)

    await user.type(screen.getByLabelText('Chat ID'), '1340857378')
    await user.type(screen.getByLabelText('Label'), 'Javad')
    await user.selectOptions(screen.getByLabelText('Role'), 'admin')
    await user.click(screen.getByRole('button', { name: 'Add chat' }))

    await waitFor(() => expect(screen.getByText('1340857378')).toBeInTheDocument())
    expect(screen.getByDisplayValue('Javad')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Admin')).toBeInTheDocument()
    expect(screen.queryByText('No Telegram chats are allowlisted yet.')).not.toBeInTheDocument()
  })

  it('keeps the add action visible and rejects an empty chat id locally', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn(async () => ok(initialState))
    vi.stubGlobal('fetch', fetchMock)

    render(<TelegramIntegration />)
    await screen.findByRole('button', { name: 'Add chat' })
    await user.click(screen.getByRole('button', { name: 'Add chat' }))

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const toasts = useUIStore.getState().toasts
    expect(toasts[toasts.length - 1]?.message).toBe('Chat ID is required')
  })
})
