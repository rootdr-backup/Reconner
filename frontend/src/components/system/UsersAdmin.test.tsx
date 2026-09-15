import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useAuthStore } from '../../store/auth'
import { useUIStore } from '../../store/ui'
import { UsersAdmin } from './UsersAdmin'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('UsersAdmin', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 1, username: 'admin', role: 'admin' }, initialized: true, loading: false })
    useUIStore.setState({ toasts: [] })
  })

  it('creates a least-privilege member and refreshes the list', async () => {
    const user = userEvent.setup()
    let created = false
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST') {
        expect(JSON.parse(String(init.body))).toEqual({ username: 'analyst', password: 'strong-password', role: 'member' })
        created = true
        return ok({ id: 2, username: 'analyst', role: 'member', disabled: false })
      }
      return ok(created ? [
        { id: 1, username: 'admin', role: 'admin', disabled: false, created_at: '2026-09-13 01:00:00', updated_at: '2026-09-13 01:00:00' },
        { id: 2, username: 'analyst', role: 'member', disabled: false, created_at: '2026-09-13 01:00:00', updated_at: '2026-09-13 01:00:00' },
      ] : [
        { id: 1, username: 'admin', role: 'admin', disabled: false, created_at: '2026-09-13 01:00:00', updated_at: '2026-09-13 01:00:00' },
      ])
    })
    vi.stubGlobal('fetch', fetchMock)

    render(<UsersAdmin />)
    await screen.findByText('you')
    await user.type(screen.getByPlaceholderText('username'), 'analyst')
    await user.type(screen.getByPlaceholderText('initial password (min 8)'), 'strong-password')
    await user.click(screen.getByRole('button', { name: 'Add user' }))

    await waitFor(() => expect(screen.getByText('analyst')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('blocks a short password before making a mutation request', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn(async () => ok([]))
    vi.stubGlobal('fetch', fetchMock)
    render(<UsersAdmin />)
    await screen.findByText(/accounts that can sign in/i)

    await user.type(screen.getByPlaceholderText('username'), 'analyst')
    await user.type(screen.getByPlaceholderText('initial password (min 8)'), 'short')
    await user.click(screen.getByRole('button', { name: 'Add user' }))

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const toasts = useUIStore.getState().toasts
    expect(toasts[toasts.length - 1]?.message).toMatch(/at least 8/i)
  })
})
