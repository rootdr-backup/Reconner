import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useUIStore } from '../../store/ui'
import { CorpusManager } from './CorpusManager'

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const category = (custom = 0) => ({
  id: 'backup', label: 'Backups & secrets', kind: 'wordlist',
  description: 'Sensitive files and configuration paths.',
  default_count: 100, custom_count: custom, total_count: 100 + custom,
  preview: custom ? ['/back/.env', '/.env'] : ['/.env'],
})

describe('CorpusManager', () => {
  beforeEach(() => useUIStore.setState({ toasts: [] }))

  it('reports added, duplicate and invalid counts and restores defaults', async () => {
    const user = userEvent.setup()
    let custom = 0
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method || 'GET'
      if (method === 'POST') {
        expect(JSON.parse(String(init?.body))).toEqual({ text: 'back/.env\n/.env\n../bad' })
        custom = 1
        return ok({ input: 3, added: 1, duplicates: 1, invalid: 1, total: 101 })
      }
      if (method === 'DELETE') {
        custom = 0
        return ok({ removed: 1 })
      }
      return ok([category(custom)])
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('confirm', vi.fn(() => true))

    render(<CorpusManager />)
    await screen.findAllByText('Backups & secrets')
    await user.type(screen.getByLabelText('Paste one entry per line'), 'back/.env\n/.env\n../bad')
    await user.click(screen.getByRole('button', { name: 'Add & deduplicate' }))

    await waitFor(() => expect(screen.getAllByText('101').length).toBeGreaterThan(0))
    expect(screen.getByText('Duplicates')).toBeInTheDocument()
    expect(screen.getByText('Invalid')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Restore default wordlist' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Restore default wordlist' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(5))
    const toasts = useUIStore.getState().toasts
    expect(toasts[toasts.length - 1]?.message).toMatch(/1 custom entry removed/i)
  })
})
