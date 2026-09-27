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

const xssCategory = () => ({
  id: 'xss', label: 'XSS', kind: 'payload',
  description: 'Browser-proof templates.',
  default_count: 20, custom_count: 0, total_count: 20,
  preview: [`<svg onload="top.document.title='%s'">`],
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

  it('explains the XSS proof format, loads examples and preserves rejected lines', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method || 'GET') === 'POST') {
        return ok({ input: 2, added: 1, duplicates: 0, invalid: 1, total: 21 })
      }
      return ok([xssCategory()])
    })
    vi.stubGlobal('fetch', fetchMock)

    render(<CorpusManager />)
    await screen.findAllByText('XSS')
    expect(screen.getByText('XSS imports require browser-proof templates')).toBeInTheDocument()
    expect(screen.getByLabelText('Valid XSS template examples')).toHaveTextContent("top.document.title='%s'")

    const editor = screen.getByLabelText('Paste one entry per line')
    await user.type(editor, `<script>alert(1)</script>\n<svg onload="top.document.title='%s'">`)
    expect(screen.getByText(/1 of 2 non-empty lines do not match/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add & deduplicate' }))

    await screen.findByRole('alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Why was 1 line rejected?')
    expect(editor).toHaveValue('<script>alert(1)</script>')
  })

  it('rejects a wordlist file over 500 MB and warns (but accepts) a large one under it', async () => {
    const fetchMock = vi.fn(async () => ok([category()]))
    vi.stubGlobal('fetch', fetchMock)
    const { container } = render(<CorpusManager />)
    await screen.findAllByText('Backups & secrets')
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    expect(input).toBeTruthy()

    // Overriding .size (rather than allocating real 500 MB content) keeps
    // this test fast — importFile's size check runs before it ever reads
    // the file's actual bytes.
    const tooBig = new File(['x'], 'huge.txt', { type: 'text/plain' })
    Object.defineProperty(tooBig, 'size', { value: 500 * 1024 * 1024 + 1 })
    await userEvent.upload(input, tooBig)
    await waitFor(() => expect(useUIStore.getState().toasts[useUIStore.getState().toasts.length - 1]?.message).toMatch(/500 MB or smaller/))
    expect(screen.getByLabelText('Paste one entry per line')).toHaveValue('')

    useUIStore.setState({ toasts: [] })
    const large = new File(['word1\nword2'], 'large.txt', { type: 'text/plain' })
    Object.defineProperty(large, 'size', { value: 30 * 1024 * 1024 })
    await userEvent.upload(input, large)
    await waitFor(() => expect(useUIStore.getState().toasts[useUIStore.getState().toasts.length - 1]?.message).toMatch(/may feel slow/))
    expect(screen.getByLabelText('Paste one entry per line')).toHaveValue('word1\nword2')
  })
})
