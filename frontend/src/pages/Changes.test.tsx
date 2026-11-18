import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Changes from './Changes'
import type { ChangeEntry, WatchRound } from '../types'

const changeRows: ChangeEntry[] = [
  {
    id: 'c1', source: 'watch', target_id: 't1', target_name: 'alpha.test',
    task_id: 'round-1', url: 'https://alpha.test', change_type: 'status_change',
    category: 'http', severity: 'medium', seen: false,
    old_value: 'status=403 title=Forbidden', new_value: 'status=200 title=OK',
    detected_at: '2026-01-02 10:00:00',
  },
  {
    id: 'c2', source: 'monitor', target_id: 't2', target_name: 'beta.test',
    task_id: '', url: 'https://beta.test/app.js', change_type: 'js_change',
    category: 'scripts', severity: 'medium', seen: false,
    old_value: 'hash=aaa', new_value: 'hash=bbb',
    detected_at: '2026-01-01 09:00:00',
  },
]

const rounds: WatchRound[] = [
  {
    id: 'round-1', target_id: 't1', target_name: 'alpha.test', status: 'finished',
    error: '', started_at: '2026-01-02 09:59:00', finished_at: '2026-01-02 10:00:00',
    change_count: 1,
  },
]

const targetList = [
  { id: 't1', name: 'alpha.test', domain: 'alpha.test' },
  { id: 't2', name: 'beta.test', domain: 'beta.test' },
]

function envelope(data: unknown[]) {
  return new Response(JSON.stringify({ data, total: data.length, page: 1, limit: 500 }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function success(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockApi(opts?: { changes?: ChangeEntry[]; rounds?: WatchRound[] }) {
  const rows = (opts?.changes ?? changeRows).map(r => ({ ...r }))
  const roundRows = opts?.rounds ?? rounds
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === '/api/changes/seen' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body || '{}')) as { ids?: string[]; seen?: boolean }
      for (const row of rows) if (body.ids?.includes(row.id)) row.seen = !!body.seen
      return success({ updated: body.ids?.length || 0 })
    }
    if (url.startsWith('/api/changes/seen-all')) {
      rows.forEach(r => { r.seen = true })
      return success({ updated: rows.length })
    }
    if (url.startsWith('/api/changes?')) {
      const u = new URL(url, 'http://localhost')
      const cat = u.searchParams.get('category')
      const filtered = cat && cat !== 'all' ? rows.filter(r => r.category === cat) : rows
      return envelope(filtered)
    }
    if (url.startsWith('/api/watch/rounds?')) return envelope(roundRows)
    if (url.startsWith('/api/targets?')) return success(targetList)
    return success([])
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

afterEach(() => { vi.unstubAllGlobals() })

describe('global Changes page', () => {
  it('renders a flat feed with field diffs and source badges', async () => {
    mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)

    await screen.findByRole('heading', { name: 'Changes' })
    expect(await screen.findByText('STATUS CODE')).toBeInTheDocument()
    expect(screen.getByText('JAVASCRIPT')).toBeInTheDocument()
    expect(screen.getAllByText('Watch').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Deep').length).toBeGreaterThan(0)
    expect(screen.getByText('403')).toBeInTheDocument()
    expect(screen.getByText('200')).toBeInTheDocument()
    expect(screen.getByText('https://alpha.test')).toBeInTheDocument()
  })

  it('filters the feed by category chip', async () => {
    const user = userEvent.setup()
    mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('JAVASCRIPT')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: 'HTTP' }))
    await waitFor(() => expect(screen.queryByText('JAVASCRIPT')).not.toBeInTheDocument())
    expect(screen.getByText('STATUS CODE')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Scripts' }))
    await waitFor(() => expect(screen.getByText('JAVASCRIPT')).toBeInTheDocument())
    expect(screen.queryByText('STATUS CODE')).not.toBeInTheDocument()
  })

  it('filters by round when a round chip is clicked', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('STATUS CODE')).toBeInTheDocument())

    const roundButton = screen.getByRole('button', { name: /alpha\.test.*finished/ })
    fetchMock.mockClear()
    await user.click(roundButton)

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) =>
      String(input).includes('task_id=round-1'))).toBe(true)
    )
    expect(await screen.findByText('Clear')).toBeInTheDocument()
  })

  it('marks all read and hides seen cards', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('STATUS CODE')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) =>
      String(input).includes('/api/changes/seen-all'))).toBe(true)
    )

    await user.click(screen.getByLabelText('Hide seen'))
    expect(await screen.findByText('All changes are marked as seen.')).toBeInTheDocument()
  })

  it('shows an empty state when there are no changes', async () => {
    mockApi({ changes: [], rounds: [] })
    render(<MemoryRouter><Changes /></MemoryRouter>)
    expect(await screen.findByText('No changes recorded yet.')).toBeInTheDocument()
  })
})
