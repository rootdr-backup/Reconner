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
    category: 'http', severity: 'medium',
    old_value: 'status=403 title=Forbidden', new_value: 'status=200 title=OK',
    detected_at: '2026-01-02 10:00:00',
  },
  {
    id: 'c2', source: 'monitor', target_id: 't2', target_name: 'beta.test',
    task_id: '', url: 'https://beta.test/app.js', change_type: 'js_change',
    category: 'scripts', severity: 'medium',
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
  const rows = opts?.changes ?? changeRows
  const roundRows = opts?.rounds ?? rounds
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.startsWith('/api/changes?')) return envelope(rows)
    if (url.startsWith('/api/watch/rounds?')) return envelope(roundRows)
    if (url.startsWith('/api/targets?')) return success(targetList)
    return success([])
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

afterEach(() => { vi.unstubAllGlobals() })

describe('global Changes page', () => {
  it('renders KPIs, rounds, and grouped change rows', async () => {
    mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)

    await screen.findByRole('heading', { name: 'Changes' })
    expect(await screen.findByText('alpha.test', { selector: 'button span' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('status_change')).toBeInTheDocument())
    expect(screen.getByText('js_change')).toBeInTheDocument()
    expect(screen.getByText('Watch')).toBeInTheDocument()
    expect(screen.getByText('Deep')).toBeInTheDocument()
    expect(screen.getByText('1 changes')).toBeInTheDocument()
  })

  it('switches subtabs and filters the list', async () => {
    const user = userEvent.setup()
    mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('js_change')).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: 'HTTP & status' }))
    await waitFor(() => expect(screen.getByText('status_change')).toBeInTheDocument())
    expect(screen.queryByText('js_change')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Scripts' }))
    await waitFor(() => expect(screen.getByText('js_change')).toBeInTheDocument())
    expect(screen.queryByText('status_change')).not.toBeInTheDocument()
  })

  it('filters by round when a round is clicked', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getByText('status_change')).toBeInTheDocument())

    const roundButton = screen.getByRole('button', { name: /alpha\.test.*1 changes/ })
    fetchMock.mockClear()
    await user.click(roundButton)

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) =>
      String(input).includes('task_id=round-1'))).toBe(true)
    )
    expect(await screen.findByText('Clear round')).toBeInTheDocument()
  })

  it('keeps identical changes from two targets in separate groups', async () => {
    const twin: ChangeEntry = {
      ...changeRows[0], id: 'c3', target_id: 't2', target_name: 'beta.test', task_id: 'round-2',
    }
    mockApi({ changes: [changeRows[0], twin] })
    render(<MemoryRouter><Changes /></MemoryRouter>)
    await waitFor(() => expect(screen.getAllByText('status_change')).toHaveLength(2))
  })

  it('shows empty states when there are no rows', async () => {
    mockApi({ changes: [], rounds: [] })
    render(<MemoryRouter><Changes /></MemoryRouter>)
    expect(await screen.findByText('No changes recorded yet.')).toBeInTheDocument()
    expect(screen.getByText('No watch rounds yet.')).toBeInTheDocument()
  })
})
