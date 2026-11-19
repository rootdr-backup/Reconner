import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ChangeLog from './ChangeLog'
import { ws } from '../../lib/websocket'
import type { ChangeEntry } from '../../types'

const rowsA: ChangeEntry[] = [
  {
    id: 'a1', source: 'watch', target_id: 't1', target_name: 'alpha.test',
    task_id: 'round-1', url: 'https://alpha.test', change_type: 'status_change',
    category: 'http', severity: 'medium', seen: false,
    old_value: 'status=403 title=Forbidden', new_value: 'status=200 title=OK',
    detected_at: '2026-01-02 10:00:00',
  },
]

const rowsB: ChangeEntry[] = [
  {
    id: 'b1', source: 'notification', target_id: 't1', target_name: 'alpha.test',
    task_id: '', url: '', change_type: 'new_subdomain',
    category: 'assets', severity: 'medium', seen: false,
    old_value: '', new_value: '1 new subdomain(s) found on alpha.test',
    metadata: { hosts: ['new.alpha.test'], total: 1 },
    detected_at: '2026-01-03 10:00:00',
  },
]

function envelope(data: unknown[]) {
  return new Response(JSON.stringify({ data, total: data.length, page: 1, limit: 200 }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })
}

function success(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}

function changesCount(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls.filter(([input]) => String(input).startsWith('/api/changes?')).length
}

function installFetch(options?: { rows?: ChangeEntry[]; firstChanges?: Promise<Response> }) {
  let changesCalls = 0
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url.startsWith('/api/changes?')) {
      changesCalls++
      if (changesCalls === 1 && options?.firstChanges) return options.firstChanges
      return envelope(options?.rows ?? rowsA)
    }
    if (url.startsWith('/api/watch/rounds?')) return envelope([])
    if (url.startsWith('/api/targets?')) return success([])
    return success([])
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

type WsHandler = (payload: unknown) => void

function captureWs() {
  const handlers = new Map<string, WsHandler[]>()
  const spy = vi.spyOn(ws, 'on').mockImplementation((type: string, handler: WsHandler) => {
    const list = handlers.get(type) ?? []
    list.push(handler)
    handlers.set(type, list)
    return () => {}
  })
  return {
    handlers,
    spy,
    fire(type: string) { (handlers.get(type) ?? []).forEach(h => h({})) },
  }
}

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('ChangeLog loading and refresh', () => {
  it('renders cards and clears the skeleton after the first load', async () => {
    installFetch()
    render(<ChangeLog />)
    expect(await screen.findByText('STATUS CODE')).toBeInTheDocument()
    await vi.waitFor(() => {
      expect(document.querySelectorAll('.skeleton').length).toBe(0)
    })
  })

  it('coalesces a refresh triggered during the first load and still clears the skeleton', async () => {
    vi.useFakeTimers()
    const first = deferred<Response>()
    const fetchMock = installFetch({ firstChanges: first.promise, rows: rowsB })
    const wsMock = captureWs()
    render(<ChangeLog />)

    expect(document.querySelectorAll('.skeleton').length).toBeGreaterThan(0)
    wsMock.fire('task_progress')
    await vi.advanceTimersByTimeAsync(2500)
    // The refresh was folded into the in-flight load; no extra query yet.
    expect(changesCount(fetchMock)).toBe(1)

    first.resolve(envelope(rowsA))
    // The follow-up refresh runs once the first load finishes.
    await vi.waitFor(() => expect(changesCount(fetchMock)).toBe(2))
    await vi.waitFor(() => expect(screen.getByText('NEW HOST')).toBeInTheDocument())
    await vi.waitFor(() => {
      expect(document.querySelectorAll('.skeleton').length).toBe(0)
    })
  })

  it('collapses a burst of WS events into one follow-up fetch', async () => {
    vi.useFakeTimers()
    const fetchMock = installFetch()
    const wsMock = captureWs()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('STATUS CODE')).toBeInTheDocument())

    const before = changesCount(fetchMock)
    wsMock.fire('task_progress')
    wsMock.fire('scope_landed')
    wsMock.fire('notification_created')
    await vi.advanceTimersByTimeAsync(2500)
    await vi.waitFor(() => expect(changesCount(fetchMock)).toBe(before + 1))

    await vi.advanceTimersByTimeAsync(5000)
    expect(changesCount(fetchMock)).toBe(before + 1)
  })

  it('does not poll the changes feed on a 30 second interval', async () => {
    vi.useFakeTimers()
    const fetchMock = installFetch()
    captureWs()
    render(<ChangeLog />)
    await vi.waitFor(() => expect(screen.getByText('STATUS CODE')).toBeInTheDocument())

    const before = changesCount(fetchMock)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(changesCount(fetchMock)).toBe(before)
  })
})
