import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import System from './System'
import { UpdateCenterProvider } from '../components/layout/UpdateCenter'
import { useAuthStore } from '../store/auth'
import { useUIStore } from '../store/ui'

const scanCfg = {
  dns_resolvers: ['1.1.1.1'],
  subdomain_recursion_depth: 4,
  subdomain_recursion_enabled: true,
  http_catchall_detection: true,
  nuclei_exclude_template_ids: [],
  nuclei_extra_template_repos: [],
  monitor_modules: [],
  default_dns_resolvers: ['1.1.1.1'],
  default_nuclei_repos: [],
  max_concurrent_scans: 2,
  max_concurrent_deep_scans: 1,
  max_concurrent_watch_scans: 1,
  envelope_total: 4,
  envelope_deep: 1,
  envelope_watch: 3,
  watch_http_threads: 10,
  watch_http_rate_limit: 25,
  watch_rounds_min_gap: 30,
  watch_round_interval_hours: 12,
  watch_source_timeout_minutes: 5,
  watch_enumeration_sources: ['subfinder', 'assetfinder'],
  watch_rows_retention_days: 30,
  watch_scope_events_retention_days: 180,
  watch_notify_host_cap: 20,
  watch_fail_limit: 3,
  watch_module_set: ['subdomain_enum', 'http_probe'],
}

function ok(data: unknown) {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

let fetchMock: ReturnType<typeof vi.fn>
let patchBody: Record<string, unknown> | null

function mockApi() {
  patchBody = null
  fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === '/api/system/scan-config' && init?.method === 'PATCH') {
      patchBody = JSON.parse(String(init.body || '{}')) as Record<string, unknown>
      return ok({ ...scanCfg, ...patchBody })
    }
    if (url === '/api/system/scan-config') return ok(scanCfg)
    if (url.startsWith('/api/system/update-check')) {
      return ok({ enabled: true, current: '5.1.1', latest: '5.1.1', channel: 'stable', update_available: false, checked_at: '' })
    }
    if (url === '/api/tools/status') return ok({})
    if (url === '/api/tools/catalog') return ok([])
    if (url === '/api/system/stats') return ok({})
    if (url === '/api/system/settings') return ok({ api_keys: [] })
    if (url === '/api/system/telegram') return ok({
      configured: false, enabled: false, masked_token: '', bot_username: '', connected: false,
      last_error: '', last_connected_at: '', pending: 0, failed: 0, chats: [],
    })
    return ok({})
  })
  vi.stubGlobal('fetch', fetchMock)
}

function renderSystem() {
  return render(
    <MemoryRouter>
      <UpdateCenterProvider>
        <System />
      </UpdateCenterProvider>
    </MemoryRouter>,
  )
}

describe('System scanning concurrency', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: { id: 1, username: 'admin', role: 'admin' }, initialized: true, loading: false } as never)
    useUIStore.setState({ toasts: [] })
    mockApi()
  })
  afterEach(() => vi.unstubAllGlobals())

  it('shows the visible hardware envelope and the new helper text, not the stale box-limit text', async () => {
    renderSystem()
    const tab = await screen.findByRole('tab', { name: 'Toolchain' })
    await userEvent.setup().click(tab)
    await waitFor(() => expect(screen.getByText('Scanning configuration')).toBeInTheDocument())
    expect(screen.getByText('Safe range for this box')).toBeInTheDocument()
    expect(screen.getByText(/Total 4 · deep 1 · watch 3/)).toBeInTheDocument()
    expect(screen.getByText(/Values apply while the box is healthy/)).toBeInTheDocument()
    expect(screen.queryByText(/The box limit lowers this further/)).not.toBeInTheDocument()
  })

  it('saves the authoritative concurrency values the operator enters', async () => {
    const user = userEvent.setup()
    renderSystem()
    const tab = await screen.findByRole('tab', { name: 'Toolchain' })
    await user.click(tab)
    await waitFor(() => expect(screen.getByText('Scanning configuration')).toBeInTheDocument())

    const watchInput = screen.getByLabelText('Watch rounds in parallel') as HTMLInputElement
    const deepInput = screen.getByLabelText('Deep scans in parallel') as HTMLInputElement
    const totalInput = screen.getByLabelText('Total scans in parallel') as HTMLInputElement
    fireEvent.change(watchInput, { target: { value: '16' } })
    fireEvent.change(deepInput, { target: { value: '8' } })
    fireEvent.change(totalInput, { target: { value: '32' } })

    await user.click(screen.getByRole('button', { name: 'Save configuration' }))
    await waitFor(() => expect(patchBody).not.toBeNull())
    expect(patchBody!.max_concurrent_watch_scans).toBe(16)
    expect(patchBody!.max_concurrent_deep_scans).toBe(8)
    expect(patchBody!.max_concurrent_scans).toBe(32)
  })
})
