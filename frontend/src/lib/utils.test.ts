import { afterEach, describe, expect, it, vi } from 'vitest'
import { timeUntil } from './utils'

describe('timeUntil', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders a future schedule as a wait', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-11-17T12:00:00Z'))
    expect(timeUntil('2026-11-17T12:37:00Z')).toBe('in 37m')
  })

  it('renders a past schedule as overdue', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-11-17T12:00:00Z'))
    expect(timeUntil('2026-11-17T11:23:00Z')).toBe('37m overdue')
  })

  it('handles a missing schedule', () => {
    expect(timeUntil(null)).toBe('not scheduled')
  })
})
