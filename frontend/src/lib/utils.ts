import { useEffect, useState } from 'react'

export function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(' ')
}

/* Debounced value — the standard fix for search/filter inputs that would
   otherwise re-query or re-filter on every keystroke. Callers filter/fetch
   against the returned value, which only settles `delay`ms after typing
   stops. 300ms is the project default for large-list search boxes. */
export function useDebouncedValue<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}

export function timeAgo(dateStr: string | null): string {
  if (!dateStr || dateStr === '0001-01-01T00:00:00Z') return 'Never'
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 10) return 'Just now'
  if (seconds < 60) return `${seconds}s ago`
  const m = Math.floor(seconds / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h`
  return `${Math.floor(hours / 24)}d`
}

// timeUntil renders a scheduled time from the viewer's point of view.
// A past timestamp means the work is due, so it reads "overdue by X" instead
// of "X ago". A future timestamp reads "in X".
export function timeUntil(dateStr: string | null): string {
  if (!dateStr || dateStr === '0001-01-01T00:00:00Z') return 'not scheduled'
  const ms = new Date(dateStr).getTime() - Date.now()
  if (!Number.isFinite(ms)) return 'unknown'
  const seconds = Math.round(ms / 1000)
  if (seconds > 0 && seconds < 10) return 'in a moment'
  if (seconds <= 0 && seconds > -10) return 'due now'
  if (seconds > 0) return `in ${formatDuration(seconds)}`
  return `${formatDuration(-seconds)} overdue`
}

export function truncate(str: string | null | undefined, max: number): string {
  if (!str) return ''
  return str.length <= max ? str : str.slice(0, max) + '…'
}

export function statusCodeColor(code: number): string {
  if (code >= 200 && code < 300) return 'text-severity-low'
  if (code >= 300 && code < 400) return 'text-accent'
  if (code >= 400 && code < 500) return 'text-severity-medium'
  if (code >= 500) return 'text-severity-critical'
  return 'text-text-muted'
}
