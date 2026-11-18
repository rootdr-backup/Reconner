import type { Notification } from './api'

export const sevDot: Record<string, string> = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-accent',
}

// Shared bell navigation. Both TopBar and the Changes notifications panel use
// the same mark-read call and route rules, so unread counts stay in sync.
export function openNotification(
  n: Notification,
  navigate: (path: string) => void,
  markRead: (ids: string[]) => Promise<unknown>,
): void {
  if (!n.is_read) void markRead([n.id]).catch(() => {})
  if (n.target_id) navigate(`/targets/${n.target_id}`)
  else if (n.url.startsWith('/') && !n.url.startsWith('//')) navigate(n.url)
  else if (/^https?:\/\//i.test(n.url)) window.open(n.url, '_blank', 'noopener,noreferrer')
}
