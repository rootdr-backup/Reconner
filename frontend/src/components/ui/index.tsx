import React, { forwardRef } from 'react'

export function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(' ')
}

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary'|'secondary'|'ghost'|'danger'
  size?: 'sm'|'md'|'lg'
  loading?: boolean
}
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant='secondary', size='md', loading, children, className, disabled, ...props }, ref) => {
    const v = { primary:'btn-primary', secondary:'btn-secondary', ghost:'btn-ghost', danger:'btn-danger' }
    const s = { sm:'text-xs px-2.5 py-1', md:'text-sm px-3 py-1.5', lg:'text-sm px-4 py-2' }
    return (
      <button ref={ref} className={cn('btn', v[variant], s[size], className)} disabled={disabled || loading} {...props}>
        {loading && <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/></svg>}
        {children}
      </button>
    )
  }
)
Button.displayName = 'Button'

export const Badge = ({ children, variant='neutral', className }: { children: React.ReactNode; variant?: string; className?: string }) => {
  const v: Record<string,string> = {
    neutral:'badge-neutral', success:'badge-low', warning:'badge-medium', error:'badge-critical', info:'badge-info',
    critical:'badge-critical', high:'badge-high', medium:'badge-medium', low:'badge-low', unknown:'badge-neutral',
  }
  return <span className={cn('badge', v[variant] || 'badge-neutral', className)}>{children}</span>
}

export const Spinner = ({ className }: { className?: string }) => (
  <svg className={cn('animate-spin text-accent', className || 'w-5 h-5')} viewBox="0 0 24 24" fill="none">
    <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3"/>
    <path className="opacity-80" fill="currentColor" d="M4 12a8 8 0 018-8v3a5 5 0 00-5 5H4z"/>
  </svg>
)

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> { label?: string; error?: string }
export const Input = forwardRef<HTMLInputElement, InputProps>(({ label, error, className, ...props }, ref) => (
  <div className="w-full">
    {label && <label className="label">{label}</label>}
    <input ref={ref} className={cn('input', error ? 'border-severity-critical' : undefined, className)} {...props}/>
    {error && <p className="mt-1 text-xs text-severity-critical">{error}</p>}
  </div>
))
Input.displayName = 'Input'

export const Modal = ({ open, onClose, title, children, width='md' }: { open: boolean; onClose: () => void; title?: string; children: React.ReactNode; width?: 'sm'|'md'|'lg'|'xl' }) => {
  const w = { sm:'max-w-sm', md:'max-w-md', lg:'max-w-2xl', xl:'max-w-4xl' }
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4">
      <div className="absolute inset-0 bg-black/75 backdrop-blur-sm" onClick={onClose}/>
      {/* Column + max-height keeps the header pinned and the BODY scrolling,
          so forms/buttons can never fall out of the viewport on small screens. */}
      <div className={cn('relative bg-surface-2 border border-border rounded-lg shadow-2xl w-full max-h-[92vh] flex flex-col', w[width])}>
        {title && <div className="flex items-center justify-between gap-3 px-4 sm:px-5 py-3.5 border-b border-border shrink-0"><h2 className="text-sm sm:text-base font-semibold truncate min-w-0 font-mono" title={title}><span className="text-accent mr-1.5">$</span>{title}</h2><button onClick={onClose} className="text-text-muted hover:text-text-primary transition-colors shrink-0 text-lg leading-none px-1">✕</button></div>}
        <div className="p-4 sm:p-5 overflow-y-auto">{children}</div>
      </div>
    </div>
  )
}

export const Empty = ({ message }: { message: string }) => (
  <div className="flex items-center justify-center py-16"><p className="text-sm text-text-muted">{message}</p></div>
)

/* ── EmptyState ──────────────────────────────────────────────────────────
   Richer than <Empty>: icon + title + description + optional call-to-action.
   Use on pages where "there's nothing here yet" should nudge an action. */
export const EmptyState = ({ icon, title, description, action }: {
  icon?: React.ReactNode; title: string; description?: string; action?: React.ReactNode
}) => (
  <div className="flex flex-col items-center justify-center text-center py-16 px-6">
    {icon && <div className="grid place-items-center w-12 h-12 rounded-xl bg-surface-3 border border-border text-text-muted mb-4">{icon}</div>}
    <p className="text-sm font-semibold text-text-primary">{title}</p>
    {description && <p className="text-xs text-text-muted mt-1 max-w-sm">{description}</p>}
    {action && <div className="mt-4">{action}</div>}
  </div>
)

/* ── Skeleton ────────────────────────────────────────────────────────────
   Content-shaped loading placeholders. `.skeleton` (index.css) supplies the
   pulse + surface tint; here we only shape it. Respects reduced-motion via
   the global media query that neutralises animation-duration. */
export const Skeleton = ({ className, style }: { className?: string; style?: React.CSSProperties }) => (
  <div className={cn('skeleton', className || 'h-4 w-full')} style={style} />
)

// A block of stacked line-skeletons (e.g. a loading paragraph or list rows).
export const SkeletonText = ({ lines = 3, className }: { lines?: number; className?: string }) => (
  <div className={cn('space-y-2', className)}>
    {Array.from({ length: lines }).map((_, i) => (
      <Skeleton key={i} className="h-3.5 rounded" style={{ width: `${90 - (i % 3) * 18}%` }} />
    ))}
  </div>
)

// A table-shaped skeleton for list pages that stream large result sets.
export const SkeletonRows = ({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) => (
  <div className="space-y-2">
    {Array.from({ length: rows }).map((_, r) => (
      <div key={r} className="flex items-center gap-4 px-4 py-2.5">
        {Array.from({ length: cols }).map((_, c) => (
          <Skeleton key={c} className="h-3.5 rounded" style={{ flex: c === 0 ? '0 0 40%' : '1 1 0%' }} />
        ))}
      </div>
    ))}
  </div>
)

/* ── VirtualList ─────────────────────────────────────────────────────────
   Lightweight fixed-height windowed list — no external dependency. Renders
   only the rows in view (plus an overscan margin), so 5k–50k rows scroll at
   60fps instead of mounting tens of thousands of DOM nodes. Requires a fixed
   `rowHeight`; the scroll container gets `height`. For variable-height rows
   fall back to pagination. */
export function VirtualList<T>({ items, rowHeight, height, overscan = 8, renderRow, className, empty }: {
  items: T[]
  rowHeight: number
  height: number
  overscan?: number
  renderRow: (item: T, index: number) => React.ReactNode
  className?: string
  empty?: React.ReactNode
}) {
  const [scrollTop, setScrollTop] = React.useState(0)
  if (items.length === 0 && empty) return <>{empty}</>
  const total = items.length * rowHeight
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan)
  const visible = Math.ceil(height / rowHeight) + overscan * 2
  const last = Math.min(items.length, first + visible)
  const slice: React.ReactNode[] = []
  for (let i = first; i < last; i++) {
    slice.push(
      <div key={i} style={{ position: 'absolute', top: i * rowHeight, left: 0, right: 0, height: rowHeight }}>
        {renderRow(items[i], i)}
      </div>
    )
  }
  return (
    <div className={cn('overflow-y-auto no-scrollbar', className)} style={{ height }}
      onScroll={e => setScrollTop((e.target as HTMLDivElement).scrollTop)}>
      <div style={{ position: 'relative', height: total }}>{slice}</div>
    </div>
  )
}

export const CopyButton = ({ text }: { text: string }) => {
  const [copied, setCopied] = React.useState(false)
  return (
    <button onClick={() => navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })}
      className="text-text-muted hover:text-text-primary transition-colors text-xs" title="Copy">
      {copied ? '✓' : '⎘'}
    </button>
  )
}

export const StatCard = ({ label, value, color }: { label: string; value: string|number; color?: string }) => (
  <div className="card-term p-4 relative overflow-hidden group">
    <p className="text-[10px] text-text-muted mb-1 uppercase tracking-[.14em] font-mono truncate">
      <span className="text-accent mr-1">$</span>{label}
    </p>
    <p className={cn('text-2xl sm:text-3xl font-bold tabular-nums tracking-tight font-mono', color || 'text-text-primary')}>{value}</p>
  </div>
)

export const Table = ({ headers, children, empty }: { headers: string[]; children?: React.ReactNode; empty?: boolean }) => (
  <div className="overflow-x-auto">
    <table className="w-full">
      <thead><tr className="border-b border-border">{headers.map(h => <th key={h} className="table-header">{h}</th>)}</tr></thead>
      <tbody>{empty ? <tr><td colSpan={headers.length}><Empty message="No data found"/></td></tr> : children}</tbody>
    </table>
  </div>
)

export { ErrorBoundary } from './ErrorBoundary'
