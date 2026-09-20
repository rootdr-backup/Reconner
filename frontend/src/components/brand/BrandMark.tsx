import { cn } from '../../lib/utils'

type BrandMarkProps = {
  className?: string
  size?: 'sm' | 'md' | 'lg'
  label?: string
}

const sizeClass = {
  sm: 'h-9 w-9 rounded-xl',
  md: 'h-11 w-11 rounded-[14px]',
  lg: 'h-16 w-16 rounded-2xl',
}

const iconClass = { sm: 'h-5 w-5', md: 'h-6 w-6', lg: 'h-9 w-9' }

// A small code-native brand asset: the outer ring is the monitored attack
// surface, the sweep is reconnaissance, and the linked nodes are discovered
// assets converging on one verified signal. Keeping it SVG makes it crisp at
// every dashboard density without shipping another image payload.
export function BrandMark({ className, size = 'md', label = 'Reconner' }: BrandMarkProps) {
  return (
    <span role="img" aria-label={label}
      className={cn('brand-mark relative grid shrink-0 place-items-center overflow-hidden text-white', sizeClass[size], className)}>
      <svg viewBox="0 0 32 32" fill="none" className={iconClass[size]} aria-hidden>
        <circle cx="16" cy="16" r="11" stroke="currentColor" strokeWidth="1.4" opacity=".78" />
        <path d="M16 5a11 11 0 0 1 10.2 6.9M16 27A11 11 0 0 1 5.7 20" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" />
        <path d="M16 16 23.2 9.8M16 16l-6.8-3.5M16 16l2.6 7.1" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" opacity=".9" />
        <circle cx="23.2" cy="9.8" r="1.8" fill="currentColor" />
        <circle cx="9.2" cy="12.5" r="1.45" fill="currentColor" opacity=".8" />
        <circle cx="18.6" cy="23.1" r="1.45" fill="currentColor" opacity=".8" />
        <circle cx="16" cy="16" r="2.4" fill="#071014" stroke="currentColor" strokeWidth="1.3" />
      </svg>
    </span>
  )
}
