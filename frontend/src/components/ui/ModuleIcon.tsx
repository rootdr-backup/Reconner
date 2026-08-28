import { moduleCode, moduleGroup } from '../../lib/moduleIcons'

// Category colors drawn from the committed token palette: recon=info (blue),
// injection=accent (teal), analysis=medium (amber).
const GROUP_STYLE: Record<string, string> = {
  recon: 'text-severity-info border-severity-info/25 bg-severity-info/10',
  inject: 'text-accent-hover border-accent/40 bg-accent/10',
  analysis: 'text-severity-medium border-severity-medium/25 bg-severity-medium/10',
}

/**
 * ModuleIcon renders a module as a compact, monochrome, group-colored letter
 * badge — a clean replacement for the old emoji icons. Recon=info, injection=
 * accent, analysis=medium. Subtle lift on hover.
 */
export function ModuleIcon({ module, size = 20 }: { module?: string; size?: number }) {
  const g = moduleGroup(module)
  return (
    <span
      title={module}
      className={`inline-flex items-center justify-center rounded-md border font-mono font-semibold leading-none tracking-tight shrink-0 transition-transform duration-150 hover:scale-110 ${GROUP_STYLE[g]}`}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.42) }}
    >
      {moduleCode(module)}
    </span>
  )
}
