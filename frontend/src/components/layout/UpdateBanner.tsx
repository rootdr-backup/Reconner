import { useUpdateCenter } from './UpdateCenter'

export const UpdateBanner = () => {
  const { info, visible, dismiss, showDetails } = useUpdateCenter()
  if (!visible || !info) return null

  return (
    <div className="relative flex flex-wrap sm:flex-nowrap items-center gap-x-3 gap-y-2 px-4 sm:px-6 py-2.5 border-b border-accent/25 bg-accent/[.08] text-xs">
      <span className="relative flex h-2.5 w-2.5 shrink-0">
        <span className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-50 animate-ping" />
        <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-accent" />
      </span>
      <p className="min-w-0 flex-1 text-text-secondary">
        <span className="font-semibold text-text-primary">Reconner v{info.latest} is ready.</span>
        <span className="hidden sm:inline"> New detections, fixes and performance improvements are available.</span>
      </p>
      <div className="flex items-center gap-1.5 ml-5 sm:ml-0">
        <button onClick={showDetails} className="btn-primary !py-1 !px-2.5 text-[11px]">Review update</button>
        <button onClick={dismiss} className="grid place-items-center w-7 h-7 rounded-md text-text-muted hover:text-text-primary hover:bg-white/[.06]" title="Hide until the next release" aria-label="Dismiss update">✕</button>
      </div>
    </div>
  )
}
