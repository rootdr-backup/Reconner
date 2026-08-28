import { useEffect, useState } from 'react'
import { system, type UpdateInfo } from '../../lib/api'

// A quiet, professional "new version available" banner. It polls the backend
// (which itself caches the GitHub lookup) once on load and then hourly, and only
// appears when a newer release is published. Dismissal is remembered per version,
// so it comes back when a newer version ships but not for the one you dismissed.
export const UpdateBanner = () => {
  const [info, setInfo] = useState<UpdateInfo | null>(null)
  const [open, setOpen] = useState(false)
  const [dismissed, setDismissed] = useState('')

  useEffect(() => {
    let alive = true
    const check = async () => {
      try {
        const u = await system.updateCheck()
        if (alive) setInfo(u)
      } catch { /* ignore */ }
    }
    check()
    const t = setInterval(check, 60 * 60 * 1000) // hourly
    return () => { alive = false; clearInterval(t) }
  }, [])

  useEffect(() => {
    if (info?.update_available) {
      setDismissed(sessionStorage.getItem('reconner_update_dismissed') || '')
    }
  }, [info])

  if (!info?.update_available || dismissed === info.latest) return null

  const dismiss = () => {
    sessionStorage.setItem('reconner_update_dismissed', info.latest)
    setDismissed(info.latest)
  }

  return (
    <>
      <div className="flex items-center gap-3 px-4 py-2 text-xs border-b border-accent/25 bg-accent/[.08] text-text-secondary">
        <span className="w-2 h-2 rounded-full bg-accent animate-pulse shrink-0" />
        <span className="min-w-0">
          <span className="font-semibold text-accent">Update available</span>
          {' '}— Reconner <span className="font-mono">v{info.latest}</span> is out
          {' '}(you're on <span className="font-mono">v{info.current}</span>).
        </span>
        <div className="ml-auto flex items-center gap-2 shrink-0">
          <button onClick={() => setOpen(true)} className="btn-secondary text-[11px] py-1">What's new</button>
          {info.url && (
            <a href={info.url} target="_blank" rel="noreferrer" className="btn-primary text-[11px] py-1">View release</a>
          )}
          <button onClick={dismiss} title="Dismiss until the next version"
            className="text-text-muted hover:text-text-primary px-1">✕</button>
        </div>
      </div>

      {open && (
        <div className="fixed inset-0 z-[90] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <div className="relative bg-surface-2 border border-border rounded-xl shadow-2xl w-full max-w-lg">
            <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-border">
              <h2 className="text-base font-semibold truncate">Reconner v{info.latest} — release notes</h2>
              <button onClick={() => setOpen(false)} className="text-text-muted hover:text-text-primary shrink-0">✕</button>
            </div>
            <div className="p-5 space-y-4">
              <pre className="text-xs text-text-secondary whitespace-pre-wrap break-words max-h-72 overflow-auto bg-bg-secondary/50 p-3 rounded border border-border">
{info.notes || 'No release notes provided.'}
              </pre>
              <div>
                <p className="text-xs font-semibold text-text-primary mb-1">How to update</p>
                <pre className="text-[11px] font-mono text-accent whitespace-pre-wrap bg-bg-secondary/50 p-3 rounded border border-border">git pull &amp;&amp; make &amp;&amp; ./reconner serve</pre>
              </div>
              <div className="flex justify-end gap-2 pt-2 border-t border-border">
                {info.url && <a href={info.url} target="_blank" rel="noreferrer" className="btn-secondary text-sm">Open on GitHub</a>}
                <button onClick={() => setOpen(false)} className="btn-primary text-sm">Close</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
