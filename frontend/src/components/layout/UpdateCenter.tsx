import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { system, type UpdateInfo } from '../../lib/api'
import { useUIStore } from '../../store/ui'
import { cn } from '../../lib/utils'

const CHECK_INTERVAL = 6 * 60 * 60 * 1000
const DISMISSED_KEY = 'reconner.dismissed-release'

interface UpdateCenterValue {
  info: UpdateInfo | null
  checking: boolean
  visible: boolean
  refresh: () => Promise<void>
  dismiss: () => void
  showDetails: () => void
}

const UpdateCenterContext = createContext<UpdateCenterValue | null>(null)

export function useUpdateCenter() {
  const value = useContext(UpdateCenterContext)
  if (!value) throw new Error('useUpdateCenter must be used inside UpdateCenterProvider')
  return value
}

export function UpdateCenterProvider({ children }: { children: React.ReactNode }) {
  const [info, setInfo] = useState<UpdateInfo | null>(null)
  const [checking, setChecking] = useState(false)
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(DISMISSED_KEY) || '')
  const [detailsOpen, setDetailsOpen] = useState(false)
  const [installMode, setInstallMode] = useState<'docker' | 'source'>('docker')
  const lastCheckedRef = useRef(0)
  const addToast = useUIStore(s => s.addToast)

  const load = useCallback(async (force = false) => {
    setChecking(true)
    try {
      const result = await system.updateCheck(force)
      setInfo(result)
      lastCheckedRef.current = result.checked_at ? Date.parse(result.checked_at) : Date.now()
    } catch {
      // Update checks must never interrupt scanning or block the dashboard.
    } finally {
      setChecking(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = window.setInterval(() => load(), CHECK_INTERVAL)
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return
      const checked = lastCheckedRef.current
      if (!checked || Date.now() - checked >= CHECK_INTERVAL) load()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      window.clearInterval(interval)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [load])

  useEffect(() => {
    if (!detailsOpen) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setDetailsOpen(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [detailsOpen])

  const refresh = useCallback(async () => { await load(true) }, [load])
  const dismiss = useCallback(() => {
    if (!info?.latest) return
    localStorage.setItem(DISMISSED_KEY, info.latest)
    setDismissed(info.latest)
  }, [info?.latest])

  const visible = Boolean(info?.enabled && info.update_available && dismissed !== info.latest)
  const value = useMemo(() => ({
    info, checking, visible, refresh, dismiss, showDetails: () => setDetailsOpen(true),
  }), [info, checking, visible, refresh, dismiss])

  const dockerCommand = `docker compose pull reconner\ndocker compose up -d --no-deps reconner\ndocker compose ps`
  const sourceCommand = `git pull --ff-only origin main\ndocker compose up -d --build reconner\ndocker compose ps`
  const command = installMode === 'docker' ? dockerCommand : sourceCommand

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(command)
      addToast('success', 'Update commands copied')
    } catch {
      addToast('error', 'Could not copy commands')
    }
  }

  return (
    <UpdateCenterContext.Provider value={value}>
      {children}
      {detailsOpen && info && (
        <div className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center sm:p-4" role="dialog" aria-modal="true" aria-labelledby="release-title">
          <button className="absolute inset-0 bg-black/75 backdrop-blur-sm" onClick={() => setDetailsOpen(false)} aria-label="Close release details" />
          <section className="relative w-full sm:max-w-2xl max-h-[92dvh] overflow-hidden rounded-t-2xl sm:rounded-2xl border border-border bg-surface-2 shadow-2xl animate-slide-up">
            <header className="flex items-start justify-between gap-4 px-5 sm:px-6 py-5 border-b border-border bg-gradient-to-r from-accent/[.10] to-transparent">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-accent">Stable release</p>
                <h2 id="release-title" className="mt-1 text-xl font-semibold">Reconner v{info.latest}</h2>
                <p className="mt-1 text-xs text-text-muted">Installed v{info.current} · update when active scans finish</p>
              </div>
              <button onClick={() => setDetailsOpen(false)} className="grid place-items-center w-9 h-9 rounded-lg text-text-muted hover:text-text-primary hover:bg-white/[.06]" aria-label="Close">✕</button>
            </header>

            <div className="overflow-y-auto max-h-[calc(92dvh-88px)] p-5 sm:p-6 space-y-5">
              <div>
                <p className="section-title">What changed</p>
                <pre className="release-notes">{info.notes || 'No release notes were provided for this version.'}</pre>
              </div>

              <div>
                <div className="flex items-center justify-between gap-3 mb-3">
                  <p className="section-title !mb-0">Update safely</p>
                  <div className="segmented-control" aria-label="Installation method">
                    <button className={cn(installMode === 'docker' && 'active')} onClick={() => setInstallMode('docker')}>Prebuilt image</button>
                    <button className={cn(installMode === 'source' && 'active')} onClick={() => setInstallMode('source')}>Local build</button>
                  </div>
                </div>
                <div className="relative rounded-xl border border-border bg-[#070a0f] p-4 pr-12 overflow-x-auto">
                  <pre className="font-mono text-xs leading-6 text-accent-hover whitespace-pre">{command}</pre>
                  <button onClick={copyCommand} className="absolute right-3 top-3 btn-ghost !p-2" title="Copy commands" aria-label="Copy update commands">⎘</button>
                </div>
                <p className="mt-2 text-[11px] leading-5 text-text-muted">Your database and configuration remain in the persistent Docker volume. Updating recreates the application container, so wait for running scans to finish first.</p>
              </div>

              <footer className="flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-3 pt-4 border-t border-border">
                <button onClick={() => { dismiss(); setDetailsOpen(false) }} className="btn-ghost justify-center text-xs">Remind me on the next release</button>
                <div className="flex gap-2">
                  {info.url && <a href={info.url} target="_blank" rel="noreferrer" className="btn-secondary flex-1 sm:flex-none justify-center">Release notes ↗</a>}
                  <button onClick={() => setDetailsOpen(false)} className="btn-primary flex-1 sm:flex-none justify-center">Done</button>
                </div>
              </footer>
            </div>
          </section>
        </div>
      )}
    </UpdateCenterContext.Provider>
  )
}
