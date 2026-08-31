import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { targets as targetsApi } from '../lib/api'
import { Button, Input, Modal, Spinner, Empty, Badge } from '../components/ui'
import { ScanModal } from '../components/targets/ScanModal'
import { useUIStore } from '../store/ui'
import { timeAgo, cn } from '../lib/utils'
import type { Target } from '../types'

// filterKind splits the unified target list back into its Web and Network
// halves (item 2 — restore the visual network/web separation). A "mixed" target
// (both domains and IP scope) shows under BOTH views, since it carries results
// for each pipeline. Undefined = the combined "All" view.
export default function Targets({ filterKind }: { filterKind?: 'web' | 'network' } = {}) {
  const navigate = useNavigate()
  const { addToast } = useUIStore()
  const [targets, setTargets] = useState<Target[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [scanTarget, setScanTarget] = useState<Target | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Target | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [form, setForm] = useState({ domain: '', name: '', description: '', tags: '', priority: 'medium', notes: '', exclude: '' })
  const [editTarget, setEditTarget] = useState<Target | null>(null)
  const [sortBy, setSortBy] = useState('findings')
  const [submitting, setSubmitting] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  // Multi-select state for bulk actions (checkbox per card + select-all).
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [selectMode, setSelectMode] = useState(false)
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkDeleting, setBulkDeleting] = useState(false)

  const load = async (q?: string) => {
    try {
      const p: Record<string, string> = {}
      if (q) p.search = q
      const list = await targetsApi.list(p) || []
      setTargets(list)
      // Drop any selected ids that no longer exist after a reload.
      setSelected(prev => {
        const next = new Set<string>()
        for (const t of list) if (prev.has(t.id)) next.add(t.id)
        return next
      })
    } catch { /**/ } finally { setLoading(false) }
  }

  useEffect(() => { setSelected(new Set()); setSelectMode(false) }, [])

  // A target matches the Web view when it carries any web scope (kind 'web' or
  // 'mixed'), the Network view when it carries any network scope ('network' or
  // 'mixed'). Older rows may have no kind set — treat those as web so they never
  // vanish from the default landing view. Undefined filterKind = combined view.
  const matchesKind = (t: Target) => {
    if (!filterKind) return true
    const k = t.kind || 'web'
    return filterKind === 'web' ? (k === 'web' || k === 'mixed') : (k === 'network' || k === 'mixed')
  }
  const kindTargets = targets.filter(matchesKind)

  const toggleSelect = (id: string) => setSelected(prev => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id); else next.add(id)
    return next
  })
  const allSelected = kindTargets.length > 0 && kindTargets.every(t => selected.has(t.id))
  const toggleSelectAll = () => setSelected(allSelected ? new Set() : new Set(kindTargets.map(t => t.id)))

  const handleBulkDelete = async () => {
    if (selected.size === 0) return
    setBulkDeleting(true)
    try {
      const res = await targetsApi.bulkDelete([...selected])
      addToast('success', `Deleted ${res.deleted} target${res.deleted === 1 ? '' : 's'}${res.failed ? ` · ${res.failed} failed` : ''}`)
      setBulkOpen(false)
      setSelected(new Set())
      setSelectMode(false)
      load(search)
    } catch {
      addToast('error', 'Bulk delete failed')
    } finally { setBulkDeleting(false) }
  }

  useEffect(() => { setLoading(true); load() }, [])
  useEffect(() => {
    const t = setTimeout(() => load(search), 300)
    return () => clearTimeout(t)
  }, [search])

  const emptyForm = { domain: '', name: '', description: '', tags: '', priority: 'medium', notes: '', exclude: '' }

  const openEdit = (t: Target) => {
    setForm({
      domain: t.domain, name: t.name || '', description: t.description || '',
      tags: (t.tags || []).join(', '), priority: t.priority || 'medium',
      notes: t.notes || '', exclude: t.exclude_scope || '',
    })
    setEditTarget(t)
  }

  const handleSubmit = async () => {
    if (!form.domain.trim()) return
    setSubmitting(true)
    const payload = {
      domain: form.domain.trim(),
      name: form.name.trim(),
      description: form.description,
      tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
      priority: form.priority,
      notes: form.notes,
      exclude_scope: form.exclude.trim(),
    }
    try {
      if (editTarget) {
        await targetsApi.update(editTarget.id, payload)
        addToast('success', `${form.name.trim() || form.domain.trim()} updated`)
        setEditTarget(null)
      } else {
        await targetsApi.create(payload)
        const hostCount = form.domain.split(/[\s,;]+/).filter(Boolean).length
        const addedLabel = form.name.trim() || (hostCount > 1 ? `${hostCount} targets` : form.domain.trim())
        addToast('success', `${addedLabel} added`)
        setCreateOpen(false)
      }
      setForm(emptyForm)
      load()
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed')
    } finally { setSubmitting(false) }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await targetsApi.delete(deleteTarget.id)
      addToast('success', `${deleteTarget.domain} deleted`)
      setDeleteTarget(null)
      load()
    } catch {
      addToast('error', 'Failed to delete target')
    } finally { setDeleting(false) }
  }

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      const res = await targetsApi.importFile(file)
      addToast('success', `Imported ${res.imported} of ${res.total}`)
      load()
    } catch { addToast('error', 'Import failed') }
    if (fileRef.current) fileRef.current.value = ''
  }

  const dot: Record<string, string> = {
    idle: 'bg-text-muted',
    running: 'bg-accent animate-pulse',
    finished: 'bg-severity-low',
    failed: 'bg-severity-critical',
  }

  const prioRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
  const sortedTargets = [...kindTargets].sort((a, b) => {
    switch (sortBy) {
      case 'findings':   return (b.finding_count || 0) - (a.finding_count || 0)
      case 'subdomains': return (b.subdomain_count || 0) - (a.subdomain_count || 0)
      case 'alive':      return (b.alive_host_count || 0) - (a.alive_host_count || 0)
      case 'name':       return (a.name || a.domain).localeCompare(b.name || b.domain)
      case 'priority':   return (prioRank[b.priority] || 0) - (prioRank[a.priority] || 0)
      case 'status':     return (a.scan_status || '').localeCompare(b.scan_status || '')
      case 'last_scan':  return (b.last_scan_at || '').localeCompare(a.last_scan_at || '')
      case 'created':
      default:           return (b.created_at || '').localeCompare(a.created_at || '')
    }
  })

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">
            {filterKind === 'web' ? 'Web Targets' : filterKind === 'network' ? 'Network Targets' : 'Targets'}
          </h1>
          <p className="text-xs text-text-muted">
            {kindTargets.length} target{kindTargets.length === 1 ? '' : 's'} · domains &amp; subdomains — web application scanning
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {kindTargets.length > 0 && (
            <Button size="sm" variant="ghost" onClick={() => { setSelectMode(m => !m); setSelected(new Set()) }}>
              {selectMode ? 'Done' : 'Select'}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => fileRef.current?.click()}>Import</Button>
          <Button size="sm" variant="primary" onClick={() => setCreateOpen(true)}>+ Add Target</Button>
          <input ref={fileRef} type="file" accept=".txt,.csv" onChange={handleImport} className="hidden" />
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <Input placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} className="sm:max-w-xs" />
        <label className="flex items-center gap-1.5 text-xs text-text-muted">
          Sort
          <select value={sortBy} onChange={e => setSortBy(e.target.value)}
            className="bg-surface-alt border border-border rounded px-2 py-1.5 text-xs text-text-primary">
            <option value="findings" className="bg-surface-3">Findings</option>
            <option value="subdomains" className="bg-surface-3">Subdomains</option>
            <option value="alive" className="bg-surface-3">Alive hosts</option>
            <option value="priority" className="bg-surface-3">Priority</option>
            <option value="name" className="bg-surface-3">Name (A–Z)</option>
            <option value="status" className="bg-surface-3">Scan status</option>
            <option value="last_scan" className="bg-surface-3">Last scan</option>
            <option value="created" className="bg-surface-3">Newest</option>
          </select>
        </label>
        {selectMode && (
          <div className="flex items-center gap-3 text-xs">
            <label className="flex items-center gap-1.5 cursor-pointer text-text-secondary select-none">
              <input type="checkbox" checked={allSelected} onChange={toggleSelectAll} className="accent-accent w-3.5 h-3.5" />
              Select all
            </label>
            <span className="text-text-muted">{selected.size} selected</span>
            <Button size="sm" variant="danger" disabled={selected.size === 0} onClick={() => setBulkOpen(true)}>
              Delete selected
            </Button>
          </div>
        )}
      </div>

      {loading
        ? <div className="flex items-center justify-center h-48"><Spinner /></div>
        : kindTargets.length === 0
          ? <Empty message={filterKind === 'web' ? 'No web targets yet — add a domain to start the web pipeline.'
              : filterKind === 'network' ? 'No network targets yet — add an IP, CIDR or range to start the network pipeline.'
              : 'No targets yet.'} />
          : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {sortedTargets.map(t => (
                <div
                  key={t.id}
                  className={cn('card-hover p-4 cursor-pointer', selectMode && selected.has(t.id) && 'ring-1 ring-accent')}
                  onClick={() => selectMode ? toggleSelect(t.id) : navigate(`/targets/${t.id}`)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2 min-w-0">
                      {selectMode && (
                        <input
                          type="checkbox"
                          checked={selected.has(t.id)}
                          onChange={() => toggleSelect(t.id)}
                          onClick={e => e.stopPropagation()}
                          className="accent-accent w-3.5 h-3.5 shrink-0"
                        />
                      )}
                      <span className={cn('w-2 h-2 rounded-full shrink-0', dot[t.scan_status] || 'bg-text-muted')} />
                      <span className="text-sm font-semibold truncate" title={t.domain}>{t.name || t.domain}</span>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={e => { e.stopPropagation(); setScanTarget(t) }}
                      >
                        Scan
                      </Button>
                      <button
                        onClick={e => { e.stopPropagation(); openEdit(t) }}
                        className="p-1.5 rounded text-text-muted hover:text-accent hover:bg-accent/10 transition-colors"
                        title="Edit target"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button
                        onClick={e => { e.stopPropagation(); setDeleteTarget(t) }}
                        className="p-1.5 rounded text-text-muted hover:text-severity-critical hover:bg-severity-critical/10 transition-colors"
                        title="Delete target"
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2 mb-3 text-center">
                    <div>
                      <p className="text-lg font-semibold text-severity-low">{t.subdomain_count}</p>
                      <p className="text-xs text-text-muted">Subdomains</p>
                    </div>
                    <div>
                      <p className="text-lg font-semibold">{t.alive_host_count}</p>
                      <p className="text-xs text-text-muted">Alive</p>
                    </div>
                    <div>
                      <p className={cn('text-lg font-semibold', t.finding_count > 0 ? 'text-severity-high' : '')}>{t.finding_count}</p>
                      <p className="text-xs text-text-muted">Findings</p>
                    </div>
                  </div>

                  {t.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {t.tags.map(tag => <Badge key={tag}>{tag}</Badge>)}
                    </div>
                  )}

                  <div className="flex justify-between text-xs text-text-muted">
                    <span className="capitalize">{t.scan_status}</span>
                    <span>{t.last_scan_at ? timeAgo(t.last_scan_at) : 'Never scanned'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

      {/* Create / Edit Modal */}
      <Modal open={createOpen || !!editTarget} onClose={() => { setCreateOpen(false); setEditTarget(null); setForm(emptyForm) }}
        title={editTarget ? 'Edit Target' : 'Add Target'} width="md">
        <div className="space-y-3">
          <Input label="Name" placeholder="friendly label for this target (optional)"
            value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          <div>
            <label className="label">Scope — domains &amp; subdomains *</label>
            <textarea className="input resize-none font-mono text-xs" rows={5}
              placeholder={"One or more web hosts — comma or newline separated:\nexample.com\napi.example.com\napp.example.com"}
              value={form.domain} onChange={e => setForm({ ...form, domain: e.target.value })} />
            <p className="text-[10px] text-text-muted mt-1">
              Add one or more domains/subdomains to scan. Subdomain enumeration runs only when you tick it in the scan dialog.
              Pasted <span className="font-mono">http://host:port/</span> is cleaned automatically.
            </p>
          </div>
          <div>
            <label className="label">Exclude (out of scope) — optional</label>
            <textarea className="input resize-none font-mono text-xs" rows={2}
              placeholder={"never scan these: dev.example.com, *.staging.example.com, 10.0.0.0/24, https://admin.example.com/"}
              value={form.exclude} onChange={e => setForm({ ...form, exclude: e.target.value })} />
            <p className="text-[10px] text-text-muted mt-1">
              Excluded hosts/IPs/CIDRs/URLs are dropped before probing — nothing excluded is ever scanned or reported. Supports
              <span className="font-mono"> *.wildcards</span> and CIDRs.
            </p>
          </div>
          <Input label="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          <Input label="Tags (comma separated)" placeholder="bug-bounty, prod" value={form.tags} onChange={e => setForm({ ...form, tags: e.target.value })} />
          <div>
            <label className="label">Priority</label>
            <select className="input" value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })}>
              {['low', 'medium', 'high', 'critical'].map(p => (
                <option key={p} value={p} className="bg-surface-3 capitalize">{p}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Notes</label>
            <textarea className="input resize-none" rows={2} value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
          </div>
          <div className="flex justify-end gap-2 pt-2 border-t border-border">
            <Button variant="ghost" onClick={() => { setCreateOpen(false); setEditTarget(null); setForm(emptyForm) }}>Cancel</Button>
            <Button variant="primary" loading={submitting} onClick={handleSubmit}>{editTarget ? 'Save changes' : 'Create'}</Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirm Modal */}
      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Delete Target" width="sm">
        <div className="space-y-4">
          <p className="text-sm text-text-secondary">
            Are you sure you want to delete <span className="font-semibold text-text-primary break-words" title={deleteTarget?.domain}>
              {deleteTarget?.name || (deleteTarget && deleteTarget.domain.length > 60 ? deleteTarget.domain.slice(0, 60) + '…' : deleteTarget?.domain)}
            </span>?
            This will permanently remove all subdomains, findings, and scan data.
          </p>
          <div className="flex justify-end gap-2 pt-2 border-t border-border">
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="danger" loading={deleting} onClick={handleDelete}>Delete</Button>
          </div>
        </div>
      </Modal>

      {/* Bulk Delete Confirm Modal */}
      <Modal open={bulkOpen} onClose={() => setBulkOpen(false)} title="Delete Selected Targets" width="sm">
        <div className="space-y-4">
          <p className="text-sm text-text-secondary">
            Permanently delete <span className="font-semibold text-text-primary">{selected.size}</span> selected
            target{selected.size === 1 ? '' : 's'} and all of their subdomains,
            findings, and scan data? This cannot be undone.
          </p>
          <div className="flex justify-end gap-2 pt-2 border-t border-border">
            <Button variant="ghost" onClick={() => setBulkOpen(false)}>Cancel</Button>
            <Button variant="danger" loading={bulkDeleting} onClick={handleBulkDelete}>Delete {selected.size}</Button>
          </div>
        </div>
      </Modal>

      {scanTarget && (
        <ScanModal
          target={scanTarget}
          open={true}
          onClose={() => setScanTarget(null)}
          onStarted={() => load()}
        />
      )}
    </div>
  )
}
