import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { bounty as bountyApi } from '../lib/api'
import { Badge, Button, EmptyState, Input, Modal, Skeleton } from '../components/ui'
import { useAuthStore } from '../store/auth'
import { useUIStore } from '../store/ui'
import { cn, timeAgo } from '../lib/utils'
import type { BountyAsset, BountyProgram, BountySyncState } from '../types'
import type { BountyProgramList } from '../lib/api'

type Filters = {
  search: string; provider: string; bounties: string; wildcard: string; assetType: string
  minAssets: string; maxAssets: string; minReward: string; programType: string
  safeHarbor: string; industry: string; status: string; sort: string
}

const initialFilters: Filters = {
  search: '', provider: '', bounties: '', wildcard: '', assetType: '', minAssets: '', maxAssets: '', minReward: '',
  programType: '', safeHarbor: '', industry: '', status: 'live', sort: 'newest',
}

const providerLabel = (p: string) => ({ hackerone: 'HackerOne', bugcrowd: 'Bugcrowd', intigriti: 'Intigriti', yeswehack: 'YesWeHack' }[p] || p)
const money = (cents: number, currency = 'USD') => cents > 0
  ? new Intl.NumberFormat(undefined, { style: 'currency', currency: currency || 'USD', maximumFractionDigits: 0 }).format(cents / 100)
  : '—'

const providerTone = (p: string) => ({
  hackerone: 'border-orange-400/30 bg-orange-400/10 text-orange-300',
  bugcrowd: 'border-red-400/30 bg-red-400/10 text-red-300',
  intigriti: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
  yeswehack: 'border-violet-400/30 bg-violet-400/10 text-violet-300',
}[p] || 'border-white/20 bg-white/5 text-text-secondary')

export default function BountyPrograms() {
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const { addToast } = useUIStore()
  const [filters, setFilters] = useState<Filters>(initialFilters)
  const [programs, setPrograms] = useState<BountyProgram[]>([])
  const [total, setTotal] = useState(0)
  const [detailIndex, setDetailIndex] = useState<BountyProgramList['detail_index'] | null>(null)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [statuses, setStatuses] = useState<BountySyncState[]>([])
  const [syncing, setSyncing] = useState(false)
  const [detail, setDetail] = useState<BountyProgram | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [assetSearch, setAssetSearch] = useState('')
  const [paidOnly, setPaidOnly] = useState(false)
  const [assetLimit, setAssetLimit] = useState(100)
  const [projectName, setProjectName] = useState('')
  const [monitor, setMonitor] = useState(true)
  const [monitorHours, setMonitorHours] = useState(12)
  const [creating, setCreating] = useState(false)

  const query = useMemo(() => {
    const q: Record<string, string> = { page: String(page), limit: '30', sort: filters.sort }
    if (filters.search.trim()) q.search = filters.search.trim()
    if (filters.provider) q.provider = filters.provider
    if (filters.bounties) q.bounties = filters.bounties
    if (filters.wildcard) q.wildcard = filters.wildcard
    if (filters.assetType) q.asset_type = filters.assetType
    if (filters.minAssets) q.min_assets = filters.minAssets
    if (filters.maxAssets) q.max_assets = filters.maxAssets
    if (filters.minReward) q.min_reward_cents = String(Number(filters.minReward) * 100)
    if (filters.programType) q.type = filters.programType
    if (filters.safeHarbor) q.safe_harbor = filters.safeHarbor
    if (filters.industry.trim()) q.industry = filters.industry.trim()
    if (filters.status) q.status = filters.status
    return q
  }, [filters, page])

  const load = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const result = await bountyApi.list(query)
      setPrograms(result.programs || []); setTotal(result.total || 0); setDetailIndex(result.detail_index || null)
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not load bounty catalog') }
    finally { setLoading(false) }
  }

  const loadStatus = () => bountyApi.status().then(setStatuses).catch(() => {})
  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [query])
  useEffect(() => {
    loadStatus(); const timer = setInterval(() => {
      bountyApi.status().then(next => { setStatuses(next); if (next.some(s => s.status === 'running')) load(true) }).catch(() => {})
    }, 15000)
    return () => clearInterval(timer)
  }, [query])
  useEffect(() => {
    if (!detailIndex?.running) return
    const timer = setInterval(() => load(true), 2500)
    return () => clearInterval(timer)
  }, [detailIndex?.running, query])
  useEffect(() => { setPage(1) }, [filters])

  const openProgram = async (p: BountyProgram) => {
    setDetailLoading(true); setDetail(p); setAssetSearch(''); setPaidOnly(false); setAssetLimit(100); setSelected(new Set()); setProjectName(p.name)
    try {
      const full = await bountyApi.get(p.id); setDetail(full)
      setSelected(new Set((full.assets || []).filter(a => a.active && a.in_scope && a.eligible_submission).map(a => a.id)))
      load()
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not fetch current program scope'); setDetail(null) }
    finally { setDetailLoading(false) }
  }

  const triggerSync = async () => {
    setSyncing(true)
    try { await bountyApi.sync(); addToast('info', 'Catalog refresh started in the background'); setTimeout(loadStatus, 800) }
    catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not start catalog refresh') }
    finally { setSyncing(false) }
  }

  const matchedAssets = (detail?.assets || []).filter(a => {
    if (!a.active || !a.in_scope || !a.eligible_submission) return false
    if (paidOnly && !a.eligible_bounty) return false
    const q = assetSearch.toLowerCase().trim()
    return !q || a.identifier.toLowerCase().includes(q) || a.asset_type.toLowerCase().includes(q) || (a.instruction || '').toLowerCase().includes(q)
  })
  const visibleAssets = matchedAssets.slice(0, assetLimit)
  useEffect(() => { setAssetLimit(100) }, [assetSearch, paidOnly, detail?.id])
  const visibleSelected = visibleAssets.length > 0 && visibleAssets.every(a => selected.has(a.id))
  const toggleAsset = (id: string) => setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  const toggleVisible = () => setSelected(prev => {
    const n = new Set(prev); if (visibleSelected) visibleAssets.forEach(a => n.delete(a.id)); else visibleAssets.forEach(a => n.add(a.id)); return n
  })

  const createProject = async () => {
    if (!detail || selected.size === 0) return
    setCreating(true)
    try {
      const created = await bountyApi.createProject(detail.id, {
        name: projectName.trim() || detail.name, description: `Imported from ${providerLabel(detail.provider)} public program`,
        priority: 'medium', notes: `Program: ${detail.url}`, asset_ids: [...selected], monitor_enabled: monitor, monitor_interval_hours: monitorHours,
      })
      addToast('success', `Project created with ${selected.size} approved assets`); navigate(created.url)
    } catch (e) { addToast('error', e instanceof Error ? e.message : 'Could not create project') }
    finally { setCreating(false) }
  }

  const pages = Math.max(1, Math.ceil(total / 30))
  const running = statuses.some(s => s.status === 'running')
  const knownPrograms = statuses.reduce((n, s) => n + (s.program_count || 0), 0)
  const filtersActive = filters.search !== '' || filters.provider !== '' || filters.bounties !== '' || filters.wildcard !== '' ||
    filters.assetType !== '' || filters.minAssets !== '' || filters.maxAssets !== '' || filters.minReward !== '' || filters.programType !== '' ||
    filters.safeHarbor !== '' || filters.industry !== '' || filters.status !== 'live' || filters.sort !== 'newest'

  return (
    <div className="space-y-5">
      <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-semibold">Bug bounty programs</h1>
            {running && <Badge variant="low">syncing official catalogs</Badge>}
          </div>
          <p className="mt-1 text-xs text-text-muted max-w-2xl">Public HackerOne, Bugcrowd, Intigriti and YesWeHack programs in one searchable catalog. Scope details load only when needed; import only the assets you choose.</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] text-text-muted">{knownPrograms || total} cached programs</span>
          {user?.role === 'admin' && <Button size="sm" variant="secondary" loading={syncing} onClick={triggerSync}>Refresh catalogs</Button>}
        </div>
      </div>

      {statuses.some(s => s.status === 'error') && (
        <div className="rounded-xl border border-severity-medium/30 bg-severity-medium/10 px-4 py-3 text-xs text-severity-medium">
          A provider refresh is retrying with backoff. Cached programs remain available. {statuses.filter(s => s.status === 'error').map(s => `${providerLabel(s.provider)}: ${s.last_error}`).join(' · ')}
        </div>
      )}

      {detailIndex?.running && (
        <div className="rounded-xl border border-accent/25 bg-accent/[.07] px-4 py-3 text-xs text-text-secondary">
          Indexing unopened program scopes for accurate scope filters: {detailIndex.completed} of {detailIndex.total} checked, {detailIndex.pending} remaining. Results update automatically.
        </div>
      )}
      {!detailIndex?.running && !!detailIndex?.last_error && (
        <div className="rounded-xl border border-severity-medium/25 bg-severity-medium/[.07] px-4 py-3 text-xs text-severity-medium">
          Scope index completed with {detailIndex.failed} temporary provider errors. Cached results are available; failed programs will retry automatically.
        </div>
      )}

      <div className="card p-3 sm:p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2.5">
          <Input placeholder="Search company, handle, industry…" value={filters.search} onChange={e => setFilters(f => ({ ...f, search: e.target.value }))} className="xl:col-span-2" />
          <Select value={filters.provider} onChange={v => setFilters(f => ({ ...f, provider: v }))} options={[['','All platforms'],['hackerone','HackerOne'],['bugcrowd','Bugcrowd'],['intigriti','Intigriti'],['yeswehack','YesWeHack']]} />
          <Select value={filters.sort} onChange={v => setFilters(f => ({ ...f, sort: v }))} options={[['newest','Newest programs'],['updated','Recently updated'],['assets_desc','Most in-scope assets'],['wildcards','Most wildcards'],['reward_desc','Highest max reward'],['name','Name A–Z']]} />
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-2.5">
          <Select value={filters.bounties} onChange={v => setFilters(f => ({ ...f, bounties: v }))} options={[['','Bounty + VDP'],['true','Pays bounties'],['false','VDP / no bounty']]} />
          <Select value={filters.wildcard} onChange={v => setFilters(f => ({ ...f, wildcard: v }))} options={[['','Any scope'],['true','Has wildcard'],['false','No wildcard']]} />
          <Select value={filters.assetType} onChange={v => setFilters(f => ({ ...f, assetType: v }))} options={[['','Any asset type'],['wildcard','Wildcard'],['domain','Domain'],['url','URL / page'],['api','API'],['js','JavaScript'],['cidr','CIDR'],['ip','IP'],['android','Android'],['ios','iOS'],['source_code','Source code'],['hardware','Hardware / IoT'],['ai_model','AI model']]} />
          <Select value={filters.programType} onChange={v => setFilters(f => ({ ...f, programType: v }))} options={[['','Any program'],['bug_bounty','Bug bounty'],['vdp','VDP']]} />
          <Select value={filters.safeHarbor} onChange={v => setFilters(f => ({ ...f, safeHarbor: v }))} options={[['','Any safe harbor'],['full','Full safe harbor'],['partial','Partial safe harbor'],['none','No declared safe harbor'],['declined','Declined']]} />
          <Select value={filters.status} onChange={v => setFilters(f => ({ ...f, status: v }))} options={[['live','Live only'],['','Any status'],['unavailable','Unavailable']]} />
          <Input type="number" min="0" placeholder="Min assets" value={filters.minAssets} onChange={e => setFilters(f => ({ ...f, minAssets: e.target.value }))} />
          <Input type="number" min="0" placeholder="Max assets" value={filters.maxAssets} onChange={e => setFilters(f => ({ ...f, maxAssets: e.target.value }))} />
          <Input type="number" min="0" placeholder="Min max reward ($)" value={filters.minReward} onChange={e => setFilters(f => ({ ...f, minReward: e.target.value }))} />
          <Input placeholder="Exact industry" value={filters.industry} onChange={e => setFilters(f => ({ ...f, industry: e.target.value }))} />
        </div>
        {filtersActive && <button className="text-[11px] text-accent hover:text-accent-hover" onClick={() => setFilters(initialFilters)}>Clear filters</button>}
      </div>

      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">{Array.from({ length: 9 }).map((_,i)=><div key={i} className="card p-4 space-y-3"><Skeleton className="h-5 w-2/3"/><Skeleton className="h-3 w-full"/><Skeleton className="h-12 w-full"/></div>)}</div>
      ) : programs.length === 0 ? (
        <div className="card"><EmptyState title={running ? 'Catalog sync is running' : detailIndex?.running ? 'Checking unopened program scopes' : 'No programs match these filters'} description={running ? 'Lightweight provider indexes are being cached; individual scopes load on demand.' : detailIndex?.running ? 'The filtered list fills automatically as every cached program scope is checked.' : 'Clear filters, or ask an administrator to refresh the public catalogs.'} action={!running && !detailIndex?.running && user?.role === 'admin' ? <Button size="sm" onClick={triggerSync}>Start refresh</Button> : undefined}/></div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {programs.map(p => <ProgramCard key={p.id} program={p} onOpen={() => openProgram(p)} />)}
        </div>
      )}

      {pages > 1 && <div className="flex items-center justify-center gap-3"><Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(p => p-1)}>Previous</Button><span className="text-xs text-text-muted">Page {page} of {pages} · {total} programs</span><Button size="sm" variant="secondary" disabled={page >= pages} onClick={() => setPage(p => p+1)}>Next</Button></div>}

      <Modal open={!!detail} onClose={() => setDetail(null)} title={detail?.name || 'Program'} width="xl">
        {detailLoading ? <div className="py-16 space-y-3"><Skeleton className="h-6 w-1/2 mx-auto"/><Skeleton className="h-4 w-3/4 mx-auto"/></div> : detail && (
          <div className="space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap"><span className={cn('text-[10px] px-2 py-1 rounded-md border font-semibold',providerTone(detail.provider))}>{providerLabel(detail.provider)}</span>{detail.offers_bounties ? <Badge variant="low">bounty</Badge> : <Badge>VDP</Badge>}{detail.wildcard_count > 0 && <Badge variant="medium">{detail.wildcard_count} wildcard</Badge>}{detail.safe_harbor && detail.safe_harbor !== 'none' && <Badge>{detail.safe_harbor} safe harbor</Badge>}</div>
                <p className="mt-2 text-xs text-text-muted">{detail.description}</p>
              </div>
              <a href={detail.url} target="_blank" rel="noreferrer" className="text-xs text-accent hover:text-accent-hover shrink-0">Open official program ↗</a>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">{[[detail.in_scope_count,'In scope'],[detail.asset_count,'All declared'],[money(detail.max_reward_cents,detail.currency),'Max reward'],[detail.started_at ? timeAgo(detail.started_at) : '—','Started']].map(([v,l])=><div key={String(l)} className="rounded-lg bg-white/[.025] border border-white/[.06] p-3 text-center"><div className="text-sm font-semibold">{v}</div><div className="text-[10px] text-text-muted mt-0.5">{l}</div></div>)}</div>
            <div className="rounded-xl border border-border overflow-hidden">
              <div className="p-3 border-b border-border space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"><p className="text-xs font-semibold">Choose project assets <span className="text-text-muted font-normal">({selected.size} selected)</span></p><div className="flex items-center gap-3 text-[11px]"><label className="flex items-center gap-1.5"><input type="checkbox" checked={paidOnly} onChange={e=>setPaidOnly(e.target.checked)} className="accent-accent"/>Bounty-eligible only</label><button onClick={toggleVisible} className="text-accent">{visibleSelected ? 'Deselect visible' : 'Select visible'}</button></div></div>
                <Input placeholder="Filter scope assets…" value={assetSearch} onChange={e=>setAssetSearch(e.target.value)} />
              </div>
              <div className="max-h-[35dvh] overflow-y-auto divide-y divide-white/[.05]">
                {visibleAssets.map(a => <AssetRow key={a.id} asset={a} checked={selected.has(a.id)} onToggle={() => toggleAsset(a.id)} />)}
                {visibleAssets.length === 0 && <p className="p-5 text-center text-xs text-text-muted">No submission-eligible assets match.</p>}
                {visibleAssets.length < matchedAssets.length && <div className="p-3 text-center"><Button size="sm" variant="secondary" onClick={() => setAssetLimit(n => n + 100)}>Load 100 more · {matchedAssets.length - visibleAssets.length} remaining</Button></div>}
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="space-y-1"><span className="text-[11px] text-text-muted">Project name</span><Input value={projectName} onChange={e=>setProjectName(e.target.value)} /></label>
              <div className="space-y-1"><span className="text-[11px] text-text-muted">Scope monitoring</span><div className="h-9 flex items-center gap-3 rounded-lg border border-border bg-surface-alt px-3"><label className="flex items-center gap-1.5 text-xs"><input type="checkbox" checked={monitor} onChange={e=>setMonitor(e.target.checked)} className="accent-accent"/>Enabled</label>{monitor && <select value={monitorHours} onChange={e=>setMonitorHours(Number(e.target.value))} className="ml-auto bg-transparent text-xs text-text-primary">{[3,6,12,24,48,168].map(h=><option key={h} value={h} className="bg-surface-3">every {h<24?`${h}h`:`${h/24}d`}</option>)}</select>}</div></div>
            </div>
            <div className="rounded-lg border border-accent/20 bg-accent/[.06] p-3 text-[11px] text-text-secondary">Upstream additions are never scanned automatically. Reconner creates a pending scope event for approval. Assets removed or made ineligible are suspended immediately and remain in history.</div>
            <div className="flex justify-end gap-2"><Button variant="secondary" onClick={()=>setDetail(null)}>Cancel</Button><Button loading={creating} disabled={selected.size===0} onClick={createProject}>Create monitored project</Button></div>
          </div>
        )}
      </Modal>
    </div>
  )
}

function Select({ value, onChange, options }: { value: string; onChange: (v:string)=>void; options: [string,string][] }) {
  return <select value={value} onChange={e=>onChange(e.target.value)} className="h-9 w-full bg-surface-alt border border-border rounded-lg px-2.5 text-xs text-text-primary outline-none focus:border-accent/60">{options.map(([v,l])=><option key={v} value={v} className="bg-surface-3">{l}</option>)}</select>
}

function ProgramCard({ program:p, onOpen }: { program:BountyProgram; onOpen:()=>void }) {
  return <button type="button" onClick={onOpen} className="card-hover p-4 text-left min-w-0">
    <div className="flex items-start gap-3"><div className="w-10 h-10 rounded-xl border border-white/[.07] bg-white/[.03] grid place-items-center shrink-0 overflow-hidden">{p.logo_url?<img src={p.logo_url} alt="" className="w-full h-full object-contain" loading="lazy"/>:<span className="text-sm font-bold text-text-muted">{p.name.slice(0,1).toUpperCase()}</span>}</div><div className="min-w-0 flex-1"><div className="flex items-center gap-1.5"><h2 className="text-sm font-semibold truncate">{p.name}</h2><span className={cn('text-[9px] px-1.5 py-0.5 rounded border shrink-0',providerTone(p.provider))}>{providerLabel(p.provider)}</span></div><p className="text-[10px] text-text-muted truncate mt-0.5">{p.industry || p.handle}</p></div></div>
    <p className="mt-3 text-[11px] text-text-secondary line-clamp-2 min-h-8">{p.description || 'Open the official scope and select assets for a project.'}</p>
    <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-white/[.05]"><Metric value={p.details_loaded?String(p.in_scope_count):'…'} label="assets"/><Metric value={String(p.wildcard_count)} label="wildcards"/><Metric value={p.offers_bounties?money(p.max_reward_cents,p.currency):'VDP'} label="max reward"/></div>
    <div className="flex items-center justify-between mt-3 text-[10px] text-text-muted"><span>{p.started_at?`Started ${timeAgo(p.started_at)}`:'Start date unavailable'}</span><span className="text-accent">View scope →</span></div>
  </button>
}

function Metric({value,label}:{value:string;label:string}){return <div><div className="text-xs font-semibold text-text-primary truncate">{value}</div><div className="text-[9px] text-text-muted">{label}</div></div>}

function AssetRow({asset:a,checked,onToggle}:{asset:BountyAsset;checked:boolean;onToggle:()=>void}){
  return <label className="flex items-start gap-2.5 p-3 hover:bg-white/[.025] cursor-pointer"><input type="checkbox" checked={checked} onChange={onToggle} className="mt-0.5 accent-accent shrink-0"/><div className="min-w-0 flex-1"><div className="flex items-center gap-2 flex-wrap"><code className="text-[11px] text-text-primary break-all">{a.identifier}</code><span className="text-[9px] uppercase rounded bg-white/[.05] px-1.5 py-0.5 text-text-muted">{a.asset_type}</span>{a.is_wildcard&&<span className="text-[9px] rounded bg-severity-medium/10 px-1.5 py-0.5 text-severity-medium">wildcard</span>}{a.eligible_bounty&&<span className="text-[9px] rounded bg-severity-low/10 px-1.5 py-0.5 text-severity-low">paid</span>}</div>{a.instruction&&<p className="mt-1 text-[10px] text-text-muted line-clamp-2">{a.instruction}</p>}</div></label>
}
