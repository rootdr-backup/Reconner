import { useEffect, useMemo, useRef, useState } from 'react'
import { type CorpusCategory, type CorpusMergeResult, system } from '../../lib/api'
import { useUIStore } from '../../store/ui'
import { Button, Spinner } from '../ui'
import { cn } from '../../lib/utils'

const XSS_TEMPLATE_EXAMPLES = [
  `<svg onload="top.document.title='%s'">`,
  `"><img src=x onerror="top.document.title='%s'">`,
  `</script><script>top.document.title='%s'</script>`,
]

function validXSSTemplate(value: string) {
  const trimmed = value.trim()
  return trimmed !== '' && trimmed.length <= 8192 &&
    (trimmed.match(/%s/g)?.length || 0) === 1 && trimmed.includes('top.document.title')
}

export function CorpusManager() {
  const [categories, setCategories] = useState<CorpusCategory[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [draft, setDraft] = useState('')
  const [kind, setKind] = useState<'all' | 'wordlist' | 'payload'>('all')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [result, setResult] = useState<CorpusMergeResult | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const { addToast } = useUIStore()

  const load = async (keepSelection = true) => {
    try {
      const next = await system.corpora()
      setCategories(next || [])
      setSelectedId(current => keepSelection && next.some(c => c.id === current) ? current : next[0]?.id || '')
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Could not load scanner dictionaries')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load(false) }, [])
  const visible = useMemo(() => kind === 'all' ? categories : categories.filter(c => c.kind === kind), [categories, kind])
  const selected = categories.find(c => c.id === selectedId) || visible[0]
  const xssDraftLines = selected?.id === 'xss'
    ? draft.split(/\r?\n/).map(value => value.trim()).filter(Boolean)
    : []
  const invalidXSSLines = xssDraftLines.filter(value => !validXSSTemplate(value))

  useEffect(() => {
    if (visible.length && !visible.some(c => c.id === selectedId)) setSelectedId(visible[0].id)
  }, [kind, visible, selectedId])

  const merge = async () => {
    if (!selected || !draft.trim()) return
    setSaving(true)
    try {
      const merged = await system.mergeCorpus(selected.id, draft)
      setResult(merged)
      // Keep rejected XSS rows in the editor so the operator can fix them. The
      // backend intentionally rejects ordinary alert/reflection payloads because
      // they cannot provide the random browser-execution proof Reconner needs.
      setDraft(selected.id === 'xss' && merged.invalid > 0 ? invalidXSSLines.join('\n') : '')
      await load()
      addToast(merged.invalid > 0 ? 'info' : 'success', `${merged.added} added · ${merged.duplicates} duplicate${merged.duplicates === 1 ? '' : 's'} · ${merged.invalid} invalid${selected.id === 'xss' && merged.invalid > 0 ? ' — XSS templates need one %s nonce and top.document.title' : ''}`)
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Could not add entries')
    } finally { setSaving(false) }
  }

  const restore = async () => {
    if (!selected || !window.confirm(`Remove every custom entry from ${selected.label} and restore compiled defaults?`)) return
    setSaving(true)
    try {
      const restored = await system.restoreCorpus(selected.id)
      setResult(null)
      setDraft('')
      await load()
      addToast('success', `Restored defaults · ${restored.removed} custom entr${restored.removed === 1 ? 'y' : 'ies'} removed`)
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Could not restore defaults')
    } finally { setSaving(false) }
  }

  const importFile = async (file?: File) => {
    if (!file) return
    if (file.size > 2 * 1024 * 1024) { addToast('error', 'Wordlist files must be 2 MB or smaller'); return }
    try {
      const text = await file.text()
      setDraft(current => current ? `${current.replace(/\s+$/, '')}\n${text}` : text)
    } catch {
      addToast('error', 'Could not read that wordlist file')
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  if (loading) return <div className="flex h-48 items-center justify-center"><Spinner className="h-8 w-8" /></div>

  return (
    <section className="grid gap-4 xl:grid-cols-[minmax(260px,.7fr)_minmax(0,1.3fr)] animate-fade-in">
      <div className="card overflow-hidden">
        <div className="border-b border-border p-4">
          <p className="text-sm font-semibold">Scanner dictionaries</p>
          <p className="mt-1 text-xs text-text-muted">Defaults stay compiled in. Your additions are deduplicated and layered on top.</p>
          <div className="mt-3 flex gap-1">
            {(['all', 'wordlist', 'payload'] as const).map(value => (
              <button key={value} onClick={() => setKind(value)} className={cn('rounded-md px-2.5 py-1.5 text-[11px] capitalize transition-colors', kind === value ? 'bg-accent/15 text-accent' : 'text-text-muted hover:bg-white/5 hover:text-text-secondary')}>{value}</button>
            ))}
          </div>
        </div>
        <div className="max-h-[620px] overflow-y-auto p-2">
          {visible.map(category => (
            <button key={category.id} onClick={() => { setSelectedId(category.id); setResult(null) }}
              className={cn('mb-1 w-full rounded-lg border p-3 text-left transition-colors', selected?.id === category.id ? 'border-accent/40 bg-accent/[.08]' : 'border-transparent hover:border-border hover:bg-white/[.025]')}>
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-semibold text-text-primary">{category.label}</span>
                <span className={cn('rounded px-1.5 py-0.5 text-[9px] uppercase tracking-wide', category.kind === 'payload' ? 'bg-severity-medium/10 text-severity-medium' : 'bg-accent/10 text-accent')}>{category.kind}</span>
              </div>
              <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-text-muted">{category.description}</p>
              <p className="mt-2 text-[10px] tabular-nums text-text-secondary">{category.total_count} effective · {category.custom_count} custom</p>
            </button>
          ))}
        </div>
      </div>

      {selected && <div className="card p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="flex items-center gap-2"><h2 className="text-base font-semibold">{selected.label}</h2><code className="rounded bg-black/20 px-1.5 py-0.5 text-[10px] text-text-muted">{selected.id}</code></div>
            <p className="mt-1 max-w-2xl text-xs text-text-muted">{selected.description}</p>
          </div>
          <div className="flex shrink-0 gap-4 text-right text-[10px] uppercase tracking-wide text-text-muted">
            <span><b className="block text-lg font-semibold normal-case text-text-primary">{selected.default_count}</b>defaults</span>
            <span><b className="block text-lg font-semibold normal-case text-accent">{selected.custom_count}</b>custom</span>
            <span><b className="block text-lg font-semibold normal-case text-text-primary">{selected.total_count}</b>effective</span>
          </div>
        </div>

        <div className="mt-5">
          {selected.id === 'xss' && <div className="mb-4 rounded-xl border border-accent/30 bg-accent/[.06] p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-xs font-semibold text-text-primary">XSS imports require browser-proof templates</p>
                <p className="mt-1 max-w-2xl text-[11px] leading-relaxed text-text-secondary">
                  Each line must contain exactly one <code className="code">%s</code> placeholder and set <code className="code">top.document.title</code>.
                  Reconner replaces <code className="code">%s</code> with a random nonce and accepts a finding only when Chromium observes that exact title change. Plain payloads such as <code className="code">&lt;script&gt;alert(1)&lt;/script&gt;</code> are rejected to prevent false positives.
                </p>
              </div>
              <Button variant="secondary" size="sm" onClick={() => setDraft(current => current.trim() ? `${current.replace(/\s+$/, '')}\n${XSS_TEMPLATE_EXAMPLES.join('\n')}` : XSS_TEMPLATE_EXAMPLES.join('\n'))}>
                Load valid examples
              </Button>
            </div>
            <div className="mt-3 space-y-1.5" aria-label="Valid XSS template examples">
              {XSS_TEMPLATE_EXAMPLES.map(example => <code key={example} className="block overflow-x-auto rounded-lg border border-border bg-black/20 px-3 py-2 text-[10px] text-accent-hover">{example}</code>)}
            </div>
            {xssDraftLines.length > 0 && <p className={cn('mt-3 text-[11px] font-medium', invalidXSSLines.length ? 'text-severity-high' : 'text-severity-low')}>
              {invalidXSSLines.length
                ? `${invalidXSSLines.length} of ${xssDraftLines.length} non-empty lines do not match this format. Rejected lines will stay in the editor so you can correct them.`
                : `All ${xssDraftLines.length} non-empty lines match the required proof format.`}
            </p>}
          </div>}
          <label htmlFor="corpus-entries" className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">Paste one entry per line</label>
          <textarea id="corpus-entries" value={draft} onChange={e => setDraft(e.target.value)} rows={12} spellCheck={false}
            placeholder={selected.kind === 'payload' ? 'Paste payload templates here…' : 'Paste words or paths here…'}
            className="input mt-2 min-h-64 resize-y whitespace-pre font-mono text-xs" />
          <input ref={fileRef} type="file" accept=".txt,.lst,.wordlist,text/plain" className="hidden" onChange={e => importFile(e.target.files?.[0])} />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button variant="primary" loading={saving} disabled={!draft.trim()} onClick={merge}>Add &amp; deduplicate</Button>
            <Button variant="secondary" disabled={saving} onClick={() => fileRef.current?.click()}>Import text file</Button>
            <Button variant="ghost" disabled={saving || selected.custom_count === 0} onClick={restore}>
              Restore default {selected.kind === 'payload' ? 'payloads' : 'wordlist'}
            </Button>
          </div>
        </div>

        {result && <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {[['Added', result.added, 'text-severity-low'], ['Duplicates', result.duplicates, 'text-severity-medium'], ['Invalid', result.invalid, 'text-severity-critical'], ['Effective total', result.total, 'text-accent']].map(([label, value, tone]) => (
            <div key={String(label)} className="rounded-lg border border-border bg-black/10 p-3"><p className="text-[10px] uppercase tracking-wide text-text-muted">{label}</p><p className={cn('mt-1 text-xl font-semibold tabular-nums', String(tone))}>{value}</p></div>
          ))}
        </div>}

        {selected.id === 'xss' && result && result.invalid > 0 && <div role="alert" className="mt-3 rounded-lg border border-severity-high/30 bg-severity-high/[.06] p-3 text-[11px] leading-relaxed text-text-secondary">
          <b className="text-severity-high">Why {result.invalid === 1 ? 'was 1 line' : `were ${result.invalid} lines`} rejected?</b>{' '}
          They were empty, too long, missing <code className="code">top.document.title</code>, or did not contain exactly one <code className="code">%s</code> nonce placeholder. The rejected lines remain above for editing; nothing invalid was saved.
        </div>}

        <div className="mt-5 border-t border-border pt-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">Effective preview</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {selected.preview.map(value => <code key={value} className="max-w-full truncate rounded-md border border-border bg-black/15 px-2 py-1 text-[10px] text-text-secondary" title={value}>{value}</code>)}
          </div>
        </div>
      </div>}
    </section>
  )
}
