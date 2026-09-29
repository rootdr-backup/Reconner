import {
  fingerprintInput, TriageEngine, TIERS,
} from './lib/analyze.js'

const MAX_ENTRIES = 5000
const MAX_BODY_BYTES = 2 * 1024 * 1024
const MAX_ANALYSIS_CHARS = 20000 // cap on how much decoded body text feeds the triage engine per response
const MAX_RENDERED_FINDINGS = 300

const entries = []
const fingerprints = new Set()
let capturing = false
let seen = 0
let duplicates = 0
let bodyBytes = 0
const engine = new TriageEngine()

const $ = id => document.getElementById(id)
const utf8Base64 = value => {
  const bytes = new TextEncoder().encode(value || '')
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}
const headerList = headers => (headers || []).map(h => ({ name: h.name, value: h.value || '' }))
const escapeHTML = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
const humanBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`

const scopes = () => $('scope').value.split(/\r?\n/).map(v => v.trim()).filter(Boolean)
const inScope = raw => scopes().some(rule => {
  try {
    const candidate = new URL(raw)
    if (!rule.includes('://')) return candidate.hostname === rule || candidate.hostname.endsWith('.' + rule)
    const wanted = new URL(rule)
    return candidate.origin === wanted.origin && (wanted.pathname === '/' || candidate.pathname.startsWith(wanted.pathname))
  } catch { return false }
})

// A base64 string's decoded length is always floor(len * 3/4) minus 0-2 for
// padding — close enough for a size *threshold* check, and avoids an atob()
// pass over multi-megabyte strings just to throw the result away.
const base64DecodedLength = b64 => b64 ? Math.floor((b64.length * 3) / 4) : 0

const getResponseContent = request => new Promise(resolve => request.getContent((content, encoding) => resolve({ content: content || '', encoding: encoding || '' })))

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

chrome.devtools.network.onRequestFinished.addListener(async item => {
  if (!capturing || !inScope(item.request.url) || entries.length >= MAX_ENTRIES) return
  seen++
  const identityLabel = $('identity').value.trim()
  const fp = await sha256Hex(fingerprintInput({
    method: item.request.method,
    url: item.request.url,
    headers: item.request.headers,
    postData: item.request.postData,
    identityLabel,
  }))
  if (fingerprints.has(fp)) { duplicates++; render(); return }
  fingerprints.add(fp)

  // Skip fetching content we already know will be blanked for exceeding
  // MAX_BODY_BYTES — DevTools reports the decoded size up front, so this
  // avoids a full getContent()+base64 round trip for large downloads/files
  // that were never going to be stored anyway.
  const declaredSize = item.response.content && typeof item.response.content.size === 'number' ? item.response.content.size : null
  const skipFetch = declaredSize != null && declaredSize >= 0 && declaredSize > MAX_BODY_BYTES

  const requestText = item.request.postData?.text || ''
  let requestBody = utf8Base64(requestText)
  if (base64DecodedLength(requestBody) > MAX_BODY_BYTES) requestBody = ''

  let responseBody = ''
  let decodedResponseText = ''
  let mime = (item.response.content && item.response.content.mimeType) || ''
  if (!skipFetch) {
    const content = await getResponseContent(item)
    decodedResponseText = content.encoding === 'base64' ? safeAtob(content.content) : content.content
    responseBody = content.encoding === 'base64' ? content.content : utf8Base64(content.content)
    if (responseBody && base64DecodedLength(responseBody) > MAX_BODY_BYTES) { responseBody = ''; }
  }
  bodyBytes += Math.floor(requestBody.length * .75) + Math.floor(responseBody.length * .75)

  const responseSize = declaredSize != null ? declaredSize : (decodedResponseText ? decodedResponseText.length : 0)
  const exchange = {
    source: 'chrome-devtools', source_id: fp, sequence: entries.length + 1,
    started_at: item.startedDateTime || new Date().toISOString(), identity_label: identityLabel,
    request: { method: item.request.method, url: item.request.url, http_version: item.request.httpVersion || '', headers: headerList(item.request.headers), body: requestBody, mime_type: item.request.postData?.mimeType || '' },
    response: { status: item.response.status || 0, http_version: item.response.httpVersion || '', headers: headerList(item.response.headers), body: responseBody, mime_type: mime, time_ms: Math.round(item.time || 0), size: responseSize },
  }
  entries.push(exchange)

  // Feed the passive triage engine. Analysis text is capped independently
  // of storage — plenty of signal for id/PII heuristics without re-walking
  // multi-megabyte bodies on every request.
  const analysisText = decodedResponseText ? decodedResponseText.slice(0, MAX_ANALYSIS_CHARS) : ''
  engine.ingest(exchange, analysisText)

  render()
})

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map(v => v.toString(16).padStart(2, '0')).join('')
}
// atob() alone yields a "binary string" (one JS char per byte) — correct
// only for ASCII bodies. Re-decoding those bytes as UTF-8 matters for the
// triage heuristics (id/PII field values, error-signature text) whenever a
// captured response contains non-ASCII text.
function safeAtob(b64) {
  try {
    const binary = atob(b64)
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0))
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  } catch { return '' }
}

// ---------------------------------------------------------------------------
// Rendering — capture table + stats
// ---------------------------------------------------------------------------

const render = () => {
  $('unique').textContent = entries.length
  $('seen').textContent = seen
  $('duplicates').textContent = duplicates
  $('bytes').textContent = humanBytes(bodyBytes)
  $('export').disabled = entries.length === 0
  $('exportFindings').disabled = engine.list().length === 0
  $('rows').innerHTML = entries.slice(-250).reverse().map(e => `<tr><td>${e.sequence}</td><td>${escapeHTML(e.identity_label || '')}</td><td>${e.request.method}</td><td class="url" title="${escapeHTML(e.request.url)}">${escapeHTML(e.request.url)}</td><td>${e.response.status || '-'}</td><td>${humanBytes((e.request.body?.length || 0) + (e.response.body?.length || 0))}</td></tr>`).join('')
  renderIdentities()
  renderFindings()
}

// ---------------------------------------------------------------------------
// Rendering — identities & role tiers
// ---------------------------------------------------------------------------

function renderIdentities() {
  const summary = engine.identitySummary()
  $('identityCount').textContent = summary.length
  // Set this before the early return: otherwise, once hidden by reaching 2+
  // identities, the hint would stay hidden forever after Clear resets the
  // identity count back to zero.
  $('autoNotice').style.display = summary.length >= 2 ? 'none' : ''
  if (!summary.length) {
    $('identities').innerHTML = '<p class="muted">No requests captured yet.</p>'
    return
  }
  const tierOptions = t => TIERS.map(o => `<option value="${o.value}" ${String(t) === o.value ? 'selected' : ''}>${o.label}</option>`).join('')
  $('identities').innerHTML = `<table><thead><tr><th>Identity</th><th>Requests</th><th>Role tier</th></tr></thead><tbody>${
    summary.map(s => `<tr><td>${escapeHTML(s.label)}</td><td>${s.count}</td><td><select data-identity="${escapeHTML(s.label)}">${tierOptions(s.tier)}</select></td></tr>`).join('')
  }</tbody></table>`
  $('identities').querySelectorAll('select[data-identity]').forEach(sel => {
    sel.addEventListener('change', () => {
      engine.setTier(sel.dataset.identity, sel.value)
      persistConfig()
      // A tier assigned after traffic was already captured must be able to
      // upgrade/create sensitive-path and cross-tier findings retroactively,
      // not only for requests captured from now on.
      reanalyzeAll()
      renderIdentities()
      renderFindings()
    })
  })
}

// ---------------------------------------------------------------------------
// Rendering — findings
// ---------------------------------------------------------------------------

const CATEGORY_LABEL = {
  object_idor: 'Cross-identity object access (IDOR/BOLA candidate)',
  sensitive_path: 'Sensitive-path access',
  cross_tier_function: 'Cross-tier function access (BFLA candidate)',
}

function renderFindings() {
  const findings = engine.list()
  const counts = { high: 0, medium: 0, info: 0 }
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
  $('findingCounts').textContent = `${findings.length} total — ${counts.high || 0} high, ${counts.medium || 0} medium`
  if (!findings.length) {
    $('findings').innerHTML = '<p class="muted">No candidates yet. Findings appear automatically once traffic from two different identity labels overlaps, or once a sensitive-path pattern / role tier is configured below.</p>'
    return
  }
  $('findings').innerHTML = findings.slice(0, MAX_RENDERED_FINDINGS).map(f => `
    <details class="finding sev-${f.severity}">
      <summary>
        <span class="badge">${f.severity}</span>
        <span class="title">${escapeHTML(f.title)}</span>
        <span class="meta">${escapeHTML(f.template)} · seen ${f.hitCount}×</span>
      </summary>
      <div class="finding-body">
        ${f.hint ? `<p class="hint">${escapeHTML(f.hint)}</p>` : ''}
        ${f.objectSignals ? `<p class="hint">Object signal: <code>${escapeHTML(f.objectSignals.join(', '))}</code>${f.sensitive ? ' — response body looks like it contains personal data.' : ''}</p>` : ''}
        ${f.pattern ? `<p class="hint">Matched pattern: <code>${escapeHTML(f.pattern)}</code></p>` : ''}
        <table class="evidence"><thead><tr><th>Identity</th><th>Tier</th><th>Status</th><th>URL</th><th>When</th></tr></thead><tbody>
          ${f.evidence.map(ev => `<tr><td>${escapeHTML(ev.label)}</td><td>${ev.tier != null && ev.tier !== '' ? escapeHTML(String(ev.tier)) : '-'}</td><td>${ev.status ?? '-'}</td><td class="url" title="${escapeHTML(ev.url || '')}">${escapeHTML(ev.url || '')}</td><td>${escapeHTML(ev.at || '')}</td></tr>`).join('')}
        </tbody></table>
      </div>
    </details>`).join('')
}

// ---------------------------------------------------------------------------
// Config persistence (scope/identity/label already existed; extend to the
// new triage inputs so a tester's setup survives closing DevTools).
// ---------------------------------------------------------------------------

function persistConfig() {
  chrome.storage.local.set({
    sensitivePatterns: $('sensitivePatterns').value,
    extraIdParams: $('extraIdParams').value,
    identityTiers: Object.fromEntries(engine.tiers),
  })
}

function applyConfigInputs() {
  engine.setSensitivePatterns($('sensitivePatterns').value.split(/\r?\n/))
  engine.setExtraIdParams($('extraIdParams').value.split(/[,\n]/))
}

// Config (role tiers, sensitive-path patterns, extra id-param names) is
// commonly set *after* a tester has already captured some traffic. Re-run
// the whole traffic history through a fresh engine so findings that only
// become detectable once config exists show up immediately, without
// needing to re-capture. Uses the already-stored (possibly truncated)
// response bodies — a bit less complete than the original live capture for
// any response that exceeded the 2 MiB storage cap, but otherwise a full
// re-read.
function decodeStoredResponseText(exchange) {
  return exchange.response.body ? safeAtob(exchange.response.body) : ''
}
function reanalyzeAll() {
  engine.reset()
  for (const e of entries) engine.ingest(e, decodeStoredResponseText(e).slice(0, MAX_ANALYSIS_CHARS))
}

// ---------------------------------------------------------------------------
// UI wiring
// ---------------------------------------------------------------------------

$('toggle').addEventListener('click', () => {
  if (!capturing && scopes().length === 0) { $('notice').textContent = 'Add at least one target hostname or URL prefix.'; return }
  capturing = !capturing
  $('toggle').textContent = capturing ? 'Stop capture' : 'Start capture'
  $('state').textContent = capturing ? 'Capturing' : 'Stopped'
  $('state').className = capturing ? 'on' : 'off'
  $('scope').disabled = capturing
  $('identity').disabled = capturing
  $('notice').textContent = capturing ? 'Capturing matching traffic. Requests are observed, never modified or replayed.' : 'Capture stopped. Export the unique request/response corpus when ready.'
})
$('clear').addEventListener('click', () => {
  entries.length = 0
  fingerprints.clear()
  seen = duplicates = bodyBytes = 0
  engine.reset()
  render()
})
$('export').addEventListener('click', () => {
  const envelope = { schema: 'reconner-capture/v1', source: 'chrome-devtools', label: $('label').value.trim(), exported_at: new Date().toISOString(), entries }
  downloadJSON(envelope, `reconner-capture-${Date.now()}.json`)
})
$('exportFindings').addEventListener('click', () => {
  const envelope = {
    schema: 'reconner-triage-findings/v1',
    label: $('label').value.trim(),
    exported_at: new Date().toISOString(),
    note: 'Heuristic, passive triage from captured DevTools traffic — every finding needs manual confirmation (or replay via Reconner Guided Analyze) before it is reported as a real IDOR/BAC issue.',
    identities: engine.identitySummary(),
    findings: engine.list(),
  }
  downloadJSON(envelope, `reconner-triage-findings-${Date.now()}.json`)
})
$('copyFindingsMd').addEventListener('click', async () => {
  const md = findingsToMarkdown(engine.list())
  try { await navigator.clipboard.writeText(md) } catch { /* clipboard permission not granted; ignore */ }
})

function downloadJSON(obj, filename) {
  const blob = new Blob([JSON.stringify(obj)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function findingsToMarkdown(findings) {
  if (!findings.length) return 'No findings.'
  return findings.map(f => {
    const evidence = f.evidence.map(ev => `  - **${ev.label}**${ev.tier != null && ev.tier !== '' ? ` (tier ${ev.tier})` : ''}: \`${ev.status ?? '-'}\` ${ev.url || ''}`).join('\n')
    return `### [${f.severity.toUpperCase()}] ${CATEGORY_LABEL[f.category] || f.category}\n${f.title} — \`${f.template}\` (seen ${f.hitCount}×)\n${f.hint ? `\n> ${f.hint}\n` : ''}\n${evidence}\n`
  }).join('\n')
}

for (const id of ['sensitivePatterns', 'extraIdParams']) {
  $(id).addEventListener('change', () => { applyConfigInputs(); persistConfig(); reanalyzeAll(); renderIdentities(); renderFindings() })
}
$('scope').addEventListener('change', () => chrome.storage.local.set({ scope: $('scope').value }))
$('identity').addEventListener('change', () => chrome.storage.local.set({ identity: $('identity').value }))

chrome.storage.local.get(['scope', 'identity', 'sensitivePatterns', 'extraIdParams', 'identityTiers'], saved => {
  if (saved.scope) $('scope').value = saved.scope
  if (saved.identity) $('identity').value = saved.identity
  if (saved.sensitivePatterns) $('sensitivePatterns').value = saved.sensitivePatterns
  if (saved.extraIdParams) $('extraIdParams').value = saved.extraIdParams
  if (saved.identityTiers) for (const [label, tier] of Object.entries(saved.identityTiers)) engine.setTier(label, tier)
  applyConfigInputs()
  render()
})
