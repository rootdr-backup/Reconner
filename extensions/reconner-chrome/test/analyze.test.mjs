// Pure-logic tests for lib/analyze.js — no chrome.* / DOM required.
// Run with: node --test extensions/reconner-chrome/test/
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  templatePath, pathIdSegments, queryIdSignals, bodyIdSignals,
  isIdParamName, looksLikeIdValue, classifyOutcome, looksLikeErrorBody,
  looksSensitiveBody, fingerprintInput, TriageEngine,
} from '../lib/analyze.js'

// ---------------------------------------------------------------------------
// Templating / id-signal extraction
// ---------------------------------------------------------------------------

test('templatePath collapses numeric, UUID and ObjectId segments', () => {
  assert.equal(templatePath('/api/users/482/orders/91a7c1e9-2b1a-4c9e-8f2e-6b6a2b6a2b6a'), '/api/users/{id}/orders/{id}')
  assert.equal(templatePath('/api/docs/5f8d0d55b54764421b7156c9'), '/api/docs/{id}')
  assert.equal(templatePath('/dashboard/settings'), '/dashboard/settings')
})

test('pathIdSegments ignores 1-2 digit segments (pagination guard) but keeps real ids', () => {
  assert.deepEqual(pathIdSegments('/reports/page/2'), [])
  assert.deepEqual(pathIdSegments('/reports/page/99'), [])
  assert.deepEqual(pathIdSegments('/orders/482'), ['482'])
  assert.deepEqual(pathIdSegments('/orders/91a7c1e9-2b1a-4c9e-8f2e-6b6a2b6a2b6a'), ['91a7c1e9-2b1a-4c9e-8f2e-6b6a2b6a2b6a'])
})

test('queryIdSignals: named id params always count, unnamed numeric values are excluded (pagination guard)', () => {
  const named = new URLSearchParams('user_id=482&page=2')
  assert.deepEqual(queryIdSignals(named, new Set()), ['user_id=482'])
  const unnamed = new URLSearchParams('ref=91a7c1e9-2b1a-4c9e-8f2e-6b6a2b6a2b6a&count=2')
  assert.deepEqual(queryIdSignals(unnamed, new Set()), ['ref=91a7c1e9-2b1a-4c9e-8f2e-6b6a2b6a2b6a'])
})

test('queryIdSignals honours user-configured extra id param names', () => {
  const p = new URLSearchParams('acct=482')
  assert.deepEqual(queryIdSignals(p, new Set()), [])
  assert.deepEqual(queryIdSignals(p, new Set(['acct'])), ['acct=482'])
})

test('isIdParamName excludes csrf/session/pagination-shaped names', () => {
  assert.equal(isIdParamName('user_id'), true)
  assert.equal(isIdParamName('csrf_token'), false)
  assert.equal(isIdParamName('page'), false)
  assert.equal(isIdParamName('valid'), false) // must not match trailing "id" without boundary
})

test('bodyIdSignals walks bounded JSON and extracts id-shaped fields', () => {
  const body = JSON.stringify({ id: 482, owner: { user_id: 91, name: 'a' }, items: [{ order_id: 7001 }] })
  const out = bodyIdSignals(body, 'application/json', new Set())
  assert.ok(out.includes('id=482'))
  assert.ok(out.includes('user_id=91'))
  assert.ok(out.includes('order_id=7001'))
})

test('bodyIdSignals ignores non-JSON mime types and malformed JSON', () => {
  assert.deepEqual(bodyIdSignals('id=482', 'application/x-www-form-urlencoded', new Set()), [])
  assert.deepEqual(bodyIdSignals('{not json', 'application/json', new Set()), [])
})

// ---------------------------------------------------------------------------
// Outcome classification
// ---------------------------------------------------------------------------

test('classifyOutcome treats 401/403/404/redirects as denied', () => {
  for (const s of [401, 403, 404, 302]) assert.equal(classifyOutcome(s, 500, 'x'.repeat(500)), 'denied')
})

test('classifyOutcome treats a hollow 200 as a soft denial', () => {
  assert.equal(classifyOutcome(200, 2, '{}'), 'denied')
})

test('classifyOutcome treats a 200 with an error-shaped body as denied', () => {
  assert.equal(classifyOutcome(200, 40, JSON.stringify({ error: 'access denied' })), 'denied')
})

test('classifyOutcome treats a normal 200/204 as success', () => {
  assert.equal(classifyOutcome(200, 300, JSON.stringify({ id: 1, name: 'ok' })), 'success')
  assert.equal(classifyOutcome(204, 0, ''), 'success')
})

test('looksLikeErrorBody / looksSensitiveBody', () => {
  assert.equal(looksLikeErrorBody('{"message":"Forbidden"}'), true)
  assert.equal(looksLikeErrorBody('{"id":1}'), false)
  assert.equal(looksSensitiveBody('{"email":"a@b.com"}'), true)
  assert.equal(looksSensitiveBody('{"id":1}'), false)
})

// ---------------------------------------------------------------------------
// Fingerprinting (dedup) — identity must be part of the identity
// ---------------------------------------------------------------------------

test('fingerprintInput differs across identity labels for an otherwise identical request', () => {
  const base = { method: 'GET', url: 'https://api.example.com/orders/482', headers: [], postData: undefined }
  const a = fingerprintInput({ ...base, identityLabel: 'User A' })
  const b = fingerprintInput({ ...base, identityLabel: 'User B' })
  assert.notEqual(a, b)
})

test('fingerprintInput is stable across volatile header/query/body noise', () => {
  const a = fingerprintInput({
    method: 'POST', url: 'https://api.example.com/x?csrf=aaa',
    headers: [{ name: 'X-CSRF-Token', value: 'aaa' }],
    postData: { text: JSON.stringify({ nonce: 'aaa', id: 1 }), mimeType: 'application/json' },
    identityLabel: 'User A',
  })
  const b = fingerprintInput({
    method: 'POST', url: 'https://api.example.com/x?csrf=bbb',
    headers: [{ name: 'X-CSRF-Token', value: 'bbb' }],
    postData: { text: JSON.stringify({ nonce: 'bbb', id: 1 }), mimeType: 'application/json' },
    identityLabel: 'User A',
  })
  assert.equal(a, b)
})

// ---------------------------------------------------------------------------
// TriageEngine — automatic (identity-only) mode
// ---------------------------------------------------------------------------

function entry({ method = 'GET', url, status, identity, at = '2026-01-01T00:00:00.000Z' }) {
  return { request: { method, url }, response: { status, mime_type: 'application/json' }, identity_label: identity, started_at: at }
}

test('two identities both succeeding on the same object -> object_idor finding', () => {
  const e = new TriageEngine()
  const created1 = e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User A' }), JSON.stringify({ id: 482, total: 10 }))
  assert.equal(created1.length, 0) // only one identity so far
  const created2 = e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User B' }), JSON.stringify({ id: 482, total: 10 }))
  assert.equal(created2.length, 1)
  assert.equal(created2[0].category, 'object_idor')
  assert.equal(created2[0].severity, 'high')
  assert.equal(e.list().length, 1)
})

test('one identity denied does not create a finding', () => {
  const e = new TriageEngine()
  e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User A' }), JSON.stringify({ id: 482 }))
  const created = e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 403, identity: 'User B' }), JSON.stringify({ error: 'forbidden' }))
  assert.equal(created.length, 0)
  assert.equal(e.list().length, 0)
})

test('a single identity revisiting its own object twice never fires', () => {
  const e = new TriageEngine()
  e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User A' }), JSON.stringify({ id: 482 }))
  const created = e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User A' }), JSON.stringify({ id: 482 }))
  assert.equal(created.length, 0)
  assert.equal(e.list().length, 0)
})

test('shared pagination values across identities do not create a false object_idor', () => {
  const e = new TriageEngine()
  e.ingest(entry({ url: 'https://app.test/api/orders?page=2', status: 200, identity: 'User A' }), JSON.stringify({ items: [] }))
  const created = e.ingest(entry({ url: 'https://app.test/api/orders?page=2', status: 200, identity: 'User B' }), JSON.stringify({ items: [] }))
  assert.equal(created.length, 0)
  assert.equal(e.list().length, 0)
})

test('repeated sightings of the same finding update hitCount instead of duplicating', () => {
  const e = new TriageEngine()
  e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User A' }), JSON.stringify({ id: 482 }))
  e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User B' }), JSON.stringify({ id: 482 }))
  e.ingest(entry({ url: 'https://app.test/api/orders/482', status: 200, identity: 'User B', at: '2026-01-01T00:05:00.000Z' }), JSON.stringify({ id: 482 }))
  assert.equal(e.list().length, 1)
  assert.equal(e.list()[0].hitCount, 2)
})

// ---------------------------------------------------------------------------
// TriageEngine — configured mode (sensitive paths, role tiers)
// ---------------------------------------------------------------------------

test('sensitive path pattern + success -> finding, escalated when tier is below the configured max', () => {
  const e = new TriageEngine({ sensitivePatterns: ['/admin'], tiers: { 'User A': 1, 'User B': 4 } })
  const created = e.ingest(entry({ url: 'https://app.test/admin/users', status: 200, identity: 'User A' }), JSON.stringify({ ok: true }))
  assert.equal(created.length, 1)
  assert.equal(created[0].category, 'sensitive_path')
  assert.equal(created[0].severity, 'high')
})

test('sensitive path pattern with no tiers configured is still flagged, at medium severity', () => {
  const e = new TriageEngine({ sensitivePatterns: ['/admin'] })
  const created = e.ingest(entry({ url: 'https://app.test/admin/users', status: 200, identity: 'User A' }), JSON.stringify({ ok: true }))
  assert.equal(created.length, 1)
  assert.equal(created[0].severity, 'medium')
})

test('sensitive path pattern does not fire on denial', () => {
  const e = new TriageEngine({ sensitivePatterns: ['/admin'] })
  const created = e.ingest(entry({ url: 'https://app.test/admin/users', status: 403, identity: 'User A' }), JSON.stringify({ error: 'forbidden' }))
  assert.equal(created.length, 0)
})

test('cross-tier function access fires regardless of capture order', () => {
  // low tier captured first
  const e1 = new TriageEngine({ tiers: { 'User A': 1, 'User B': 4 } })
  e1.ingest(entry({ url: 'https://app.test/api/reports/export', status: 200, identity: 'User A' }), JSON.stringify({ ok: true }))
  const created1 = e1.ingest(entry({ url: 'https://app.test/api/reports/export', status: 200, identity: 'User B' }), JSON.stringify({ ok: true }))
  assert.equal(created1.filter(f => f.category === 'cross_tier_function').length, 1)

  // high tier captured first (regression guard for the order-dependency bug)
  const e2 = new TriageEngine({ tiers: { 'User A': 1, 'User B': 4 } })
  e2.ingest(entry({ url: 'https://app.test/api/reports/export', status: 200, identity: 'User B' }), JSON.stringify({ ok: true }))
  const created2 = e2.ingest(entry({ url: 'https://app.test/api/reports/export', status: 200, identity: 'User A' }), JSON.stringify({ ok: true }))
  assert.equal(created2.filter(f => f.category === 'cross_tier_function').length, 1)
})

test('cross-tier check does not fire when the lower tier was denied', () => {
  const e = new TriageEngine({ tiers: { 'User A': 1, 'User B': 4 } })
  e.ingest(entry({ url: 'https://app.test/api/reports/export', status: 403, identity: 'User A' }), JSON.stringify({ error: 'forbidden' }))
  const created = e.ingest(entry({ url: 'https://app.test/api/reports/export', status: 200, identity: 'User B' }), JSON.stringify({ ok: true }))
  assert.equal(created.filter(f => f.category === 'cross_tier_function').length, 0)
})

test('a re-sighting after tiers are configured refreshes severity in place (supports panel.js reanalyzeAll)', () => {
  const e = new TriageEngine({ sensitivePatterns: ['/admin'] })
  const first = e.ingest(entry({ url: 'https://app.test/admin/users', status: 200, identity: 'User A' }), JSON.stringify({ ok: true }))
  assert.equal(first[0].severity, 'medium')
  e.setTier('User A', 1)
  e.setTier('User B', 4)
  e.ingest(entry({ url: 'https://app.test/admin/users', status: 200, identity: 'User A', at: '2026-01-01T00:05:00.000Z' }), JSON.stringify({ ok: true }))
  assert.equal(e.list().length, 1)
  assert.equal(e.list()[0].severity, 'high')
})

test('identitySummary reports counts and configured tiers', () => {
  const e = new TriageEngine({ tiers: { 'User A': 2 } })
  e.ingest(entry({ url: 'https://app.test/x', status: 200, identity: 'User A' }), '{}')
  e.ingest(entry({ url: 'https://app.test/y', status: 200, identity: 'User A' }), '{}')
  e.ingest(entry({ url: 'https://app.test/x', status: 200, identity: 'User B' }), '{}')
  const summary = Object.fromEntries(e.identitySummary().map(s => [s.label, s]))
  assert.equal(summary['User A'].count, 2)
  assert.equal(summary['User A'].tier, 2)
  assert.equal(summary['User B'].tier, '')
})
