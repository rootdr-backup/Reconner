import { describe, expect, it } from 'vitest'
import {
  categoryForChangeType,
  changeBadgeVariant,
  groupMonitorChanges,
  inlineDiffPieces,
  monitorRowKind,
  parseStatusTransition,
} from './changesModel'
import type { MonitoringChange } from '../../types'

describe('categoryForChangeType', () => {
  it('maps the new watch change types', () => {
    expect(categoryForChangeType('status_change')).toBe('http')
    expect(categoryForChangeType('page_change')).toBe('http')
    expect(categoryForChangeType('new_subdomain')).toBe('assets')
    expect(categoryForChangeType('scope_landed')).toBe('assets')
  })

  it('routes stylesheets and scripts to scripts, not css', () => {
    expect(categoryForChangeType('css_change')).toBe('scripts')
    expect(categoryForChangeType('js_change')).toBe('scripts')
    expect(categoryForChangeType('security:script_added')).toBe('scripts')
    expect(categoryForChangeType('security:stylesheet_added')).toBe('scripts')
    expect(monitorRowKind({ change_type: 'css_change' })).toBe('scripts')
  })

  it('routes header changes to headers before the security prefix', () => {
    expect(categoryForChangeType('security_header_removed')).toBe('headers')
    expect(categoryForChangeType('security:header_removed')).toBe('headers')
  })

  it('falls back to http for unknown or missing types', () => {
    expect(categoryForChangeType('')).toBe('http')
    expect(categoryForChangeType('something_new')).toBe('http')
  })
})

describe('changeBadgeVariant', () => {
  it('honours a stored severity including critical', () => {
    expect(changeBadgeVariant({ severity: 'critical' })).toBe('critical')
    expect(changeBadgeVariant({ severity: 'high' })).toBe('high')
    expect(changeBadgeVariant({ severity: 'info' })).toBe('info')
  })

  it('falls back by type when severity is missing', () => {
    expect(changeBadgeVariant({ change_type: 'js_change' })).toBe('medium')
    expect(changeBadgeVariant({ change_type: 'security:script_added' })).toBe('high')
    expect(changeBadgeVariant({ change_type: 'tech_change' })).toBe('low')
    expect(changeBadgeVariant({ change_type: 'status_change' })).toBe('info')
  })
})

describe('groupMonitorChanges', () => {
  const row = (over: Partial<MonitoringChange>): MonitoringChange => ({
    id: over.id || 'x',
    target_id: over.target_id || '',
    url: over.url || '',
    change_type: over.change_type || '',
    old_value: over.old_value || '',
    new_value: over.new_value || '',
    severity: over.severity || 'info',
    detected_at: over.detected_at || '2026-01-01 00:00:00',
  })

  it('keeps the legacy three-part key for an empty identity', () => {
    const rows = [
      row({ id: '1', change_type: 'status_change', old_value: '403', new_value: '200' }),
      row({ id: '2', change_type: 'status_change', old_value: '403', new_value: '200', url: 'https://b.test' }),
    ]
    const groups = groupMonitorChanges(rows)
    expect(groups).toHaveLength(1)
    expect(groups[0].items).toHaveLength(2)
    expect(groups[0].urls).toEqual(['', 'https://b.test'])
  })

  it('separates identical changes from different targets when identity is supplied', () => {
    const rows = [
      row({ id: '1', target_id: 'a', change_type: 'status_change', old_value: '403', new_value: '200' }),
      row({ id: '2', target_id: 'b', change_type: 'status_change', old_value: '403', new_value: '200' }),
    ]
    const groups = groupMonitorChanges(rows, (r: MonitoringChange) => r.target_id)
    expect(groups).toHaveLength(2)
  })
})

describe('parseStatusTransition', () => {
  it('reads codes from the monitor value format', () => {
    expect(parseStatusTransition('status=403 title=Forbidden', 'status=200 title=OK')).toEqual({ oldCode: 403, newCode: 200 })
  })

  it('reads bare codes', () => {
    expect(parseStatusTransition('301', '302')).toEqual({ oldCode: 301, newCode: 302 })
  })

  it('prefers the explicit status code over an earlier bare number', () => {
    expect(parseStatusTransition('2026-01-02 status=403', '2026-01-02 status=200')).toEqual({ oldCode: 403, newCode: 200 })
  })

  it('returns undefined when no code is present', () => {
    expect(parseStatusTransition('title changed', 'new title')).toEqual({ oldCode: undefined, newCode: undefined })
  })
})

describe('inlineDiffPieces', () => {
  it('marks only the changed words', () => {
    const pieces = inlineDiffPieces('Server: nginx', 'Server: apache')
    const removed = pieces.filter(p => p.kind === 'removed').map(p => p.text).join('')
    const added = pieces.filter(p => p.kind === 'added').map(p => p.text).join('')
    expect(removed).toContain('nginx')
    expect(added).toContain('apache')
    expect(pieces.some(p => p.kind === 'same' && p.text.includes('Server'))).toBe(true)
  })
})
