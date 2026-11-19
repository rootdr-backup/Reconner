import { describe, expect, it } from 'vitest'
import { groupMonitorChanges } from './TargetDetail'
import type { MonitoringChange } from '../types'

const row = (over: Partial<MonitoringChange>): MonitoringChange => ({
  id: 'id',
  target_id: 't1',
  url: 'https://a.example.test/',
  change_type: 'http_change',
  old_value: '',
  new_value: '',
  severity: 'info',
  detected_at: '2026-01-01 00:00:00',
  ...over,
})

describe('groupMonitorChanges', () => {
  it('keeps every occurrence and dedupes only the URL list', () => {
    const groups = groupMonitorChanges([
      row({ id: '1', url: 'https://a.example.test/' }),
      row({ id: '2', url: 'https://b.example.test/' }),
      row({ id: '3', url: 'https://a.example.test/' }),
    ])
    expect(groups).toHaveLength(1)
    expect(groups[0].items.map(i => i.id)).toEqual(['1', '2', '3'])
    expect(groups[0].urls).toEqual(['https://a.example.test/', 'https://b.example.test/'])
    expect(groups[0].rep.id).toBe('1')
    expect(groups[0].key).toBe('http_change\u0000\u0000')
  })

  it('separates groups by change type and old/new values', () => {
    const groups = groupMonitorChanges([
      row({ id: '1' }),
      row({ id: '2', change_type: 'tech_change' }),
      row({ id: '3', old_value: 'a', new_value: 'b' }),
    ])
    expect(groups.map(g => g.key)).toEqual([
      'http_change\u0000\u0000',
      'tech_change\u0000\u0000',
      'http_change\u0000a\u0000b',
    ])
  })
})
