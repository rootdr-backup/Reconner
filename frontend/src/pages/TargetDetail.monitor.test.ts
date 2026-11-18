import { describe, expect, it } from 'vitest'
import { changeBadgeVariant, monitorRowKind } from './TargetDetail'
import type { MonitoringChange } from '../types'

// Regression: clicking the Changes tab used to render the PREVIOUS tab's rows
// for one frame (data is replaced only after the fetch resolves). A subdomain
// row has no change_type, and the old helpers dereferenced it directly:
//   TypeError: Cannot read properties of undefined (reading 'includes')
// The chips call monitorRowKind() for every loaded row, so the throw happened
// before React could commit the tab. Both helpers must classify any row shape.
describe('Changes tab row helpers tolerate foreign rows', () => {
  it('classifies a stale non-monitor row instead of throwing', () => {
    const stale = { id: 's1', target_id: 't1', subdomain: 'a.example.test' } as unknown as MonitoringChange
    expect(monitorRowKind(stale)).toBe('http')
    expect(changeBadgeVariant(stale)).toBe('info')
  })

  it('still classifies real monitor rows', () => {
    const css = { change_type: 'css_change', severity: 'info' } as MonitoringChange
    const js = { change_type: 'js_change', severity: 'medium' } as MonitoringChange
    const sheet = { change_type: 'security:stylesheet_added', severity: 'info' } as MonitoringChange
    const header = { change_type: 'security:header_removed', severity: 'high' } as MonitoringChange
    expect(monitorRowKind(css)).toBe('css')
    expect(monitorRowKind(js)).toBe('scripts')
    expect(monitorRowKind(sheet)).toBe('css')
    expect(monitorRowKind(header)).toBe('headers')
    expect(changeBadgeVariant(css)).toBe('info')
    expect(changeBadgeVariant(js)).toBe('medium')
    expect(changeBadgeVariant(header)).toBe('high')
  })
})
