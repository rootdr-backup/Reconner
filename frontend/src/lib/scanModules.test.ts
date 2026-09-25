import { describe, expect, it } from 'vitest'
import {
  MODULE_BY_ID,
  SAFE_PROFILE,
  SCAN_BUNDLES,
  SCAN_MODULES,
  STANDARD_PROFILE,
  resolveModuleSelection,
} from './scanModules'

describe('scan module catalog', () => {
  it('contains unique modules and only resolvable dependencies', () => {
    const ids = SCAN_MODULES.map(module => module.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const module of SCAN_MODULES) {
      for (const dependency of module.requires || []) {
        expect(MODULE_BY_ID.has(dependency), `${module.id} -> ${dependency}`).toBe(true)
      }
    }
  })

  it('keeps every preset and bundle free of stale module ids', () => {
    const selections = [SAFE_PROFILE, STANDARD_PROFILE, ...SCAN_BUNDLES.map(bundle => bundle.modules)]
    for (const selection of selections) {
      for (const id of selection) expect(MODULE_BY_ID.has(id), id).toBe(true)
    }
  })

  it('expands a focused detector into a complete ordered dependency set', () => {
    const resolved = resolveModuleSelection(new Set(['sqli']))
    for (const id of ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery', 'param_reflection', 'sqli', 'verify']) {
      expect(resolved.has(id), id).toBe(true)
    }
    expect(resolved.has('xss')).toBe(false)
    expect(resolved.has('subdomain_enum')).toBe(false)
  })

  it('plans file upload validation without unrelated detectors', () => {
    const resolved = resolveModuleSelection(new Set(['file_upload']))
    for (const id of ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery', 'param_reflection', 'file_upload', 'verify']) {
      expect(resolved.has(id), id).toBe(true)
    }
    expect(resolved.has('xss')).toBe(false)
    expect(resolved.has('xxe')).toBe(false)
  })
})
