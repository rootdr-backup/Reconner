import { describe, expect, it } from 'vitest'
import {
  INITIAL_ACCESS_PROFILE,
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
    const selections = [SAFE_PROFILE, STANDARD_PROFILE, INITIAL_ACCESS_PROFILE, ...SCAN_BUNDLES.map(bundle => bundle.modules)]
    for (const selection of selections) {
      for (const id of selection) expect(MODULE_BY_ID.has(id), id).toBe(true)
    }
  })

  it('Initial Access profile covers panel/RCE/network-access detectors only', () => {
    const ia = new Set(INITIAL_ACCESS_PROFILE)
    // Must include: RCE-class, panel/credential-access, and network-access
    // (SSRF + its OOB confirmation channel) detectors.
    for (const id of ['sqli', 'cmdi', 'ssti', 'lfi', 'xxe', 'file_upload', 'nuclei',
      'dir_discovery', 'backup_discovery', 'exposure', 'intel', 'takeover',
      'jwt', 'idor', 'authz', 'ato', 'ssrf', 'oast']) {
      expect(ia.has(id), id).toBe(true)
    }
    // Must exclude classes that cannot by themselves hand over a panel, RCE,
    // or network pivot — kept out to stay a focused objective.
    for (const id of ['xss', 'csrf', 'cors', 'cache_poison', 'race', 'smuggling',
      'vuln_scan', 'open_redirect', 'blh', 'nosqli', 'csti', 'api_data_exposure']) {
      expect(ia.has(id), id).toBe(false)
    }
    // Every module in the preset must resolve into a complete, valid plan
    // (the same closure the backend independently re-derives).
    const resolved = resolveModuleSelection(ia)
    for (const id of ia) expect(resolved.has(id), id).toBe(true)
    expect(resolved.has('verify')).toBe(true)
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

  it('plans API data exposure with the request-vocabulary pipeline', () => {
    const resolved = resolveModuleSelection(new Set(['api_data_exposure']))
    for (const id of ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery', 'param_reflection', 'api_data_exposure', 'verify']) {
      expect(resolved.has(id), id).toBe(true)
    }
    expect(resolved.has('subdomain_enum')).toBe(false)
    expect(resolved.has('sqli')).toBe(false)
  })
})
