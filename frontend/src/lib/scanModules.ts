export type ScanModuleTier = 'safe' | 'active' | 'advanced'

export type ScanModule = {
  id: string
  label: string
  desc: string
  group: string
  tier: ScanModuleTier
  automatic?: boolean
  requires?: string[]
}

export const SCAN_GROUPS = [
  { id: 'surface', label: '1. Surface mapping', desc: 'Build the live, JavaScript and parameter inventory first.' },
  { id: 'exposure', label: '2. Passive & exposure checks', desc: 'Low-impact checks over the discovered surface.' },
  { id: 'validation', label: '3. Vulnerability validation', desc: 'Focused active checks; each selection brings its required discovery pipeline.' },
  { id: 'identity', label: '4. Identity & access', desc: 'Authentication-aware checks; IDOR/Authz require configured identities.' },
  { id: 'advanced', label: '5. Advanced opt-in', desc: 'Higher-cost or timing-sensitive checks. Never enabled by the safe profile.' },
]

const core = ['http_probe']
const params = ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery', 'param_reflection']

export const SCAN_MODULES: ScanModule[] = [
  { id: 'subdomain_enum', label: 'Subdomain discovery', desc: 'Discover subdomains. Explicit opt-in; selecting other checks never enables it.', group: 'surface', tier: 'active' },
  { id: 'http_probe', label: 'HTTP service probe', desc: 'Find reachable HTTP(S) services and record fingerprints.', group: 'surface', tier: 'safe' },
  { id: 'js_analysis', label: 'JavaScript analysis', desc: 'Extract endpoints, technologies and potential secret candidates from collected JavaScript.', group: 'surface', tier: 'safe', requires: core },
  { id: 'js_endpoints', label: 'JavaScript endpoints', desc: 'Resolve and probe endpoints found in JavaScript.', group: 'surface', tier: 'safe', requires: ['http_probe', 'js_analysis'] },
  { id: 'param_discovery', label: 'Parameter discovery', desc: 'Collect query, form, OpenAPI and crawl parameters using inert discovery requests.', group: 'surface', tier: 'safe', requires: ['http_probe', 'js_analysis', 'js_endpoints'] },
  { id: 'param_reflection', label: 'Reflection map', desc: 'Identify parameters reflected by the application for focused downstream validation.', group: 'surface', tier: 'active', requires: ['http_probe', 'param_discovery'] },
  { id: 'headless_crawl', label: 'Rendered SPA crawl', desc: 'Use Chromium to collect DOM-rendered routes and form contracts.', group: 'surface', tier: 'active', requires: core },
  { id: 'timemachine', label: 'Archive enrichment', desc: 'Mine historical URLs. Optional because parameter discovery already performs bounded archive collection.', group: 'surface', tier: 'advanced', requires: core },
  { id: 'paramfuzz', label: 'Hidden parameter mining', desc: 'Use inert markers and negative controls to identify undocumented parameters.', group: 'surface', tier: 'active', requires: params },

  { id: 'passive', label: 'Passive security review', desc: 'Review headers, cookies, stack traces and exposed metadata.', group: 'exposure', tier: 'safe', requires: core },
  { id: 'exposure', label: 'Exposure checks', desc: 'Detect exposed API specifications, GraphQL schemas, buckets and sensitive files.', group: 'exposure', tier: 'safe', requires: core },
  { id: 'intel', label: 'Technology intelligence', desc: 'Technology-specific fingerprinting and version-based candidates.', group: 'exposure', tier: 'safe', requires: core },
  { id: 'dir_discovery', label: 'Path discovery', desc: 'Discover additional application paths with bounded requests.', group: 'exposure', tier: 'active', requires: core },
  { id: 'backup_discovery', label: 'Backup/config exposure', desc: 'Check for exposed backup and configuration artifacts.', group: 'exposure', tier: 'active', requires: core },
  { id: 'nuclei', label: 'Nuclei templates', desc: 'Run the configured curated template set. Kept out of the safe preset.', group: 'exposure', tier: 'active', requires: core },
  { id: 'takeover', label: 'Known-subdomain takeover', desc: 'Check already-known subdomains for dangling DNS. Use the takeover bundle to discover subdomains first.', group: 'exposure', tier: 'safe', requires: core },
  { id: 'origin_ip', label: 'Origin intelligence', desc: 'Passive origin-IP enrichment; requires configured provider credentials.', group: 'exposure', tier: 'safe', requires: core },
  { id: 'shodan', label: 'Shodan intelligence', desc: 'Passive Shodan enrichment; requires an API key.', group: 'exposure', tier: 'safe', requires: core },

  { id: 'open_redirect', label: 'Open redirect', desc: 'Focused redirect validation over discovered parameters.', group: 'validation', tier: 'active', requires: params },
  { id: 'xss', label: 'XSS', desc: 'Context-aware XSS validation; findings require real browser execution proof.', group: 'validation', tier: 'active', requires: params },
  { id: 'sqli', label: 'SQL injection', desc: 'Differential SQL injection detection over preserved request contracts.', group: 'validation', tier: 'active', requires: params },
  { id: 'nosqli', label: 'NoSQL injection', desc: 'Focused NoSQL operator and error-differential checks.', group: 'validation', tier: 'active', requires: params },
  { id: 'ssrf', label: 'SSRF', desc: 'Validate server-side request behavior on URL-shaped inputs.', group: 'validation', tier: 'active', requires: params },
  { id: 'lfi', label: 'Path traversal / LFI', desc: 'Validate file/path handling over discovered inputs.', group: 'validation', tier: 'active', requires: params },
  { id: 'ssti', label: 'Server template injection', desc: 'Use safe arithmetic differentials to identify server template evaluation.', group: 'validation', tier: 'active', requires: params },
  { id: 'csti', label: 'Client template injection', desc: 'Use dual safe arithmetic proof after browser rendering.', group: 'validation', tier: 'active', requires: params },
  { id: 'xxe', label: 'XML entity handling', desc: 'Focused XML parser validation on compatible request contracts.', group: 'validation', tier: 'active', requires: params },
  { id: 'file_upload', label: 'File upload validation', desc: 'Proof-gated executable, SVG/image-processing, archive and web-root configuration checks.', group: 'validation', tier: 'active', requires: params },
  { id: 'cmdi', label: 'Command injection signal', desc: 'Focused command-execution detection on compatible inputs.', group: 'validation', tier: 'advanced', requires: params },
  { id: 'cors', label: 'CORS policy', desc: 'Validate cross-origin policy behavior.', group: 'validation', tier: 'active', requires: core },
  { id: 'csrf', label: 'CSRF controls', desc: 'Review state-changing request protections.', group: 'validation', tier: 'active', requires: core },
  { id: 'vuln_scan', label: 'Web behavior checks', desc: 'Combined prototype-pollution, 403-bypass, host-header, CRLF and cache-deception checks.', group: 'validation', tier: 'advanced', requires: params },
  { id: 'blh', label: 'Broken-link hijacking', desc: 'Check discovered outbound links for abandoned destinations.', group: 'validation', tier: 'active', requires: params },

  { id: 'jwt', label: 'JWT / OAuth review', desc: 'Review JWT claims/configuration and OAuth flows.', group: 'identity', tier: 'active', requires: params },
  { id: 'idor', label: 'IDOR / BOLA', desc: 'Cross-user object-access validation; requires two identities.', group: 'identity', tier: 'active', requires: params },
  { id: 'authz', label: 'Authorization workflows', desc: 'Replay captured read-only workflows across configured identities.', group: 'identity', tier: 'active', requires: params },
  { id: 'ato', label: 'Account-takeover chains', desc: 'Correlate independently detected authentication and redirect weaknesses.', group: 'identity', tier: 'active', requires: params },

  { id: 'oast', label: 'Out-of-band correlation', desc: 'Out-of-band callback correlation across supported blind classes.', group: 'advanced', tier: 'advanced', requires: params },
  { id: 'cache_poison', label: 'Cache poisoning', desc: 'Timing/cache-sensitive unkeyed-input validation.', group: 'advanced', tier: 'advanced', requires: core },
  { id: 'race', label: 'Race conditions', desc: 'Parallel-burst timing validation. Explicit opt-in only.', group: 'advanced', tier: 'advanced', requires: params },
  { id: 'smuggling', label: 'Request smuggling', desc: 'Timing-based HTTP desynchronization detection. Explicit opt-in only.', group: 'advanced', tier: 'advanced', requires: core },

  { id: 'verify', label: 'Result verification', desc: 'Automatically re-check and score detector output.', group: 'advanced', tier: 'safe', automatic: true },
]

export const MODULE_BY_ID = new Map(SCAN_MODULES.map(module => [module.id, module]))

export const DETECTOR_IDS = new Set(SCAN_MODULES.filter(module =>
  !['surface'].includes(module.group) && module.id !== 'verify'
).map(module => module.id).concat([
  'open_redirect', 'xss', 'sqli', 'nosqli', 'ssrf', 'lfi', 'ssti', 'csti', 'xxe', 'file_upload', 'cmdi',
  'cors', 'csrf', 'vuln_scan', 'blh', 'jwt', 'idor', 'authz', 'ato', 'oast', 'cache_poison',
  'race', 'smuggling', 'nuclei', 'takeover', 'origin_ip', 'shodan', 'passive', 'exposure', 'intel',
  'dir_discovery', 'backup_discovery',
]))

export function resolveModuleSelection(explicit: Set<string>): Set<string> {
  const resolved = new Set(explicit)
  const queue = [...explicit]
  let hasDetector = false
  while (queue.length > 0) {
    const id = queue.shift()!
    if (DETECTOR_IDS.has(id)) hasDetector = true
    for (const dependency of MODULE_BY_ID.get(id)?.requires || []) {
      if (!resolved.has(dependency)) {
        resolved.add(dependency)
        queue.push(dependency)
      }
    }
  }
  if (hasDetector) resolved.add('verify')
  return resolved
}

export const SCAN_BUNDLES = [
  { id: 'surface', label: 'Complete surface map', desc: 'HTTP + JavaScript + parameters', modules: ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery'] },
  { id: 'exposure', label: 'Exposure review', desc: 'Passive, files and technology signals', modules: ['passive', 'exposure', 'intel', 'backup_discovery'] },
  { id: 'takeover', label: 'Subdomains + takeover', desc: 'Discovery followed by dangling-DNS checks', modules: ['subdomain_enum', 'takeover'] },
  { id: 'injection', label: 'Injection validation', desc: 'Focused parameter-driven detectors', modules: ['open_redirect', 'xss', 'sqli', 'nosqli', 'ssrf', 'lfi', 'ssti', 'csti', 'xxe', 'file_upload'] },
  { id: 'access', label: 'Identity & access', desc: 'JWT, IDOR, authorization and chains', modules: ['jwt', 'idor', 'authz', 'ato'] },
]

export const SAFE_PROFILE = ['http_probe', 'js_analysis', 'js_endpoints', 'param_discovery', 'passive', 'exposure', 'intel']
export const STANDARD_PROFILE = [...SAFE_PROFILE, 'param_reflection', 'backup_discovery', 'open_redirect', 'xss', 'sqli', 'cors', 'jwt']
