// Module identity — no emoji. Each module maps to a short mono code and a group,
// rendered as a clean colored letter-badge by the <ModuleIcon> component.

type Group = 'recon' | 'inject' | 'analysis'

const MODULE_GROUP: Record<string, Group> = {
  scheduler: 'analysis', tools: 'analysis',
  subdomain_enum: 'recon', http_probe: 'recon', js_analysis: 'recon',
  js_endpoints: 'recon', param_discovery: 'recon', timemachine: 'recon',
  param_reflection: 'recon', paramfuzz: 'recon', dir_discovery: 'recon',
  backup_discovery: 'recon',
  open_redirect: 'inject', api_data_exposure: 'inject', nuclei: 'inject', dast: 'inject', vuln_scan: 'inject',
  sqli: 'inject', nosqli: 'inject', ssrf: 'inject', idor: 'inject', race: 'inject',
  smuggling: 'inject', cache_poison: 'inject', oast: 'inject', lfi: 'inject',
  ssti: 'inject', csti: 'inject', xxe: 'inject', file_upload: 'inject', cmdi: 'inject', blh: 'inject', csrf: 'inject',
  passive: 'analysis', takeover: 'analysis', origin_ip: 'analysis',
  shodan: 'analysis', exposure: 'analysis', intel: 'analysis', verify: 'analysis',
  monitor: 'analysis',
	network: 'recon', network_nuclei_only: 'inject', network_initial_access: 'inject', network_brute: 'inject',
}

const MODULE_CODE: Record<string, string> = {
  scheduler: 'SC', tools: 'TL',
  subdomain_enum: 'SD', http_probe: 'HT', js_analysis: 'JS', js_endpoints: 'JE',
  param_discovery: 'PD', timemachine: 'TM', param_reflection: 'RF', paramfuzz: 'PF',
  dir_discovery: 'DR', backup_discovery: 'BK', api_data_exposure: 'PI',
  open_redirect: 'OR', nuclei: 'NU', dast: 'DA', vuln_scan: 'VN', sqli: 'SQ',
  nosqli: 'NQ', ssrf: 'SR', idor: 'ID', race: 'RC', smuggling: 'SM',
  cache_poison: 'CP', oast: 'OA', lfi: 'LF', ssti: 'ST', csti: 'CT', xxe: 'XX', file_upload: 'FU', cmdi: 'CM',
  blh: 'BL', csrf: 'CS',
  passive: 'PA', takeover: 'TK', origin_ip: 'OI', shodan: 'SH', exposure: 'EX',
  intel: 'IN', verify: 'VF', monitor: 'MO',
	network: 'NW', network_nuclei_only: 'NN', network_initial_access: 'NA', network_brute: 'NB',
}

export const moduleGroup = (m?: string): Group => (m && MODULE_GROUP[m]) || 'analysis'
export const moduleCode = (m?: string): string =>
  (m && MODULE_CODE[m]) || (m ? m.slice(0, 2).toUpperCase() : '··')
