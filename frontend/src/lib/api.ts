import type {
  Target, Subdomain, HTTPService, JSFile, JSFinding,
  Parameter, DirectoryFinding, BackupFinding, OpenRedirectFinding,
  NucleiFinding, VulnFinding, MonitoringChange, Task, TaskLog, TaskPhase, DashboardStats, AttackPath,
  NetworkService, IngramCamera, Asset,
  BountyProgram, BountySyncState, BountyScopeEvent,
} from '../types'

const BASE = '/api'

export class APIError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

async function req<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  const text = await res.text()
  if (!res.ok) {
    let msg = text
    try { msg = JSON.parse(text).error || text } catch { /**/ }
    throw new APIError(res.status, msg)
  }
  if (!text) return undefined as T
  const json = JSON.parse(text)
  if (json && typeof json === 'object') {
    if ('success' in json && 'data' in json) return json.data as T
    if ('data' in json && 'total' in json) return json.data as T
  }
  return json as T
}

export const auth = {
  login: (username: string, password: string) =>
    req<{message: string}>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => req<void>('/auth/logout', { method: 'POST' }),
  me: () => req<{id: number; username: string; role: string; must_change_password?: boolean}>('/auth/me'),
  changePassword: (oldPassword: string, newPassword: string) =>
    req<{message: string}>('/auth/change-password', { method: 'POST', body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }) }),
}

export interface AccountUser {
  id: number
  username: string
  role: 'admin' | 'member'
  disabled: boolean
  created_at: string
  updated_at: string
}

// Admin-only user administration. Every call is gated server-side by requireAdmin.
export const users = {
  list: () => req<AccountUser[]>('/users'),
  create: (username: string, password: string, role: string) =>
    req<AccountUser>('/users', { method: 'POST', body: JSON.stringify({ username, password, role }) }),
  update: (id: number, patch: { role?: string; disabled?: boolean; password?: string }) =>
    req<AccountUser>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  remove: (id: number) => req<{ message: string }>(`/users/${id}`, { method: 'DELETE' }),
}

export interface DashboardCharts {
  top_targets?: { id: string; domain: string; name: string; kind: string; subdomains: number; alive_hosts: number; findings: number }[]
  severity_breakdown?: { severity: string; count: number }[]
  vuln_by_type?: { type: string; count: number }[]
  scans_over_time?: { date: string; scans: number }[]
}

export const dashboard = {
  stats: () => req<DashboardStats>('/dashboard/stats'),
  charts: () => req<DashboardCharts>('/dashboard/charts'),
}

export const targets = {
  list: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return req<Target[]>(`/targets${q}`)
  },
  get: (id: string) => req<Target>(`/targets/${id}`),
  create: (data: {domain: string; name?: string; description?: string; tags?: string[]; priority?: string; notes?: string; kind?: string; exclude_scope?: string; scan_user_agent?: string; scan_headers?: Record<string, string>}) =>
    req<Target>('/targets', { method: 'POST', body: JSON.stringify(data) }),
  networkServices: (id: string) => req<NetworkService[]>(`/targets/${id}/network-services`),
  assets: (id: string) => req<Asset[]>(`/targets/${id}/assets`),
  addAsset: (id: string, value: string, name: string, assetType?: string) =>
    req<Asset>(`/targets/${id}/assets`, { method: 'POST', body: JSON.stringify({ value, name, asset_type: assetType }) }),
  updateAsset: (id: string, aid: string, data: { name?: string; value?: string; asset_type?: string }) =>
    req<void>(`/targets/${id}/assets/${aid}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAsset: (id: string, aid: string) =>
    req<void>(`/targets/${id}/assets/${aid}`, { method: 'DELETE' }),
  scanAsset: (id: string, aid: string, modules: string[]) =>
    req<{ id: string }>(`/targets/${id}/assets/${aid}/scan`, { method: 'POST', body: JSON.stringify({ modules }) }),
  update: (id: string, data: Partial<Target>) =>
    req<void>(`/targets/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id: string) => req<void>(`/targets/${id}`, { method: 'DELETE' }),
  bulkDelete: (ids: string[]) =>
    req<{ deleted: number; failed: number; requested: number }>('/targets/bulk-delete', { method: 'POST', body: JSON.stringify({ ids }) }),
  updateMonitor: (id: string, enabled: boolean, hours: number) =>
    req<void>(`/targets/${id}/monitor`, { method: 'PATCH', body: JSON.stringify({ monitor_enabled: enabled, monitor_interval_hours: hours }) }),
  setAuth: (id: string, headers: Record<string,string>) =>
    req<void>(`/targets/${id}/auth`, { method: 'PATCH', body: JSON.stringify({ auth_headers: headers }) }),
  graph: (id: string) => req<{ attack_paths: AttackPath[]; nodes: unknown[]; edges: unknown[] }>(`/targets/${id}/graph`),
  reportURL: (id: string) => `${BASE}/targets/${id}/report`,
  reportPdfURL: (id: string) => `${BASE}/targets/${id}/report.pdf`,
  startScan: (id: string, modules: string[], priority = 5) =>
    req<Task>(`/targets/${id}/scan`, { method: 'POST', body: JSON.stringify({ modules, priority }) }),
  pauseScan: (id: string) => req<void>(`/targets/${id}/pause`, { method: 'POST' }),
  resumeScan: (id: string) => req<void>(`/targets/${id}/resume`, { method: 'POST' }),
  skipPhase: (id: string) => req<void>(`/targets/${id}/skip-phase`, { method: 'POST' }),
  cancelScan: (id: string) => req<void>(`/targets/${id}/cancel`, { method: 'POST' }),
  identities: (id: string) => req<{ id: string; label: string; role: string; is_baseline: boolean; status: string; auth_method: string; last_verified_at: string }[]>(`/targets/${id}/identities`),
  addIdentity: (id: string, body: { label: string; role?: string; headers: Record<string,string>; is_baseline: boolean; validation_url?: string; validation_signal?: string; origin?: string }) =>
    req<{ id: string }>(`/targets/${id}/identities`, { method: 'POST', body: JSON.stringify(body) }),
  delIdentity: (id: string, iid: string) => req<void>(`/targets/${id}/identities/${iid}`, { method: 'DELETE' }),
  validateIdentity: (id: string, iid: string) => req<{ status: string }>(`/targets/${id}/identities/${iid}/validate`, { method: 'POST' }),
  evidence: (id: string, fid: string) => req<{ identity_label: string; request: string; response: string; comparison: string; note: string }[]>(`/targets/${id}/findings/${fid}/evidence`),
  replay: (id: string, body: { method?: string; url: string; body?: string; content_type?: string; identity_id?: string }) =>
    req<{ results: { identity_label: string; status: number; content_type: string; length: number; body: string; verdict: string; timing_ms: number }[]; comparison?: string }>(`/targets/${id}/replay`, { method: 'POST', body: JSON.stringify(body) }),
  objects: (id: string) => req<{ type: string; identifier: string; endpoint: string; param: string; owner: string; source_url: string }[]>(`/targets/${id}/objects`),
  hypotheses: (id: string) => req<{ kind: string; identity: string; object_type: string; object_id: string; action: string; endpoint: string; expected: string; observed: string; status: string; confidence: number; test_plan: string; reason: string; finding_id: string }[]>(`/targets/${id}/hypotheses`),
  relationships: (id: string) => req<{ object_type: string; object_id: string; endpoint: string; identity: string; role: string; provenance: string }[]>(`/targets/${id}/relationships`),
  verifyWrite: (id: string, body: { owner_label: string; attacker_label: string; object_type: string; object_id: string; read_url: string; write_method: string; write_url: string; write_body?: string; content_type?: string; hypothesis_id?: string }) =>
    req<{ side_effect: boolean; summary: string; observed: string; finding_id: string; before_status: number; after_status: number; write_status: number }>(`/targets/${id}/verify-write`, { method: 'POST', body: JSON.stringify(body) }),
  findingGroups: (id: string) => req<{ key: string; type: string; severity: string; affected_count: number; confidence: number; root_evidence: string }[]>(`/targets/${id}/finding-groups`),
  workflowGraph: (id: string) => req<{ nodes: { id: string; type: string; label: string; sub: string }[]; edges: { from: string; to: string; label: string; kind: string }[] }>(`/targets/${id}/workflow-graph`),
  runWorkflow: (id: string, steps: unknown[], seed?: Record<string, string>) =>
    req<{ steps: { index: number; identity: string; method: string; url: string; status: number; verdict: string; missing_refs: string[]; extracted: Record<string, string>; flagged: boolean }[]; vars: Record<string, string>; aborted: boolean; abort_reason: string; flagged_step: number }>(`/targets/${id}/workflow/run`, { method: 'POST', body: JSON.stringify({ steps, seed: seed || {} }) }),
  importSession: (id: string, body: { label: string; origin: string; storage_state: string; is_baseline: boolean; validation_url?: string; validation_signal?: string }) =>
    req<{ id: string }>(`/targets/${id}/identities/import`, { method: 'POST', body: JSON.stringify(body) }),
  importFile: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return req<{ imported: number; total: number; invalid: number; duplicates: number }>('/targets/import', { method: 'POST', headers: {}, body: form })
  },
}

export interface CapturePreviewItem {
  sequence: number; method: string; route: string; status: number
  operation_kind: string; sensitive: boolean; header_names?: string[]
  request_body_bytes: number; response_body_bytes: number
  accepted: boolean; reject_reason?: string; suggested_tests?: string[]; auto_eligible: boolean
}

export interface CapturePreview {
  source: string; total: number; accepted: number; rejected: number; sensitive: number
  read_only: number; state_changing: number; authentication: number; unknown: number
  items: CapturePreviewItem[]
}

export interface CapturedRequest { method: string; url: string; http_version?: string; headers: { name: string; value: string }[]; body: string | null; mime_type: string }
export interface GuidedFinding { type: string; parameter: string; severity: string; verdict: string; evidence: string; payload: string; test_case?: CapturedRequest; finding_id?: string }
export interface GuidedReport { results?: { template_id: string; module: string; status: string; reason: string; requests: number; findings: GuidedFinding[] }[]; manual_modules?: Record<string, string> }
export interface GuidedRun { id: string; task_id: string; status: string; report: GuidedReport; created_at: string }
export interface GuidedOpportunity { module: string; parameter: string; location: string; confidence: number; reason: string; payloads?: string[]; automated: boolean }
export interface GuidedCheck { template_id: string; module: string }
export interface CaptureTemplate { id: string; method: string; route: string; kind: string; preflight_status: string; version: string; suggestions: GuidedOpportunity[] }
export interface CapturePreflight {
  capture_id: string; ready: number; blocked: number; failed_or_stale: number
  requests_sent: number; mutations_sent: number; mode: string
  results: { template_id: string; method: string; route: string; status: string; http_status: number; captured_status: number; baseline_match: boolean; reason: string; timing_ms: number }[]
}

function captureForm(file: File, source: string, identityLabel: string, label: string) {
  const form = new FormData()
  form.append('file', file)
  form.append('source', source)
  form.append('identity_label', identityLabel)
  form.append('label', label)
  return form
}

export const captures = {
  remove: (targetId: string, captureId: string) => req<{ deleted: boolean }>(`/targets/${targetId}/captures/${captureId}`, { method: 'DELETE' }),
  templates: (targetId: string, captureId: string) => req<CaptureTemplate[]>(`/targets/${targetId}/captures/${captureId}/templates`),
  reveal: (targetId: string, captureId: string, id: string) => req<{ request: CapturedRequest; version: string }>(`/targets/${targetId}/captures/${captureId}/templates/${id}/reveal`, { method: 'POST' }),
  edit: (targetId: string, captureId: string, id: string, request: CapturedRequest, version: string) => req<{ version: string }>(`/targets/${targetId}/captures/${captureId}/templates/${id}`, { method: 'PUT', body: JSON.stringify({ request, version }) }),
  analyze: (targetId: string, captureId: string, template_ids: string[], modules: string[], allow_unsafe: boolean) => req<{ run_id: string; task_id: string }>(`/targets/${targetId}/captures/${captureId}/analyze`, { method: 'POST', body: JSON.stringify({ template_ids, modules, allow_unsafe, confirm_active: true }) }),
  analyzeChecks: (targetId: string, captureId: string, checks: GuidedCheck[], allow_unsafe: boolean) => req<{ run_id: string; task_id: string }>(`/targets/${targetId}/captures/${captureId}/analyze`, { method: 'POST', body: JSON.stringify({ checks, allow_unsafe, confirm_active: true }) }),
  runs: (targetId: string, captureId: string) => req<GuidedRun[]>(`/targets/${targetId}/captures/${captureId}/runs`),
  revealReport: (targetId: string, captureId: string, id: string) => req<GuidedReport>(`/targets/${targetId}/captures/${captureId}/runs/${id}/reveal`, { method: 'POST' }),
  preview: (targetId: string, file: File, source: string, identityLabel: string, label: string) =>
    req<{ preview: CapturePreview; passive: boolean; traffic_sent: number }>(`/targets/${targetId}/captures/preview`, {
      method: 'POST', headers: {}, body: captureForm(file, source, identityLabel, label),
    }),
  import: (targetId: string, file: File, source: string, identityLabel: string, label: string) =>
    req<{ capture_id: string; preview: CapturePreview; templates_stored: number; passive: boolean; traffic_sent: number }>(`/targets/${targetId}/captures`, {
      method: 'POST', headers: {}, body: captureForm(file, source, identityLabel, label),
    }),
  list: (targetId: string) => req<{ id: string; source: string; identity_label: string; label: string; status: string; imported: number; accepted: number; rejected: number; created_at: string; expires_at: string }[]>(`/targets/${targetId}/captures`),
  preflight: (targetId: string, captureId: string, templateIds: string[] = []) => req<CapturePreflight>(`/targets/${targetId}/captures/${captureId}/preflight`, { method: 'POST', body: JSON.stringify({ template_ids: templateIds }) }),
}

export interface BountyProgramList {
  programs: BountyProgram[]
  total: number
  page: number
  limit: number
  detail_index: {
    running: boolean
    total: number
    pending: number
    completed: number
    failed: number
    started_at?: string
    completed_at?: string
    last_error?: string
  }
}

export const bounty = {
  list: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return req<BountyProgramList>(`/bounty/programs${q}`)
  },
  get: (id: string) => req<BountyProgram>(`/bounty/programs/${id}`),
  status: () => req<BountySyncState[]>('/bounty/status'),
  sync: () => req<{ status: string }>('/bounty/sync', { method: 'POST' }),
  createProject: (id: string, body: { name?: string; description?: string; priority?: string; notes?: string; asset_ids: string[]; monitor_enabled: boolean; monitor_interval_hours: number }) =>
    req<{ id: string; url: string }>(`/bounty/programs/${id}/projects`, { method: 'POST', body: JSON.stringify(body) }),
  events: (targetId: string) => req<BountyScopeEvent[]>(`/targets/${targetId}/bounty-events`),
  resolveEvent: (targetId: string, eventId: string, decision: 'approve' | 'reject') =>
    req<{ status: string }>(`/targets/${targetId}/bounty-events/${eventId}`, { method: 'POST', body: JSON.stringify({ decision }) }),
}

export const findings = {
  subdomains: (id: string, p?: Record<string,string>) => req<Subdomain[]>(`/targets/${id}/subdomains${p ? '?'+new URLSearchParams(p) : ''}`),
  httpServices: (id: string) => req<HTTPService[]>(`/targets/${id}/http-services`),
  jsFiles: (id: string) => req<JSFile[]>(`/targets/${id}/js-files`),
  jsFindings: (id: string) => req<JSFinding[]>(`/targets/${id}/js-findings`),
  parameters: (id: string, reflectedOnly = true) =>
    req<Parameter[]>(`/targets/${id}/parameters${reflectedOnly ? '?reflected=true' : ''}`),
  directoryFindings: (id: string) => req<DirectoryFinding[]>(`/targets/${id}/directory-findings`),
  backupFindings: (id: string) => req<BackupFinding[]>(`/targets/${id}/backup-findings`),
  openRedirects: (id: string) => req<OpenRedirectFinding[]>(`/targets/${id}/open-redirects`),
  nucleiFindings: (id: string) => req<NucleiFinding[]>(`/targets/${id}/nuclei-findings`),
  nucleiAffected: (id: string, templateId: string) =>
    req<{ matched_url: string; curl_command: string; request: string; response: string; created_at: string }[]>(
      `/targets/${id}/nuclei-findings/affected?template_id=${encodeURIComponent(templateId)}`),
  vulnFindings: (id: string, status?: string, triage?: string) => {
    const q = new URLSearchParams()
    if (status) q.set('status', status)
    if (triage) q.set('triage', triage)
    const s = q.toString()
    return req<VulnFinding[]>(`/targets/${id}/vuln-findings${s ? '?' + s : ''}`)
  },
  // False-Positive management: record an operator triage decision on a finding.
  setTriage: (id: string, fid: string, triage: string, note = '') =>
    req<{ triage: string }>(`/targets/${id}/findings/${fid}/triage`, {
      method: 'POST', body: JSON.stringify({ triage, note }),
    }),
  monitoringChanges: (id: string) => req<MonitoringChange[]>(`/targets/${id}/monitoring-changes`),
  ingram: (id: string) => req<IngramCamera[]>(`/targets/${id}/ingram`),
  // Global findings across all of the caller's targets (top-level Findings page).
  all: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return req<AllFinding[]>(`/findings${q}`)
  },
}

export interface AllFinding {
  id: string; target_id: string; domain: string; type: string; severity: string
  url: string; parameter: string; confidence: number; priority: number
  status: string; evidence: string; created_at: string
}

export const tasks = {
  list: (params?: Record<string,string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return req<Task[]>(`/tasks${q}`)
  },
  cancel: (id: string) => req<void>(`/tasks/${id}/cancel`, { method: 'POST' }),
  resume: (id: string) => req<Task>(`/tasks/${id}/resume`, { method: 'POST' }),
  logs: (id: string) => req<TaskLog[]>(`/tasks/${id}/logs`),
  phases: (id: string) => req<TaskPhase[]>(`/tasks/${id}/phases`),
}

export interface ApiKeyState { name: string; label: string; hint: string; set: boolean; masked: string }

export type TelegramRole = 'viewer' | 'operator' | 'admin'
export interface TelegramChat {
  id: string; chat_id: string; label: string; role: TelegramRole; enabled: boolean
  notify_scan_started: boolean; notify_phase_finished: boolean; notify_scan_finished: boolean
  notify_findings: boolean; notify_monitoring: boolean; created_at: string; updated_at: string
}
export interface TelegramState {
  configured: boolean; enabled: boolean; masked_token: string; bot_username: string
  connected: boolean; last_error: string; last_connected_at: string
  pending: number; failed: number; chats: TelegramChat[]
}

export interface ToolCatalogEntry {
  name: string; installed: boolean; method: string; command: string
  doc: string; notes: string; one_click: boolean
}
export interface ToolInstallResult {
  installed: boolean; manual?: boolean; command?: string; doc?: string
  notes?: string; output?: string; message: string
}

export const system = {
  tools: () => req<Record<string, boolean>>('/tools/status'),
  toolCatalog: () => req<ToolCatalogEntry[]>('/tools/catalog'),
  installTool: (tool: string) =>
    req<ToolInstallResult>('/tools/install', { method: 'POST', body: JSON.stringify({ tool }) }),
  stats: () => req<Record<string, number>>('/system/stats'),
  updateTemplates: () => req<{ message: string }>('/system/update-templates', { method: 'POST' }),
  updateCheck: (refresh = false) => req<UpdateInfo>(`/system/update-check${refresh ? '?refresh=1' : ''}`),
  getSettings: () => req<{ api_keys: ApiKeyState[] }>('/system/settings'),
  updateSettings: (patch: Record<string, string>) =>
    req<{ api_keys: ApiKeyState[] }>('/system/settings', { method: 'PATCH', body: JSON.stringify(patch) }),
  telegram: () => req<TelegramState>('/system/telegram'),
  updateTelegram: (patch: { bot_token?: string; enabled?: boolean }) =>
    req<TelegramState>('/system/telegram', { method: 'PATCH', body: JSON.stringify(patch) }),
  addTelegramChat: (chat: { chat_id: string; label: string; role: TelegramRole }) =>
    req<TelegramChat>('/system/telegram/chats', { method: 'POST', body: JSON.stringify(chat) }),
  updateTelegramChat: (id: string, patch: Partial<Omit<TelegramChat, 'id' | 'chat_id' | 'created_at' | 'updated_at'>>) =>
    req<TelegramState>(`/system/telegram/chats/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  deleteTelegramChat: (id: string) => req<{ message: string }>(`/system/telegram/chats/${id}`, { method: 'DELETE' }),
  testTelegramChat: (id: string) => req<{ message: string }>(`/system/telegram/chats/${id}/test`, { method: 'POST' }),
  retryTelegram: () => req<{ message: string }>('/system/telegram/retry', { method: 'POST' }),
}

export interface UpdateInfo {
  enabled: boolean
  current: string
  current_commit: string
  build_date: string
  latest: string
  release_name: string
  update_available: boolean
  notes: string
  url: string
  published_at: string
  checked_at: string
  next_check_at: string
  channel: string
  stale: boolean
  error?: string
}

export interface Notification {
  id: string
  target_id: string
  type: string
  title: string
  body: string
  url: string
  severity: string
  is_read: boolean
  created_at: string
}

export const notifications = {
  list: () => req<{ notifications: Notification[]; unread: number }>('/notifications'),
  markRead: (ids?: string[]) =>
    req<{ message: string }>('/notifications/read', { method: 'POST', body: JSON.stringify({ ids: ids || [] }) }),
}
