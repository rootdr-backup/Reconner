export interface NetworkService {
  ip: string
  port: number
  protocol: string
  service: string
  product: string
  version: string
  banner: string
  is_web: boolean
  web_url: string
  web_title: string
  web_status: number
  tls: boolean
}

export interface Asset {
  id: string
  target_id: string
  name: string
  value: string
  kind: string
  asset_type: string
  source: string
  source_id: string
  approval_status: 'approved' | 'pending' | 'suspended'
  monitor_enabled: boolean
  metadata: string
  created_at: string
  updated_at: string
}

export interface BountyAsset {
  id: string
  program_id: string
  external_id: string
  identifier: string
  asset_type: string
  category: string
  is_wildcard: boolean
  in_scope: boolean
  eligible_submission: boolean
  eligible_bounty: boolean
  max_severity: string
  instruction: string
  reward?: Record<string, unknown>
  metadata?: Record<string, unknown>
  active: boolean
  provider_created_at?: string | null
  provider_updated_at?: string | null
}

export interface BountyProgram {
  id: string
  provider: 'hackerone' | 'bugcrowd' | 'intigriti' | 'yeswehack'
  external_id: string
  handle: string
  name: string
  url: string
  logo_url: string
  description: string
  status: string
  program_type: string
  industry: string
  offers_bounties: boolean
  open_scope: boolean
  safe_harbor: string
  asset_count: number
  in_scope_count: number
  wildcard_count: number
  scope_rank: number
  min_reward_cents: number
  max_reward_cents: number
  currency: string
  started_at: string | null
  published_at: string | null
  provider_updated_at: string | null
  last_synced_at: string | null
  detail_synced_at: string | null
  details_loaded: boolean
  assets?: BountyAsset[]
}

export interface BountySyncState {
  provider: string
  status: string
  last_started_at: string | null
  last_completed_at: string | null
  next_sync_at: string | null
  program_count: number
  asset_count: number
  last_error: string
  failure_count: number
}

export interface BountyScopeEvent {
  id: string
  target_id: string
  program_id: string
  program_asset_id: string
  event_type: 'added' | 'removed' | 'modified'
  identifier: string
  old_json: string
  new_json: string
  status: 'pending' | 'approved' | 'rejected'
  detected_at: string
  resolved_at: string | null
}

export interface Target {
  id: string
  domain: string
  name?: string
  kind?: string
  description: string
  tags: string[]
  priority: string
  notes: string
  exclude_scope?: string
  status: string
  scan_status: string
  enabled_modules: string[]
  last_scan_at: string | null
  created_at: string
  updated_at: string
  subdomain_count: number
  alive_host_count: number
  finding_count: number
  monitor_enabled: boolean
  monitor_interval_hours: number
  monitor_last_run: string | null
  scan_user_agent?: string
  scan_headers?: Record<string, string>
}

export interface Subdomain {
  id: string
  target_id: string
  subdomain: string
  ip: string
  is_alive: boolean
  status_code: number
  page_title: string
  has_https: boolean
  has_http: boolean
  response_time_ms: number
  technologies: string[]
  server: string
  framework: string
  cdn: string
  waf: string
  source: string
  last_seen: string
  created_at: string
}

export interface HTTPService {
  id: string
  target_id: string
  url: string
  status_code: number
  title: string
  server: string
  content_type: string
  content_length: number
  redirect_url: string
  technologies: string[]
  response_time_ms: number
  waf?: string
  cms?: string
  last_seen: string
  created_at: string
}

export interface JSFile {
  id: string
  target_id: string
  url: string
  size: number
  hash: string
  analyzed: boolean
  last_seen: string
  created_at: string
}

export interface JSFinding {
  id: string
  target_id: string
  js_file_id: string
  js_file_url: string
  type: string
  value: string
  context: string
  severity: string
  verified?: boolean
  created_at: string
}

export interface Parameter {
  id: string
  target_id: string
  url: string
  parameter: string
  value: string
  source: string
  is_reflected: boolean
  created_at: string
}

export interface DirectoryFinding {
  id: string
  target_id: string
  url: string
  status_code: number
  content_length: number
  content_type: string
  redirect_url: string
  created_at: string
}

export interface BackupFinding {
  id: string
  target_id: string
  url: string
  status_code: number
  content_length: number
  backup_type: string
  created_at: string
}

export interface OpenRedirectFinding {
  id: string
  target_id: string
  url: string
  redirect_to: string
  parameter: string
  verified: boolean
  created_at: string
}

export interface NucleiFinding {
  id: string
  target_id: string
  template_id: string
  template_name: string
  severity: string
  url: string
  matched_url: string
  matched_at: string
  description: string
  tags: string[]
  curl_command: string
  request: string
  response: string
  created_at: string
  affected_count?: number
}

export interface AttackPath {
  host: string
  severity: string
  confidence: number
  summary: string
  steps: string[]
  tech?: string[]
}

export interface VulnFinding {
  id: string
  target_id: string
  type: string
  severity: string
  url: string
  parameter: string
  payload: string
  evidence: string
  confidence?: number
  priority?: number
  status?: string
  provenance?: string
  lifecycle?: string
  candidate_id?: string
  triage?: string
  triage_note?: string
  created_at: string
}

export interface MonitoringChange {
  id: string
  target_id: string
  url: string
  change_type: string
  old_value: string
  new_value: string
  detected_at: string
}

export interface IngramCamera {
  id: string
  address: string      // ip:port
  product: string
  severity: string
  poc: string
  description: string
  impact: string
  image: string        // /screenshots/{id} or ""
  created_at: string
}

export interface Task {
  id: string
  target_id: string
  name: string
  type: string
  status: string
  priority: number
  progress: number
  total: number
  current_module: string
  eta_seconds?: number
  module_eta_seconds?: number
  modules: string[]
  completed_modules: string[]
  error: string
  started_at: string | null
  finished_at: string | null
  created_at: string
  updated_at: string
  target_domain: string
}

export interface TaskLog {
  id: number
  task_id: string
  level: string
  message: string
  module: string
  created_at: string
}

export interface DashboardStats {
  targets: number
  alive_hosts: number
  subdomains: number
  http_services: number
  js_files: number
  parameters: number
  reflected_parameters: number
  directory_findings: number
  backup_findings: number
  open_redirect_findings: number
  nuclei_findings: number
  vuln_findings: number
  running_tasks: number
  finished_tasks: number
  failed_tasks: number
  pending_tasks: number
}
