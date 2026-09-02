package database

import (
	"fmt"
	"strings"
)

func isDuplicateColumnError(err error) bool {
	return strings.Contains(err.Error(), "duplicate column name")
}

func RunMigrations(db *DB) error {
	migrations := []string{
		createUsersTable,
		createSessionsTable,
		createTargetsTable,
		createSubdomainsTable,
		createHTTPServicesTable,
		createJSFilesTable,
		createJSFindingsTable,
		createParametersTable,
		createDirectoryFindingsTable,
		createBackupFindingsTable,
		createOpenRedirectFindingsTable,
		createNucleiFindingsTable,
		createVulnFindingsTable,
		createTasksTable,
		createTaskLogsTable,
		createScreenshotsTable,
		createMonitoringChangesTable,
		createNotificationsTable,
		alterHTTPServicesAddHash,
		alterTargetsAddMonitoring,
		alterTargetsAddMonitorInterval,
		alterTargetsAddMonitorLastRun,
		alterJSFindingsAddVerified,
		alterParametersAddMethod,
		alterParametersAddContentType,
		alterTargetsAddAuthHeaders,
		alterVulnFindingsAddConfidence,
		alterVulnFindingsAddPriority,
		createBlindXSSProbesTable,
		createOOBProbesTable,
		alterHTTPServicesAddSource,
		alterHTTPServicesAddNormHash,
		alterHTTPServicesAddSecuritySnapshot,
		alterHTTPServicesAddWAF,
		alterHTTPServicesAddCMS,
		createOpenPortsTable,
		alterMonitoringChangesAddSeverity,
		alterVulnFindingsAddStatus,
		alterVulnFindingsAddTriage,
		alterVulnFindingsAddTriageNote,
		alterVulnFindingsAddProvenance,
		alterVulnFindingsAddCorrelation,
		alterVulnFindingsAddRootID,
		alterOpenRedirectAddStatus,
		alterOpenRedirectAddProvenance,
		alterTargetsAddScope,
		createIdentitiesTable,
		alterIdentitiesAddAuthMethod,
		alterIdentitiesAddOrigin,
		alterIdentitiesAddUserAgent,
		alterIdentitiesAddStorageJSON,
		alterIdentitiesAddValidationURL,
		alterIdentitiesAddValidationSignal,
		alterIdentitiesAddStatus,
		alterIdentitiesAddCapturedAt,
		alterIdentitiesAddVerifiedAt,
		alterIdentitiesAddExpiresAt,
		createEvidenceTable,
		createHTTPInteractionsTable,
		createObjectsTable,
		createActionsTable,
		createObjectRelationshipsTable,
		createWorkflowVariablesTable,
		createAuthzObservationsTable,
		createHypothesesTable,
		createStateSnapshotsTable,
		createCandidatesTable,
		alterNucleiFindingsAddVerification,
		alterNucleiFindingsAddConfidence,
		alterSubdomainsAddSource,
		alterCandidatesAddStateVersion,
		alterVulnFindingsAddCandidateID,
		alterVulnFindingsAddLifecycle,
		createCandidateTransitionsTable,
		alterTargetsAddKind,
		alterTargetsAddName,
		createNetworkHostsTable,
		createNetworkServicesTable,
		alterTasksAddCompletedModules,
		alterNucleiFindingsAddCurlCommand,
		alterNucleiFindingsAddRequest,
		alterNucleiFindingsAddResponse,
		alterEvidenceAddImage,
		createIndexes,
		alterTargetsAddExcludeScope,
		createAssetsTable,
		alterTasksAddScopeOverride,
		alterUsersAddRole,
		alterUsersAddDisabled,
		alterTargetsAddOwner,
		alterTasksAddEta,
		alterTasksAddModuleEta,
		alterParametersAddLocation,
		createBountyProgramsTable,
		createBountyProgramAssetsTable,
		createBountySyncStateTable,
		createProjectProgramsTable,
		createBountyScopeEventsTable,
		alterAssetsAddAssetType,
		alterAssetsAddSource,
		alterAssetsAddSourceID,
		alterAssetsAddApprovalStatus,
		alterAssetsAddMonitorEnabled,
		alterAssetsAddMetadata,
		alterAssetsAddUpdatedAt,
		createBountyIndexes,
	}

	for i, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			// Ignore "duplicate column" errors from ALTER TABLE
			if !isDuplicateColumnError(err) {
				return fmt.Errorf("migration %d failed: %w", i, err)
			}
		}
	}
	if err := migrateParametersRequestIdentity(db); err != nil {
		return fmt.Errorf("parameters request-identity migration failed: %w", err)
	}
	if err := migrateBrowserlessXSSConfirmations(db); err != nil {
		return fmt.Errorf("XSS runtime-proof migration failed: %w", err)
	}

	return nil
}

// migrateBrowserlessXSSConfirmations repairs findings created by pre-1.3 builds
// that treated raw executable-looking markup as proof of JavaScript execution.
// Those observations remain valuable candidates, but only an xss-browser nonce
// may remain CONFIRMED. The migration is idempotent and preserves an audit row.
func migrateBrowserlessXSSConfirmations(db *DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	predicate := `type='xss' AND status='CONFIRMED' AND (
		verification_method='dast-differential' OR
		(verification_method='xss-context' AND COALESCE(confidence,0)<99) OR
		detection_method LIKE '%/differential')`
	if _, err = tx.Exec(`INSERT OR IGNORE INTO candidate_transitions
		(id,candidate_id,target_id,from_state,to_state,actor,method,reason,state_version)
		SELECT 'xss-runtime-proof-v1:' || id,id,target_id,'CONFIRMED','INCONCLUSIVE',
		'migration','runtime-proof-policy','browserless markup survival requires browser execution proof',COALESCE(state_version,0)+1
		FROM candidates WHERE ` + predicate); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE vuln_findings SET status='candidate',lifecycle='INCONCLUSIVE',
		confidence=MIN(COALESCE(confidence,85),85),priority=MIN(COALESCE(priority,0),85)
		WHERE candidate_id IN (SELECT id FROM candidates WHERE ` + predicate + `)`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE candidates SET status='INCONCLUSIVE',confidence=MIN(COALESCE(confidence,85),85),
		verification_method='xss-runtime-required',
		verification_reason='browserless markup survival requires browser execution proof',
		state_version=COALESCE(state_version,0)+1 WHERE ` + predicate); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateParametersRequestIdentity removes the legacy uniqueness constraint
// (target,url,parameter), which collapsed GET/POST/JSON/path variants of the same
// field into one row. Active scanners need each request placement independently.
// SQLite cannot drop an inline UNIQUE constraint, so rebuild once and detect the
// new schema from sqlite_master on subsequent startups.
func migrateParametersRequestIdentity(db *DB) error {
	var schema string
	if err := db.QueryRow(`SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='table' AND name='parameters'`).Scan(&schema); err != nil {
		return err
	}
	compact := strings.NewReplacer(" ", "", "\n", "", "\t", "", "\r", "").Replace(strings.ToLower(schema))
	if strings.Contains(compact, "unique(target_id,url,parameter,method,location,content_type)") {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`DROP TABLE IF EXISTS parameters_request_v2`,
		`CREATE TABLE parameters_request_v2 (
			id TEXT PRIMARY KEY,
			target_id TEXT NOT NULL,
			url TEXT NOT NULL,
			parameter TEXT NOT NULL,
			value TEXT DEFAULT '',
			source TEXT DEFAULT '',
			is_reflected INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			method TEXT DEFAULT 'GET',
			content_type TEXT DEFAULT '',
			location TEXT DEFAULT 'query',
			FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
			UNIQUE(target_id,url,parameter,method,location,content_type)
		)`,
		`INSERT OR IGNORE INTO parameters_request_v2
			(id,target_id,url,parameter,value,source,is_reflected,created_at,method,content_type,location)
		 SELECT id,target_id,url,parameter,COALESCE(value,''),COALESCE(source,''),COALESCE(is_reflected,0),created_at,
			COALESCE(NULLIF(method,''),'GET'),COALESCE(content_type,''),
			CASE
			 WHEN UPPER(COALESCE(NULLIF(method,''),'GET'))<>'GET' AND LOWER(COALESCE(content_type,'')) LIKE '%multipart/form-data%' THEN 'multipart'
			 WHEN UPPER(COALESCE(NULLIF(method,''),'GET'))<>'GET' AND LOWER(COALESCE(content_type,'')) LIKE '%xml%' THEN 'xml'
			 WHEN UPPER(COALESCE(NULLIF(method,''),'GET'))<>'GET' AND LOWER(COALESCE(content_type,'')) LIKE '%json%' THEN 'json'
			 WHEN UPPER(COALESCE(NULLIF(method,''),'GET'))<>'GET' AND COALESCE(content_type,'')<>'' THEN 'body'
			 ELSE COALESCE(NULLIF(location,''),'query') END
		 FROM parameters`,
		`DROP TABLE parameters`,
		`ALTER TABLE parameters_request_v2 RENAME TO parameters`,
		`CREATE INDEX IF NOT EXISTS idx_parameters_target ON parameters(target_id)`,
		`CREATE INDEX IF NOT EXISTS idx_parameters_reflected ON parameters(is_reflected)`,
	}
	for _, stmt := range statements {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- Network scanning (P1) ---
// A target's kind ∈ web|network. 'network' targets carry an IP/CIDR/range/list
// scope in `domain` and run the network pipeline (port scan → service discovery
// → CVE/protocol analysis) instead of the web recon pipeline.
// exclude_scope holds out-of-scope hosts/IPs/CIDRs/URLs (comma/newline list) that
// must NOT be scanned even though they fall under the target — the standard
// bug-bounty "these subdomains/ranges are excluded" case. Enforced at subdomain
// storage so nothing excluded ever enters the web pipeline.
const alterTargetsAddExcludeScope = `ALTER TABLE targets ADD COLUMN exclude_scope TEXT DEFAULT '';`

// assets are the individually-scannable entries of a target (a domain, an IP, a
// CIDR/range). Each can be named, added/removed, and scanned on its own — so a
// target with many assets scans them one at a time, not all at once. Findings
// still aggregate under target_id; an asset just pins a scan's scope.
const createAssetsTable = `
CREATE TABLE IF NOT EXISTS assets (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	name TEXT DEFAULT '',
	value TEXT NOT NULL,
	kind TEXT DEFAULT 'web',
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, value),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// Public HackerOne/Bugcrowd/Intigriti/YesWeHack programs are cached locally. The catalog is a
// cache, never the authority for scan scope: imported assets are copied into a
// project and new upstream scope entries stay pending until the operator
// explicitly approves them.
const createBountyProgramsTable = `
CREATE TABLE IF NOT EXISTS bounty_programs (
	id TEXT PRIMARY KEY,
	provider TEXT NOT NULL,
	external_id TEXT NOT NULL,
	handle TEXT NOT NULL,
	name TEXT NOT NULL,
	url TEXT DEFAULT '',
	logo_url TEXT DEFAULT '',
	description TEXT DEFAULT '',
	status TEXT DEFAULT 'unknown',
	program_type TEXT DEFAULT 'vdp',
	industry TEXT DEFAULT '',
	offers_bounties INTEGER DEFAULT 0,
	open_scope INTEGER DEFAULT 0,
	safe_harbor TEXT DEFAULT '',
	asset_count INTEGER DEFAULT 0,
	in_scope_count INTEGER DEFAULT 0,
	wildcard_count INTEGER DEFAULT 0,
	scope_rank INTEGER DEFAULT 0,
	min_reward_cents INTEGER DEFAULT 0,
	max_reward_cents INTEGER DEFAULT 0,
	currency TEXT DEFAULT 'USD',
	started_at DATETIME,
	published_at DATETIME,
	provider_updated_at DATETIME,
	last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	detail_synced_at DATETIME,
	scope_hash TEXT DEFAULT '',
	raw_json TEXT DEFAULT '{}',
	UNIQUE(provider, external_id)
);`

const createBountyProgramAssetsTable = `
CREATE TABLE IF NOT EXISTS bounty_program_assets (
	id TEXT PRIMARY KEY,
	program_id TEXT NOT NULL,
	external_id TEXT NOT NULL,
	identifier TEXT NOT NULL,
	asset_type TEXT DEFAULT 'other',
	category TEXT DEFAULT 'other',
	is_wildcard INTEGER DEFAULT 0,
	in_scope INTEGER DEFAULT 1,
	eligible_submission INTEGER DEFAULT 1,
	eligible_bounty INTEGER DEFAULT 0,
	max_severity TEXT DEFAULT '',
	instruction TEXT DEFAULT '',
	reward_json TEXT DEFAULT '{}',
	metadata TEXT DEFAULT '{}',
	active INTEGER DEFAULT 1,
	provider_created_at DATETIME,
	provider_updated_at DATETIME,
	first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	raw_hash TEXT DEFAULT '',
	FOREIGN KEY (program_id) REFERENCES bounty_programs(id) ON DELETE CASCADE,
	UNIQUE(program_id, external_id)
);`

const createBountySyncStateTable = `
CREATE TABLE IF NOT EXISTS bounty_sync_state (
	provider TEXT PRIMARY KEY,
	status TEXT DEFAULT 'never',
	last_started_at DATETIME,
	last_completed_at DATETIME,
	next_sync_at DATETIME,
	program_count INTEGER DEFAULT 0,
	asset_count INTEGER DEFAULT 0,
	last_error TEXT DEFAULT '',
	failure_count INTEGER DEFAULT 0,
	etag TEXT DEFAULT ''
);`

const createProjectProgramsTable = `
CREATE TABLE IF NOT EXISTS project_programs (
	target_id TEXT NOT NULL,
	program_id TEXT NOT NULL,
	auto_sync INTEGER DEFAULT 1,
	last_scope_hash TEXT DEFAULT '',
	last_checked_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (target_id, program_id),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	FOREIGN KEY (program_id) REFERENCES bounty_programs(id) ON DELETE CASCADE
);`

const createBountyScopeEventsTable = `
CREATE TABLE IF NOT EXISTS bounty_scope_events (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	program_id TEXT NOT NULL,
	program_asset_id TEXT,
	event_type TEXT NOT NULL,
	identifier TEXT NOT NULL,
	old_json TEXT DEFAULT '{}',
	new_json TEXT DEFAULT '{}',
	status TEXT DEFAULT 'pending',
	detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	resolved_at DATETIME,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	FOREIGN KEY (program_id) REFERENCES bounty_programs(id) ON DELETE CASCADE,
	FOREIGN KEY (program_asset_id) REFERENCES bounty_program_assets(id) ON DELETE SET NULL
);`

const alterAssetsAddAssetType = `ALTER TABLE assets ADD COLUMN asset_type TEXT DEFAULT 'domain';`
const alterAssetsAddSource = `ALTER TABLE assets ADD COLUMN source TEXT DEFAULT 'manual';`
const alterAssetsAddSourceID = `ALTER TABLE assets ADD COLUMN source_id TEXT DEFAULT '';`
const alterAssetsAddApprovalStatus = `ALTER TABLE assets ADD COLUMN approval_status TEXT DEFAULT 'approved';`
const alterAssetsAddMonitorEnabled = `ALTER TABLE assets ADD COLUMN monitor_enabled INTEGER DEFAULT 1;`
const alterAssetsAddMetadata = `ALTER TABLE assets ADD COLUMN metadata TEXT DEFAULT '{}';`
const alterAssetsAddUpdatedAt = `ALTER TABLE assets ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;`

const createBountyIndexes = `
CREATE INDEX IF NOT EXISTS idx_bounty_programs_filter ON bounty_programs(provider, status, offers_bounties, wildcard_count, asset_count);
CREATE INDEX IF NOT EXISTS idx_bounty_programs_started ON bounty_programs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_bounty_assets_program_scope ON bounty_program_assets(program_id, active, in_scope, eligible_submission);
CREATE INDEX IF NOT EXISTS idx_project_programs_program ON project_programs(program_id, auto_sync);
CREATE INDEX IF NOT EXISTS idx_bounty_events_pending ON bounty_scope_events(target_id, status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_assets_source ON assets(target_id, source, source_id, approval_status);
`

// scope_override pins a task to ONE asset's value (empty = scan the whole target).
const alterTasksAddScopeOverride = `ALTER TABLE tasks ADD COLUMN scope_override TEXT DEFAULT '';`

const alterTargetsAddKind = `ALTER TABLE targets ADD COLUMN kind TEXT DEFAULT 'web';`

// User-supplied friendly name for a target, given when the target is added — so
// it's identified by a human label instead of a bare IP/CIDR/domain. Empty falls
// back to the domain in the UI.
const alterTargetsAddName = `ALTER TABLE targets ADD COLUMN name TEXT DEFAULT '';`

// network_hosts: one row per live IP discovered in a network target's scope.
const createNetworkHostsTable = `
CREATE TABLE IF NOT EXISTS network_hosts (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	ip TEXT NOT NULL,
	is_alive INTEGER DEFAULT 0,
	open_ports INTEGER DEFAULT 0,
	os_guess TEXT DEFAULT '',
	rdns TEXT DEFAULT '',
	last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, ip),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// network_services: one row per open ip:port, with detected service/product/
// version/banner and (for web ports) title + status. This is the network
// equivalent of http_services.
const createNetworkServicesTable = `
CREATE TABLE IF NOT EXISTS network_services (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	ip TEXT NOT NULL,
	port INTEGER NOT NULL,
	protocol TEXT DEFAULT 'tcp',
	service TEXT DEFAULT '',
	product TEXT DEFAULT '',
	version TEXT DEFAULT '',
	banner TEXT DEFAULT '',
	is_web INTEGER DEFAULT 0,
	web_url TEXT DEFAULT '',
	web_title TEXT DEFAULT '',
	web_status INTEGER DEFAULT 0,
	tls INTEGER DEFAULT 0,
	notes TEXT DEFAULT '',
	last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, ip, port, protocol),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// identities holds the labelled test users a researcher arms a target with, so
// authorization scanners (IDOR/BOLA/BFLA/priv-esc) can replay the SAME request
// across DIFFERENT users and PROVE cross-user access — impossible with a single
// auth blob. headers_json is a JSON object of raw request headers (Cookie,
// Authorization, X-CSRF-Token, …). Exactly one identity per target may be the
// baseline (the "me" whose objects we try to reach as someone else).
const createIdentitiesTable = `
CREATE TABLE IF NOT EXISTS identities (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	label TEXT NOT NULL DEFAULT 'user',
	role TEXT NOT NULL DEFAULT 'user',
	headers_json TEXT NOT NULL DEFAULT '{}',
	is_baseline INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// Structured authentication-context columns (Phase 1). headers_json holds the
// request headers to REPLAY (Cookie/Authorization/CSRF); storage_json holds
// browser-captured local/session storage; validation_* drive session checks;
// status ∈ authenticated|expired|unknown|unauthenticated. Secrets in headers_json
// / storage_json are encrypted at rest via the secret abstraction.
const alterIdentitiesAddAuthMethod = `ALTER TABLE identities ADD COLUMN auth_method TEXT DEFAULT 'headers';`
const alterIdentitiesAddOrigin = `ALTER TABLE identities ADD COLUMN origin TEXT DEFAULT '';`
const alterIdentitiesAddUserAgent = `ALTER TABLE identities ADD COLUMN user_agent TEXT DEFAULT '';`
const alterIdentitiesAddStorageJSON = `ALTER TABLE identities ADD COLUMN storage_json TEXT DEFAULT '';`
const alterIdentitiesAddValidationURL = `ALTER TABLE identities ADD COLUMN validation_url TEXT DEFAULT '';`
const alterIdentitiesAddValidationSignal = `ALTER TABLE identities ADD COLUMN validation_signal TEXT DEFAULT '';`
const alterIdentitiesAddStatus = `ALTER TABLE identities ADD COLUMN status TEXT DEFAULT 'unknown';`
const alterIdentitiesAddCapturedAt = `ALTER TABLE identities ADD COLUMN captured_at DATETIME;`
const alterIdentitiesAddVerifiedAt = `ALTER TABLE identities ADD COLUMN last_verified_at DATETIME;`
const alterIdentitiesAddExpiresAt = `ALTER TABLE identities ADD COLUMN expires_at DATETIME;`

// evidence stores structured, reproducible, REDACTED proof behind a finding —
// the request/response pairs (per identity for cross-identity findings), the
// comparison, and reproduction steps. Credentials are redacted before storage.
const createEvidenceTable = `
CREATE TABLE IF NOT EXISTS evidence (
	id TEXT PRIMARY KEY,
	finding_id TEXT NOT NULL,
	target_id TEXT NOT NULL,
	kind TEXT NOT NULL DEFAULT 'http',
	identity_label TEXT DEFAULT '',
	request_text TEXT DEFAULT '',
	response_text TEXT DEFAULT '',
	comparison TEXT DEFAULT '',
	note TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`

// http_interactions is the canonical, normalized request/response log (Request
// Intelligence, P0-3). Bodies are truncated + redacted. Drives evidence and
// future response-diff correlation.
const createHTTPInteractionsTable = `
CREATE TABLE IF NOT EXISTS http_interactions (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	identity_label TEXT DEFAULT '',
	method TEXT DEFAULT 'GET',
	url TEXT DEFAULT '',
	norm_url TEXT DEFAULT '',
	status INTEGER DEFAULT 0,
	content_type TEXT DEFAULT '',
	resp_len INTEGER DEFAULT 0,
	resp_hash TEXT DEFAULT '',
	timing_ms INTEGER DEFAULT 0,
	scanner TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`

// objects models the application's resources discovered from authenticated
// traffic (Phase 8): the foundation for reliable BOLA/IDOR. owner_identity is
// the identity that legitimately accessed it; endpoint_template groups by the
// normalized endpoint so A→B replay knows which URL to try.
const createObjectsTable = `
CREATE TABLE IF NOT EXISTS objects (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	obj_type TEXT NOT NULL DEFAULT 'unknown',
	identifier TEXT NOT NULL,
	source_url TEXT DEFAULT '',
	endpoint_template TEXT DEFAULT '',
	param TEXT DEFAULT '',
	owner_identity TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, endpoint_template, identifier, param)
);`

// actions are the semantic operations classified from interactions (Phase 2):
// CREATE/READ/UPDATE/DELETE/SHARE/… tied to an identity + object, keeping the
// raw interaction authoritative (semantic layer is metadata w/ provenance).
const createActionsTable = `
CREATE TABLE IF NOT EXISTS actions (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	identity_id TEXT DEFAULT '',
	identity_label TEXT DEFAULT '',
	verb TEXT NOT NULL DEFAULT 'READ',
	method TEXT DEFAULT 'GET',
	url TEXT DEFAULT '',
	endpoint_template TEXT DEFAULT '',
	object_type TEXT DEFAULT '',
	object_id TEXT DEFAULT '',
	status INTEGER DEFAULT 0,
	source TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// object_relationships models Object Ownership 2.0 (Phase 6): an object can have
// MANY relationships to identities (CREATOR/OWNER/MEMBER/VIEWER/EDITOR/ADMIN),
// each with provenance, instead of a single "owner" column that conflated access
// with ownership.
const createObjectRelationshipsTable = `
CREATE TABLE IF NOT EXISTS object_relationships (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	object_type TEXT DEFAULT '',
	object_id TEXT NOT NULL,
	endpoint_template TEXT DEFAULT '',
	identity_id TEXT DEFAULT '',
	identity_label TEXT DEFAULT '',
	role TEXT NOT NULL DEFAULT 'accessor',
	provenance TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, object_type, object_id, identity_label, role),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// workflow_variables holds values extracted from one interaction for reuse in
// later actions (Phase 4 dataflow), each with full provenance.
const createWorkflowVariablesTable = `
CREATE TABLE IF NOT EXISTS workflow_variables (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	workflow_id TEXT DEFAULT '',
	name TEXT NOT NULL,
	value TEXT DEFAULT '',
	object_type TEXT DEFAULT '',
	source_identity TEXT DEFAULT '',
	source_url TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// authorization_observations record what Reconner actually observed/verified for
// an (identity × object × action) — expected vs observed verdict kept separate,
// raw HTTP remains authoritative elsewhere (evidence). Phase 1/2.
const createAuthzObservationsTable = `
CREATE TABLE IF NOT EXISTS authorization_observations (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	identity_label TEXT DEFAULT '',
	object_type TEXT DEFAULT '',
	object_id TEXT DEFAULT '',
	action_verb TEXT DEFAULT 'READ',
	endpoint_template TEXT DEFAULT '',
	expected TEXT DEFAULT 'UNKNOWN',
	observed TEXT DEFAULT 'UNKNOWN',
	confidence INTEGER DEFAULT 0,
	source TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, identity_label, object_type, object_id, action_verb),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// hypotheses persist the OBSERVATION→CANDIDATE→HYPOTHESIS→TESTED→VERIFIED/REJECTED
// lifecycle (Phase 7). A hypothesis is NOT a finding; finding_id is set only when
// verified. Phase 7/12.
const createHypothesesTable = `
CREATE TABLE IF NOT EXISTS hypotheses (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	kind TEXT NOT NULL DEFAULT 'BOLA',
	identity_label TEXT DEFAULT '',
	object_type TEXT DEFAULT '',
	object_id TEXT DEFAULT '',
	action_verb TEXT DEFAULT 'READ',
	endpoint_template TEXT DEFAULT '',
	expected TEXT DEFAULT 'DENIED',
	observed TEXT DEFAULT 'UNKNOWN',
	status TEXT DEFAULT 'HYPOTHESIS',
	confidence INTEGER DEFAULT 0,
	test_plan TEXT DEFAULT '',
	reason TEXT DEFAULT '',
	finding_id TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// state_snapshots capture an object's observable state (from an owner READ)
// before/after a state-changing test, so WRITE/DELETE/BFLA can be verified by a
// real SIDE EFFECT rather than a status code (P2). fingerprint is a stable hash;
// fields_json holds the extracted salient field values (redacted). No secrets.
const createStateSnapshotsTable = `
CREATE TABLE IF NOT EXISTS state_snapshots (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	object_type TEXT DEFAULT '',
	object_id TEXT DEFAULT '',
	phase TEXT DEFAULT 'before',
	observer_label TEXT DEFAULT '',
	status INTEGER DEFAULT 0,
	fingerprint TEXT DEFAULT '',
	fields_json TEXT DEFAULT '',
	source TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// candidates is the unified pre-finding lifecycle (CANDIDATE→DETECTED→VERIFYING→
// VERIFIED→CONFIRMED / REJECTED / INCONCLUSIVE / DUPLICATE). Detectors register a
// candidate here; the VerificationOrchestrator promotes only what it can PROVE
// into vuln_findings. "detection ≠ verification ≠ finding" made explicit.
const createCandidatesTable = `
CREATE TABLE IF NOT EXISTS candidates (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	type TEXT NOT NULL,
	subtype TEXT DEFAULT '',
	url TEXT DEFAULT '',
	method TEXT DEFAULT 'GET',
	parameter TEXT DEFAULT '',
	location TEXT DEFAULT 'query',
	payload TEXT DEFAULT '',
	detection_source TEXT DEFAULT '',
	detection_method TEXT DEFAULT '',
	severity TEXT DEFAULT 'medium',
	confidence INTEGER DEFAULT 0,
	status TEXT DEFAULT 'DETECTED',
	verification_method TEXT DEFAULT '',
	verification_reason TEXT DEFAULT '',
	evidence TEXT DEFAULT '',
	finding_id TEXT DEFAULT '',
	fingerprint TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(target_id, fingerprint),
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`

// Multi-user support: role gates admin-only actions (user management); disabled
// blocks login without deleting history. The existing sole admin migrates to
// role 'admin' via the column default.
const alterUsersAddRole = `ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';`
const alterUsersAddDisabled = `ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;`

// Per-user data isolation: a target belongs to the user who created it. A member
// sees only their own targets (and everything under them); an admin sees all.
// owner_id 0 = legacy targets created before this column (admin-owned).
const alterTargetsAddOwner = `ALTER TABLE targets ADD COLUMN owner_id INTEGER NOT NULL DEFAULT 0;`

const createSessionsTable = `
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	data TEXT NOT NULL DEFAULT '{}',
	expires_at DATETIME NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);`

const createTargetsTable = `
CREATE TABLE IF NOT EXISTS targets (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL UNIQUE,
	description TEXT DEFAULT '',
	tags TEXT DEFAULT '[]',
	priority TEXT DEFAULT 'medium',
	notes TEXT DEFAULT '',
	status TEXT DEFAULT 'idle',
	scan_status TEXT DEFAULT 'idle',
	enabled_modules TEXT DEFAULT '[]',
	last_scan_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	subdomain_count INTEGER DEFAULT 0,
	alive_host_count INTEGER DEFAULT 0,
	finding_count INTEGER DEFAULT 0
);`

const createSubdomainsTable = `
CREATE TABLE IF NOT EXISTS subdomains (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	subdomain TEXT NOT NULL,
	ip TEXT DEFAULT '',
	is_alive INTEGER DEFAULT 0,
	status_code INTEGER DEFAULT 0,
	page_title TEXT DEFAULT '',
	has_https INTEGER DEFAULT 0,
	has_http INTEGER DEFAULT 0,
	response_time_ms INTEGER DEFAULT 0,
	technologies TEXT DEFAULT '[]',
	server TEXT DEFAULT '',
	framework TEXT DEFAULT '',
	cdn TEXT DEFAULT '',
	waf TEXT DEFAULT '',
	last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, subdomain)
);`

// source records HOW a subdomain was discovered: 'dns' (default — passive/active
// DNS enumeration) or 'vhost' (served on a known IP via a Host header but does
// NOT resolve in DNS — found by the virtual-host scan). Lets the UI flag vhost
// hosts, which are often internal/forgotten and high-value.
const alterSubdomainsAddSource = `ALTER TABLE subdomains ADD COLUMN source TEXT DEFAULT 'dns';`

// ── P1 canonical lifecycle bridge ────────────────────────────────────────────
// candidates is the AUTHORITATIVE lifecycle state source. state_version is a
// monotonic counter used for optimistic, concurrency-safe transitions.
const alterCandidatesAddStateVersion = `ALTER TABLE candidates ADD COLUMN state_version INTEGER DEFAULT 0;`

// vuln_findings is the finding/report PROJECTION. candidate_id links a projected
// finding back to its authoritative candidate; lifecycle mirrors the candidate's
// state for efficient reporting. Legacy rows (created before P1) default to
// 'LEGACY' and candidate_id ” — they are NEVER auto-marked CONFIRMED.
const alterVulnFindingsAddCandidateID = `ALTER TABLE vuln_findings ADD COLUMN candidate_id TEXT DEFAULT '';`
const alterVulnFindingsAddLifecycle = `ALTER TABLE vuln_findings ADD COLUMN lifecycle TEXT DEFAULT 'LEGACY';`

// candidate_transitions is a minimal, append-only audit trail of lifecycle state
// changes (who/what, when, from→to, why). Reason text is redacted before insert.
const createCandidateTransitionsTable = `
CREATE TABLE IF NOT EXISTS candidate_transitions (
	id TEXT PRIMARY KEY,
	candidate_id TEXT NOT NULL,
	target_id TEXT DEFAULT '',
	from_state TEXT DEFAULT '',
	to_state TEXT NOT NULL,
	actor TEXT DEFAULT '',
	method TEXT DEFAULT '',
	reason TEXT DEFAULT '',
	state_version INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`

const createHTTPServicesTable = `
CREATE TABLE IF NOT EXISTS http_services (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	subdomain_id TEXT,
	url TEXT NOT NULL,
	status_code INTEGER DEFAULT 0,
	title TEXT DEFAULT '',
	server TEXT DEFAULT '',
	content_type TEXT DEFAULT '',
	content_length INTEGER DEFAULT 0,
	redirect_url TEXT DEFAULT '',
	technologies TEXT DEFAULT '[]',
	headers TEXT DEFAULT '{}',
	favicon_hash TEXT DEFAULT '',
	response_time_ms INTEGER DEFAULT 0,
	screenshot_id TEXT,
	last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, url)
);`

const createJSFilesTable = `
CREATE TABLE IF NOT EXISTS js_files (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	size INTEGER DEFAULT 0,
	hash TEXT DEFAULT '',
	analyzed INTEGER DEFAULT 0,
	last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, url)
);`

const createJSFindingsTable = `
CREATE TABLE IF NOT EXISTS js_findings (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	js_file_id TEXT NOT NULL,
	type TEXT NOT NULL,
	value TEXT NOT NULL,
	context TEXT DEFAULT '',
	severity TEXT DEFAULT 'info',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	FOREIGN KEY (js_file_id) REFERENCES js_files(id) ON DELETE CASCADE
);`

const createParametersTable = `
CREATE TABLE IF NOT EXISTS parameters (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	parameter TEXT NOT NULL,
	value TEXT DEFAULT '',
	source TEXT DEFAULT '',
	is_reflected INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	method TEXT DEFAULT 'GET',
	content_type TEXT DEFAULT '',
	location TEXT DEFAULT 'query',
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id,url,parameter,method,location,content_type)
);`

const createDirectoryFindingsTable = `
CREATE TABLE IF NOT EXISTS directory_findings (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	status_code INTEGER DEFAULT 0,
	content_length INTEGER DEFAULT 0,
	redirect_url TEXT DEFAULT '',
	content_type TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, url)
);`

const createBackupFindingsTable = `
CREATE TABLE IF NOT EXISTS backup_findings (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	status_code INTEGER DEFAULT 0,
	content_length INTEGER DEFAULT 0,
	file_type TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, url)
);`

const createOpenRedirectFindingsTable = `
CREATE TABLE IF NOT EXISTS open_redirect_findings (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	redirect_to TEXT DEFAULT '',
	parameter TEXT DEFAULT '',
	verified INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, url)
);`

const createNucleiFindingsTable = `
CREATE TABLE IF NOT EXISTS nuclei_findings (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	template_id TEXT NOT NULL,
	template_name TEXT DEFAULT '',
	severity TEXT DEFAULT 'info',
	matched_url TEXT DEFAULT '',
	description TEXT DEFAULT '',
	tags TEXT DEFAULT '[]',
	meta TEXT DEFAULT '{}',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// verification ∈ unverified|verified|rejected|inconclusive. Nuclei's verifiable
// hits (sqli/xss/open-redirect) are routed through Reconner's orchestrator: a
// REJECTED template hit (e.g. an XSS template that only proved reflection, not
// execution) is marked 'rejected' and kept out of the actionable findings, while
// a VERIFIED one is marked 'verified' and promoted. Non-verifiable templates stay
// 'unverified'. confidence mirrors the verifier's score (0 when unverified).
// alterTasksAddCompletedModules tracks which modules a task finished
// successfully, so a failed/cancelled task (e.g. a watchdog timeout on a big
// target) can be RESUMED as a new task covering only the remaining modules
// instead of restarting the whole scan from scratch.
const alterTasksAddCompletedModules = `ALTER TABLE tasks ADD COLUMN completed_modules TEXT DEFAULT '[]';`

const alterNucleiFindingsAddVerification = `ALTER TABLE nuclei_findings ADD COLUMN verification TEXT DEFAULT 'unverified';`
const alterNucleiFindingsAddConfidence = `ALTER TABLE nuclei_findings ADD COLUMN confidence INTEGER DEFAULT 0;`

// PoC evidence for medium+ severity hits — a ready-to-run curl repro plus the
// raw request/response nuclei actually sent/received, so a finding can be
// proven without re-running the scan by hand. Populated only for
// medium/high/critical (see nuclei.go/network.go) to keep low-severity rows
// (which are far more numerous) from bloating the DB with raw HTTP bodies.
const alterNucleiFindingsAddCurlCommand = `ALTER TABLE nuclei_findings ADD COLUMN curl_command TEXT DEFAULT '';`
const alterNucleiFindingsAddRequest = `ALTER TABLE nuclei_findings ADD COLUMN request TEXT DEFAULT '';`
const alterNucleiFindingsAddResponse = `ALTER TABLE nuclei_findings ADD COLUMN response TEXT DEFAULT '';`

const createTasksTable = `
CREATE TABLE IF NOT EXISTS tasks (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	type TEXT NOT NULL,
	status TEXT DEFAULT 'pending',
	priority INTEGER DEFAULT 5,
	progress INTEGER DEFAULT 0,
	total INTEGER DEFAULT 0,
	current_module TEXT DEFAULT '',
	modules TEXT DEFAULT '[]',
	error TEXT DEFAULT '',
	started_at DATETIME,
	finished_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

const createTaskLogsTable = `
CREATE TABLE IF NOT EXISTS task_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id TEXT NOT NULL,
	level TEXT DEFAULT 'info',
	message TEXT NOT NULL,
	module TEXT DEFAULT '',
	data TEXT DEFAULT '{}',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);`

const createScreenshotsTable = `
CREATE TABLE IF NOT EXISTS screenshots (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	file_path TEXT NOT NULL,
	thumbnail_path TEXT DEFAULT '',
	width INTEGER DEFAULT 0,
	height INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

const createMonitoringChangesTable = `
CREATE TABLE IF NOT EXISTS monitoring_changes (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	change_type TEXT NOT NULL,
	old_value TEXT DEFAULT '',
	new_value TEXT DEFAULT '',
	detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

const createNotificationsTable = `
CREATE TABLE IF NOT EXISTS notifications (
	id TEXT PRIMARY KEY,
	target_id TEXT,
	type TEXT NOT NULL,
	title TEXT NOT NULL,
	body TEXT DEFAULT '',
	url TEXT DEFAULT '',
	severity TEXT DEFAULT 'info',
	is_read INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(is_read, created_at DESC);`

const createVulnFindingsTable = `
CREATE TABLE IF NOT EXISTS vuln_findings (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	type TEXT NOT NULL,
	severity TEXT DEFAULT 'medium',
	url TEXT NOT NULL,
	parameter TEXT DEFAULT '',
	payload TEXT DEFAULT '',
	evidence TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, type, url, parameter)
);`

const alterHTTPServicesAddHash = `
ALTER TABLE http_services ADD COLUMN hash TEXT DEFAULT '';
`

const alterTargetsAddMonitoring = `
ALTER TABLE targets ADD COLUMN monitor_enabled INTEGER DEFAULT 0;
`

const alterTargetsAddMonitorInterval = `
ALTER TABLE targets ADD COLUMN monitor_interval_hours INTEGER DEFAULT 12;
`

const alterTargetsAddMonitorLastRun = `
ALTER TABLE targets ADD COLUMN monitor_last_run DATETIME;
`

const alterJSFindingsAddVerified = `
ALTER TABLE js_findings ADD COLUMN verified INTEGER DEFAULT 0;
`

const alterParametersAddMethod = `
ALTER TABLE parameters ADD COLUMN method TEXT DEFAULT 'GET';
`

const alterParametersAddContentType = `
ALTER TABLE parameters ADD COLUMN content_type TEXT DEFAULT '';
`

// alterParametersAddLocation records WHERE in the request a parameter is injected:
// "query" (default, a ?name=value pair) or "path:<index>" for a value that is a
// PATH SEGMENT (e.g. /appointment/<id> → the id at that segment index). Path-based
// insertion points let the active modules fuzz REST-style path values (/user/1,
// /item/abc) — a real injection surface a query-only model walks straight past.
const alterParametersAddLocation = `
ALTER TABLE parameters ADD COLUMN location TEXT DEFAULT 'query';
`

const alterTargetsAddAuthHeaders = `
ALTER TABLE targets ADD COLUMN auth_headers TEXT DEFAULT '';
`

const alterVulnFindingsAddConfidence = `
ALTER TABLE vuln_findings ADD COLUMN confidence INTEGER DEFAULT 0;
`

const alterVulnFindingsAddPriority = `
ALTER TABLE vuln_findings ADD COLUMN priority INTEGER DEFAULT 0;
`

// blind_xss_probes records every out-of-band XSS beacon we plant, keyed by its
// unique token. When a victim browser executes the payload and calls back to
// /bx/<token>, we look the token up here to learn which target/url/sink it came
// from and raise a confirmed blind-XSS finding. hit_count/last_hit/evidence are
// filled on callback.
const createBlindXSSProbesTable = `
CREATE TABLE IF NOT EXISTS blind_xss_probes (
	token TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	parameter TEXT DEFAULT '',
	sink TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	hit_count INTEGER DEFAULT 0,
	last_hit DATETIME,
	evidence TEXT DEFAULT '',
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// oob_probes backs out-of-band (OAST) blind SSRF/RCE detection. We inject a
// payload that makes the TARGET SERVER call back to /oob/<token>; when that hit
// arrives we look the token up here to learn which injection point and bug class
// (ssrf/rce/xxe) it proves, and raise a confirmed finding.
// source distinguishes real probed hosts ('probe') from URLs injected by the
// JS-endpoint loop ('js'). The HTTP tab shows only real hosts; active scanners
// still reach the js-derived endpoints (they don't filter by source).
const alterHTTPServicesAddSource = `
ALTER TABLE http_services ADD COLUMN source TEXT DEFAULT 'probe';
`

// norm_hash stores a NORMALIZED content hash (volatile values stripped) so change
// monitoring doesn't false-positive on dynamic pages. security_snapshot stores
// the JSON of security-sensitive attributes (external scripts/iframes/forms/…)
// for supply-chain / form-hijack change detection.
const alterHTTPServicesAddNormHash = `
ALTER TABLE http_services ADD COLUMN norm_hash TEXT DEFAULT '';
`
const alterHTTPServicesAddSecuritySnapshot = `
ALTER TABLE http_services ADD COLUMN security_snapshot TEXT DEFAULT '';
`

const alterHTTPServicesAddWAF = `
ALTER TABLE http_services ADD COLUMN waf TEXT DEFAULT '';
`

const alterHTTPServicesAddCMS = `
ALTER TABLE http_services ADD COLUMN cms TEXT DEFAULT '';
`

const createOOBProbesTable = `
CREATE TABLE IF NOT EXISTS oob_probes (
	token TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	url TEXT NOT NULL,
	parameter TEXT DEFAULT '',
	kind TEXT DEFAULT '',
	sink TEXT DEFAULT '',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	hit_count INTEGER DEFAULT 0,
	last_hit DATETIME,
	evidence TEXT DEFAULT '',
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);`

// open_ports records naabu port-scan results per host. A newly-exposed port on
// an established target is itself a monitoring signal.
const createOpenPortsTable = `
CREATE TABLE IF NOT EXISTS open_ports (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	host TEXT NOT NULL,
	ip TEXT DEFAULT '',
	port INTEGER NOT NULL,
	service TEXT DEFAULT '',
	first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
	UNIQUE(target_id, host, port)
);`

// severity classifies each monitoring change (info|low|medium|high) so alerts
// can be prioritised — a removed HSTS/CSP header is high, a body tweak is info.
const alterMonitoringChangesAddSeverity = `
ALTER TABLE monitoring_changes ADD COLUMN severity TEXT DEFAULT 'info';
`

// status separates confirmed findings ('finding') from unconfirmed ones
// ('candidate'). Candidates are shown apart in the UI, excluded from severity
// counts and from attack-path generation. provenance stores the raw evidence
// (DNS output, curl response, redirect chain) proving/justifying the verdict.
const alterVulnFindingsAddStatus = `
ALTER TABLE vuln_findings ADD COLUMN status TEXT DEFAULT 'finding';
`
const alterVulnFindingsAddProvenance = `
ALTER TABLE vuln_findings ADD COLUMN provenance TEXT DEFAULT '';
`

// triage is the OPERATOR's decision on a finding (False-Positive management):
// ” (untriaged) | new | confirmed | false_positive | accepted_risk | fixed.
// It is orthogonal to `status` (the engine's finding/candidate verdict); the UI
// and reports filter on it so a triaged FP disappears from the working list and
// the exported report. triage_note stores the operator's justification.
const alterVulnFindingsAddTriage = `
ALTER TABLE vuln_findings ADD COLUMN triage TEXT DEFAULT '';
`
const alterVulnFindingsAddTriageNote = `
ALTER TABLE vuln_findings ADD COLUMN triage_note TEXT DEFAULT '';
`

// Correlation (P3): findings sharing a root cause (same vuln type + endpoint
// template) are grouped under a root finding so the researcher sees ONE issue
// with N affected resources instead of N duplicates. Individual rows + evidence
// are preserved; only the presentation collapses.
const alterVulnFindingsAddCorrelation = `
ALTER TABLE vuln_findings ADD COLUMN correlation_key TEXT DEFAULT '';
`
const alterVulnFindingsAddRootID = `
ALTER TABLE vuln_findings ADD COLUMN root_finding_id TEXT DEFAULT '';
`
const alterOpenRedirectAddStatus = `
ALTER TABLE open_redirect_findings ADD COLUMN status TEXT DEFAULT 'finding';
`
const alterOpenRedirectAddProvenance = `
ALTER TABLE open_redirect_findings ADD COLUMN provenance TEXT DEFAULT '';
`

// scope='single' restricts URL/endpoint gathering to the EXACT host (used by the
// CLI's --single mode); 'full' (default) allows the whole domain + subdomains.
const alterTargetsAddScope = `
ALTER TABLE targets ADD COLUMN scope TEXT DEFAULT 'full';
`

// image holds an optional API path (e.g. /screenshots/<id>) to a picture that
// backs the evidence — used by the Ingram camera scanner to attach the live
// snapshot it captured from a cracked device to that finding's evidence.
const alterEvidenceAddImage = `ALTER TABLE evidence ADD COLUMN image TEXT DEFAULT '';`

const createIndexes = `
CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_alive ON subdomains(is_alive);
CREATE INDEX IF NOT EXISTS idx_http_services_target ON http_services(target_id);
CREATE INDEX IF NOT EXISTS idx_js_files_target ON js_files(target_id);
CREATE INDEX IF NOT EXISTS idx_js_findings_target ON js_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_parameters_target ON parameters(target_id);
CREATE INDEX IF NOT EXISTS idx_parameters_reflected ON parameters(is_reflected);
CREATE INDEX IF NOT EXISTS idx_directory_findings_target ON directory_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_backup_findings_target ON backup_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_target ON nuclei_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_severity ON nuclei_findings(severity);
CREATE INDEX IF NOT EXISTS idx_tasks_target ON tasks(target_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_monitoring_changes_target ON monitoring_changes(target_id);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_target ON vuln_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_type ON vuln_findings(type);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vuln_findings(severity);
CREATE INDEX IF NOT EXISTS idx_identities_target ON identities(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_http_interactions_target ON http_interactions(target_id);
CREATE INDEX IF NOT EXISTS idx_objects_target ON objects(target_id);
CREATE INDEX IF NOT EXISTS idx_actions_target ON actions(target_id);
CREATE INDEX IF NOT EXISTS idx_actions_object ON actions(target_id, object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_objrel_target ON object_relationships(target_id);
CREATE INDEX IF NOT EXISTS idx_objrel_object ON object_relationships(target_id, object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_wfvars_target ON workflow_variables(target_id);
CREATE INDEX IF NOT EXISTS idx_authzobs_target ON authorization_observations(target_id);
CREATE INDEX IF NOT EXISTS idx_authzobs_object ON authorization_observations(target_id, object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(target_id, status);
CREATE INDEX IF NOT EXISTS idx_snapshots_target ON state_snapshots(target_id, object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_candidates_target ON candidates(target_id, status);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_candidate ON vuln_findings(candidate_id);
CREATE INDEX IF NOT EXISTS idx_cand_transitions ON candidate_transitions(candidate_id);
CREATE INDEX IF NOT EXISTS idx_candidates_type ON candidates(target_id, type);
`

// eta_seconds / module_eta_seconds carry the scheduler's live estimate of the
// seconds remaining for the whole scan and for the current module, so the UI can
// show a countdown per scan without recomputing it client-side.
const alterTasksAddEta = `ALTER TABLE tasks ADD COLUMN eta_seconds INTEGER DEFAULT 0;`
const alterTasksAddModuleEta = `ALTER TABLE tasks ADD COLUMN module_eta_seconds INTEGER DEFAULT 0;`
