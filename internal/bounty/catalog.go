package bounty

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	assetutil "github.com/recon-platform/internal/assets"
)

type ListOptions struct {
	Search         string
	Provider       string
	Status         string
	ProgramType    string
	Industry       string
	SafeHarbor     string
	AssetType      string
	OffersBounties *bool
	HasWildcard    *bool
	MinAssets      int
	MaxAssets      int
	MinRewardCents int
	Sort           string
	Page           int
	Limit          int
}

type ListResult struct {
	Programs    []Program         `json:"programs"`
	Total       int               `json:"total"`
	Page        int               `json:"page"`
	Limit       int               `json:"limit"`
	DetailIndex DetailIndexStatus `json:"detail_index"`
}

const programColumns = `p.id,p.provider,p.external_id,p.handle,p.name,p.url,p.logo_url,p.description,p.status,p.program_type,p.industry,
	p.offers_bounties,p.open_scope,p.safe_harbor,p.asset_count,p.in_scope_count,p.wildcard_count,p.scope_rank,
	p.min_reward_cents,p.max_reward_cents,p.currency,p.started_at,p.published_at,p.provider_updated_at,p.last_synced_at,p.detail_synced_at,p.scope_hash`

func scanProgram(scanner interface{ Scan(...any) error }) (Program, error) {
	var p Program
	var bounty, open int
	var started, published, providerUpdated, lastSync, detail sql.NullTime
	err := scanner.Scan(&p.ID, &p.Provider, &p.ExternalID, &p.Handle, &p.Name, &p.URL, &p.LogoURL, &p.Description, &p.Status, &p.ProgramType, &p.Industry,
		&bounty, &open, &p.SafeHarbor, &p.AssetCount, &p.InScopeCount, &p.WildcardCount, &p.ScopeRank, &p.MinRewardCents, &p.MaxRewardCents, &p.Currency,
		&started, &published, &providerUpdated, &lastSync, &detail, &p.ScopeHash)
	if err != nil {
		return p, err
	}
	p.OffersBounties = bounty == 1
	p.OpenScope = open == 1
	if started.Valid {
		p.StartedAt = &started.Time
	}
	if published.Valid {
		p.PublishedAt = &published.Time
	}
	if providerUpdated.Valid {
		p.ProviderUpdatedAt = &providerUpdated.Time
	}
	if lastSync.Valid {
		p.LastSyncedAt = &lastSync.Time
	}
	if detail.Valid {
		p.DetailSyncedAt = &detail.Time
		p.DetailsLoaded = true
	}
	return p, nil
}

func (s *Service) ListPrograms(ctx context.Context, o ListOptions) (ListResult, error) {
	detailIndex := s.DetailIndexStatus()
	// Scope-derived filters cannot be correct while provider details are still
	// lazy. Start a bounded background index automatically; callers receive
	// progress and can refresh without opening every program by hand.
	if o.HasWildcard != nil || o.AssetType != "" || o.MinAssets > 0 || o.MaxAssets > 0 || o.Sort == "assets_desc" || o.Sort == "assets_asc" || o.Sort == "wildcards" {
		detailIndex = s.StartDetailIndex()
	}
	if o.Page < 1 {
		o.Page = 1
	}
	if o.Limit < 1 {
		o.Limit = 30
	}
	if o.Limit > 100 {
		o.Limit = 100
	}
	where := []string{"1=1"}
	args := []any{}
	add := func(cond string, arg any) { where = append(where, cond); args = append(args, arg) }
	if q := strings.TrimSpace(o.Search); q != "" {
		where = append(where, "(p.name LIKE ? OR p.handle LIKE ? OR p.description LIKE ? OR p.industry LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	if o.Provider != "" {
		add("p.provider=?", o.Provider)
	}
	if o.Status != "" {
		add("p.status=?", o.Status)
	}
	if o.ProgramType != "" {
		add("p.program_type=?", o.ProgramType)
	}
	if o.Industry != "" {
		add("p.industry=?", o.Industry)
	}
	if o.SafeHarbor != "" {
		add("p.safe_harbor=?", o.SafeHarbor)
	}
	if o.OffersBounties != nil {
		add("p.offers_bounties=?", boolInt(*o.OffersBounties))
	}
	if o.HasWildcard != nil {
		if *o.HasWildcard {
			where = append(where, "p.wildcard_count>0")
		} else {
			// An unloaded program is unknown, not a confirmed non-wildcard.
			where = append(where, "p.detail_synced_at IS NOT NULL AND p.wildcard_count=0")
		}
	}
	if o.MinAssets > 0 {
		add("p.in_scope_count>=?", o.MinAssets)
	}
	if o.MaxAssets > 0 {
		where = append(where, "p.detail_synced_at IS NOT NULL")
		add("p.in_scope_count<=?", o.MaxAssets)
	}
	if o.MinRewardCents > 0 {
		add("p.max_reward_cents>=?", o.MinRewardCents)
	}
	if o.AssetType != "" {
		add("EXISTS(SELECT 1 FROM bounty_program_assets a WHERE a.program_id=p.id AND a.active=1 AND a.in_scope=1 AND a.eligible_submission=1 AND a.asset_type=?)", o.AssetType)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM bounty_programs p WHERE "+clause, args...).Scan(&total); err != nil {
		return ListResult{}, err
	}
	order := map[string]string{"newest": "COALESCE(p.started_at,p.published_at,p.last_synced_at) DESC", "updated": "COALESCE(p.provider_updated_at,p.detail_synced_at,p.last_synced_at) DESC", "assets_desc": "p.in_scope_count DESC,p.name", "assets_asc": "p.in_scope_count ASC,p.name", "reward_desc": "p.max_reward_cents DESC,p.name", "name": "p.name COLLATE NOCASE ASC", "wildcards": "p.wildcard_count DESC,p.in_scope_count DESC"}[o.Sort]
	if order == "" {
		order = "COALESCE(p.started_at,p.published_at,p.last_synced_at) DESC"
	}
	query := "SELECT " + programColumns + " FROM bounty_programs p WHERE " + clause + " ORDER BY " + order + " LIMIT ? OFFSET ?"
	args = append(args, o.Limit, (o.Page-1)*o.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()
	items := make([]Program, 0, o.Limit)
	for rows.Next() {
		p, err := scanProgram(rows)
		if err != nil {
			return ListResult{}, err
		}
		items = append(items, p)
	}
	return ListResult{Programs: items, Total: total, Page: o.Page, Limit: o.Limit, DetailIndex: detailIndex}, rows.Err()
}

func (s *Service) GetProgram(ctx context.Context, id string) (Program, error) {
	detailErr := s.EnsureDetails(ctx, id)
	p, err := scanProgram(s.db.QueryRowContext(ctx, "SELECT "+programColumns+" FROM bounty_programs p WHERE p.id=?", id))
	if err != nil {
		return p, err
	}
	if detailErr != nil && !p.DetailsLoaded {
		return p, detailErr
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,program_id,external_id,identifier,asset_type,category,is_wildcard,in_scope,
		eligible_submission,eligible_bounty,max_severity,instruction,reward_json,metadata,active,provider_created_at,provider_updated_at,raw_hash
		FROM bounty_program_assets WHERE program_id=? ORDER BY in_scope DESC,eligible_submission DESC,identifier COLLATE NOCASE`, id)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	p.Assets = []Asset{}
	for rows.Next() {
		var a Asset
		var wildcard, inScope, submission, bounty, active int
		var rewardJSON, metadataJSON string
		var created, updated sql.NullTime
		if err := rows.Scan(&a.ID, &a.ProgramID, &a.ExternalID, &a.Identifier, &a.AssetType, &a.Category, &wildcard, &inScope, &submission, &bounty, &a.MaxSeverity, &a.Instruction, &rewardJSON, &metadataJSON, &active, &created, &updated, &a.RawHash); err != nil {
			return p, err
		}
		a.IsWildcard = wildcard == 1
		a.InScope = inScope == 1
		a.EligibleSubmission = submission == 1
		a.EligibleBounty = bounty == 1
		a.Active = active == 1
		if created.Valid {
			a.ProviderCreatedAt = &created.Time
		}
		if updated.Valid {
			a.ProviderUpdatedAt = &updated.Time
		}
		_ = json.Unmarshal([]byte(rewardJSON), &a.Reward)
		_ = json.Unmarshal([]byte(metadataJSON), &a.Metadata)
		p.Assets = append(p.Assets, a)
	}
	return p, rows.Err()
}

type CreateProjectRequest struct {
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	Priority             string   `json:"priority"`
	Notes                string   `json:"notes"`
	AssetIDs             []string `json:"asset_ids"`
	MonitorEnabled       bool     `json:"monitor_enabled"`
	MonitorIntervalHours int      `json:"monitor_interval_hours"`
	// WatchOnly creates a BREADTH project: it runs the cheap watch rounds
	// (passive discovery + one HTTP probe) instead of the deep pipeline.
	// The backend is the enforcement point — network/IP assets are filtered
	// out so the project can never end up mixed, and the old monitor tier is
	// switched off (both flags on would double-scan the project).
	WatchOnly bool `json:"watch_only"`
}

func projectAssetKind(t string) string {
	switch t {
	case "cidr", "ip":
		return "network"
	case "domain", "wildcard", "url", "page", "js", "api":
		return "web"
	case "app_store", "android", "ios", "hardware", "source_code", "other", "reference":
		return "reference"
	default:
		return "reference"
	}
}

// managedAssetKind also demotes web-typed assets whose identifier is not a
// host or URL. Old catalog rows can carry a prose note with type "domain";
// those values must never become project roots.
func managedAssetKind(a Asset) string {
	kind := projectAssetKind(a.AssetType)
	if kind != "web" {
		return kind
	}
	if !assetutil.IsScannableWebAsset(a.AssetType, a.Identifier) {
		return "reference"
	}
	return "web"
}

func (s *Service) CreateProject(ctx context.Context, ownerID int64, programID string, req CreateProjectRequest) (string, error) {
	p, err := s.GetProgram(ctx, programID)
	if err != nil {
		return "", err
	}
	return s.createProjectFromProgram(ctx, ownerID, p, req, 0)
}

// createProjectFromProgram holds the import logic so a bulk import can reuse a
// program that was already loaded. That avoids a second provider detail fetch
// for every program in the batch. watchStartOffsetMinutes staggers the first
// round of bulk-created breadth projects; a single create passes 0.
func (s *Service) createProjectFromProgram(ctx context.Context, ownerID int64, p Program, req CreateProjectRequest, watchStartOffsetMinutes int) (string, error) {
	if len(req.AssetIDs) == 0 {
		return "", fmt.Errorf("select at least one current scope asset")
	}
	selected := map[string]bool{}
	for _, id := range req.AssetIDs {
		selected[id] = true
	}
	assets := []Asset{}
	outScope := []string{}
	for _, a := range p.Assets {
		if !a.Active {
			continue
		}
		if !a.InScope || !a.EligibleSubmission {
			if a.Identifier != "" {
				outScope = append(outScope, a.Identifier)
			}
			continue
		}
		if len(selected) > 0 && !selected[a.ID] {
			continue
		}
		assets = append(assets, a)
	}
	if len(assets) == 0 {
		return "", fmt.Errorf("select at least one active, submission-eligible asset")
	}
	if len(assets) != len(selected) {
		return "", fmt.Errorf("one or more selected assets are missing or no longer submission-eligible; refresh the program scope")
	}
	values := make([]string, 0, len(assets))
	hasWeb, hasNet := false, false
	skippedNetwork := []string{}
	skippedAppStore := []string{}
	for _, a := range assets {
		if a.AssetType == "app_store" || assetutil.IsAppStoreAsset(a.Identifier) {
			skippedAppStore = append(skippedAppStore, a.Identifier)
			continue
		}
		kind := managedAssetKind(a)
		if kind == "reference" {
			continue
		}
		// A breadth project runs WEB modules only. Network assets (CIDR/IP) have
		// no place in a watch round, and a mixed project cannot run one at all —
		// so the backend drops them here instead of creating a broken project.
		if req.WatchOnly && kind == "network" {
			skippedNetwork = append(skippedNetwork, a.Identifier)
			continue
		}
		values = append(values, a.Identifier)
		if kind == "network" {
			hasNet = true
		} else {
			hasWeb = true
		}
	}
	if req.WatchOnly && len(values) == 0 {
		return "", fmt.Errorf("no web assets: a breadth project needs at least one web asset")
	}
	if len(skippedNetwork) > 0 && s.log != nil {
		s.log.Info("Breadth project import dropped network assets", "count", len(skippedNetwork), "assets", strings.Join(skippedNetwork, ", "))
	}
	if len(skippedAppStore) > 0 && s.log != nil {
		s.log.Info("Project import dropped app-store assets", "count", len(skippedAppStore), "assets", strings.Join(skippedAppStore, ", "))
	}
	if len(values) == 0 {
		values = []string{p.Provider + ":" + p.Handle}
	}
	kind := "web"
	if hasNet && !hasWeb {
		kind = "network"
	} else if hasNet && hasWeb {
		kind = "mixed"
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = p.Name
	}
	priority := strings.TrimSpace(req.Priority)
	if priority == "" {
		priority = "medium"
	}
	hours := req.MonitorIntervalHours
	if hours < 1 {
		hours = 12
	}
	scope := strings.Join(values, ",")
	targetID := uuid.New().String()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// A breadth project starts in the watch tier: the old monitor tier is off
	// (both flags on would scan the project twice) and the first watch round is
	// due immediately.
	monitorEnabled := req.MonitorEnabled
	watchOnly := 0
	if req.WatchOnly {
		monitorEnabled = false
		watchOnly = 1
	}
	// watch_next_run must be a real SQLite timestamp, not a bound string: the
	// due query compares watch_next_run <= datetime('now') as TEXT, and the
	// literal "CURRENT_TIMESTAMP" sorts after "2026-..." so the first round
	// would never be due. For breadth projects, a single create starts now;
	// bulk creates spread their first rounds across the normal interval.
	// Deep projects keep NULL ("not scheduled").
	_, err = tx.ExecContext(ctx, `INSERT INTO targets(id,domain,name,description,priority,notes,kind,exclude_scope,owner_id,monitor_enabled,monitor_interval_hours,watch_only,watch_next_run,watch_paused,watch_fail_count,watch_root_index)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ? = 1 THEN datetime('now','+' || ? || ' minutes') ELSE NULL END,0,0,0)`, targetID, scope, name, req.Description, priority, req.Notes, kind, strings.Join(outScope, "\n"), ownerID, boolInt(monitorEnabled), hours, watchOnly, watchOnly, watchStartOffsetMinutes)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO project_programs(target_id,program_id,auto_sync,last_scope_hash,last_checked_at) VALUES(?,?,1,?,CURRENT_TIMESTAMP)`, targetID, p.ID, p.ScopeHash)
	if err != nil {
		return "", err
	}
	for _, a := range assets {
		if req.WatchOnly && managedAssetKind(a) == "network" {
			continue // network assets are not part of a breadth project
		}
		if managedAssetKind(a) == "reference" {
			continue // prose notes and app listings are not project assets
		}
		meta, _ := json.Marshal(map[string]any{"provider": p.Provider, "program": p.Handle, "raw_hash": a.RawHash, "eligible_bounty": a.EligibleBounty, "max_severity": a.MaxSeverity, "instruction": a.Instruction})
		assetMonitor := 1
		if req.WatchOnly {
			assetMonitor = 0 // the old monitor tier is off for breadth projects
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at)
		VALUES(?,?,?,?,?,?,?,?, 'approved',?,?,CURRENT_TIMESTAMP)`, uuid.New().String(), targetID, a.Identifier, a.Identifier, managedAssetKind(a), a.AssetType, "bounty:"+p.Provider, a.ID, assetMonitor, string(meta))
		if err != nil {
			return "", err
		}
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return targetID, nil
}

// maxBulkProjectCreations bounds one bulk request. Program detail fetches can
// reach providers, so an unbounded list could tie up the API for a long time.
const maxBulkProjectCreations = 100

type BulkCreateProjectsRequest struct {
	ProgramIDs           []string `json:"program_ids"`
	Coverage             string   `json:"coverage"`     // breadth or deep
	AssetPolicy          string   `json:"asset_policy"` // all_eligible_web or all_eligible
	Priority             string   `json:"priority"`
	NameTemplate         string   `json:"name_template"` // {program}, {handle}, {provider}
	MonitorEnabled       bool     `json:"monitor_enabled"`
	MonitorIntervalHours int      `json:"monitor_interval_hours"`
	SkipExisting         bool     `json:"skip_existing"`
	// WatchIntervalMinutes is internal. The API handler fills it from config
	// so bulk-created breadth projects can spread their first rounds.
	WatchIntervalMinutes int `json:"-"`
}

type BulkCreateProjectResult struct {
	ProgramID       string `json:"program_id"`
	ProgramName     string `json:"program_name,omitempty"`
	OK              bool   `json:"ok"`
	TargetID        string `json:"target_id,omitempty"`
	Assets          int    `json:"assets,omitempty"`
	SkippedNetwork  int    `json:"skipped_network,omitempty"`
	SkippedAppStore int    `json:"skipped_app_store,omitempty"`
	SkippedInvalid  int    `json:"skipped_invalid,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// CreateProjectsBulk imports many bounty programs in one call. Each program is
// independent: one failure never rolls back the others. The caller gets one
// result per program so the UI can show created, skipped and failed projects.
func (s *Service) CreateProjectsBulk(ctx context.Context, ownerID int64, req BulkCreateProjectsRequest) ([]BulkCreateProjectResult, error) {
	ids := make([]string, 0, len(req.ProgramIDs))
	seen := map[string]bool{}
	for _, raw := range req.ProgramIDs {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("select at least one program")
	}
	if len(ids) > maxBulkProjectCreations {
		return nil, fmt.Errorf("bulk import is limited to %d programs", maxBulkProjectCreations)
	}

	coverage := strings.ToLower(strings.TrimSpace(req.Coverage))
	if coverage == "" {
		coverage = "breadth"
	}
	if coverage != "breadth" && coverage != "deep" {
		return nil, fmt.Errorf("coverage must be breadth or deep")
	}
	assetPolicy := strings.ToLower(strings.TrimSpace(req.AssetPolicy))
	if assetPolicy == "" {
		assetPolicy = "all_eligible_web"
	}
	if assetPolicy != "all_eligible_web" && assetPolicy != "all_eligible" {
		return nil, fmt.Errorf("asset_policy must be all_eligible_web or all_eligible")
	}

	interval := req.WatchIntervalMinutes
	if interval <= 0 {
		interval = 12 * 60
	}
	total := len(ids)
	results := make([]BulkCreateProjectResult, 0, len(ids))
	for i, programID := range ids {
		result := BulkCreateProjectResult{ProgramID: programID}
		p, err := s.GetProgram(ctx, programID)
		if err != nil {
			result.Reason = "program unavailable"
			results = append(results, result)
			continue
		}
		result.ProgramName = p.Name

		if req.SkipExisting {
			var existingID string
			err := s.db.QueryRowContext(ctx, `
				SELECT t.id FROM project_programs pp
				JOIN targets t ON t.id = pp.target_id
				WHERE pp.program_id = ? AND t.owner_id = ? LIMIT 1`, programID, ownerID).Scan(&existingID)
			if err == nil {
				result.Reason = "already_linked"
				result.TargetID = existingID
				results = append(results, result)
				continue
			}
			if err != sql.ErrNoRows {
				result.Reason = "lookup failed"
				results = append(results, result)
				continue
			}
		}

		assetIDs := []string{}
		skippedNetwork := 0
		skippedAppStore := 0
		skippedInvalid := 0
		for _, a := range p.Assets {
			if !a.Active || !a.InScope || !a.EligibleSubmission {
				continue
			}
			if a.AssetType == "app_store" || assetutil.IsAppStoreAsset(a.Identifier) {
				skippedAppStore++
				continue
			}
			kind := managedAssetKind(a)
			if kind == "reference" {
				if projectAssetKind(a.AssetType) == "web" {
					skippedInvalid++
				}
				continue
			}
			if kind == "network" {
				if coverage == "breadth" || assetPolicy == "all_eligible_web" {
					skippedNetwork++
					continue
				}
			}
			assetIDs = append(assetIDs, a.ID)
		}
		if len(assetIDs) == 0 {
			result.Reason = "no eligible web assets"
			results = append(results, result)
			continue
		}

		name := p.Name
		if strings.TrimSpace(req.NameTemplate) != "" {
			name = strings.NewReplacer(
				"{program}", p.Name,
				"{handle}", p.Handle,
				"{provider}", p.Provider,
			).Replace(req.NameTemplate)
		}
		notes := ""
		if p.URL != "" {
			notes = "Program: " + p.URL
		}
		createReq := CreateProjectRequest{
			Name:                 name,
			Description:          "Bulk import from " + p.Provider + " public program",
			Priority:             req.Priority,
			Notes:                notes,
			AssetIDs:             assetIDs,
			MonitorEnabled:       req.MonitorEnabled && coverage == "deep",
			MonitorIntervalHours: req.MonitorIntervalHours,
			WatchOnly:            coverage == "breadth",
		}
		// Spread first rounds of breadth projects across one normal interval.
		// Deep projects ignore the offset: their watch_next_run stays NULL.
		watchStartOffsetMinutes := 0
		if coverage == "breadth" && total > 0 {
			watchStartOffsetMinutes = (i * interval / total) % interval
		}
		targetID, err := s.createProjectFromProgram(ctx, ownerID, p, createReq, watchStartOffsetMinutes)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				result.Reason = "already_linked"
			} else {
				result.Reason = err.Error()
			}
			results = append(results, result)
			continue
		}
		result.OK = true
		result.TargetID = targetID
		result.Assets = len(assetIDs)
		result.SkippedNetwork = skippedNetwork
		result.SkippedAppStore = skippedAppStore
		result.SkippedInvalid = skippedInvalid
		results = append(results, result)
	}
	return results, nil
}

type ScopeEvent struct {
	ID             string     `json:"id"`
	TargetID       string     `json:"target_id"`
	ProgramID      string     `json:"program_id"`
	ProgramAssetID string     `json:"program_asset_id"`
	EventType      string     `json:"event_type"`
	Identifier     string     `json:"identifier"`
	OldJSON        string     `json:"old_json"`
	NewJSON        string     `json:"new_json"`
	Status         string     `json:"status"`
	DetectedAt     time.Time  `json:"detected_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

func (s *Service) ListScopeEvents(ctx context.Context, targetID string) ([]ScopeEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,target_id,program_id,COALESCE(program_asset_id,''),event_type,identifier,old_json,new_json,status,detected_at,resolved_at FROM bounty_scope_events WHERE target_id=? ORDER BY detected_at DESC`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopeEvent{}
	for rows.Next() {
		var e ScopeEvent
		var resolved sql.NullTime
		if err := rows.Scan(&e.ID, &e.TargetID, &e.ProgramID, &e.ProgramAssetID, &e.EventType, &e.Identifier, &e.OldJSON, &e.NewJSON, &e.Status, &e.DetectedAt, &resolved); err != nil {
			return nil, err
		}
		if resolved.Valid {
			e.ResolvedAt = &resolved.Time
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) reconcileLinkedProjects(ctx context.Context, programID string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id FROM project_programs WHERE program_id=? AND auto_sync=1`, programID)
	if err != nil {
		return err
	}
	targets := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			targets = append(targets, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	// Release the read cursor before reconciliation starts writes. This matters
	// when SQLite is configured with a small connection pool and avoids holding a
	// reader open across GetProgram/UPDATE calls.
	if err := rows.Close(); err != nil {
		return err
	}
	for _, targetID := range targets {
		if err := s.reconcileProject(ctx, targetID, programID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reconcileProject(ctx context.Context, targetID, programID string) error {
	p, err := s.GetProgram(ctx, programID)
	if err != nil {
		return err
	}
	existing := map[string]struct{ ID, Value, Status, Raw string }{}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.source_id,a.value,a.approval_status,a.metadata
		FROM assets a JOIN bounty_program_assets b ON b.id=a.source_id
		WHERE a.target_id=? AND b.program_id=? AND a.source LIKE 'bounty:%'`, targetID, programID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, sid, value, status, meta string
		if rows.Scan(&id, &sid, &value, &status, &meta) == nil {
			var m map[string]any
			_ = json.Unmarshal([]byte(meta), &m)
			raw, _ := m["raw_hash"].(string)
			existing[sid] = struct{ ID, Value, Status, Raw string }{id, value, status, raw}
		}
	}
	rows.Close()
	current := map[string]Asset{}
	added, removed, modified := 0, 0, 0
	for _, a := range p.Assets {
		if a.Active && a.InScope && a.EligibleSubmission {
			current[a.ID] = a
			if old, ok := existing[a.ID]; !ok {
				s.createScopeEvent(ctx, targetID, p.ID, a.ID, "added", a.Identifier, "{}", mustJSON(a))
				added++
			} else if old.Raw != "" && old.Raw != a.RawHash {
				s.createScopeEvent(ctx, targetID, p.ID, a.ID, "modified", a.Identifier, mustJSON(old), mustJSON(a))
				modified++
			}
		}
	}
	for sid, old := range existing {
		if _, ok := current[sid]; !ok && old.Status != "suspended" {
			_, _ = s.db.ExecContext(ctx, `UPDATE assets SET approval_status='suspended',monitor_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE id=?`, old.ID)
			s.createScopeEvent(ctx, targetID, p.ID, sid, "removed", old.Value, mustJSON(old), "{}")
			removed++
		}
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE project_programs SET last_scope_hash=?,last_checked_at=CURRENT_TIMESTAMP WHERE target_id=? AND program_id=?`, p.ScopeHash, targetID, p.ID)
	if added+removed+modified > 0 {
		body := fmt.Sprintf("%s scope changed: %d added, %d removed, %d modified. New assets require approval; removed assets were suspended.", p.Name, added, removed, modified)
		_, _ = s.db.ExecContext(ctx, `INSERT INTO notifications(id,target_id,type,title,body,url,severity) VALUES(?,?,?,?,?,?,?)`, uuid.New().String(), targetID, "bounty_scope_change", "Bug bounty scope changed", body, "/targets/"+url.PathEscape(targetID), "medium")
	}
	return nil
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// scopeEventFingerprint identifies one specific scope state. "added" and
// "modified" events are keyed by the new program-asset state; "removed" events
// are keyed by the old state that was taken away. A rejected or approved
// decision on this fingerprint suppresses the same event on later syncs. A
// genuine later change produces a different JSON state and is reported again.
func scopeEventFingerprint(eventType, identifier, oldJSON, newJSON string) string {
	state := newJSON
	if eventType == "removed" {
		state = oldJSON
	}
	sum := sha256.Sum256([]byte(eventType + "\x00" + identifier + "\x00" + state))
	return hex.EncodeToString(sum[:])
}

func (s *Service) createScopeEvent(ctx context.Context, targetID, programID, assetID, eventType, identifier, oldJSON, newJSON string) {
	fingerprint := scopeEventFingerprint(eventType, identifier, oldJSON, newJSON)
	var decided int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bounty_scope_decisions WHERE target_id=? AND program_id=? AND program_asset_id=? AND event_type=? AND fingerprint=?`, targetID, programID, assetID, eventType, fingerprint).Scan(&decided)
	if decided > 0 {
		return
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bounty_scope_events WHERE target_id=? AND program_asset_id=? AND event_type=? AND status='pending'`, targetID, assetID, eventType).Scan(&n)
	if n > 0 {
		return
	}
	eventID := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `INSERT INTO bounty_scope_events(id,target_id,program_id,program_asset_id,event_type,identifier,old_json,new_json,status) VALUES(?,?,?,?,?,?,?,?, 'pending')`, eventID, targetID, programID, assetID, eventType, identifier, oldJSON, newJSON)
	if err == nil && s.onScopeEvent != nil {
		s.onScopeEvent(ctx, targetID, programID, eventID, eventType, identifier)
	}
}

func (s *Service) ResolveScopeEvent(ctx context.Context, targetID, eventID, decision string) error {
	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("decision must be approve or reject")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var eventType, assetID, status, programID, identifier, oldJSON, newJSON string
	err = tx.QueryRowContext(ctx, `SELECT event_type,COALESCE(program_asset_id,''),status,program_id,identifier,old_json,new_json FROM bounty_scope_events WHERE id=? AND target_id=?`, eventID, targetID).Scan(&eventType, &assetID, &status, &programID, &identifier, &oldJSON, &newJSON)
	if err != nil {
		return err
	}
	if status != "pending" && status != "rejected" {
		return fmt.Errorf("scope event already resolved")
	}
	if status == "rejected" && decision == "reject" {
		return fmt.Errorf("scope event already dismissed")
	}
	if decision == "approve" {
		switch eventType {
		case "added", "modified":
			var a Asset
			var wild, inScope, submit, bounty, active int
			var reward, metadata string
			err = tx.QueryRowContext(ctx, `SELECT id,program_id,external_id,identifier,asset_type,category,is_wildcard,in_scope,eligible_submission,eligible_bounty,max_severity,instruction,reward_json,metadata,active,raw_hash FROM bounty_program_assets WHERE id=?`, assetID).Scan(&a.ID, &a.ProgramID, &a.ExternalID, &a.Identifier, &a.AssetType, &a.Category, &wild, &inScope, &submit, &bounty, &a.MaxSeverity, &a.Instruction, &reward, &metadata, &active, &a.RawHash)
			if err != nil {
				return err
			}
			if active != 1 || inScope != 1 || submit != 1 {
				return fmt.Errorf("scope asset is no longer active and submission-eligible")
			}
			meta := map[string]any{"raw_hash": a.RawHash, "eligible_bounty": bounty == 1, "max_severity": a.MaxSeverity, "instruction": a.Instruction}
			metaJSON, _ := json.Marshal(meta)
			// The upsert must NOT rewrite a row the watch tier landed
			// (source='watch:scope'): that row is the operator's landed scope
			// and keeps its own source, asset_type and metadata. The WHERE on
			// the conflict clause leaves the landed row untouched.
			_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at) VALUES(?,?,?,?,?,?, 'bounty:catalog',?,'approved',1,?,CURRENT_TIMESTAMP) ON CONFLICT(target_id,value) DO UPDATE SET value=excluded.value,kind=excluded.kind,asset_type=excluded.asset_type,source='bounty:catalog',source_id=excluded.source_id,approval_status='approved',monitor_enabled=1,metadata=excluded.metadata,updated_at=CURRENT_TIMESTAMP WHERE assets.source <> 'watch:scope'`, uuid.New().String(), targetID, a.Identifier, a.Identifier, managedAssetKind(a), a.AssetType, a.ID, string(metaJSON))
			if err != nil {
				return err
			}
		case "removed":
			_, err = tx.ExecContext(ctx, `UPDATE assets SET approval_status='suspended',monitor_enabled=0,updated_at=CURRENT_TIMESTAMP WHERE target_id=? AND source_id=?`, targetID, assetID)
			if err != nil {
				return err
			}
		}
	}
	fingerprint := scopeEventFingerprint(eventType, identifier, oldJSON, newJSON)
	// One decision per fingerprint. Upserting also lets an operator approve a
	// scope change they dismissed earlier: the approve path below still runs,
	// and the stored decision flips so the event cannot come back again.
	_, err = tx.ExecContext(ctx, `INSERT INTO bounty_scope_decisions
		(id,target_id,program_id,program_asset_id,event_type,identifier,fingerprint,decision,resolved_event_id)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id,program_id,program_asset_id,event_type,fingerprint)
		DO UPDATE SET decision=excluded.decision,resolved_event_id=excluded.resolved_event_id,decided_at=CURRENT_TIMESTAMP`,
		uuid.New().String(), targetID, programID, assetID, eventType, identifier, fingerprint, decision, eventID)
	if err != nil {
		return err
	}
	resolved := "rejected"
	if decision == "approve" {
		resolved = "approved"
	}
	_, err = tx.ExecContext(ctx, `UPDATE bounty_scope_events SET status=?,resolved_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`, resolved, eventID, targetID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
