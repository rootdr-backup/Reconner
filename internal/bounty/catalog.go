package bounty

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
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
	Programs []Program `json:"programs"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	Limit    int       `json:"limit"`
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
			where = append(where, "p.wildcard_count=0")
		}
	}
	if o.MinAssets > 0 {
		add("p.in_scope_count>=?", o.MinAssets)
	}
	if o.MaxAssets > 0 {
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
	return ListResult{Programs: items, Total: total, Page: o.Page, Limit: o.Limit}, rows.Err()
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
}

func projectAssetKind(t string) string {
	switch t {
	case "cidr", "ip":
		return "network"
	case "domain", "wildcard", "url", "page", "js", "api":
		return "web"
	default:
		return "reference"
	}
}

func (s *Service) CreateProject(ctx context.Context, ownerID int64, programID string, req CreateProjectRequest) (string, error) {
	p, err := s.GetProgram(ctx, programID)
	if err != nil {
		return "", err
	}
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
	for _, a := range assets {
		if a.AssetType == "other" || a.AssetType == "android" || a.AssetType == "ios" || a.AssetType == "hardware" || a.AssetType == "source_code" {
			continue
		}
		values = append(values, a.Identifier)
		if projectAssetKind(a.AssetType) == "network" {
			hasNet = true
		} else {
			hasWeb = true
		}
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
	_, err = tx.ExecContext(ctx, `INSERT INTO targets(id,domain,name,description,priority,notes,kind,exclude_scope,owner_id,monitor_enabled,monitor_interval_hours)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, targetID, scope, name, req.Description, priority, req.Notes, kind, strings.Join(outScope, "\n"), ownerID, boolInt(req.MonitorEnabled), hours)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO project_programs(target_id,program_id,auto_sync,last_scope_hash,last_checked_at) VALUES(?,?,1,?,CURRENT_TIMESTAMP)`, targetID, p.ID, p.ScopeHash)
	if err != nil {
		return "", err
	}
	for _, a := range assets {
		meta, _ := json.Marshal(map[string]any{"provider": p.Provider, "program": p.Handle, "raw_hash": a.RawHash, "eligible_bounty": a.EligibleBounty, "max_severity": a.MaxSeverity, "instruction": a.Instruction})
		_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at)
		VALUES(?,?,?,?,?,?,?,?, 'approved',1,?,CURRENT_TIMESTAMP)`, uuid.New().String(), targetID, a.Identifier, a.Identifier, projectAssetKind(a.AssetType), a.AssetType, "bounty:"+p.Provider, a.ID, string(meta))
		if err != nil {
			return "", err
		}
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return targetID, nil
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
func (s *Service) createScopeEvent(ctx context.Context, targetID, programID, assetID, eventType, identifier, oldJSON, newJSON string) {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bounty_scope_events WHERE target_id=? AND program_asset_id=? AND event_type=? AND status='pending'`, targetID, assetID, eventType).Scan(&n)
	if n > 0 {
		return
	}
	_, _ = s.db.ExecContext(ctx, `INSERT INTO bounty_scope_events(id,target_id,program_id,program_asset_id,event_type,identifier,old_json,new_json,status) VALUES(?,?,?,?,?,?,?,?, 'pending')`, uuid.New().String(), targetID, programID, assetID, eventType, identifier, oldJSON, newJSON)
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
	var eventType, assetID, status string
	err = tx.QueryRowContext(ctx, `SELECT event_type,COALESCE(program_asset_id,''),status FROM bounty_scope_events WHERE id=? AND target_id=?`, eventID, targetID).Scan(&eventType, &assetID, &status)
	if err != nil {
		return err
	}
	if status != "pending" {
		return fmt.Errorf("scope event already resolved")
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
			_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at) VALUES(?,?,?,?,?,?, 'bounty:catalog',?,'approved',1,?,CURRENT_TIMESTAMP) ON CONFLICT(target_id,value) DO UPDATE SET value=excluded.value,kind=excluded.kind,asset_type=excluded.asset_type,source='bounty:catalog',source_id=excluded.source_id,approval_status='approved',monitor_enabled=1,metadata=excluded.metadata,updated_at=CURRENT_TIMESTAMP`, uuid.New().String(), targetID, a.Identifier, a.Identifier, projectAssetKind(a.AssetType), a.AssetType, a.ID, string(metaJSON))
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
