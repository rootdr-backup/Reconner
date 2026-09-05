package bounty

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

const (
	defaultSyncInterval = 6 * time.Hour
	detailRefreshAge    = 24 * time.Hour
	linkedRefreshAge    = 6 * time.Hour
	userAgent           = "Reconner/1.3 (+https://github.com/rootdr-backup/Reconner)"
)

// Endpoints are variables so provider contract tests can use httptest without
// touching the public services.
var (
	hackerOneGraphQLURL = "https://hackerone.com/graphql"
	bugcrowdBaseURL     = "https://bugcrowd.com"
	intigritiCoreURL    = "https://app.intigriti.com/api/core"
	yesWeHackAPIURL     = "https://api.yeswehack.com"
)

type Program struct {
	ID                string     `json:"id"`
	Provider          string     `json:"provider"`
	ExternalID        string     `json:"external_id"`
	Handle            string     `json:"handle"`
	Name              string     `json:"name"`
	URL               string     `json:"url"`
	LogoURL           string     `json:"logo_url"`
	Description       string     `json:"description"`
	Status            string     `json:"status"`
	ProgramType       string     `json:"program_type"`
	Industry          string     `json:"industry"`
	OffersBounties    bool       `json:"offers_bounties"`
	OpenScope         bool       `json:"open_scope"`
	SafeHarbor        string     `json:"safe_harbor"`
	AssetCount        int        `json:"asset_count"`
	InScopeCount      int        `json:"in_scope_count"`
	WildcardCount     int        `json:"wildcard_count"`
	ScopeRank         int        `json:"scope_rank"`
	MinRewardCents    int        `json:"min_reward_cents"`
	MaxRewardCents    int        `json:"max_reward_cents"`
	Currency          string     `json:"currency"`
	StartedAt         *time.Time `json:"started_at"`
	PublishedAt       *time.Time `json:"published_at"`
	ProviderUpdatedAt *time.Time `json:"provider_updated_at"`
	LastSyncedAt      *time.Time `json:"last_synced_at"`
	DetailSyncedAt    *time.Time `json:"detail_synced_at"`
	ScopeHash         string     `json:"scope_hash"`
	DetailsLoaded     bool       `json:"details_loaded"`
	Assets            []Asset    `json:"assets,omitempty"`
}

type Asset struct {
	ID                 string         `json:"id"`
	ProgramID          string         `json:"program_id"`
	ExternalID         string         `json:"external_id"`
	Identifier         string         `json:"identifier"`
	AssetType          string         `json:"asset_type"`
	Category           string         `json:"category"`
	IsWildcard         bool           `json:"is_wildcard"`
	InScope            bool           `json:"in_scope"`
	EligibleSubmission bool           `json:"eligible_submission"`
	EligibleBounty     bool           `json:"eligible_bounty"`
	MaxSeverity        string         `json:"max_severity"`
	Instruction        string         `json:"instruction"`
	Reward             map[string]any `json:"reward,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	Active             bool           `json:"active"`
	ProviderCreatedAt  *time.Time     `json:"provider_created_at"`
	ProviderUpdatedAt  *time.Time     `json:"provider_updated_at"`
	RawHash            string         `json:"-"`
}

type SyncState struct {
	Provider        string     `json:"provider"`
	Status          string     `json:"status"`
	LastStartedAt   *time.Time `json:"last_started_at"`
	LastCompletedAt *time.Time `json:"last_completed_at"`
	NextSyncAt      *time.Time `json:"next_sync_at"`
	ProgramCount    int        `json:"program_count"`
	AssetCount      int        `json:"asset_count"`
	LastError       string     `json:"last_error"`
	FailureCount    int        `json:"failure_count"`
}

type Service struct {
	db          *database.DB
	client      *http.Client
	log         *logger.Logger
	mu          sync.Mutex
	detailMu    sync.Mutex
	detailLocks map[string]*sync.Mutex
	indexMu     sync.Mutex
	indexState  DetailIndexStatus
	indexRetry  map[string]time.Time
}

func NewService(db *database.DB, log *logger.Logger) *Service {
	return &Service{
		db: db,
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			MaxIdleConns: 20, MaxIdleConnsPerHost: 6, IdleConnTimeout: 60 * time.Second,
		}},
		log: log, detailLocks: map[string]*sync.Mutex{}, indexRetry: map[string]time.Time{},
	}
}

func (s *Service) SetHTTPClient(client *http.Client) {
	if client != nil {
		s.client = client
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func parseTime(v string) *time.Time {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil
	}
	return &t
}

func hashJSON(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeAssetType(provider, typ, identifier string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	id := strings.ToLower(strings.TrimSpace(identifier))
	plainID := strings.TrimSpace(strings.TrimPrefix(id, "*."))
	if provider == "intigriti" && strings.HasPrefix(t, "intigriti:") {
		switch strings.TrimPrefix(t, "intigriti:") {
		case "1": // URL / domain
			if strings.HasPrefix(id, "http://") || strings.HasPrefix(id, "https://") {
				if strings.HasSuffix(strings.Split(id, "?")[0], ".js") {
					return "js"
				}
				return "url"
			}
			return "domain"
		case "2":
			return "android"
		case "3":
			return "ios"
		case "4":
			if net.ParseIP(plainID) != nil {
				return "ip"
			}
			return "cidr"
		case "5":
			return "hardware"
		case "7":
			return "wildcard"
		case "8":
			return "source_code"
		case "9":
			return "ai_model"
		}
	}
	switch {
	case strings.Contains(t, "wildcard") || strings.HasPrefix(id, "*.") || strings.Contains(id, "/*"):
		return "wildcard"
	case strings.Contains(t, "url"):
		if strings.HasSuffix(strings.Split(id, "?")[0], ".js") {
			return "js"
		}
		return "url"
	case strings.Contains(t, "domain") || t == "website" || t == "web_app":
		if strings.HasPrefix(id, "http://") || strings.HasPrefix(id, "https://") {
			if strings.HasSuffix(strings.Split(id, "?")[0], ".js") {
				return "js"
			}
			return "url"
		}
		return "domain"
	case strings.Contains(t, "api"):
		return "api"
	case strings.Contains(t, "cidr"):
		return "cidr"
	case strings.Contains(t, "ip") || t == "network":
		return "ip"
	case strings.Contains(t, "android"):
		return "android"
	case strings.Contains(t, "ios"):
		return "ios"
	case strings.Contains(t, "source") || strings.Contains(t, "code"):
		return "source_code"
	case strings.Contains(t, "hardware") || strings.Contains(t, "iot"):
		return "hardware"
	case strings.Contains(t, "firmware"):
		return "hardware"
	default:
		// Providers do not share one asset taxonomy (and Intigriti exposes
		// numeric type IDs). Infer obvious web/network shapes from the identifier
		// so useful scopes are not demoted to opaque references.
		if _, _, err := net.ParseCIDR(plainID); err == nil {
			return "cidr"
		}
		if net.ParseIP(plainID) != nil {
			return "ip"
		}
		if u, err := url.Parse(id); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			if strings.HasSuffix(strings.ToLower(u.Path), ".js") {
				return "js"
			}
			return "url"
		}
		if !strings.ContainsAny(plainID, " /@") && strings.Contains(plainID, ".") {
			return "domain"
		}
		_ = provider
		return "other"
	}
}

func (s *Service) doJSON(ctx context.Context, method, endpoint string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

func (s *Service) getText(ctx context.Context, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s returned %d", endpoint, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return string(b), err
}

// SyncAll refreshes due providers. It is safe for the scheduler and manual API
// endpoint to race: only one pass can run in a process at a time.
func (s *Service) SyncAll(ctx context.Context, force bool) error {
	if !s.mu.TryLock() {
		return errors.New("catalog sync already running")
	}
	defer s.mu.Unlock()

	var errs []string
	for _, provider := range []string{"hackerone", "bugcrowd", "intigriti", "yeswehack"} {
		if !force && !s.providerDue(provider) {
			continue
		}
		s.markSyncStarted(provider)
		var err error
		switch provider {
		case "hackerone":
			err = s.syncHackerOne(ctx)
		case "bugcrowd":
			err = s.syncBugcrowd(ctx)
		case "intigriti":
			err = s.syncIntigriti(ctx)
		case "yeswehack":
			err = s.syncYesWeHack(ctx)
		}
		if err == nil {
			err = s.refreshLinkedProviderDetails(ctx, provider)
		}
		if err != nil {
			s.markSyncFailed(provider, err)
			errs = append(errs, provider+": "+err.Error())
			if s.log != nil {
				s.log.Warn("Bounty catalog sync failed", "provider", provider, "error", err)
			}
			continue
		}
		s.markSyncCompleted(provider)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Service) providerDue(provider string) bool {
	var next sql.NullTime
	err := s.db.QueryRow(`SELECT next_sync_at FROM bounty_sync_state WHERE provider=?`, provider).Scan(&next)
	return err != nil || !next.Valid || !next.Time.After(time.Now())
}

func (s *Service) markSyncStarted(provider string) {
	_, _ = s.db.Exec(`INSERT INTO bounty_sync_state(provider,status,last_started_at,last_error)
		VALUES(?,'running',CURRENT_TIMESTAMP,'')
		ON CONFLICT(provider) DO UPDATE SET status='running',last_started_at=CURRENT_TIMESTAMP,last_error=''`, provider)
}

func (s *Service) markSyncCompleted(provider string) {
	_, _ = s.db.Exec(`INSERT INTO bounty_sync_state(provider,status,last_completed_at,next_sync_at,program_count,asset_count,last_error,failure_count)
		VALUES(?,'ok',CURRENT_TIMESTAMP,datetime('now','+6 hours'),
		 (SELECT COUNT(*) FROM bounty_programs WHERE provider=?),
		 (SELECT COUNT(*) FROM bounty_program_assets a JOIN bounty_programs p ON p.id=a.program_id WHERE p.provider=? AND a.active=1),'',0)
		ON CONFLICT(provider) DO UPDATE SET status='ok',last_completed_at=CURRENT_TIMESTAMP,
		 next_sync_at=datetime('now','+6 hours'),program_count=excluded.program_count,asset_count=excluded.asset_count,last_error='',failure_count=0`, provider, provider, provider)
}

func (s *Service) markSyncFailed(provider string, syncErr error) {
	msg := syncErr.Error()
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	_, _ = s.db.Exec(`INSERT INTO bounty_sync_state(provider,status,last_error,failure_count,next_sync_at)
		VALUES(?,'error',?,1,datetime('now','+30 minutes'))
		ON CONFLICT(provider) DO UPDATE SET status='error',last_error=excluded.last_error,
		 failure_count=failure_count+1,
		 next_sync_at=datetime('now','+' || MIN(360, 15 * (1 << MIN(failure_count,4))) || ' minutes')`, provider, msg)
}

func (s *Service) Status(ctx context.Context) ([]SyncState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider,status,last_started_at,last_completed_at,next_sync_at,
		program_count,asset_count,last_error,failure_count FROM bounty_sync_state ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SyncState, 0, 4)
	for rows.Next() {
		var st SyncState
		var started, completed, next sql.NullTime
		if err := rows.Scan(&st.Provider, &st.Status, &started, &completed, &next, &st.ProgramCount, &st.AssetCount, &st.LastError, &st.FailureCount); err != nil {
			return nil, err
		}
		if started.Valid {
			st.LastStartedAt = &started.Time
		}
		if completed.Valid {
			st.LastCompletedAt = &completed.Time
		}
		if next.Valid {
			st.NextSyncAt = &next.Time
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Service) upsertProgram(ctx context.Context, p *Program, raw any) error {
	if p.ID == "" {
		p.ID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.Provider+":"+p.ExternalID)).String()
	}
	rawJSON, _ := json.Marshal(raw)
	_, err := s.db.ExecContext(ctx, `INSERT INTO bounty_programs(
		id,provider,external_id,handle,name,url,logo_url,description,status,program_type,industry,
		offers_bounties,open_scope,safe_harbor,asset_count,in_scope_count,wildcard_count,scope_rank,
		min_reward_cents,max_reward_cents,currency,started_at,published_at,provider_updated_at,last_synced_at,
		detail_synced_at,scope_hash,raw_json)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,?,?)
		ON CONFLICT(provider,external_id) DO UPDATE SET handle=excluded.handle,name=excluded.name,url=excluded.url,
		logo_url=CASE WHEN excluded.logo_url<>'' THEN excluded.logo_url ELSE bounty_programs.logo_url END,
		description=CASE WHEN excluded.description<>'' THEN excluded.description ELSE bounty_programs.description END,
		status=excluded.status,program_type=excluded.program_type,
		industry=CASE WHEN excluded.industry<>'' THEN excluded.industry ELSE bounty_programs.industry END,
		offers_bounties=excluded.offers_bounties,open_scope=excluded.open_scope,
		safe_harbor=CASE WHEN excluded.safe_harbor<>'' THEN excluded.safe_harbor ELSE bounty_programs.safe_harbor END,
		asset_count=CASE WHEN excluded.detail_synced_at IS NOT NULL OR excluded.asset_count>0 THEN excluded.asset_count ELSE bounty_programs.asset_count END,
		in_scope_count=CASE WHEN excluded.detail_synced_at IS NOT NULL OR excluded.in_scope_count>0 THEN excluded.in_scope_count ELSE bounty_programs.in_scope_count END,
		wildcard_count=CASE WHEN excluded.detail_synced_at IS NOT NULL OR excluded.wildcard_count>0 THEN excluded.wildcard_count ELSE bounty_programs.wildcard_count END,
		scope_rank=excluded.scope_rank,min_reward_cents=excluded.min_reward_cents,max_reward_cents=excluded.max_reward_cents,
		currency=excluded.currency,started_at=COALESCE(excluded.started_at,bounty_programs.started_at),
		published_at=COALESCE(excluded.published_at,bounty_programs.published_at),
		provider_updated_at=COALESCE(excluded.provider_updated_at,bounty_programs.provider_updated_at),
		last_synced_at=CURRENT_TIMESTAMP,detail_synced_at=COALESCE(excluded.detail_synced_at,bounty_programs.detail_synced_at),
		scope_hash=CASE WHEN excluded.scope_hash<>'' THEN excluded.scope_hash ELSE bounty_programs.scope_hash END,
		raw_json=excluded.raw_json`,
		p.ID, p.Provider, p.ExternalID, p.Handle, p.Name, p.URL, p.LogoURL, p.Description, p.Status, p.ProgramType, p.Industry,
		boolInt(p.OffersBounties), boolInt(p.OpenScope), p.SafeHarbor, p.AssetCount, p.InScopeCount, p.WildcardCount, p.ScopeRank,
		p.MinRewardCents, p.MaxRewardCents, p.Currency, p.StartedAt, p.PublishedAt, p.ProviderUpdatedAt, p.DetailSyncedAt, p.ScopeHash, string(rawJSON))
	return err
}

func (s *Service) replaceAssets(ctx context.Context, p *Program) error {
	if p.ID == "" {
		return errors.New("missing program id")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE bounty_program_assets SET active=0 WHERE program_id=?`, p.ID); err != nil {
		return err
	}
	for i := range p.Assets {
		a := &p.Assets[i]
		a.ProgramID = p.ID
		if a.ExternalID == "" {
			a.ExternalID = hashJSON([]string{a.Identifier, a.AssetType, strconv.FormatBool(a.InScope)})
		}
		a.ID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.ID+":"+a.ExternalID)).String()
		if a.RawHash == "" {
			a.RawHash = hashJSON(a)
		}
		reward, _ := json.Marshal(a.Reward)
		metadata, _ := json.Marshal(a.Metadata)
		_, err = tx.ExecContext(ctx, `INSERT INTO bounty_program_assets(
			id,program_id,external_id,identifier,asset_type,category,is_wildcard,in_scope,eligible_submission,
			eligible_bounty,max_severity,instruction,reward_json,metadata,active,provider_created_at,
			provider_updated_at,first_seen_at,last_seen_at,raw_hash)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?)
			ON CONFLICT(program_id,external_id) DO UPDATE SET identifier=excluded.identifier,asset_type=excluded.asset_type,
			category=excluded.category,is_wildcard=excluded.is_wildcard,in_scope=excluded.in_scope,
			eligible_submission=excluded.eligible_submission,eligible_bounty=excluded.eligible_bounty,
			max_severity=excluded.max_severity,instruction=excluded.instruction,reward_json=excluded.reward_json,
			metadata=excluded.metadata,active=1,provider_updated_at=excluded.provider_updated_at,
			last_seen_at=CURRENT_TIMESTAMP,raw_hash=excluded.raw_hash`,
			a.ID, p.ID, a.ExternalID, a.Identifier, a.AssetType, a.Category, boolInt(a.IsWildcard), boolInt(a.InScope),
			boolInt(a.EligibleSubmission), boolInt(a.EligibleBounty), a.MaxSeverity, a.Instruction, string(reward), string(metadata),
			a.ProviderCreatedAt, a.ProviderUpdatedAt, a.RawHash)
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE bounty_programs SET asset_count=?,in_scope_count=?,wildcard_count=?,
		detail_synced_at=CURRENT_TIMESTAMP,scope_hash=? WHERE id=?`, p.AssetCount, p.InScopeCount, p.WildcardCount, p.ScopeHash, p.ID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return s.reconcileLinkedProjects(ctx, p.ID)
}

func (s *Service) markMissingPrograms(ctx context.Context, provider string, seen map[string]bool) error {
	// An empty result is much more likely to be a provider contract change than
	// every public program disappearing at once. Fail closed and keep the cache.
	if len(seen) == 0 {
		return fmt.Errorf("%s catalog returned no supported public programs", provider)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM bounty_programs WHERE provider=? AND status<>'unavailable'`, provider)
	if err != nil {
		return err
	}
	missing := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range missing {
		if _, err = tx.ExecContext(ctx, `UPDATE bounty_programs SET status='unavailable',last_synced_at=CURRENT_TIMESTAMP WHERE id=?`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE bounty_program_assets SET active=0 WHERE program_id=?`, id); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for _, id := range missing {
		if err := s.reconcileLinkedProjects(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func finalizeProgramAssets(p *Program) {
	sort.Slice(p.Assets, func(i, j int) bool { return p.Assets[i].ExternalID < p.Assets[j].ExternalID })
	p.AssetCount = len(p.Assets)
	p.InScopeCount = 0
	p.WildcardCount = 0
	for i := range p.Assets {
		a := &p.Assets[i]
		a.AssetType = normalizeAssetType(p.Provider, a.AssetType, a.Identifier)
		a.IsWildcard = a.AssetType == "wildcard" || strings.HasPrefix(strings.TrimSpace(a.Identifier), "*.")
		if a.InScope && a.EligibleSubmission {
			p.InScopeCount++
		}
		if a.InScope && a.IsWildcard {
			p.WildcardCount++
		}
	}
	p.ScopeHash = hashJSON(p.Assets)
	now := time.Now().UTC()
	p.DetailSyncedAt = &now
}
