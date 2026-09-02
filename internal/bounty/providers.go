package bounty

import (
	"context"
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const hackerOneCatalogQuery = `query ReconnerDirectory($first:Int!,$after:String){
  teams(first:$first,after:$after){
    pageInfo{hasNextPage endCursor}
    edges{node{
      id handle name state type offers_bounties launched_at last_updated_at currency allows_bounty_splitting
      declarative_policy{id protected_by_gold_standard_safe_harbor}
    }}
  }
}`

const hackerOneScopeQuery = `query ReconnerProgramScope($handle:String!,$first:Int!,$after:String){
  team(handle:$handle){
    structured_scopes(first:$first,after:$after,archived:false){
      pageInfo{hasNextPage endCursor}
      nodes{id asset_identifier asset_type eligible_for_submission eligible_for_bounty max_severity instruction created_at updated_at}
    }
  }
}`

type h1Scope struct {
	ID                 string `json:"id"`
	Identifier         string `json:"asset_identifier"`
	Type               string `json:"asset_type"`
	EligibleSubmission bool   `json:"eligible_for_submission"`
	EligibleBounty     bool   `json:"eligible_for_bounty"`
	MaxSeverity        string `json:"max_severity"`
	Instruction        string `json:"instruction"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type h1Connection struct {
	PageInfo struct {
		HasNext   bool   `json:"hasNextPage"`
		EndCursor string `json:"endCursor"`
	} `json:"pageInfo"`
	Nodes []h1Scope `json:"nodes"`
}

type h1ProgramNode struct {
	ID                string `json:"id"`
	Handle            string `json:"handle"`
	Name              string `json:"name"`
	State             string `json:"state"`
	Type              string `json:"type"`
	OffersBounties    bool   `json:"offers_bounties"`
	LaunchedAt        string `json:"launched_at"`
	UpdatedAt         string `json:"last_updated_at"`
	Currency          string `json:"currency"`
	AllowsSplitting   bool   `json:"allows_bounty_splitting"`
	DeclarativePolicy *struct {
		SafeHarbor bool `json:"protected_by_gold_standard_safe_harbor"`
	} `json:"declarative_policy"`
}

type graphQLError struct {
	Message string `json:"message"`
}

func (s *Service) syncHackerOne(ctx context.Context) error {
	after := ""
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		var response struct {
			Data struct {
				Teams struct {
					PageInfo struct {
						HasNext   bool   `json:"hasNextPage"`
						EndCursor string `json:"endCursor"`
					} `json:"pageInfo"`
					Edges []struct {
						Node h1ProgramNode `json:"node"`
					} `json:"edges"`
				} `json:"teams"`
			} `json:"data"`
			Errors []graphQLError `json:"errors"`
		}
		vars := map[string]any{"first": 50, "after": nil}
		if after != "" {
			vars["after"] = after
		}
		if err := s.doJSON(ctx, http.MethodPost, hackerOneGraphQLURL, map[string]any{"query": hackerOneCatalogQuery, "variables": vars}, &response); err != nil {
			return err
		}
		if len(response.Errors) > 0 {
			return fmt.Errorf("HackerOne GraphQL: %s", response.Errors[0].Message)
		}
		for _, edge := range response.Data.Teams.Edges {
			n := edge.Node
			if n.Handle == "" || n.State != "public_mode" || (!strings.Contains(n.Type, "BugBountyProgram") && !strings.Contains(n.Type, "VulnerabilityDisclosureProgram")) {
				continue
			}
			p := Program{Provider: "hackerone", ExternalID: n.ID, Handle: n.Handle, Name: n.Name,
				URL: "https://hackerone.com/" + url.PathEscape(n.Handle), Status: "live", OffersBounties: n.OffersBounties,
				ProgramType: "vdp", Currency: strings.ToUpper(n.Currency), SafeHarbor: "none",
				StartedAt: parseTime(n.LaunchedAt), ProviderUpdatedAt: parseTime(n.UpdatedAt)}
			if n.OffersBounties {
				p.ProgramType = "bug_bounty"
			}
			if n.DeclarativePolicy != nil && n.DeclarativePolicy.SafeHarbor {
				p.SafeHarbor = "full"
			}
			p.ID = stableProgramID(p.Provider, p.ExternalID)
			if err := s.upsertProgram(ctx, &p, n); err != nil {
				return err
			}
			seen[p.ID] = true
		}
		if !response.Data.Teams.PageInfo.HasNext {
			break
		}
		after = response.Data.Teams.PageInfo.EndCursor
	}
	// A program disappearing from the public catalog is not deleted. It is
	// marked unavailable, its cached assets become inactive, and linked projects
	// suspend those assets while preserving their history.
	return s.markMissingPrograms(ctx, "hackerone", seen)
}

func (s *Service) enrichHackerOneProgram(ctx context.Context, p *Program) error {
	scopes, err := s.fetchHackerOneScopes(ctx, p.Handle, "")
	if err != nil {
		return fmt.Errorf("HackerOne %s scope: %w", p.Handle, err)
	}
	p.Assets = nil
	for _, sc := range scopes {
		p.Assets = append(p.Assets, Asset{ExternalID: sc.ID, Identifier: sc.Identifier, AssetType: sc.Type,
			InScope: sc.EligibleSubmission, EligibleSubmission: sc.EligibleSubmission, EligibleBounty: sc.EligibleBounty,
			MaxSeverity: sc.MaxSeverity, Instruction: sc.Instruction, Active: true,
			ProviderCreatedAt: parseTime(sc.CreatedAt), ProviderUpdatedAt: parseTime(sc.UpdatedAt)})
	}
	finalizeProgramAssets(p)
	if err := s.upsertProgram(ctx, p, scopes); err != nil {
		return err
	}
	return s.replaceAssets(ctx, p)
}

func (s *Service) fetchHackerOneScopes(ctx context.Context, handle, after string) ([]h1Scope, error) {
	out := []h1Scope{}
	for page := 0; page < 100; page++ {
		var response struct {
			Data struct {
				Team struct {
					Scopes h1Connection `json:"structured_scopes"`
				} `json:"team"`
			} `json:"data"`
			Errors []graphQLError `json:"errors"`
		}
		vars := map[string]any{"handle": handle, "first": 100, "after": after}
		if after == "" {
			vars["after"] = nil
		}
		if err := s.doJSON(ctx, http.MethodPost, hackerOneGraphQLURL, map[string]any{"query": hackerOneScopeQuery, "variables": vars}, &response); err != nil {
			return nil, err
		}
		if len(response.Errors) > 0 {
			return nil, fmt.Errorf("GraphQL: %s", response.Errors[0].Message)
		}
		out = append(out, response.Data.Team.Scopes.Nodes...)
		if !response.Data.Team.Scopes.PageInfo.HasNext {
			break
		}
		after = response.Data.Team.Scopes.PageInfo.EndCursor
	}
	return out, nil
}

type bcListing struct {
	Name         string `json:"name"`
	Tagline      string `json:"tagline"`
	BriefURL     string `json:"briefUrl"`
	LogoURL      string `json:"logoUrl"`
	ScopeRank    int    `json:"scopeRank"`
	AccessStatus string `json:"accessStatus"`
	EndsAt       string `json:"endsAt"`
	Industry     string `json:"industryName"`
	Reward       *struct {
		Min string `json:"minReward"`
		Max string `json:"maxReward"`
	} `json:"rewardSummary"`
	EngagementType struct {
		Label string `json:"label"`
	} `json:"productEngagementType"`
	Private  bool `json:"isPrivate"`
	Demo     bool `json:"isDemo"`
	External bool `json:"isExternalListing"`
}

var bcBriefPathRE = regexp.MustCompile(`"getBriefVersionDocument"\s*:\s*"([^"]+)"`)

func stableProgramID(provider, external string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(provider+":"+external)).String()
}

func moneyCents(v string) int {
	clean := strings.NewReplacer("$", "", ",", "", "€", "", "£", "", " ", "").Replace(v)
	if clean == "" || strings.EqualFold(clean, "points") {
		return 0
	}
	n, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		return 0
	}
	return int(n * 100)
}

func normalizeBugcrowdStatus(label, fallback string) string {
	status := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(label), " ", "_"))
	switch status {
	case "", "unknown":
		return fallback
	case "in_progress", "live", "open", "accepting_submissions":
		return "live"
	case "ended", "closed", "archived":
		return "closed"
	default:
		return status
	}
}

func (s *Service) syncBugcrowd(ctx context.Context) error {
	all := []bcListing{}
	for page := 1; page <= 100; page++ {
		endpoint := fmt.Sprintf("%s/engagement_listings?category=bug_bounty&page=%d&sort_by=starts&sort_direction=desc", bugcrowdBaseURL, page)
		var response struct {
			Engagements []bcListing `json:"engagements"`
			Pagination  struct {
				Total int `json:"totalCount"`
				Limit int `json:"limit"`
			} `json:"paginationMeta"`
		}
		if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &response); err != nil {
			return err
		}
		all = append(all, response.Engagements...)
		if len(all) >= response.Pagination.Total || len(response.Engagements) == 0 {
			break
		}
	}

	safeHarbor, safeHarborErr := s.fetchBugcrowdSafeHarborIndex(ctx)
	if safeHarborErr != nil && s.log != nil {
		s.log.Warn("Bugcrowd safe-harbor facets unavailable; keeping cached values", "error", safeHarborErr)
	}
	seen := make(map[string]bool, len(all))
	for _, item := range all {
		if item.Private || item.Demo || item.External || item.BriefURL == "" {
			continue
		}
		handle := bugcrowdHandle(item.BriefURL)
		p := Program{Provider: "bugcrowd", ExternalID: handle, Handle: handle, Name: item.Name, URL: item.BriefURL, LogoURL: item.LogoURL,
			Description: item.Tagline, Status: "live", ProgramType: "bug_bounty", Industry: item.Industry, OffersBounties: item.Reward != nil,
			ScopeRank: item.ScopeRank, Currency: "USD"}
		if item.AccessStatus != "open" {
			p.Status = normalizeBugcrowdStatus(item.AccessStatus, p.Status)
		}
		if item.Reward != nil {
			p.MinRewardCents = moneyCents(item.Reward.Min)
			p.MaxRewardCents = moneyCents(item.Reward.Max)
		}
		p.SafeHarbor = safeHarbor[handle]
		if p.SafeHarbor == "" && safeHarborErr == nil {
			p.SafeHarbor = "none"
		}
		p.ID = stableProgramID(p.Provider, p.ExternalID)
		if err := s.upsertProgram(ctx, &p, item); err != nil {
			return err
		}
		seen[p.ID] = true
	}
	return s.markMissingPrograms(ctx, "bugcrowd", seen)
}

func bugcrowdHandle(briefURL string) string {
	if u, err := url.Parse(briefURL); err == nil {
		return strings.Trim(strings.TrimPrefix(u.Path, "/engagements/"), "/")
	}
	return strings.Trim(strings.TrimPrefix(briefURL, bugcrowdBaseURL+"/engagements/"), "/")
}

// Bugcrowd exposes its public safe-harbor filter as a catalog facet rather than
// an engagement field. Build a handle index from that official facet so the
// normalized catalog can offer the same full/partial filter locally.
func (s *Service) fetchBugcrowdSafeHarborIndex(ctx context.Context) (map[string]string, error) {
	index := map[string]string{}
	type result struct {
		level   string
		handles []string
		err     error
	}
	results := make(chan result, 3)
	for _, level := range []string{"full", "partial", "declined"} {
		level := level
		go func() {
			var handles []string
			collected := 0
			for page := 1; page <= 100; page++ {
				endpoint := fmt.Sprintf("%s/engagement_listings?category=bug_bounty&page=%d&safe_harbor_status=%s", bugcrowdBaseURL, page, level)
				var response struct {
					Engagements []bcListing `json:"engagements"`
					Pagination  struct {
						Total int `json:"totalCount"`
					} `json:"paginationMeta"`
				}
				if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &response); err != nil {
					results <- result{level: level, err: err}
					return
				}
				for _, item := range response.Engagements {
					if handle := bugcrowdHandle(item.BriefURL); handle != "" {
						handles = append(handles, handle)
					}
				}
				collected += len(response.Engagements)
				if collected >= response.Pagination.Total || len(response.Engagements) == 0 {
					break
				}
			}
			results <- result{level: level, handles: handles}
		}()
	}
	var failures []string
	for range 3 {
		res := <-results
		if res.err != nil {
			failures = append(failures, res.level+": "+res.err.Error())
			continue
		}
		for _, handle := range res.handles {
			index[handle] = res.level
		}
	}
	if len(failures) > 0 {
		return index, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return index, nil
}

func (s *Service) enrichBugcrowdProgram(ctx context.Context, p *Program) error {
	page, err := s.getText(ctx, p.URL)
	if err != nil {
		return err
	}
	decoded := html.UnescapeString(page)
	m := bcBriefPathRE.FindStringSubmatch(decoded)
	if len(m) < 2 {
		return fmt.Errorf("brief document endpoint not found")
	}
	path := strings.ReplaceAll(m[1], `\/`, `/`)
	endpoint := path
	base, baseErr := url.Parse(p.URL)
	ref, refErr := url.Parse(path)
	if baseErr == nil && refErr == nil {
		endpoint = base.ResolveReference(ref).String()
	} else if strings.HasPrefix(path, "/") {
		endpoint = bugcrowdBaseURL + path
	}
	if !strings.HasSuffix(endpoint, ".json") {
		endpoint += ".json"
	}
	var doc struct {
		ID               string `json:"engagementId"`
		PublishedAt      string `json:"publishedAt"`
		LastTransitionAt string `json:"lastTransitionAt"`
		Status           string `json:"statusLabel"`
		Data             struct {
			Brief struct {
				Name    string `json:"name"`
				Details string `json:"details"`
			} `json:"brief"`
			Engagement struct {
				StartsAt string `json:"startsAt"`
				EndsAt   string `json:"endsAt"`
			} `json:"engagement"`
			Scope []struct {
				ID          string         `json:"id"`
				Name        string         `json:"name"`
				InScope     bool           `json:"inScope"`
				Description string         `json:"descriptionHtml"`
				Reward      map[string]any `json:"rewardRangeData"`
				Targets     []struct {
					ID          string `json:"id"`
					URI         string `json:"uri"`
					Name        string `json:"name"`
					Category    string `json:"category"`
					IP          string `json:"ipAddress"`
					Description string `json:"description"`
					Tags        []struct {
						Name string `json:"name"`
					} `json:"tags"`
				} `json:"targets"`
			} `json:"scope"`
		} `json:"data"`
	}
	if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &doc); err != nil {
		return err
	}
	p.PublishedAt = parseTime(doc.PublishedAt)
	p.ProviderUpdatedAt = parseTime(doc.LastTransitionAt)
	p.StartedAt = parseTime(doc.Data.Engagement.StartsAt)
	if doc.Status != "" {
		p.Status = normalizeBugcrowdStatus(doc.Status, p.Status)
	}
	for _, group := range doc.Data.Scope {
		for _, t := range group.Targets {
			identifier := strings.TrimSpace(t.URI)
			if identifier == "" {
				identifier = strings.TrimSpace(t.Name)
			}
			if identifier == "" {
				identifier = strings.TrimSpace(t.IP)
			}
			meta := map[string]any{"group_id": group.ID, "group": group.Name}
			if len(t.Tags) > 0 {
				tags := make([]string, 0, len(t.Tags))
				for _, tag := range t.Tags {
					tags = append(tags, tag.Name)
				}
				meta["tags"] = tags
			}
			p.Assets = append(p.Assets, Asset{ExternalID: t.ID, Identifier: identifier, AssetType: t.Category, Category: t.Category, InScope: group.InScope,
				EligibleSubmission: group.InScope, EligibleBounty: group.InScope && p.OffersBounties, Instruction: strings.TrimSpace(t.Description + "\n" + group.Description),
				Reward: group.Reward, Metadata: meta, Active: true})
		}
	}
	finalizeProgramAssets(p)
	if err := s.upsertProgram(ctx, p, doc); err != nil {
		return err
	}
	return s.replaceAssets(ctx, p)
}

// EnsureDetails lazily fetches structured scope only when a user opens/imports a
// program. Catalog sync remains list-only, except for programs already linked to
// monitored projects, which are refreshed every six hours for scope changes.
func (s *Service) EnsureDetails(ctx context.Context, programID string) error {
	return s.ensureDetails(ctx, programID, detailRefreshAge)
}

func (s *Service) detailLock(programID string) *sync.Mutex {
	s.detailMu.Lock()
	defer s.detailMu.Unlock()
	lock := s.detailLocks[programID]
	if lock == nil {
		lock = &sync.Mutex{}
		s.detailLocks[programID] = lock
	}
	return lock
}

func (s *Service) ensureDetails(ctx context.Context, programID string, maxAge time.Duration) error {
	p, err := scanProgram(s.db.QueryRowContext(ctx, "SELECT "+programColumns+" FROM bounty_programs p WHERE p.id=?", programID))
	if err != nil {
		return err
	}
	detailFresh := p.DetailSyncedAt != nil && time.Since(*p.DetailSyncedAt) < maxAge &&
		(p.ProviderUpdatedAt == nil || !p.ProviderUpdatedAt.After(*p.DetailSyncedAt))
	if detailFresh {
		return nil
	}
	lock := s.detailLock(programID)
	lock.Lock()
	defer lock.Unlock()
	// Another request may have completed while this one waited.
	var detail, providerUpdated sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT detail_synced_at,provider_updated_at FROM bounty_programs WHERE id=?`, programID).Scan(&detail, &providerUpdated); err == nil &&
		detail.Valid && time.Since(detail.Time) < maxAge && (!providerUpdated.Valid || !providerUpdated.Time.After(detail.Time)) {
		return nil
	}
	switch p.Provider {
	case "hackerone":
		return s.enrichHackerOneProgram(ctx, &p)
	case "bugcrowd":
		return s.enrichBugcrowdProgram(ctx, &p)
	case "intigriti":
		return s.enrichIntigritiProgram(ctx, &p)
	case "yeswehack":
		return s.enrichYesWeHackProgram(ctx, &p)
	default:
		return fmt.Errorf("unsupported bounty provider %q", p.Provider)
	}
}

func (s *Service) refreshLinkedProviderDetails(ctx context.Context, provider string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT p.id FROM bounty_programs p
		JOIN project_programs pp ON pp.program_id=p.id WHERE p.provider=? AND pp.auto_sync=1`, provider)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	var failures []string
	for _, id := range ids {
		if err := s.ensureDetails(ctx, id, linkedRefreshAge); err != nil {
			failures = append(failures, err.Error())
			if len(failures) >= 3 {
				break
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("linked scope refresh: %s", strings.Join(failures, "; "))
	}
	return nil
}
