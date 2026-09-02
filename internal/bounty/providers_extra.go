package bounty

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type intigritiMoney struct {
	Value    float64 `json:"value"`
	Currency string  `json:"currency"`
}

type intigritiListing struct {
	ProgramID       string         `json:"programId"`
	Status          int            `json:"status"`
	Confidentiality int            `json:"confidentialityLevel"`
	CompanyHandle   string         `json:"companyHandle"`
	CompanyName     string         `json:"companyName"`
	Handle          string         `json:"handle"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	Industry        string         `json:"industry"`
	MinBounty       intigritiMoney `json:"minBounty"`
	MaxBounty       intigritiMoney `json:"maxBounty"`
	LastUpdatedAt   int64          `json:"lastUpdatedAt"`
	CreatedAt       int64          `json:"createdAt"`
}

func unixTime(seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	t := time.Unix(seconds, 0).UTC()
	return &t
}

func intigritiStatus(status int) string {
	switch status {
	case 3:
		return "live"
	case 4:
		return "paused"
	default:
		return "unknown"
	}
}

func (s *Service) syncIntigriti(ctx context.Context) error {
	var listings []intigritiListing
	if err := s.doJSON(ctx, http.MethodGet, intigritiCoreURL+"/public/programs", nil, &listings); err != nil {
		return err
	}
	seen := make(map[string]bool, len(listings))
	for _, item := range listings {
		// confidentialityLevel 2 is an application program: it is advertised,
		// but its scope endpoint returns 403 until the hunter is accepted. Only
		// level 4 has public scope that Reconner can safely import.
		if item.ProgramID == "" || item.Handle == "" || item.CompanyHandle == "" || item.Confidentiality != 4 {
			continue
		}
		currency := strings.ToUpper(item.MaxBounty.Currency)
		if currency == "" {
			currency = strings.ToUpper(item.MinBounty.Currency)
		}
		p := Program{
			Provider: "intigriti", ExternalID: item.ProgramID,
			Handle: item.CompanyHandle + "/" + item.Handle,
			Name:   item.Name, Description: item.Description, Industry: item.Industry,
			URL:    "https://app.intigriti.com/programs/" + url.PathEscape(item.CompanyHandle) + "/" + url.PathEscape(item.Handle) + "/detail",
			Status: intigritiStatus(item.Status), ProgramType: "bug_bounty",
			OffersBounties: item.MaxBounty.Value > 0, SafeHarbor: "none",
			MinRewardCents: int(item.MinBounty.Value * 100), MaxRewardCents: int(item.MaxBounty.Value * 100), Currency: currency,
			StartedAt: unixTime(item.CreatedAt), ProviderUpdatedAt: unixTime(item.LastUpdatedAt),
		}
		if !p.OffersBounties {
			p.ProgramType = "vdp"
		}
		p.ID = stableProgramID(p.Provider, p.ExternalID)
		if err := s.upsertProgram(ctx, &p, item); err != nil {
			return err
		}
		seen[p.ID] = true
	}
	return s.markMissingPrograms(ctx, "intigriti", seen)
}

type intigritiAssetNode struct {
	Discriminator  int                  `json:"discriminator"`
	ID             string               `json:"id"`
	CompanyAssetID string               `json:"companyAssetId"`
	TypeID         int                  `json:"typeId"`
	Name           string               `json:"name"`
	BountyTierID   int                  `json:"bountyTierId"`
	Description    string               `json:"description"`
	Assets         []intigritiAssetNode `json:"assets"`
}

type intigritiAssetCollection struct {
	CreatedAt int64 `json:"createdAt"`
	Content   struct {
		Assets []intigritiAssetNode `json:"assetsAndGroups"`
	} `json:"content"`
}

type intigritiDetail struct {
	ProgramID       string                     `json:"programId"`
	Status          int                        `json:"status"`
	Confidentiality int                        `json:"confidentialityLevel"`
	Description     string                     `json:"description"`
	Collections     []intigritiAssetCollection `json:"assetsCollection"`
}

func intigritiGroupOutOfScope(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(name, "out of scope") || strings.Contains(name, "out-of-scope") ||
		strings.Contains(name, "excluded") || strings.Contains(name, "not in scope")
}

func appendIntigritiAssets(p *Program, nodes []intigritiAssetNode, inheritedScope bool, group string) {
	for _, node := range nodes {
		if node.Discriminator == 2 || len(node.Assets) > 0 {
			inScope := inheritedScope && !intigritiGroupOutOfScope(node.Name)
			appendIntigritiAssets(p, node.Assets, inScope, node.Name)
			continue
		}
		identifier := strings.TrimSpace(node.Name)
		if identifier == "" {
			continue
		}
		inScope := inheritedScope && node.BountyTierID != 5
		externalID := node.CompanyAssetID
		if externalID == "" {
			externalID = node.ID
		}
		meta := map[string]any{"type_id": node.TypeID, "bounty_tier_id": node.BountyTierID}
		if group != "" {
			meta["group"] = group
		}
		p.Assets = append(p.Assets, Asset{
			ExternalID: externalID, Identifier: identifier,
			AssetType: "intigriti:" + strconv.Itoa(node.TypeID), Category: "intigriti:" + strconv.Itoa(node.TypeID),
			InScope: inScope, EligibleSubmission: inScope,
			EligibleBounty: inScope && p.OffersBounties, Instruction: strings.TrimSpace(node.Description),
			Metadata: meta, Active: true,
		})
	}
}

func (s *Service) enrichIntigritiProgram(ctx context.Context, p *Program) error {
	parts := strings.SplitN(p.Handle, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid Intigriti handle %q", p.Handle)
	}
	endpoint := intigritiCoreURL + "/public/programs/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	var doc intigritiDetail
	if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &doc); err != nil {
		return err
	}
	if doc.Confidentiality != 4 {
		return fmt.Errorf("Intigriti scope is not public")
	}
	if doc.Description != "" {
		p.Description = doc.Description
	}
	p.Status = intigritiStatus(doc.Status)
	if len(doc.Collections) == 0 {
		return fmt.Errorf("Intigriti program has no public asset collection")
	}
	sort.Slice(doc.Collections, func(i, j int) bool { return doc.Collections[i].CreatedAt < doc.Collections[j].CreatedAt })
	latest := doc.Collections[len(doc.Collections)-1]
	p.ProviderUpdatedAt = unixTime(latest.CreatedAt)
	p.Assets = nil
	appendIntigritiAssets(p, latest.Content.Assets, true, "")
	finalizeProgramAssets(p)
	if err := s.upsertProgram(ctx, p, doc); err != nil {
		return err
	}
	return s.replaceAssets(ctx, p)
}

type yesWeHackLogo struct {
	URL string `json:"url"`
}

type yesWeHackBusinessUnit struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Currency    string        `json:"currency"`
	Logo        yesWeHackLogo `json:"logo"`
}

type yesWeHackListing struct {
	Title        string                `json:"title"`
	Slug         string                `json:"slug"`
	ActivityArea string                `json:"activity_area"`
	Type         string                `json:"type"`
	Status       string                `json:"status"`
	Public       bool                  `json:"public"`
	Demo         bool                  `json:"demo"`
	Disabled     bool                  `json:"disabled"`
	Archived     bool                  `json:"archived"`
	Bounty       bool                  `json:"bounty"`
	VDP          bool                  `json:"vdp"`
	MinReward    float64               `json:"bounty_reward_min"`
	MaxReward    float64               `json:"bounty_reward_max"`
	ScopeCount   int                   `json:"scopes_count"`
	LastUpdateAt string                `json:"last_update_at"`
	Thumbnail    yesWeHackLogo         `json:"thumbnail"`
	BusinessUnit yesWeHackBusinessUnit `json:"business_unit"`
}

func yesWeHackStatus(item yesWeHackListing) string {
	if item.Archived || item.Disabled {
		return "closed"
	}
	if item.Status == "V" {
		return "live"
	}
	return "unknown"
}

func (s *Service) syncYesWeHack(ctx context.Context) error {
	seen := map[string]bool{}
	for page := 1; page <= 100; page++ {
		var response struct {
			Items      []yesWeHackListing `json:"items"`
			Pagination struct {
				Pages int `json:"nb_pages"`
			} `json:"pagination"`
		}
		endpoint := fmt.Sprintf("%s/programs?page=%d", yesWeHackAPIURL, page)
		if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &response); err != nil {
			return err
		}
		for _, item := range response.Items {
			if item.Slug == "" || !item.Public || item.Demo {
				continue
			}
			currency := strings.ToUpper(item.BusinessUnit.Currency)
			if currency == "" {
				currency = "EUR"
			}
			programType := "vdp"
			if item.Bounty || strings.Contains(strings.ToLower(item.Type), "bounty") {
				programType = "bug_bounty"
			}
			p := Program{
				Provider: "yeswehack", ExternalID: item.Slug, Handle: item.Slug,
				Name: item.Title, URL: "https://yeswehack.com/programs/" + url.PathEscape(item.Slug),
				LogoURL: item.Thumbnail.URL, Description: item.BusinessUnit.Description,
				Status: yesWeHackStatus(item), ProgramType: programType, Industry: item.ActivityArea,
				OffersBounties: item.Bounty, SafeHarbor: "none", AssetCount: item.ScopeCount, InScopeCount: item.ScopeCount,
				MinRewardCents: int(item.MinReward * 100), MaxRewardCents: int(item.MaxReward * 100), Currency: currency,
				ProviderUpdatedAt: parseTime(item.LastUpdateAt),
			}
			p.ID = stableProgramID(p.Provider, p.ExternalID)
			if err := s.upsertProgram(ctx, &p, item); err != nil {
				return err
			}
			seen[p.ID] = true
		}
		if response.Pagination.Pages <= page || len(response.Items) == 0 {
			break
		}
	}
	return s.markMissingPrograms(ctx, "yeswehack", seen)
}

type yesWeHackScope struct {
	Scope         string `json:"scope"`
	ScopeType     string `json:"scope_type"`
	ScopeTypeName string `json:"scope_type_name"`
	AssetValue    string `json:"asset_value"`
}

type yesWeHackDetail struct {
	yesWeHackListing
	Scopes []yesWeHackScope `json:"scopes"`
}

func (s *Service) enrichYesWeHackProgram(ctx context.Context, p *Program) error {
	endpoint := yesWeHackAPIURL + "/programs/" + url.PathEscape(p.Handle)
	var doc yesWeHackDetail
	if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &doc); err != nil {
		return err
	}
	if doc.Title != "" {
		p.Name = doc.Title
	}
	if doc.BusinessUnit.Description != "" {
		p.Description = doc.BusinessUnit.Description
	}
	p.Status = yesWeHackStatus(doc.yesWeHackListing)
	p.Assets = nil
	for _, scope := range doc.Scopes {
		identifier := strings.TrimSpace(scope.Scope)
		if identifier == "" {
			continue
		}
		externalID := hashJSON([]string{identifier, scope.ScopeType})
		p.Assets = append(p.Assets, Asset{
			ExternalID: externalID, Identifier: identifier, AssetType: scope.ScopeType, Category: scope.ScopeTypeName,
			InScope: true, EligibleSubmission: true, EligibleBounty: p.OffersBounties,
			Metadata: map[string]any{"asset_value": scope.AssetValue}, Active: true,
		})
	}
	finalizeProgramAssets(p)
	if err := s.upsertProgram(ctx, p, doc); err != nil {
		return err
	}
	return s.replaceAssets(ctx, p)
}
