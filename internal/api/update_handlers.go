package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/version"
)

const (
	updateTTL       = 6 * time.Hour
	updateErrorTTL  = 30 * time.Minute
	forceCheckFloor = time.Minute
)

// updateInfo is deployment-agnostic: the UI presents both the GHCR and source
// update paths without the server attempting to mutate itself. Self-update is
// unsafe for active scans and a container should not control its Docker host.
type updateInfo struct {
	Enabled         bool   `json:"enabled"`
	Current         string `json:"current"`
	CurrentCommit   string `json:"current_commit"`
	BuildDate       string `json:"build_date"`
	Latest          string `json:"latest"`
	ReleaseName     string `json:"release_name"`
	UpdateAvailable bool   `json:"update_available"`
	Notes           string `json:"notes"`
	URL             string `json:"url"`
	PublishedAt     string `json:"published_at"`
	CheckedAt       string `json:"checked_at"`
	NextCheckAt     string `json:"next_check_at"`
	Channel         string `json:"channel"`
	Stale           bool   `json:"stale"`
	Error           string `json:"error,omitempty"`
}

// releaseChecker coalesces concurrent UI requests, caches responses and keeps
// GitHub's ETag for conditional refreshes. A busy multi-user dashboard costs at
// most four GitHub API requests per day in the healthy case.
type releaseChecker struct {
	mu       sync.Mutex
	cached   updateInfo
	hasCache bool
	checked  time.Time
	etag     string
	inFlight chan struct{}
	client   *http.Client
	apiBase  string
}

func newReleaseChecker() *releaseChecker {
	return &releaseChecker{
		client:  &http.Client{Timeout: 12 * time.Second},
		apiBase: "https://api.github.com",
	}
}

func currentBuildInfo() updateInfo {
	return updateInfo{
		Enabled:       true,
		Current:       strings.TrimPrefix(strings.TrimSpace(version.Current), "v"),
		CurrentCommit: strings.TrimSpace(version.Commit),
		BuildDate:     strings.TrimSpace(version.BuildDate),
		Channel:       "stable",
	}
}

// handleUpdateCheck reports the newest stable GitHub release. Only admins may
// bypass the cache with ?refresh=1, and even they get a one-minute floor.
func (h *Handler) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-cache")
	if !h.cfg.UpdateCheckEnabled {
		info := currentBuildInfo()
		info.Enabled = false
		now := time.Now().UTC()
		info.CheckedAt = now.Format(time.RFC3339)
		info.NextCheckAt = now.Add(updateTTL).Format(time.RFC3339)
		h.writeSuccess(w, info)
		return
	}

	force := false
	if r.URL.Query().Get("refresh") == "1" {
		_, force = h.callerScope(r)
	}
	checker := h.updates
	if checker == nil { // defensive for tests constructing Handler directly
		checker = newReleaseChecker()
		h.updates = checker
	}
	h.writeSuccess(w, checker.check(r.Context(), h.cfg, force))
}

func (c *releaseChecker) check(ctx context.Context, cfg *config.Config, force bool) updateInfo {
	now := time.Now().UTC()
	c.mu.Lock()
	if c.hasCache && ((!force && now.Sub(c.checked) < cacheTTL(c.cached)) ||
		(force && now.Sub(c.checked) < forceCheckFloor)) {
		info := c.cached
		c.mu.Unlock()
		return info
	}
	if c.inFlight != nil {
		wait := c.inFlight
		c.mu.Unlock()
		select {
		case <-wait:
			c.mu.Lock()
			info := c.cached
			c.mu.Unlock()
			return info
		case <-ctx.Done():
			info := currentBuildInfo()
			info.Error = "update check cancelled"
			info.CheckedAt = now.Format(time.RFC3339)
			info.NextCheckAt = now.Add(updateErrorTTL).Format(time.RFC3339)
			return info
		}
	}

	wait := make(chan struct{})
	c.inFlight = wait
	previous, etag := c.cached, c.etag
	hadPrevious := c.hasCache
	c.mu.Unlock()

	info, newETag, notModified := c.fetch(ctx, cfg, previous, etag, hadPrevious)
	if notModified {
		info = previous
		refreshBuildFields(&info)
		info.Error = ""
		info.Stale = false
		info.CheckedAt = now.Format(time.RFC3339)
		info.NextCheckAt = now.Add(updateTTL).Format(time.RFC3339)
	}

	c.mu.Lock()
	if info.Error != "" && hadPrevious {
		lastError := info.Error
		info = previous
		refreshBuildFields(&info)
		info.Error = lastError
		info.Stale = true
		info.CheckedAt = now.Format(time.RFC3339)
		info.NextCheckAt = now.Add(updateErrorTTL).Format(time.RFC3339)
	}
	c.cached = info
	c.hasCache = true
	c.checked = now
	if newETag != "" {
		c.etag = newETag
	}
	close(wait)
	c.inFlight = nil
	c.mu.Unlock()
	return info
}

func cacheTTL(info updateInfo) time.Duration {
	if info.Error != "" {
		return updateErrorTTL
	}
	return updateTTL
}

func refreshBuildFields(info *updateInfo) {
	build := currentBuildInfo()
	info.Enabled = true
	info.Current = build.Current
	info.CurrentCommit = build.CurrentCommit
	info.BuildDate = build.BuildDate
	info.Channel = build.Channel
	info.UpdateAvailable = semverGreater(info.Latest, info.Current)
}

func (c *releaseChecker) fetch(parent context.Context, cfg *config.Config, previous updateInfo, etag string, hadPrevious bool) (updateInfo, string, bool) {
	info := currentBuildInfo()
	now := time.Now().UTC()
	info.CheckedAt = now.Format(time.RFC3339)
	info.NextCheckAt = now.Add(updateTTL).Format(time.RFC3339)

	repo := strings.Trim(strings.TrimSpace(cfg.GitHubRepo), "/")
	if repo == "" || strings.Count(repo, "/") != 1 {
		info.Error = "invalid github_repo configuration"
		info.NextCheckAt = now.Add(updateErrorTTL).Format(time.RFC3339)
		return info, "", false
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	url := strings.TrimRight(c.apiBase, "/") + "/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.Error = "could not create update request"
		return info, "", false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Reconner/"+info.Current+" update-checker")
	if etag != "" && hadPrevious {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		info.Error = "could not reach GitHub"
		info.NextCheckAt = now.Add(updateErrorTTL).Format(time.RFC3339)
		return info, "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified && hadPrevious {
		return previous, resp.Header.Get("ETag"), true
	}
	if resp.StatusCode == http.StatusNotFound {
		return info, resp.Header.Get("ETag"), false // valid repo with no releases yet
	}
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("GitHub update check returned %d", resp.StatusCode)
		info.NextCheckAt = now.Add(updateErrorTTL).Format(time.RFC3339)
		return info, "", false
	}

	var rel struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		HTMLURL     string `json:"html_url"`
		Body        string `json:"body"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil || json.Unmarshal(body, &rel) != nil {
		info.Error = "GitHub returned an invalid release response"
		info.NextCheckAt = now.Add(updateErrorTTL).Format(time.RFC3339)
		return info, "", false
	}
	if rel.Draft || rel.Prerelease { // defensive; /latest excludes both
		return info, resp.Header.Get("ETag"), false
	}

	info.Latest = strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	info.ReleaseName = strings.TrimSpace(rel.Name)
	info.URL = rel.HTMLURL
	info.Notes = truncateNotes(rel.Body, 6000)
	info.PublishedAt = rel.PublishedAt
	info.UpdateAvailable = semverGreater(info.Latest, info.Current)
	return info, resp.Header.Get("ETag"), false
}

func truncateNotes(s string, max int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return strings.TrimSpace(string(r[:max])) + "\n…"
}

type parsedVersion struct {
	major, minor, patch int
	pre                 []string
	valid               bool
}

func parseVersion(raw string) parsedVersion {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	s = strings.SplitN(s, "+", 2)[0]
	parts := strings.SplitN(s, "-", 2)
	core := strings.Split(parts[0], ".")
	if len(core) != 3 {
		return parsedVersion{}
	}
	nums := [3]int{}
	for i, p := range core {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return parsedVersion{}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return parsedVersion{}
		}
		nums[i] = n
	}
	v := parsedVersion{major: nums[0], minor: nums[1], patch: nums[2], valid: true}
	if len(parts) == 2 {
		if parts[1] == "" {
			return parsedVersion{}
		}
		v.pre = strings.Split(parts[1], ".")
	}
	return v
}

// semverGreater implements SemVer 2.0.0 precedence including prereleases.
// Invalid/development versions never produce a misleading update alert.
func semverGreater(a, b string) bool {
	av, bv := parseVersion(a), parseVersion(b)
	if !av.valid || !bv.valid {
		return false
	}
	for _, pair := range [][2]int{{av.major, bv.major}, {av.minor, bv.minor}, {av.patch, bv.patch}} {
		if pair[0] != pair[1] {
			return pair[0] > pair[1]
		}
	}
	if len(av.pre) == 0 || len(bv.pre) == 0 {
		return len(av.pre) == 0 && len(bv.pre) > 0
	}
	for i := 0; i < len(av.pre) && i < len(bv.pre); i++ {
		if av.pre[i] == bv.pre[i] {
			continue
		}
		an, ae := strconv.Atoi(av.pre[i])
		bn, be := strconv.Atoi(bv.pre[i])
		switch {
		case ae == nil && be == nil:
			return an > bn
		case ae == nil:
			return false
		case be == nil:
			return true
		default:
			return av.pre[i] > bv.pre[i]
		}
	}
	return len(av.pre) > len(bv.pre)
}
