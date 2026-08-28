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

	"github.com/recon-platform/internal/version"
)

// updateInfo is what the UI needs to render the "update available" banner.
type updateInfo struct {
	Current         string `json:"current"`          // running version
	Latest          string `json:"latest"`           // newest tag on GitHub (or "")
	UpdateAvailable bool   `json:"update_available"` // latest > current
	Notes           string `json:"notes"`            // release changelog (truncated)
	URL             string `json:"url"`              // release page
	CheckedAt       string `json:"checked_at"`
	Error           string `json:"error,omitempty"` // set when the check couldn't run
}

// updateCache memoizes the GitHub lookup so we hit the API at most once per TTL
// no matter how often the UI polls.
var (
	updateMu    sync.Mutex
	updateCache *updateInfo
	updateAt    time.Time
)

const updateTTL = 6 * time.Hour

// handleUpdateCheck reports whether a newer Reconner release is published on
// GitHub. Result is cached for updateTTL; pass ?refresh=1 to force a re-check.
func (h *Handler) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.UpdateCheckEnabled {
		h.writeSuccess(w, updateInfo{Current: version.Current, CheckedAt: time.Now().UTC().Format(time.RFC3339)})
		return
	}

	force := r.URL.Query().Get("refresh") == "1"

	updateMu.Lock()
	if !force && updateCache != nil && time.Since(updateAt) < updateTTL {
		cached := *updateCache
		updateMu.Unlock()
		h.writeSuccess(w, cached)
		return
	}
	updateMu.Unlock()

	info := h.fetchLatestRelease(r.Context())

	updateMu.Lock()
	updateCache = &info
	updateAt = time.Now()
	updateMu.Unlock()

	h.writeSuccess(w, info)
}

// fetchLatestRelease queries the GitHub Releases API for the configured repo.
func (h *Handler) fetchLatestRelease(parent context.Context) updateInfo {
	info := updateInfo{Current: version.Current, CheckedAt: time.Now().UTC().Format(time.RFC3339)}

	repo := strings.TrimSpace(h.cfg.GitHubRepo)
	if repo == "" {
		info.Error = "no github_repo configured"
		return info
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.Error = "request build failed"
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Reconner-update-checker")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		info.Error = "could not reach GitHub"
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// No releases published yet — not an error, just nothing to update to.
		return info
	}
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("GitHub returned %d", resp.StatusCode)
		return info
	}

	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if json.Unmarshal(body, &rel) != nil {
		info.Error = "bad response from GitHub"
		return info
	}

	info.Latest = strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	info.URL = rel.HTMLURL
	info.Notes = truncateNotes(rel.Body, 1200)
	info.UpdateAvailable = semverGreater(info.Latest, info.Current)
	return info
}

func truncateNotes(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "\n…"
	}
	return s
}

// semverGreater reports whether version a is strictly newer than b. Both are
// dot-separated numeric strings ("1.2.0"); non-numeric parts compare as 0, and a
// missing component is treated as 0 so "1.1" < "1.1.1".
func semverGreater(a, b string) bool {
	if a == "" {
		return false
	}
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(strings.TrimSpace(as[i]))
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(strings.TrimSpace(bs[i]))
		}
		if av != bv {
			return av > bv
		}
	}
	return false
}
