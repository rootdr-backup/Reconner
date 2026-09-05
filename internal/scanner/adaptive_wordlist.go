package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

const adaptiveWordLimit = 1200

var adaptiveTokenRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_-]{2,47}`)

var adaptiveStopWords = map[string]bool{
	"about": true, "after": true, "also": true, "and": true, "are": true,
	"before": true, "but": true, "can": true, "com": true, "contact": true,
	"cookie": true, "copyright": true, "for": true, "from": true, "have": true,
	"html": true, "http": true, "https": true, "into": true, "javascript": true,
	"more": true, "not": true, "our": true, "page": true, "please": true,
	"privacy": true, "that": true, "the": true, "their": true, "this": true,
	"use": true, "using": true, "was": true, "web": true, "website": true,
	"with": true, "www": true, "you": true, "your": true,
}

type adaptiveCandidate struct {
	word  string
	score int
	hits  int
}

func normalizeAdaptiveWord(raw string) string {
	w := strings.ToLower(strings.TrimSpace(raw))
	w = strings.Trim(w, "-_")
	if dot := strings.LastIndexByte(w, '.'); dot > 1 {
		ext := w[dot+1:]
		switch ext {
		case "php", "aspx", "asp", "jsp", "html", "htm", "json", "xml", "js", "css", "map", "txt":
			w = w[:dot]
		}
	}
	if len(w) < 3 || len(w) > 40 || adaptiveStopWords[w] || isAllDigits(w) {
		return ""
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return ""
		}
	}
	// Long hex/base64-looking strings are usually hashes, cache keys or secrets,
	// not reusable program vocabulary. Never persist them into the wordlist.
	if len(w) >= 16 {
		hexOnly := true
		for i := 0; i < len(w); i++ {
			if !strings.ContainsRune("0123456789abcdef", rune(w[i])) {
				hexOnly = false
				break
			}
		}
		if hexOnly {
			return ""
		}
	}
	return w
}

func adaptiveWordlistPath(dir, domain string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(domain))))
	return filepath.Join(dir, fmt.Sprintf("adaptive-subdomain-%x.txt", sum[:8]))
}

// buildAdaptiveWordlist creates a deterministic, target-specific vocabulary
// from data Reconner already obtained in scope: program metadata, approved
// assets, hosts, crawled/JS paths, parameter names and validated directories.
// It never follows a new URL itself and never persists response values/secrets.
func buildAdaptiveWordlist(ctx context.Context, db *database.DB, cfg *config.Config, targetID string, extraURLs []string) []string {
	candidates := map[string]*adaptiveCandidate{}
	add := func(raw string, weight int) {
		w := normalizeAdaptiveWord(raw)
		if w == "" {
			return
		}
		c := candidates[w]
		if c == nil {
			c = &adaptiveCandidate{word: w}
			candidates[w] = c
		}
		if c.score < 200 {
			c.score += weight
		}
		c.hits++
	}
	addText := func(text string, weight int) {
		for _, token := range adaptiveTokenRE.FindAllString(text, -1) {
			add(token, weight)
			for _, part := range strings.FieldsFunc(token, func(r rune) bool { return r == '-' || r == '_' }) {
				add(part, weight)
			}
		}
	}
	addURL := func(raw string, weight int) {
		raw = strings.TrimSpace(raw)
		if decoded, err := url.QueryUnescape(raw); err == nil {
			raw = decoded
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		for _, label := range strings.Split(u.Hostname(), ".") {
			addText(label, weight)
		}
		for _, segment := range strings.Split(u.EscapedPath(), "/") {
			if decoded, err := url.PathUnescape(segment); err == nil {
				addText(decoded, weight)
			}
		}
		for name := range u.Query() {
			add(name, weight+3)
		}
	}

	var domain, name, description string
	if err := db.QueryRowContext(ctx, `SELECT domain,COALESCE(name,''),COALESCE(description,'') FROM targets WHERE id=?`, targetID).Scan(&domain, &name, &description); err != nil {
		return nil
	}
	addURL("https://"+strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://"), 12)
	addText(name, 10)
	addText(description, 2)

	rows, err := db.QueryContext(ctx, `SELECT COALESCE(name,''),value FROM assets WHERE target_id=? AND COALESCE(approval_status,'approved')='approved' LIMIT 2000`, targetID)
	if err == nil {
		for rows.Next() {
			var n, value string
			if rows.Scan(&n, &value) == nil {
				addText(n, 8)
				addURL(value, 12)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT subdomain FROM subdomains WHERE target_id=? LIMIT 10000`, targetID)
	if err == nil {
		for rows.Next() {
			var host string
			if rows.Scan(&host) == nil {
				addURL("https://"+host, 6)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT url,COALESCE(title,'') FROM http_services WHERE target_id=? LIMIT 10000`, targetID)
	if err == nil {
		for rows.Next() {
			var raw, title string
			if rows.Scan(&raw, &title) == nil {
				addURL(raw, 7)
				addText(title, 1)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT url FROM js_files WHERE target_id=? LIMIT 10000`, targetID)
	if err == nil {
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) == nil {
				addURL(raw, 8)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT value FROM js_findings WHERE target_id=? AND type IN ('endpoint','api_url','graphql','debug_endpoint','auth_endpoint','config') LIMIT 5000`, targetID)
	if err == nil {
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) == nil {
				addURL(raw, 11)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT parameter,url FROM parameters WHERE target_id=? LIMIT 10000`, targetID)
	if err == nil {
		for rows.Next() {
			var parameter, raw string
			if rows.Scan(&parameter, &raw) == nil {
				add(parameter, 15)
				addURL(raw, 8)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT url FROM directory_findings WHERE target_id=? LIMIT 5000`, targetID)
	if err == nil {
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) == nil {
				addURL(raw, 12)
			}
		}
		rows.Close()
	}
	for _, raw := range extraURLs {
		addURL(raw, 10)
	}

	ranked := make([]adaptiveCandidate, 0, len(candidates))
	for _, c := range candidates {
		ranked = append(ranked, *c)
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		if ranked[i].hits != ranked[j].hits {
			return ranked[i].hits > ranked[j].hits
		}
		return ranked[i].word < ranked[j].word
	})
	if len(ranked) > adaptiveWordLimit {
		ranked = ranked[:adaptiveWordLimit]
	}
	words := make([]string, 0, len(ranked))
	for _, c := range ranked {
		words = append(words, c.word)
	}
	if cfg != nil && cfg.WordlistsDir != "" {
		persistAdaptiveWordlist(cfg.WordlistsDir, domain, words)
	}
	return words
}

func persistAdaptiveWordlist(dir, domain string, words []string) {
	if len(words) == 0 || os.MkdirAll(dir, 0o750) != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".adaptive-*.tmp")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	_ = tmp.Chmod(0o600)
	w := bufio.NewWriter(tmp)
	for _, word := range words {
		_, _ = fmt.Fprintln(w, word)
	}
	if w.Flush() != nil || tmp.Close() != nil {
		return
	}
	_ = os.Rename(name, adaptiveWordlistPath(dir, domain))
}

func loadAdaptiveWordlist(dir, domain string, limit int) []string {
	if dir == "" || limit <= 0 {
		return nil
	}
	f, err := os.Open(adaptiveWordlistPath(dir, domain))
	if err != nil {
		return nil
	}
	defer f.Close()
	words := make([]string, 0, limit)
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(words) < limit {
		if word := normalizeAdaptiveWord(sc.Text()); word != "" {
			words = append(words, word)
		}
	}
	return words
}

func adaptiveDirectoryPaths(words []string, limit int) []string {
	if len(words) > limit {
		words = words[:limit]
	}
	paths := make([]string, 0, len(words)*2)
	seen := map[string]bool{}
	for _, word := range words {
		if word = normalizeAdaptiveWord(word); word == "" {
			continue
		}
		for _, p := range []string{"/" + word, "/api/" + word} {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	return paths
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if path != "" && !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}
