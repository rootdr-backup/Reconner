package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	assetutil "github.com/recon-platform/internal/assets"
	"github.com/recon-platform/internal/database"
	"golang.org/x/net/idna"
)

// WatchScopeEntry is one eligible program asset identifier.
//
// The eligible set is the UNION over every program linked to the project
// (project_programs is a join table), never the single program id stored on a
// previously landed row. A host that is eligible under ANY linked program is
// landable.
type WatchScopeEntry struct {
	ProgramID  string
	AssetID    string
	Identifier string
	IsWildcard bool

	// host is the normalized hostname used for matching (lowercase, punycode,
	// no trailing dot, no port).
	host string
}

// WatchScopeHost is a discovered host ready for landing.
type WatchScopeHost struct {
	// Value is what gets stored in assets.value: the hostname, or "host:port"
	// when the port is not 80/443, so a non-default port is never lost.
	Value string
	// Host is the hostname used for matching.
	Host string
	// Port is the explicit port of the discovered host, empty when there is
	// none or when it is the default for the scheme.
	Port string
}

// LoadWatchEligibleScope reads the eligible program scope of a project.
//
// Returns the entries, whether the project has ANY linked program (a project
// without one is a manual project: nothing is ever landable for it), and an
// error. Identifiers that cannot be bare hosts (a path-scoped URL) or that use
// an unsupported glob are skipped with one warning line each.
func LoadWatchEligibleScope(ctx context.Context, db *database.DB, targetID string) ([]WatchScopeEntry, bool, error) {
	var linked int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_programs WHERE target_id = ?`, targetID).Scan(&linked); err != nil {
		return nil, false, fmt.Errorf("count linked programs: %w", err)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT pp.program_id, a.id, a.identifier, COALESCE(a.is_wildcard,0), COALESCE(a.asset_type,'')
		FROM project_programs pp
		JOIN bounty_program_assets a ON a.program_id = pp.program_id
		WHERE pp.target_id = ?
		  AND a.active = 1 AND a.in_scope = 1 AND a.eligible_submission = 1
	`, targetID)
	if err != nil {
		return nil, linked > 0, fmt.Errorf("query eligible scope: %w", err)
	}
	defer rows.Close()

	var entries []WatchScopeEntry
	var skipped []string
	for rows.Next() {
		var e WatchScopeEntry
		var wildcard int
		var assetType string
		if err := rows.Scan(&e.ProgramID, &e.AssetID, &e.Identifier, &wildcard, &assetType); err != nil {
			continue
		}
		if !assetutil.IsScannableWebAsset(assetType, e.Identifier) {
			// App listings, app packages, prose notes, and network assets
			// cannot become watch-landed hosts.
			continue
		}
		e.IsWildcard = wildcard == 1
		host, ok := normalizeScopeIdentifier(e.Identifier)
		if !ok {
			skipped = append(skipped, e.Identifier)
			continue
		}
		e.host = host
		entries = append(entries, e)
	}
	return entries, linked > 0, nil
}

// normalizeScopeIdentifier normalizes a program identifier to a bare hostname.
//
// It returns ok=false when the identifier cannot cover a bare host:
//   - a path-scoped URL (https://example.com/api/v1/) covers only that subpath,
//     so landing the bare domain would approve scope the program never gave;
//   - an unsupported glob (*example.com without the dot, sub.*.example.com).
func normalizeScopeIdentifier(raw string) (string, bool) {
	host, _, ok := splitScopeHostPort(raw)
	if !ok {
		return "", false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	if strings.Contains(host, "*") {
		// Only the "*.<domain>" form is supported.
		if !strings.HasPrefix(host, "*.") || strings.Contains(host[2:], "*") {
			return "", false
		}
		host = host[2:]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", false
	}
	return strings.ToLower(ascii), true
}

// splitScopeHostPort splits a raw scope token into its hostname, its explicit
// port and whether the token carries a path. A token with a path is not a bare
// host.
func splitScopeHostPort(raw string) (host, port string, bareHost bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", "", false
		}
		if p := strings.TrimSpace(u.EscapedPath()); p != "" && p != "/" {
			return "", "", false
		}
		h, pt := splitHostPort(u.Host)
		return h, pt, true
	}
	// No scheme: split off a path by hand.
	if i := strings.Index(raw, "/"); i >= 0 {
		if p := strings.Trim(raw[i:], "/"); p != "" {
			return "", "", false
		}
		raw = raw[:i]
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}
	h, pt := splitHostPort(raw)
	return h, pt, true
}

// splitHostPort separates an explicit port from a hostname. A non-numeric
// colon suffix is treated as part of the host.
func splitHostPort(raw string) (host, port string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		if _, perr := strconv.Atoi(p); perr == nil {
			return h, p
		}
	}
	return strings.Trim(raw, "[]"), ""
}

// normalizeWatchHost normalizes a discovered host for matching and for storage.
func normalizeWatchHost(raw string) (WatchScopeHost, bool) {
	host, port, bare := splitScopeHostPort(raw)
	if !bare || host == "" {
		return WatchScopeHost{}, false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return WatchScopeHost{}, false
	}
	host = strings.ToLower(ascii)
	if host == "" {
		return WatchScopeHost{}, false
	}
	value := host
	if port != "" && port != "80" && port != "443" {
		value = host + ":" + port
	}
	return WatchScopeHost{Value: value, Host: host, Port: port}, true
}

// matchWatchHost finds the eligible entry that covers a discovered host.
//
// An exact match wins over a wildcard match. A wildcard "*.<base>" covers
// "a.<base>" and "a.b.<base>" but NOT the apex "<base>". The port never blocks
// a match: it is stripped for matching, so a program asset "example.com:8443"
// still covers the host "example.com".
func matchWatchHost(entries []WatchScopeEntry, host WatchScopeHost) (WatchScopeEntry, bool) {
	var wildcardHit WatchScopeEntry
	var wildcardOK bool
	for _, e := range entries {
		if e.IsWildcard {
			base := strings.TrimSuffix(e.host, ".")
			if base == "" || host.Host == base {
				continue // a wildcard never covers the apex
			}
			if strings.HasSuffix(host.Host, "."+base) {
				if !wildcardOK {
					wildcardHit = e
					wildcardOK = true
				}
				continue
			}
			continue
		}
		if e.host == host.Host {
			return e, true // exact match wins
		}
	}
	return wildcardHit, wildcardOK
}

// LandWatchScopeHosts lands the eligible hosts of a watch round.
//
// Only hosts that came back from the HTTP phase are considered: a host that was
// never probed is not verified and must not become approved scope. Every landed
// host gets an assets row (approved scope) and a watch_scope_events row (the
// operator audit trail, announced=0 until the grouped message is sent).
//
// Returns the newly landed host values (empty when nothing was landed).
func LandWatchScopeHosts(ctx context.Context, db *database.DB, targetID string, hosts []string, logFn LogFunc) []string {
	if len(hosts) == 0 {
		return nil
	}
	entries, hasProgram, err := LoadWatchEligibleScope(ctx, db, targetID)
	if err != nil {
		logFn("warn", "watch_scope", fmt.Sprintf("Scope landing skipped: %v", err))
		return nil
	}
	if !hasProgram {
		logFn("info", "watch_scope", "no bounty program linked: scope landing disabled for this project")
		return nil
	}
	if len(entries) == 0 {
		logFn("info", "watch_scope", "no eligible program assets: nothing landed this round")
		return nil
	}

	seen := map[string]bool{}
	var landed []string
	for _, raw := range hosts {
		host, ok := normalizeWatchHost(raw)
		if !ok || seen[host.Value] {
			continue
		}
		seen[host.Value] = true
		entry, ok := matchWatchHost(entries, host)
		if !ok {
			continue // outside the eligible scope: not added, not notified
		}
		changed, err := landWatchHost(ctx, db, targetID, host, entry)
		if err != nil {
			logFn("warn", "watch_scope", fmt.Sprintf("Failed to land %s: %v", host.Value, err))
			continue
		}
		if changed {
			landed = append(landed, host.Value)
		}
	}
	if len(landed) > 0 {
		logFn("info", "watch_scope", fmt.Sprintf("Landed %d new eligible host(s) as approved scope", len(landed)))
	}
	return landed
}

// landWatchHost writes the asset row and the audit event for one host.
//
// A host that already exists under another source is never rewritten. A host
// that was landed before and later fell out of scope is re-activated: the
// out-of-scope flag is cleared, a NEW event row is written and it is announced
// again.
func landWatchHost(ctx context.Context, db *database.DB, targetID string, host WatchScopeHost, entry WatchScopeEntry) (bool, error) {
	assetID, source, metadata, found := lookupWatchAsset(ctx, db, targetID, host.Value)
	if found {
		if source != "watch:scope" {
			return false, nil // owned by another source (program import): never rewritten
		}
		if !watchMetadataOutOfScope(metadata) {
			return false, nil // already known and in scope
		}
		// Re-eligible: clear the flag and announce it again with a new event.
		if err := reactivateWatchAsset(ctx, db, targetID, assetID, host, entry); err != nil {
			return false, err
		}
		return true, nil
	}

	eventID := uuid.New().String()
	assetID = uuid.New().String()
	meta := map[string]any{
		"program_id":    entry.ProgramID,
		"program_asset": entry.AssetID,
		"out_of_scope":  0,
	}
	metaJSON, _ := json.Marshal(meta)
	if err := insertWatchScopeEvent(ctx, db, targetID, entry.ProgramID, host.Value, "landed", assetID, metaJSON); err != nil {
		return false, err
	}
	// assets has UNIQUE(target_id, value): a row that already exists is left
	// alone. The stored value is lowercased, because SQLite compares text with
	// BINARY collation and "Example.com" would otherwise be a second row.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,source_id,approval_status,monitor_enabled,metadata,updated_at)
		VALUES(?,?,?,?, 'web','subdomain','watch:scope',?,'approved',0,?,CURRENT_TIMESTAMP)
		ON CONFLICT(target_id,value) DO NOTHING`,
		assetID, targetID, host.Value, host.Value, eventID, string(metaJSON)); err != nil {
		return false, err
	}
	return true, nil
}

// lookupWatchAsset finds the assets row for a host.
//
// The exact value is tried first, then a case-insensitive match: SQLite
// compares text with BINARY collation, so "Example.com" and "example.com" can
// be two rows in the same project. Both paths must be able to REACTIVATE an
// out-of-scope watch:scope row, otherwise a host that was landed with different
// casing never comes back into scope.
func lookupWatchAsset(ctx context.Context, db *database.DB, targetID, value string) (id, source, metadata string, found bool) {
	err := db.QueryRowContext(ctx,
		`SELECT id, COALESCE(source,''), COALESCE(metadata,'') FROM assets WHERE target_id = ? AND value = ?`,
		targetID, value).Scan(&id, &source, &metadata)
	if err == nil {
		return id, source, metadata, true
	}
	err = db.QueryRowContext(ctx,
		`SELECT id, COALESCE(source,''), COALESCE(metadata,'') FROM assets
		 WHERE target_id = ? AND LOWER(value) = LOWER(?) LIMIT 1`,
		targetID, value).Scan(&id, &source, &metadata)
	if err == nil {
		return id, source, metadata, true
	}
	return "", "", "", false
}

// reactivateWatchAsset clears the out-of-scope flag on a landed host and writes
// a NEW audit event, so the grouped message announces it again.
func reactivateWatchAsset(ctx context.Context, db *database.DB, targetID, assetID string, host WatchScopeHost, entry WatchScopeEntry) error {
	meta := map[string]any{
		"program_id":    entry.ProgramID,
		"program_asset": entry.AssetID,
		"out_of_scope":  0,
	}
	metaJSON, _ := json.Marshal(meta)
	if _, err := db.ExecContext(ctx,
		`UPDATE assets SET metadata = ?, approval_status = 'approved', monitor_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(metaJSON), assetID); err != nil {
		return err
	}
	return insertWatchScopeEvent(ctx, db, targetID, entry.ProgramID, host.Value, "re_eligible", assetID, metaJSON)
}

// insertWatchScopeEvent writes the audit row for a landing. announced stays 0
// until the grouped message has claimed and sent it.
func insertWatchScopeEvent(ctx context.Context, db *database.DB, targetID, programID, identifier, eventType, assetID string, metadata []byte) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO watch_scope_events(id,target_id,program_id,identifier,event_type,asset_id,detected_at,announced,metadata)
		VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP,0,?)`,
		uuid.New().String(), targetID, programID, identifier, eventType, assetID, string(metadata))
	return err
}

// watchMetadataOutOfScope reports whether an assets metadata blob marks the row
// as out of scope.
func watchMetadataOutOfScope(metadata string) bool {
	if strings.TrimSpace(metadata) == "" {
		return false
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(metadata), &meta); err != nil {
		return false
	}
	switch v := meta["out_of_scope"].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != "" && v != "0" && v != "false"
	}
	return false
}

// SweepWatchScopeOutOfScope marks landed hosts that are no longer eligible.
//
// It compares every watch:scope asset of the project with the FULL eligible
// set (the UNION over every linked program) and sets metadata.out_of_scope=1 on
// the rows that fell out. The rows are never deleted: the operator keeps the
// history and can promote them later.
func SweepWatchScopeOutOfScope(ctx context.Context, db *database.DB, targetID string, logFn LogFunc) int {
	entries, hasProgram, err := LoadWatchEligibleScope(ctx, db, targetID)
	if err != nil {
		return 0
	}
	if !hasProgram {
		return 0
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, value, COALESCE(metadata,'') FROM assets
		WHERE target_id = ? AND source = 'watch:scope'`, targetID)
	if err != nil {
		return 0
	}
	type assetRow struct {
		id       string
		value    string
		metadata string
	}
	var list []assetRow
	for rows.Next() {
		var a assetRow
		if err := rows.Scan(&a.id, &a.value, &a.metadata); err == nil {
			list = append(list, a)
		}
	}
	rows.Close()

	marked := 0
	for _, a := range list {
		host, ok := normalizeWatchHost(a.value)
		if !ok {
			continue
		}
		if _, ok := matchWatchHost(entries, host); ok {
			continue // still eligible
		}
		if watchMetadataOutOfScope(a.metadata) {
			continue // already marked
		}
		var meta map[string]any
		if strings.TrimSpace(a.metadata) == "" {
			meta = map[string]any{}
		} else if err := json.Unmarshal([]byte(a.metadata), &meta); err != nil || meta == nil {
			meta = map[string]any{}
		}
		meta["out_of_scope"] = 1
		metaJSON, _ := json.Marshal(meta)
		if _, err := db.ExecContext(ctx,
			`UPDATE assets SET metadata = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			string(metaJSON), a.id); err == nil {
			marked++
		}
	}
	if marked > 0 {
		logFn("info", "watch_scope", fmt.Sprintf("Marked %d landed host(s) as out of scope", marked))
	}
	return marked
}
