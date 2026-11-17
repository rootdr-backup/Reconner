package scanner

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

// Backup / config-dump discovery with two false-positive-killing techniques:
//   1. Magic-byte confirmation — a real backup is an archive or a DB dump, so we
//      verify the response body against known file signatures instead of trusting
//      status/size alone. This turns "possible" hits into CONFIRMED ones and kills
//      the last class of false positives (a 200 that isn't HTML but also isn't a
//      real backup).
//   2. Smarter candidate generation — domain-derived names, common config files
//      with backup suffixes, and dated variants (backup_2026.zip, db2025.sql).

// magicSignatures maps a leading byte signature to a human file-type label.
var magicSignatures = []struct {
	sig   []byte
	label string
}{
	{[]byte("PK\x03\x04"), "ZIP"},
	{[]byte("PK\x05\x06"), "ZIP (empty)"},
	{[]byte("Rar!\x1a\x07"), "RAR"},
	{[]byte("7z\xbc\xaf\x27\x1c"), "7-Zip"},
	{[]byte("\x1f\x8b"), "GZIP"},
	{[]byte("BZh"), "BZIP2"},
	{[]byte("SQLite format 3\x00"), "SQLite DB"},
	{[]byte("\xfd7zXZ\x00"), "XZ"},
	// ZSTD — now a very common dump/archive codec (`pg_dump | zstd`,
	// `mysqldump | zstd`, tar --zstd). Magic: 0x28 0xB5 0x2F 0xFD (little-endian
	// 0xFD2FB528). Was absent, so a .zst backup was invisible to signature
	// confirmation and only caught (if at all) by the weaker extension heuristic.
	{[]byte("\x28\xb5\x2f\xfd"), "ZSTD"},
	// Java KeyStore — the corpus already requests /keystore.jks, but a real hit
	// could never be magic-confirmed (and detectFileType has no .jks case, so
	// credibleSensitiveBackup's extension switch had nothing to match either).
	// A leaked JKS keystore carries TLS/signing private keys, so this is a
	// real, high-value confirmation gap, not a cosmetic one.
	{[]byte("\xfe\xed\xfe\xed"), "Java KeyStore (JKS)"},
}

// sqlTextMarkers identify a plaintext SQL dump.
var sqlTextMarkers = [][]byte{
	[]byte("-- mysql dump"), []byte("create table"), []byte("insert into"),
	[]byte("pg_dump"), []byte("-- phpmyadmin sql dump"), []byte("begin transaction"),
	[]byte("drop table if exists"),
}

// checkMagicBytes returns a confirmation label if the body matches a known
// archive/dump signature, or "" if it doesn't look like a real backup file.
func checkMagicBytes(body []byte) string {
	for _, m := range magicSignatures {
		if bytes.HasPrefix(body, m.sig) {
			return m.label
		}
	}
	// TAR: "ustar" appears at offset 257.
	if len(body) > 262 && bytes.Equal(body[257:262], []byte("ustar")) {
		return "TAR"
	}
	// Plaintext SQL dump.
	n := len(body)
	if n > 512 {
		n = 512
	}
	lowered := bytes.ToLower(body[:n])
	for _, marker := range sqlTextMarkers {
		if bytes.Contains(lowered, marker) {
			return "SQL dump"
		}
	}
	return ""
}

// backupExtensions are appended to domain-derived names. Includes the common
// archive/dump suffixes plus a few ad-hoc ones seen in the wild (.sql.zip,
// .sql.bak, and plain .txt — a frequent ad-hoc DB-dump extension).
var backupExtensions = []string{
	".zip", ".rar", ".sql", ".bak", ".tar.gz", ".tar", ".7z", ".gz",
	".backup", ".old", ".db", ".sql.gz", ".sql.zip", ".sql.bak", ".txt",
	".zst", ".tar.zst", ".sql.zst", ".xz", ".tar.xz",
	".tgz", ".war", ".tar.bz2", ".dump",
}

// coreBackupExts is the smaller, highest-signal set used for the bulky wordlist /
// dated combinations so the per-host request count stays bounded across a scan
// that runs over dozens of hosts.
var coreBackupExts = []string{".zip", ".rar", ".sql", ".tar.gz", ".bak", ".7z", ".gz", ".old"}

// backupSuffixes are appended to REAL config/source filenames in place
// (index.php -> index.php.bak, .env -> .env.save).
var backupSuffixes = []string{".bak", ".old", ".swp", ".save", ".orig", "~", ".1", ".zip"}

// backupConfigFiles are config/source files that frequently get backed up in place.
// Each is cross-producted with backupSuffixes (.bak/.old/~/.swp/…) so e.g.
// "config/database.php.bak" and "local.settings.json~" are probed — the exact
// editor/deploy leftovers that leak credentials.
var backupConfigFiles = []string{
	"index.php", "config.php", "wp-config.php", "configuration.php",
	"settings.py", "web.config", "application.properties", ".env",
	"database.yml", "appsettings.json", "docker-compose.yml", ".git/config",
	"config.json", "app.js", "main.py", "server.js",
	// Framework/cloud config + secret files that are very commonly left behind as
	// an in-place backup/editor-swap and leak credentials when they are:
	"application.yml", "application.yaml", "config/database.php", "config/app.php",
	"local.settings.json", "appsettings.Production.json", "secrets.json",
	"credentials.json", "firebase.json", "ormconfig.json", "knexfile.js",
	"settings.php", "parameters.yml", ".env.production", ".env.local",
	"wp-config-sample.php", "config.inc.php", "connect.php", "db.php",
}

// backupWords is a curated ~130-word set of common backup/dump base names
// (deduped; purely-numeric junk like "1"/"123" dropped as near-zero signal).
// The word count matters more than it might look: each word is
// multiplied by coreBackupExts (8 extensions) below, so going from 26->~130
// words means ~5x the wordlist-phase requests per host — accepted deliberately
// per the "don't hold back on coverage" ask; scanBackupCandidates' concurrency
// was raised accordingly (see its worker semaphore).
var backupWords = []string{
	"backup", "backups", "back", "db", "database", "databases", "db_backup",
	"database_backup", "dump", "dumps", "export", "exports", "import",
	"site", "website", "home", "main", "app", "application", "project",
	"www", "web", "webmail", "mail", "ftp",
	"data", "dataset", "old", "old_site", "new_site", "site_backup",
	"website_backup", "archive", "release", "build", "dist", "deploy",
	"deployment", "full", "full_backup", "final", "latest", "current",
	"temp", "tmp", "copy",
	"admin", "admins", "administrator", "users", "user", "support", "staff",
	"client", "clients", "customer", "customers",
	"payment", "payments", "billing", "invoice", "order", "orders",
	"auth", "login", "logout", "session",
	"sourcecode", "source", "src", "code", "repo", "git",
	"config", "configs", "configuration", "settings", "setting",
	"env", "environment", "secret", "secrets", "key", "keys", "token", "tokens",
	"credential", "credentials", "password", "passwords", "pass",
	"api", "api_backup", "service", "services", "server",
	"test", "testing", "tests", "dev", "development",
	"stage", "staging", "prod", "production", "demo", "sample",
	"log", "logs", "error", "errors", "debug", "report", "reports",
	"upload", "uploads", "file", "files", "media", "images", "img",
	"assets", "static", "public", "private", "internal",
	"mysql", "postgres", "postgresql", "mongo",
	"db1", "db2", "db_old", "db_new",
}

// domainBrandNames extracts the site's own short "brand" word(s) from a
// domain field — the leftmost label (e.g. "shop" from shop.example.com) and
// the second-level domain (e.g. "example"). These are exactly the words a
// real sysadmin names a backup after ("acmecorp_backup.zip"), which is why
// both generateBackupCandidates (bare name) and generateBrandedBackupCandidates
// (name combined with a backup word) start from the same extraction.
//
// Reuses SplitScope (a target's domain field may hold a comma/space-separated
// multi-host list or a full endpoint URL, not just a bare hostname — the
// single-endpoint scan flow stores one) and hostOfURL (handles a scheme, a
// port, and IDN normalization). An earlier version of this function did its
// own strings.Split(domain, ":")[0] BEFORE stripping any "https://" prefix,
// which silently truncated a URL-shaped domain down to the literal word
// "https" (the colon in "https://" was cut on first, before the scheme could
// ever be removed) — every brand-derived candidate below it was then built
// from garbage instead of the site's real name.
func domainBrandNames(domain string) []string {
	host := ""
	if tokens, _ := SplitScope(domain); len(tokens) > 0 {
		host = hostOfURL(tokens[0])
	}
	if host == "" {
		host = hostOfURL(domain)
	}
	if host == "" {
		return nil
	}
	parts := strings.Split(host, ".")
	seen := map[string]bool{}
	var out []string
	add := func(w string) {
		w = strings.ToLower(strings.TrimSpace(w))
		if w != "" && !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	if len(parts) > 0 {
		add(parts[0])
	}
	if len(parts) >= 2 {
		add(parts[len(parts)-2])
	}
	return out
}

// generateBackupCandidates builds extra backup paths from the target domain:
// domain-derived names, config files with backup suffixes, dated variants, and a
// bounded wordlist — all as absolute paths (leading slash).
func generateBackupCandidates(domain string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	// Base names derived from the domain: subdomain label + apex/SLD label.
	baseNames := domainBrandNames(domain)

	// Config files + in-place backup suffixes.
	for _, f := range backupConfigFiles {
		for _, suf := range backupSuffixes {
			add("/" + f + suf)
		}
	}

	// Domain-derived names + archive extensions.
	for _, name := range baseNames {
		for _, ext := range backupExtensions {
			add("/" + name + ext)
		}
	}

	// Dated variants of common backup words (core extensions only).
	year := time.Now().Year()
	for _, w := range []string{"backup", "db", "database", "site", "dump", "full"} {
		for _, y := range []int{year, year - 1} {
			for _, ext := range coreBackupExts {
				add(fmt.Sprintf("/%s_%d%s", w, y, ext))
			}
		}
	}

	// Bounded wordlist × core extensions.
	for _, w := range backupWords {
		for _, ext := range coreBackupExts {
			add("/" + w + ext)
		}
	}

	return out
}

// generateAdaptiveBackupCandidates tests only the highest-ranked program words
// with a small, high-signal extension set. This keeps the extra request budget
// predictable while finding product-specific dumps such as billing.sql or
// inventory.tar.gz that a generic list cannot name.
func generateAdaptiveBackupCandidates(words []string, limit int) []string {
	if len(words) > limit {
		words = words[:limit]
	}
	exts := []string{".zip", ".sql", ".tar.gz", ".bak", ".gz", ".old"}
	out := make([]string, 0, len(words)*len(exts))
	seen := map[string]bool{}
	for _, raw := range words {
		word := normalizeAdaptiveWord(raw)
		if word == "" {
			continue
		}
		for _, ext := range exts {
			p := "/" + word + ext
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// backupBrandSuffixes/backupBrandPrefixes model how a real backup actually
// gets named in practice: combined with the site's own name, not standing
// alone. This is the single highest-yield real-world backup-naming pattern
// (acmecorp_backup.zip, acmecorp-db-2024.sql, backup_acmecorp.tar.gz) and was
// previously not modeled at all — domain-derived candidates only tried the
// bare brand name (acmecorp.zip); the generic wordlist only tried bare backup
// words (backup.zip) — never the two combined.
var backupBrandSuffixes = []string{
	"_backup", "-backup", "_bak", "_old", "_db", "_dump", "_full", "_copy",
}

var backupBrandPrefixes = []string{
	"backup_", "backup-", "old_", "db_",
}

// brandBackupExts is deliberately smaller than coreBackupExts: each brand
// word already fans out across BOTH suffixes and prefixes below, so keeping
// the extension set tight is what keeps the per-word request cost bounded.
var brandBackupExts = []string{".zip", ".sql", ".tar.gz", ".bak"}

// generateBrandedBackupCandidates cross-products a pool of site-specific
// "brand" words — the domain's own name/subdomain labels and the target's
// highest-ranked adaptive vocabulary (product names, JS chunk names, API
// path segments, parameter names — all already mined and SCORED by
// buildAdaptiveWordlist from exactly the sources the caller passes in, so
// the caller can afford to pass a genuinely wide slice of it, not just the
// single top word) — with the naming patterns real backups actually use,
// plus a couple of dated variants. A generic wordlist alone never guesses
// the site's OWN name; the bare domain-name candidates never guess that
// it's combined with a backup word. This closes that gap.
func generateBrandedBackupCandidates(brandWords []string, limit int) []string {
	if len(brandWords) > limit {
		brandWords = brandWords[:limit]
	}
	year := time.Now().Year()
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, raw := range brandWords {
		word := normalizeAdaptiveWord(raw)
		if word == "" {
			continue
		}
		for _, suf := range backupBrandSuffixes {
			for _, ext := range brandBackupExts {
				add("/" + word + suf + ext)
			}
		}
		for _, pre := range backupBrandPrefixes {
			for _, ext := range brandBackupExts {
				add("/" + pre + word + ext)
			}
		}
		for _, y := range []int{year, year - 1} {
			add(fmt.Sprintf("/%s_%d.zip", word, y))
			add(fmt.Sprintf("/%s_%d.sql", word, y))
			add(fmt.Sprintf("/%s-%d.tar.gz", word, y))
		}
	}
	return out
}

const (
	// Raised from 18 to 20 to fit "bak"/"dumps" into the static list below
	// without shrinking the 2 slots reserved for observed application prefixes.
	nestedBackupDirectoryBudget = 20
	nestedBackupCandidateBudget = 256
)

// commonBackupDirs are the directories a real backup archive most often lives in
// (sysadmins rarely drop a dump at web root). Crossed with brand/word names below.
var commonBackupDirs = []string{
	"backup", "backups", "back", "old", "archive", "archives", "bak",
	"db", "database", "dump", "dumps", "sql", "data", "export", "exports",
	"files", "download", "downloads", "tmp", "temp", "storage", "private", "_backup",
}

// dirBackupNames are the highest-signal generic archive base names tried under
// each backup directory, IN ADDITION to the site's own brand words.
var dirBackupNames = []string{
	"backup", "db", "database", "dump", "site", "www", "web", "full", "data",
	"export", "archive", "latest", "all",
}

// dirBackupExts is the archive/dump extension set used under directories. Wider
// than the brand set (these are the likeliest dump formats), still bounded.
var dirBackupExts = []string{".zip", ".sql", ".tar.gz", ".sql.gz", ".bak", ".gz", ".7z", ".tgz"}

// generateDirectoryBackupCandidates places brand- and word-named archives UNDER
// the common backup directories (e.g. /backup/acmecorp.zip, /db/db_2025.sql.gz,
// /dumps/database.sql). The root-only generators miss this — the single most
// common real layout — so this is a pure recall win. Still zero-false-positive:
// every hit is magic-byte confirmed downstream. Bounded by `limit` so a large
// target's request budget stays predictable; directories and brand words are
// prioritised ahead of the generic fill so the likeliest paths schedule first.
func generateDirectoryBackupCandidates(brandWords []string, limit int) []string {
	if limit <= 0 {
		limit = 1500
	}
	year := time.Now().Year()
	seen := map[string]bool{}
	var out []string
	add := func(p string) bool {
		if p == "" || seen[p] {
			return true
		}
		seen[p] = true
		out = append(out, p)
		return len(out) < limit
	}

	// Normalize brand words once (dedup against generics handled per-pass).
	var brands []string
	bseen := map[string]bool{}
	for _, w := range brandWords {
		if w = normalizeAdaptiveWord(w); w != "" && !bseen[w] {
			bseen[w] = true
			brands = append(brands, w)
		}
	}

	// Pass 1 — the site's OWN name under EVERY backup directory, including dated
	// variants. This is the highest-yield layout, so it runs first and in full.
	for _, name := range brands {
		for _, dir := range commonBackupDirs {
			for _, ext := range dirBackupExts {
				if !add("/" + dir + "/" + name + ext) {
					return out
				}
			}
			for _, y := range []int{year, year - 1} {
				if !add(fmt.Sprintf("/%s/%s_%d.sql.gz", dir, name, y)) {
					return out
				}
				if !add(fmt.Sprintf("/%s/%s_%d.zip", dir, name, y)) {
					return out
				}
			}
		}
	}

	// Pass 2 — generic archive names under each directory, filling the remaining
	// budget (dir-outer so the likeliest directories are covered first).
	for _, dir := range commonBackupDirs {
		for _, name := range dirBackupNames {
			if bseen[name] {
				continue
			}
			for _, ext := range dirBackupExts {
				if !add("/" + dir + "/" + name + ext) {
					return out
				}
			}
		}
	}
	return out
}

// generateNestedBackupCandidates covers high-signal sensitive files below a
// small set of common or already-observed directories. It deliberately does not
// form a Cartesian product of the full backup corpus: the hard directory and
// request budgets keep this extension predictable even on a very large target.
// Static priorities include /back, so /back/.env is always covered.
func generateNestedBackupCandidates(observedURLs []string) []string {
	directories := []string{
		"back", "backup", "backups", "old", "archive", "archives", "private",
		"config", "configs", "conf", "data", "db", "database", "dump", "dumps",
		"bak", "tmp", "temp",
	}
	seenDir := map[string]bool{}
	orderedDirs := make([]string, 0, nestedBackupDirectoryBudget)
	addDir := func(raw string) {
		raw = strings.Trim(strings.TrimSpace(raw), "/")
		if raw == "" || seenDir[raw] || strings.Contains(raw, "..") || len(orderedDirs) >= nestedBackupDirectoryBudget {
			return
		}
		for _, segment := range strings.Split(raw, "/") {
			if segment == "" || strings.ContainsAny(segment, `?#\\`) {
				return
			}
		}
		seenDir[raw] = true
		orderedDirs = append(orderedDirs, raw)
	}
	for _, directory := range directories {
		addDir(directory)
	}
	// Observed application prefixes receive the remaining two budget slots.
	// This can cover app-specific layouts such as /portal/config/.env without
	// allowing crawl cardinality to multiply the backup request count.
	for _, raw := range observedURLs {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		clean := strings.Trim(path.Clean(parsed.Path), "/")
		if clean == "" || clean == "." {
			continue
		}
		parts := strings.Split(clean, "/")
		if len(parts) > 2 {
			parts = parts[:2]
		}
		// A final segment with a dot is likely a file rather than a directory.
		if len(parts) > 0 && strings.Contains(parts[len(parts)-1], ".") {
			parts = parts[:len(parts)-1]
		}
		if len(parts) > 0 {
			addDir(strings.Join(parts, "/"))
		}
	}

	leaves := []string{
		".env", ".env.local", ".env.production", ".env.backup", ".git/HEAD",
		"config.php", "config.php.bak", "wp-config.php", "wp-config.php.bak",
		"database.yml", "appsettings.json", "db.sql", "dump.sql", "backup.zip",
	}
	out := make([]string, 0, min(nestedBackupCandidateBudget, len(orderedDirs)*len(leaves)))
	for _, directory := range orderedDirs {
		for _, leaf := range leaves {
			if len(out) >= nestedBackupCandidateBudget {
				return out
			}
			out = append(out, "/"+directory+"/"+leaf)
		}
	}
	return out
}
