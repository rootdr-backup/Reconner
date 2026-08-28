package scanner

import (
	"bytes"
	"fmt"
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
}

// coreBackupExts is the smaller, highest-signal set used for the bulky wordlist /
// dated combinations so the per-host request count stays bounded across a scan
// that runs over dozens of hosts.
var coreBackupExts = []string{".zip", ".rar", ".sql", ".tar.gz", ".bak", ".7z", ".gz", ".old"}

// backupSuffixes are appended to REAL config/source filenames in place
// (index.php -> index.php.bak, .env -> .env.save).
var backupSuffixes = []string{".bak", ".old", ".swp", ".save", ".orig", "~", ".1", ".zip"}

// backupConfigFiles are config/source files that frequently get backed up in place.
var backupConfigFiles = []string{
	"index.php", "config.php", "wp-config.php", "configuration.php",
	"settings.py", "web.config", "application.properties", ".env",
	"database.yml", "appsettings.json", "docker-compose.yml", ".git/config",
	"config.json", "app.js", "main.py", "server.js",
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
	baseNames := map[string]bool{}
	host := strings.Split(domain, ":")[0]
	parts := strings.Split(host, ".")
	if len(parts) > 0 && parts[0] != "" {
		baseNames[parts[0]] = true
	}
	if len(parts) >= 2 {
		baseNames[parts[len(parts)-2]] = true
	}

	// Config files + in-place backup suffixes.
	for _, f := range backupConfigFiles {
		for _, suf := range backupSuffixes {
			add("/" + f + suf)
		}
	}

	// Domain-derived names + archive extensions.
	for name := range baseNames {
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
