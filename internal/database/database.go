package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
}

func New(path string) (*DB, error) {
	// _txlock=immediate makes every BEGIN IMMEDIATE-style write transaction take
	// the write lock up front. Without it SQLite starts a DEFERRED transaction and
	// only tries to upgrade to a write lock at the first write, which deadlocks
	// when two lanes (a deep scan and a watch round) and the hourly retention
	// prune try to upgrade at the same time: SQLITE_BUSY on one of them.
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000&_synchronous=NORMAL&_cache_size=-20000&_txlock=immediate", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)
	db.SetConnMaxIdleTime(time.Minute * 10)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	return &DB{db}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

// screenshotSeq disambiguates two captures for the same host landing in the
// same nanosecond-resolution instant — plausible in practice, since captures
// now run concurrently (see internal/scanner/screenshot.go's capture
// semaphore) and a coarse system clock can still tie.
var screenshotSeq atomic.Uint64

func ScreenshotPath(screenshotsDir, host string) string {
	seq := screenshotSeq.Add(1)
	return filepath.Join(screenshotsDir, fmt.Sprintf("%s_%d_%d.png", sanitizeFilename(host), time.Now().UnixNano(), seq))
}

func sanitizeFilename(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
