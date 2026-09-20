package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

func TestBootRespectsConfiguredResourceLimits(t *testing.T) {
	dataDir := t.TempDir()
	cpath := filepath.Join(dataDir, "config.json")
	configJSON := map[string]any{
		"host":             "127.0.0.1",
		"port":             0,
		"data_dir":         dataDir,
		"database_path":    filepath.Join(dataDir, "recon.db"),
		"tools_dir":        filepath.Join(dataDir, "tools"),
		"screenshots_dir":  filepath.Join(dataDir, "screenshots"),
		"wordlists_dir":    filepath.Join(dataDir, "wordlists"),
		"nuclei_templates": filepath.Join(dataDir, "nuclei"),
		"session_secret":   "test-session-secret-do-not-use",
		"admin_username":   "admin",
		"admin_password":   "test-password",
		"workers": map[string]any{
			"subdomain_enumeration": 2,
			"http_probing":          3,
			"crawling":              1,
			"js_analysis":           2,
			"directory_discovery":   1,
			"nuclei":                1,
		},
		"limits": map[string]any{
			"max_concurrent_targets": 1,
			"max_scans_per_target":   1,
			"max_tool_executions":    2,
			"max_memory_mb":          256,
			"parallel_modules":       false,
			"http_rate_limit":        20,
		},
	}
	raw, err := json.Marshal(configJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cpath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECON_CONFIG", cpath)
	t.Setenv("RECON_NO_AUTOTUNE", "1")

	app, err := boot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		app.scheduler.Stop()
		app.telegram.Stop()
		_ = app.db.Close()
	})

	if app.cfg.Limits.MaxMemoryMB != 256 || app.cfg.Limits.ParallelModules {
		t.Fatalf("boot overwrote configured limits: %+v", app.cfg.Limits)
	}
	wantWorkers := config.WorkerConfig{
		SubdomainEnumeration: 2,
		HTTPProbing:          3,
		Crawling:             1,
		JSAnalysis:           2,
		DirectoryDiscovery:   1,
		Nuclei:               1,
	}
	if app.cfg.Workers != wantWorkers {
		t.Fatalf("boot overwrote configured workers: got %+v want %+v", app.cfg.Workers, wantWorkers)
	}
}

func TestRotateStoredSecretsRekeysDatabaseAndIsRetrySafe(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "rotation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	const oldKey, newKey = "old-deployment-key", "new-deployment-key"
	oldBox := secret.New(oldKey)
	headers := oldBox.Encrypt(`{"Cookie":"session=private"}`)
	storage := oldBox.Encrypt(`{"access_token":"private"}`)
	botToken := oldBox.Encrypt("123456:bot-secret")
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target-1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identities(id,target_id,headers_json,storage_json) VALUES('identity-1','target-1',?,?)`, headers, storage); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telegram_config(id,encrypted_bot_token) VALUES(1,?)`, botToken); err != nil {
		t.Fatal(err)
	}

	if err := rotateStoredSecrets(db.DB, oldKey, newKey); err != nil {
		t.Fatal(err)
	}
	readCiphertexts := func() (string, string, string) {
		t.Helper()
		var gotHeaders, gotStorage, gotToken string
		if err := db.QueryRow(`SELECT headers_json,storage_json FROM identities WHERE id='identity-1'`).Scan(&gotHeaders, &gotStorage); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT encrypted_bot_token FROM telegram_config WHERE id=1`).Scan(&gotToken); err != nil {
			t.Fatal(err)
		}
		return gotHeaders, gotStorage, gotToken
	}
	gotHeaders, gotStorage, gotToken := readCiphertexts()
	newBox := secret.New(newKey)
	if newBox.Decrypt(gotHeaders) != `{"Cookie":"session=private"}` ||
		newBox.Decrypt(gotStorage) != `{"access_token":"private"}` ||
		newBox.Decrypt(gotToken) != "123456:bot-secret" {
		t.Fatal("one or more stored secrets were not re-keyed")
	}
	if oldBox.Decrypt(gotHeaders) != "" || oldBox.Decrypt(gotStorage) != "" || oldBox.Decrypt(gotToken) != "" {
		t.Fatal("old deployment key still decrypts a rotated value")
	}

	beforeRetry := []string{gotHeaders, gotStorage, gotToken}
	if err := rotateStoredSecrets(db.DB, oldKey, newKey); err != nil {
		t.Fatal(err)
	}
	afterHeaders, afterStorage, afterToken := readCiphertexts()
	afterRetry := []string{afterHeaders, afterStorage, afterToken}
	for i := range beforeRetry {
		if afterRetry[i] != beforeRetry[i] {
			t.Fatal("retry changed ciphertext that was already encrypted with the new key")
		}
	}
}

func TestRotateStoredSecretsRecoversUndecryptableTelegramToken(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "rotation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	const oldKey, newKey = "old-deployment-key", "new-deployment-key"
	headers := secret.New(oldKey).Encrypt(`{"Cookie":"session=private"}`)
	badToken := secret.New("unrelated-key").Encrypt("123456:bot-secret")
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target-1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identities(id,target_id,headers_json) VALUES('identity-1','target-1',?)`, headers); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telegram_config(id,encrypted_bot_token,enabled) VALUES(1,?,1)`, badToken); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telegram_chats(id,chat_id,label,role) VALUES('chat-1','1340857378','owner','admin')`); err != nil {
		t.Fatal(err)
	}

	if err := rotateStoredSecrets(db.DB, oldKey, newKey); err != nil {
		t.Fatal(err)
	}
	var token, lastError, rotatedHeaders string
	var enabled, chats int
	if err := db.QueryRow(`SELECT encrypted_bot_token,enabled,last_error FROM telegram_config WHERE id=1`).Scan(&token, &enabled, &lastError); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT headers_json FROM identities WHERE id='identity-1'`).Scan(&rotatedHeaders); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM telegram_chats`).Scan(&chats); err != nil {
		t.Fatal(err)
	}
	if token != "" || enabled != 0 || !strings.Contains(lastError, "enter it again") {
		t.Fatalf("telegram recovery = token %q, enabled %d, error %q", token, enabled, lastError)
	}
	if secret.New(newKey).Decrypt(rotatedHeaders) != `{"Cookie":"session=private"}` {
		t.Fatal("identity secret was not rotated")
	}
	if chats != 1 {
		t.Fatalf("telegram chats = %d, want 1", chats)
	}
}

func TestRotateStoredSecretsFailsClosedForIdentitySecrets(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "rotation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	badHeaders := secret.New("unrelated-key").Encrypt(`{"Authorization":"private"}`)
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target-1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identities(id,target_id,headers_json) VALUES('identity-1','target-1',?)`, badHeaders); err != nil {
		t.Fatal(err)
	}
	if err := rotateStoredSecrets(db.DB, "old-key", "new-key"); err == nil || !strings.Contains(err.Error(), "identities.headers_json") {
		t.Fatalf("rotation error = %v, want fail-closed identity error", err)
	}
}
