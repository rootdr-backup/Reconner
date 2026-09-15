package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFreshConfigGeneratesUniqueDeploymentSecrets(t *testing.T) {
	loadAt := func(path string) *Config {
		t.Helper()
		t.Setenv("RECON_CONFIG", path)
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg1 := loadAt(filepath.Join(t.TempDir(), "one.json"))
	cfg2 := loadAt(filepath.Join(t.TempDir(), "two.json"))
	if cfg1.SessionSecret == "" || cfg1.CSRFSecret == "" || cfg1.SessionSecret == legacySessionSecret || cfg1.CSRFSecret == legacyCSRFSecret {
		t.Fatal("fresh config retained an empty or historical static secret")
	}
	if cfg1.SessionSecret == cfg2.SessionSecret || cfg1.CSRFSecret == cfg2.CSRFSecret {
		t.Fatal("independent installs received identical deployment secrets")
	}
	info, err := os.Stat(cfg1.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
	for _, dir := range []string{cfg1.DataDir, cfg1.ToolsDir, cfg1.ScreenshotsDir, cfg1.WordlistsDir, cfg1.NucleiTemplates} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Errorf("fresh install directory %q is unavailable: %v", dir, err)
		}
	}
}

func TestLegacySecretRotationMarkerIsPersistedAndCleared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	raw, _ := json.Marshal(map[string]any{
		"session_secret": legacySessionSecret,
		"csrf_secret":    legacyCSRFSecret,
	})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECON_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	old, needed, err := cfg.BeginLegacySecretRotation()
	if err != nil || !needed || old != legacySessionSecret {
		t.Fatalf("begin rotation = (%q,%v,%v)", old, needed, err)
	}
	if cfg.SessionSecret == old || cfg.CSRFSecret == legacyCSRFSecret || cfg.PreviousSessionSecret != old || !cfg.SecretRotationPending {
		t.Fatal("rotation did not install new secrets with a resumable old-key marker")
	}
	reloaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if resumeOld, resume, err := reloaded.BeginLegacySecretRotation(); err != nil || !resume || resumeOld != old {
		t.Fatalf("resume rotation = (%q,%v,%v)", resumeOld, resume, err)
	}
	if err := reloaded.FinishLegacySecretRotation(); err != nil {
		t.Fatal(err)
	}
	final, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if final.PreviousSessionSecret != "" || final.SecretRotationPending || final.SessionSecret != reloaded.SessionSecret {
		t.Fatal("rotation marker was not cleared without changing the new key")
	}
}

func TestEmptyLegacySecretRotationCanResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-legacy.json")
	if err := os.WriteFile(path, []byte(`{"session_secret":"","csrf_secret":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECON_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	old, needed, err := cfg.BeginLegacySecretRotation()
	if err != nil || !needed || old != "" || !cfg.SecretRotationPending {
		t.Fatalf("begin empty-key rotation = (%q,%v,%v), pending=%v", old, needed, err, cfg.SecretRotationPending)
	}
	reloaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	resumeOld, resume, err := reloaded.BeginLegacySecretRotation()
	if err != nil || !resume || resumeOld != "" || reloaded.SessionSecret != cfg.SessionSecret {
		t.Fatalf("resume empty-key rotation = (%q,%v,%v)", resumeOld, resume, err)
	}
}
