package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReconnerNucleiTemplatesUseHighSignalProofs(t *testing.T) {
	required := map[string][]string{
		"aws-credentials-exposure.yaml": {"aws_access_key_id", "aws_secret_access_key", "condition: and"},
		"composer-auth-exposure.yaml":   {"application/json", "username|password", "condition: and"},
		"npmrc-auth-exposure.yaml":      {"_authToken|_auth", "condition: and"},
		"svn-wcdb-exposure.yaml":        {"type: binary", "53514c69746520666f726d6174203300"},
	}
	for name, proofs := range required {
		raw, err := reconnerTemplateFS.ReadFile("nucleitemplates/" + name)
		if err != nil {
			t.Fatalf("read embedded template %s: %v", name, err)
		}
		text := string(raw)
		for _, proof := range proofs {
			if !strings.Contains(text, proof) {
				t.Errorf("template %s is missing strict proof %q", name, proof)
			}
		}
		if !strings.Contains(text, "status:\n          - 200") {
			t.Errorf("template %s must require HTTP 200", name)
		}
	}
}

func TestReconnerNucleiPackLocalPositiveAndPatchedFixture(t *testing.T) {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		t.Skip("nuclei binary is not installed")
	}
	dir := materializeReconnerTemplates(t.TempDir())
	template := filepath.Join(dir, "aws-credentials-exposure.yaml")
	run := func(t *testing.T, contentType, body string) string {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.aws/credentials" && r.URL.Path != "/aws/credentials" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write([]byte(body))
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-u", server.URL, "-t", template, "-jsonl", "-silent", "-duc", "-nc") // #nosec G204 -- fixed local test arguments
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("local nuclei fixture: %v: %s", err, out)
		}
		return string(out)
	}
	credentialText := "[default]\naws_access_key_id = AKIAABCDEFGHIJKLMNOP\naws_secret_access_key = abcdefghijklmnopqrstuvwxyz0123456789ABCD\n"
	if out := run(t, "text/plain", credentialText); !strings.Contains(out, "reconner-aws-credentials-exposure") {
		t.Fatalf("strict local credential fixture was missed: %s", out)
	}
	if out := run(t, "text/html", "<pre>documentation example\n"+credentialText+"</pre>"); strings.Contains(out, "reconner-aws-credentials-exposure") {
		t.Fatalf("HTML documentation fixture produced a false positive: %s", out)
	}
}

func TestExistingReconnerTemplatesRejectGenericDocumentationPages(t *testing.T) {
	checks := map[string][]string{
		"laravel-ignition-rce.yaml": {"can_execute_commands", "application/json"},
		"phpinfo-exposure.yaml":     {"phpinfo()", "Server API"},
		"wp-config-backup.yaml":     {"DB_USER", "define(", "negative: true"},
		"git-head-exposure.yaml":    {"(?m)^ref:", "negative: true"},
	}
	for name, fragments := range checks {
		raw, err := reconnerTemplateFS.ReadFile("nucleitemplates/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range fragments {
			if !strings.Contains(string(raw), fragment) {
				t.Errorf("template %s missing FP guard %q", name, fragment)
			}
		}
	}
}
