package scanner

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

type captureTransport struct{ req *http.Request }

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
}

func TestRequestIdentityTargetOverrideAndScope(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO targets (id,domain,scan_user_agent,scan_headers) VALUES ('t','example.com','Target Agent','{"X-Program":"target","X-Only":"yes"}')`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ScanUserAgent: "Global Agent", ScanHeaders: map[string]string{"X-Program": "global", "X-Global": "yes"}}
	ctx := WithTargetRequestIdentity(context.Background(), db, cfg, "t")

	cap := &captureTransport{}
	client := &http.Client{Transport: identityRoundTripper{base: cap}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/path", nil)
	req.Header.Set("X-Only", "detector")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if got := cap.req.Header.Get("User-Agent"); got != "Target Agent" {
		t.Fatalf("User-Agent=%q", got)
	}
	if got := cap.req.Header.Get("X-Program"); got != "target" {
		t.Fatalf("target header did not override global: %q", got)
	}
	if got := cap.req.Header.Get("X-Only"); got != "detector" {
		t.Fatalf("explicit detector header was overwritten: %q", got)
	}
	if cap.req.Header.Get("X-Global") != "yes" {
		t.Fatal("global non-conflicting header missing")
	}

	offScope, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://telemetry.invalid/", nil)
	if _, err := client.Do(offScope); err != nil {
		t.Fatal(err)
	}
	if cap.req.Header.Get("X-Program") != "" || cap.req.Header.Get("User-Agent") != "" {
		t.Fatalf("identity leaked off-scope: %#v", cap.req.Header)
	}

	originProbe, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://192.0.2.20/", nil)
	originProbe.Host = "example.com"
	if _, err := client.Do(originProbe); err != nil {
		t.Fatal(err)
	}
	if cap.req.Header.Get("User-Agent") != "Target Agent" || cap.req.Header.Get("X-Program") != "target" {
		t.Fatalf("direct-origin probe missed target identity: %#v", cap.req.Header)
	}
}

func TestRequestIdentityOptOutAndToolArgs(t *testing.T) {
	id := requestIdentity{userAgent: "Required UA", headers: http.Header{"X-Program": {"token"}}, hosts: []string{"example.com"}}
	ctx := context.WithValue(context.Background(), requestIdentityKey{}, id)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "SQLI-PAYLOAD")
	if got := ApplyRequestIdentity(SkipRequestIdentity(req)).Header.Get("User-Agent"); got != "SQLI-PAYLOAD" {
		t.Fatalf("payload UA overwritten: %q", got)
	}
	args := strings.Join(ToolRequestIdentityArgs(ctx, "nuclei"), "|")
	if !strings.Contains(args, "User-Agent: Required UA") || !strings.Contains(args, "X-Program: token") {
		t.Fatalf("tool args missing identity: %q", args)
	}
	katana := ToolRequestIdentityArgs(ctx, "katana")
	if len(katana) != 4 || katana[0] != "-H" || katana[2] != "-H" {
		t.Fatalf("unexpected katana args: %#v", katana)
	}
	hakrawler := ToolRequestIdentityArgs(ctx, "hakrawler")
	if len(hakrawler) != 2 || hakrawler[0] != "-h" || !strings.Contains(hakrawler[1], ";;") {
		t.Fatalf("unexpected hakrawler args: %#v", hakrawler)
	}
	if got := ToolRequestIdentityArgs(ctx, "subfinder"); got != nil {
		t.Fatalf("identity must not be sent to a passive provider: %#v", got)
	}
}

func TestRequestURLInTargetScopeHandlesMultipleAssets(t *testing.T) {
	ctx := context.Background()
	if !requestURLInTargetScope(ctx, "one.example,https://two.example/app", "https://api.two.example/data") {
		t.Fatal("multi-asset scope rejected an allowed subdomain")
	}
	if requestURLInTargetScope(ctx, "one.example,https://two.example/app", "https://telemetry.invalid/") {
		t.Fatal("multi-asset scope allowed an unrelated host")
	}
}

func TestRequestIdentityPreservesURLDelimiters(t *testing.T) {
	seed := "https://api.example.com/v1/items;active?q=one,two"
	parts, _ := SplitScope(seed)
	if len(parts) != 1 || parts[0] != seed {
		t.Fatalf("endpoint URL was split into fake assets: %#v", parts)
	}
	hosts := appendScopeHosts(nil, seed)
	if len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Fatalf("endpoint URL produced wrong identity hosts: %#v", hosts)
	}
}

func TestSplitScopeDoesNotTreatMixedURLAndHostAsOneSeed(t *testing.T) {
	parts, _ := SplitScope("https://app.example.com/path, api.second.test")
	if len(parts) != 2 || parts[0] != "https://app.example.com/path" || parts[1] != "api.second.test" {
		t.Fatalf("mixed target scope parsed incorrectly: %#v", parts)
	}
	hosts := appendScopeHosts(nil, "https://app.example.com/path, api.second.test")
	if len(hosts) != 2 || hosts[0] != "app.example.com" || hosts[1] != "api.second.test" {
		t.Fatalf("mixed target identity hosts parsed incorrectly: %#v", hosts)
	}
}
