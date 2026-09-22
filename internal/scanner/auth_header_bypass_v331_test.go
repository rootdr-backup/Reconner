package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestAuthHeaderBypassV331_MalformedCredentialMatrix(t *testing.T) {
	withLoopbackAllowed(t)
	cases := []struct {
		name       string
		status     int
		authorizer string
		wantLabel  string
	}{
		{"401-bare-basic", http.StatusUnauthorized, "Basic", "missing credentials"},
		{"403-bare-basic", http.StatusForbidden, "Basic", "missing credentials"},
		{"401-invalid-basic-token", http.StatusUnauthorized, "Basic !!!", "invalid token68"},
		{"401-empty-basic-pair", http.StatusUnauthorized, "Basic Og==", "empty user/password"},
		{"401-bare-bearer", http.StatusUnauthorized, "Bearer", "missing token"},
		{"401-null-bearer", http.StatusUnauthorized, "Bearer null", "Bearer null"},
		{"401-undefined-bearer", http.StatusUnauthorized, "Bearer undefined", "Bearer undefined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == tc.authorizer {
					fmt.Fprint(w, `{"account":"local-admin","scope":"settings:read","proof":"stable-private-response"}`)
					return
				}
				w.Header().Set("WWW-Authenticate", `Basic realm="local-fixture"`)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, "stable local authentication wall with no protected account data")
			}))
			defer srv.Close()

			method, evidence, confidence, location := check403Bypass(context.Background(), srv.URL+"/api/private")
			if !strings.Contains(method, tc.wantLabel) {
				t.Fatalf("method=%q, want label containing %q", method, tc.wantLabel)
			}
			wantControl := fmt.Sprintf("%d/%d", tc.status, tc.status)
			if !strings.Contains(evidence, wantControl) {
				t.Fatalf("evidence=%q, want stable %s control", evidence, wantControl)
			}
			if confidence != ConfPoC || location != "authorization_header" {
				t.Fatalf("confidence/location=%d/%q, want %d/authorization_header", confidence, location, ConfPoC)
			}
		})
	}
}

func TestAuthHeaderBypassV331_RejectsMalformedCredentialsWithoutAccess(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="local-fixture"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "stable local authentication wall with no protected account data")
	}))
	defer srv.Close()

	if method, evidence, confidence, location := check403Bypass(context.Background(), srv.URL+"/api/private"); method != "" || evidence != "" || confidence != 0 || location != "" {
		t.Fatalf("rejected malformed credentials produced finding: %q %q %d %q", method, evidence, confidence, location)
	}
}

func TestAuthHeaderBypassV331_RequiresStableDenialStatus(t *testing.T) {
	withLoopbackAllowed(t)
	var controls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Basic" {
			fmt.Fprint(w, `{"account":"local-admin","scope":"settings:read","proof":"stable-private-response"}`)
			return
		}
		if controls.Add(1) > 1 {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "stable local authorization wall that changed status")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "stable local authentication wall that changed status")
	}))
	defer srv.Close()

	if method, _, _, _ := check403Bypass(context.Background(), srv.URL+"/api/private"); method != "" {
		t.Fatalf("unstable 401/403 controls promoted via %s", method)
	}
}

func TestAuthHeaderBypassV331_RunIncludes401And403Services(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Basic" {
			fmt.Fprint(w, `{"account":"local-admin","scope":"settings:read","proof":"stable-private-response"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/unauthorized") {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		fmt.Fprint(w, "stable local access-control wall with no protected account data")
	}))
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	for _, item := range []struct {
		path   string
		status int
	}{{"/unauthorized", 401}, {"/forbidden", 403}} {
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,?,'probe')`,
			uuid.NewString(), targetID, srv.URL+item.path, item.status); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run403Bypass(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var confirmed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='403_bypass'
		AND location='authorization_header' AND severity='high' AND status='CONFIRMED'`, targetID).Scan(&confirmed); err != nil {
		t.Fatal(err)
	}
	if confirmed != 2 {
		t.Fatalf("confirmed 401/403 malformed-authorization bypasses=%d, want 2", confirmed)
	}
}
