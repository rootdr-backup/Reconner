package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

func newIsoHandler(t *testing.T) (*Handler, int64) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AdminUsername: "admin", AdminPassword: config.DefaultAdminPassword}
	a := auth.New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatal(err)
	}
	var adminID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	return &Handler{db: db, cfg: cfg, auth: a, logger: logger.New("error")}, adminID
}

// serveWithVars runs h.targetScopeMiddleware around a 200 handler, injecting the
// {id} mux var and the given session cookie, mirroring how gorilla routes it.
func serveWithVars(h *Handler, sid, targetID string) *httptest.ResponseRecorder {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest("GET", "/api/targets/"+targetID, nil)
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	h.targetScopeMiddleware(next).ServeHTTP(rec, req)
	return rec
}

func TestTargetScopeIsolation(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	// admin owns t-admin, bob owns t-bob
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)

	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	// bob may reach his own target...
	if rec := serveWithVars(h, bobSID, "t-bob"); rec.Code != http.StatusOK {
		t.Errorf("bob → own target: got %d, want 200", rec.Code)
	}
	// ...but NOT the admin's target.
	if rec := serveWithVars(h, bobSID, "t-admin"); rec.Code != http.StatusForbidden {
		t.Errorf("bob → admin's target: got %d, want 403", rec.Code)
	}
	// admin may reach any target.
	if rec := serveWithVars(h, adminSID, "t-bob"); rec.Code != http.StatusOK {
		t.Errorf("admin → member's target: got %d, want 200", rec.Code)
	}
}

func TestListTargetsScopedToOwner(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, _ := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)

	list := func(uid int64) []map[string]any {
		req := httptest.NewRequest("GET", "/api/targets", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, uid))
		rec := httptest.NewRecorder()
		h.handleListTargets(rec, req)
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Data
	}

	if got := list(bob.ID); len(got) != 1 || got[0]["domain"] != "bob.example" {
		t.Errorf("member list must show only their own target, got %v", got)
	}
	if got := list(adminID); len(got) != 2 {
		t.Errorf("admin list must show all targets, got %d", len(got))
	}
}
