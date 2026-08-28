package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// TestNucleiFindingsCollapseByTemplate proves the list view collapses one
// template's many near-identical URL hits into a single row with affected_count,
// picking the shortest (cleanest) URL as the representative.
func TestNucleiFindingsCollapseByTemplate(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatal(err)
	}
	// One noisy template on 3 URLs + a second distinct template on 1 URL.
	urls := []string{
		"https://example.com/a.css/api/user",
		"https://example.com/api/user", // shortest → representative
		"https://example.com/b/c/d/api/user",
	}
	for _, u := range urls {
		h.db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url) VALUES (?,?,?,?,?,?)`,
			uuid.New().String(), "t1", "jwt-confusion", "JWT Confusion", "critical", u)
	}
	h.db.Exec(`INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url) VALUES (?,?,?,?,?,?)`,
		uuid.New().String(), "t1", "nextjs-cache", "Next Cache", "high", "https://example.com/x")

	req := httptest.NewRequest("GET", "/api/targets/t1/nuclei-findings", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	rec := httptest.NewRecorder()
	h.handleListNucleiFindings(rec, req)

	var resp struct {
		Data []struct {
			TemplateID    string `json:"template_id"`
			MatchedURL    string `json:"matched_url"`
			AffectedCount int    `json:"affected_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 collapsed rows, got %d", len(resp.Data))
	}
	// critical (jwt) sorts first.
	jwt := resp.Data[0]
	if jwt.TemplateID != "jwt-confusion" || jwt.AffectedCount != 3 {
		t.Fatalf("jwt row wrong: %+v", jwt)
	}
	if jwt.MatchedURL != "https://example.com/api/user" {
		t.Fatalf("representative should be the shortest URL, got %s", jwt.MatchedURL)
	}
	if resp.Data[1].AffectedCount != 1 {
		t.Fatalf("second template affected_count = %d, want 1", resp.Data[1].AffectedCount)
	}
}
