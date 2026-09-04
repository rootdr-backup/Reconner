package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/websocket"
)

func TestTargetRequestIdentityRoundTrip(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	body, _ := json.Marshal(map[string]any{
		"domain":          "example.com",
		"scan_user_agent": "researcher ywh-public",
		"scan_headers": map[string]string{
			"x-bug-bounty": "program-token",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/targets", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleCreateTarget(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Data.ID == "" {
		t.Fatalf("invalid create response: %v %s", err, rec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/targets/"+created.Data.ID, nil)
	getReq = mux.SetURLVars(getReq, map[string]string{"id": created.Data.ID})
	getRec := httptest.NewRecorder()
	h.handleGetTarget(getRec, getReq)
	var got struct {
		Data struct {
			ScanUserAgent string            `json:"scan_user_agent"`
			ScanHeaders   map[string]string `json:"scan_headers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Data.ScanUserAgent != "researcher ywh-public" || got.Data.ScanHeaders["X-Bug-Bounty"] != "program-token" {
		t.Fatalf("identity did not round-trip: %#v", got.Data)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
	listReq = listReq.WithContext(context.WithValue(listReq.Context(), ctxUserIDKey, adminID))
	listRec := httptest.NewRecorder()
	h.handleListTargets(listRec, listReq)
	if bytes.Contains(listRec.Body.Bytes(), []byte("program-token")) {
		t.Fatalf("private program token leaked through target list: %s", listRec.Body.String())
	}
}

func TestNormalizeScanIdentityRejectsHeaderInjection(t *testing.T) {
	bad := []map[string]string{
		{"X-Test\r\nInjected": "yes"},
		{"Bad Header": "yes"},
		{"Host": "attacker.invalid"},
		{"Keep-Alive": "timeout=5"},
		{"User-Agent": "use-the-dedicated-field"},
		{"X-Test": "one", "x-test": "two"},
	}
	for _, headers := range bad {
		if _, _, _, err := normalizeScanIdentity("", headers); err == nil {
			t.Fatalf("accepted unsafe headers: %#v", headers)
		}
	}
	if _, _, _, err := normalizeScanIdentity("ok\r\nInjected: yes", nil); err == nil {
		t.Fatal("accepted a multi-line User-Agent")
	}
}

func TestPartialTargetUpdatePreservesOmittedFields(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, err := h.db.Exec(`INSERT INTO targets(id,domain,name,description,tags,priority,notes,exclude_scope,enabled_modules,scan_user_agent,scan_headers)
		VALUES('partial-target','example.com','old name','keep description','["keep-tag"]','high','keep notes','out.example','["http_probe","monitor"]','keep-agent','{"X-Program":"keep-token"}')`)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/targets/partial-target", strings.NewReader(`{"name":"new name"}`))
	req = mux.SetURLVars(req, map[string]string{"id": "partial-target"})
	rec := httptest.NewRecorder()
	h.handleUpdateTarget(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body.String())
	}

	var name, description, tags, priority, notes, exclude, modules, userAgent, headers string
	if err := h.db.QueryRow(`SELECT name,description,tags,priority,notes,exclude_scope,enabled_modules,scan_user_agent,scan_headers
		FROM targets WHERE id='partial-target'`).Scan(&name, &description, &tags, &priority, &notes, &exclude, &modules, &userAgent, &headers); err != nil {
		t.Fatal(err)
	}
	if name != "new name" || description != "keep description" || tags != `["keep-tag"]` || priority != "high" ||
		notes != "keep notes" || exclude != "out.example" || modules != `["http_probe","monitor"]` ||
		userAgent != "keep-agent" || !strings.Contains(headers, "keep-token") {
		t.Fatalf("partial update erased data: name=%q description=%q tags=%q priority=%q notes=%q exclude=%q modules=%q ua=%q headers=%q",
			name, description, tags, priority, notes, exclude, modules, userAgent, headers)
	}
}

func TestPartialAssetUpdatePreservesNameAndValue(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain) VALUES('asset-target','example.com')`)
	_, err := h.db.Exec(`INSERT INTO assets(id,target_id,name,value,kind,asset_type,source,approval_status)
		VALUES('asset-one','asset-target','keep label','example.com','web','domain','manual','approved')`)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/targets/asset-target/assets/asset-one", strings.NewReader(`{"asset_type":"api"}`))
	req = mux.SetURLVars(req, map[string]string{"id": "asset-target", "aid": "asset-one"})
	rec := httptest.NewRecorder()
	h.handleUpdateAsset(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset update status=%d body=%s", rec.Code, rec.Body.String())
	}
	var name, value, assetType string
	if err := h.db.QueryRow(`SELECT name,value,asset_type FROM assets WHERE id='asset-one'`).Scan(&name, &value, &assetType); err != nil {
		t.Fatal(err)
	}
	if name != "keep label" || value != "example.com" || assetType != "api" {
		t.Fatalf("partial asset update erased data: name=%q value=%q type=%q", name, value, assetType)
	}
}
