package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test the FP/FN-critical response classifiers and the cross-identity replay
// primitive against a mock app that models a real BOLA: object 1 belongs to
// user-a, object 2 to user-b; each user may read their own; unauth is denied.
// A vulnerable endpoint additionally lets ANY authenticated user read ANY object.

func mockApp(vulnerable bool) *httptest.Server {
	// token → owner
	owner := map[string]string{"tok-a": "user-a", "tok-b": "user-b"}
	objects := map[string]string{
		"1": "user-a", // object 1 owned by user-a
		"2": "user-b",
	}
	body := func(objID, who string) string {
		return strings.Repeat("X", 200) + "\nobject=" + objID + " owner=" + who + " viewer=" + who
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		objID := strings.TrimPrefix(r.URL.Path, "/api/objects/")
		who := owner[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if who == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		obj, ok := objects[objID]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if obj != who && !vulnerable {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// vulnerable app returns the OWNER'S object bytes to any viewer
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body(objID, obj)))
	}))
}

func idA() Identity {
	return Identity{ID: "a", Label: "User A", Headers: map[string]string{"Authorization": "Bearer tok-a"}, IsBaseline: true}
}
func idB() Identity {
	return Identity{ID: "b", Label: "User B", Headers: map[string]string{"Authorization": "Bearer tok-b"}}
}

func TestClassifiers(t *testing.T) {
	if deniesAccess(IdentityResponse{Status: 200, Len: 300, Body: strings.Repeat("x", 300), CT: "application/json"}) {
		t.Error("a substantial 200 JSON must NOT be classified as denied")
	}
	if !deniesAccess(IdentityResponse{Status: 403}) {
		t.Error("403 must be denied")
	}
	if !deniesAccess(IdentityResponse{Status: 302}) {
		t.Error("redirect must be denied")
	}
	if !looksLikeAuthObject(IdentityResponse{Status: 200, Len: 300, Body: strings.Repeat("x", 300), CT: "application/json"}) {
		t.Error("substantial 200 object must be an auth object")
	}
	if looksLikeAuthObject(IdentityResponse{Status: 200, Len: 300, Body: strings.Repeat("x", 300), CT: "image/png"}) {
		t.Error("static content-type must not be an auth object")
	}
}

func TestBodiesSameObject(t *testing.T) {
	a := strings.Repeat("A", 500)
	if !bodiesSameObject(a, a) {
		t.Error("identical bodies must match")
	}
	if bodiesSameObject(a, strings.Repeat("B", 500)) {
		t.Error("same-length different bodies must NOT match")
	}
}

// The decisive test: replaying user-a's object as user-b must yield user-a's
// bytes on a vulnerable app (→ provable BOLA) and be denied on a safe one.
func TestCrossIdentityReplay(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()

	vuln := mockApp(true)
	defer vuln.Close()
	url := vuln.URL + "/api/objects/1" // object owned by user-a
	owner := fetchAs(ctx, url, ptr(idA()))
	unauth := fetchAs(ctx, url, nil)
	attacker := fetchAs(ctx, url, ptr(idB()))
	if !looksLikeAuthObject(owner) {
		t.Fatal("owner must see their object")
	}
	if !deniesAccess(unauth) {
		t.Fatal("unauth must be denied")
	}
	if !looksLikeAuthObject(attacker) || !bodiesSameObject(owner.Body, attacker.Body) {
		t.Fatal("vulnerable app: attacker must read the owner's object (BOLA)")
	}

	safe := mockApp(false)
	defer safe.Close()
	surl := safe.URL + "/api/objects/1"
	sowner := fetchAs(ctx, surl, ptr(idA()))
	sattacker := fetchAs(ctx, surl, ptr(idB()))
	if !looksLikeAuthObject(sowner) {
		t.Fatal("owner must see their object on safe app")
	}
	if looksLikeAuthObject(sattacker) {
		t.Fatal("safe app: attacker must be denied — no false-positive BOLA")
	}
}

func ptr(i Identity) *Identity { return &i }

// Session validation must not equate 200 with authenticated: it fetches a
// profile endpoint that returns the username only WITH a valid session.
func TestSessionValidation(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			if r.Header.Get("Authorization") == "Bearer tok-a" {
				_, _ = w.Write([]byte(strings.Repeat("x", 200) + "\nusername: alice"))
				return
			}
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	good := Identity{Label: "A", Headers: map[string]string{"Authorization": "Bearer tok-a"},
		ValidationURL: srv.URL + "/me", ValidationSignal: "username: alice"}
	if got := ValidateSession(ctx, good); got != "authenticated" {
		t.Fatalf("valid session must be authenticated, got %q", got)
	}

	expired := Identity{Label: "A", Headers: map[string]string{"Authorization": "Bearer stale"},
		ValidationURL: srv.URL + "/me", ValidationSignal: "username: alice"}
	if got := ValidateSession(ctx, expired); got != "expired" {
		t.Fatalf("stale session must be expired, got %q", got)
	}
}

// The authorization matrix must record authorized own-access and denied
// cross-access on a SECURE app (no false vuln).
func TestAuthzMatrixSecure(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	app := mockApp(false)
	defer app.Close()
	cells := AuthzMatrix(ctx, idA(), idB(), app.URL+"/api/objects/1", app.URL+"/api/objects/2")
	// order: A→A, B→B, A→B, B→A
	if cells[0].Verdict != "authorized" || cells[1].Verdict != "authorized" {
		t.Fatalf("own-object access must be authorized: %+v", cells[:2])
	}
	if cells[2].Verdict != "denied" || cells[3].Verdict != "denied" {
		t.Fatalf("cross-object access must be denied on a secure app: %+v", cells[2:])
	}
}
