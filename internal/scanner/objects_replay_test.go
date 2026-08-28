package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestExtractObjects(t *testing.T) {
	// path id after a collection word → object
	objs := ExtractObjects("https://x.com/api/orders/1024/items", "User A")
	if len(objs) == 0 {
		t.Fatal("expected an object id from /orders/1024")
	}
	found := false
	for _, o := range objs {
		if o.Identifier == "1024" && o.Type == "numeric-id" && o.Owner == "User A" {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not extract order id: %+v", objs)
	}

	// query id by param name
	q := ExtractObjects("https://x.com/view?user_id=55&page=2", "User B")
	var gotUID, gotPage bool
	for _, o := range q {
		if o.Param == "user_id" && o.Identifier == "55" {
			gotUID = true
		}
		if o.Param == "page" {
			gotPage = true
		}
	}
	if !gotUID {
		t.Fatal("must extract user_id as object")
	}
	if gotPage {
		t.Fatal("must NOT treat page= as an object identifier")
	}

	// bare number NOT after a collection word → not an object (avoid FP on dates)
	none := ExtractObjects("https://x.com/2024/report", "User A")
	if len(none) != 0 {
		t.Fatalf("date-like path must not be an object: %+v", none)
	}
}

func TestReplayAuthorizedVsDenied(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	app := mockApp(false) // secure app
	defer app.Close()

	// owner reading own object → authorized
	own := Replay(ctx, ReplaySpec{Method: "GET", URL: app.URL + "/api/objects/1"}, ptr(idA()))
	if own.Verdict != "authorized" {
		t.Fatalf("owner must be authorized, got %q", own.Verdict)
	}
	// attacker reading owner's object on secure app → denied
	att := Replay(ctx, ReplaySpec{Method: "GET", URL: app.URL + "/api/objects/1"}, ptr(idB()))
	if att.Verdict != "denied" {
		t.Fatalf("attacker must be denied on secure app, got %q", att.Verdict)
	}
	// unauth → denied
	un := Replay(ctx, ReplaySpec{Method: "GET", URL: app.URL + "/api/objects/1"}, nil)
	if un.Verdict != "denied" {
		t.Fatalf("unauth must be denied, got %q", un.Verdict)
	}
	// replayed body must be redacted (no raw cookie leakage even if echoed)
	if strings.Contains(own.Body, "tok-a") {
		t.Fatal("replay body must not leak credentials")
	}
}

func TestReplayAcrossVulnerable(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	app := mockApp(true) // vulnerable app: any user reads any object
	defer app.Close()
	results, comparison := ReplayAcrossIdentities(ctx,
		ReplaySpec{Method: "GET", URL: app.URL + "/api/objects/1"},
		[]Identity{idA(), idB()})
	if len(results) != 3 { // unauth + A + B
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !strings.Contains(comparison, "authorized=2") {
		t.Fatalf("both identities should be authorized on vulnerable app: %q", comparison)
	}
}
