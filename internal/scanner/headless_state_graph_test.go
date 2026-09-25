package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestHeadlessExtractionModelsSafeClientStates(t *testing.T) {
	for _, want := range []string{"shadowRoot", "contentDocument", `[role="tab"]`, "details:not([open])", "stateCount", "transitionURLs", "states:[...states]"} {
		if !strings.Contains(extractJS, want) {
			t.Fatalf("state-aware crawler script missing %q", want)
		}
	}
	for _, unsafe := range []string{"button:not", "form.submit(", "requestSubmit("} {
		if strings.Contains(extractJS, unsafe) {
			t.Fatalf("state-aware crawler must not auto-trigger generic mutations: %q", unsafe)
		}
	}
}

func TestHeadlessStateGraphPersistsTransitionChain(t *testing.T) {
	db, targetID := testDB(t)
	defer db.Close()
	crawler := NewHeadlessCrawler(db, nil, nil)
	crawler.storeStates(context.Background(), targetID, "https://app.test/dashboard", []string{
		"https://app.test/dashboard|FORM:profile",
		"https://app.test/dashboard|FORM:profile,DIALOG:settings",
	})
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM browser_states WHERE target_id=?`, targetID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("browser state count=%d err=%v, want 2", count, err)
	}
	var parent string
	if err := db.QueryRow(`SELECT parent_fingerprint FROM browser_states WHERE target_id=? AND sequence=1`, targetID).Scan(&parent); err != nil || parent == "" {
		t.Fatalf("second state missing transition parent: parent=%q err=%v", parent, err)
	}
}
