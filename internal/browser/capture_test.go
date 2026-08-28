package browser

import "testing"

const sampleState = `{
  "cookies": [
    {"name":"session","value":"SECRET1","domain":".app.example.com","path":"/"},
    {"name":"csrf","value":"TOK2","domain":"app.example.com","path":"/"},
    {"name":"other","value":"X","domain":"tracker.evil.com","path":"/"}
  ],
  "origins": [
    {"origin":"https://app.example.com","localStorage":[{"name":"auth","value":"LS1"}]},
    {"origin":"https://cdn.example.com","localStorage":[{"name":"junk","value":"NO"}]}
  ]
}`

func TestParseStorageState(t *testing.T) {
	cc, err := ParseStorageState([]byte(sampleState), "https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// cookies for the target host only (session + csrf), sorted; NOT the evil.com one
	if cc.CookieHeader != "csrf=TOK2; session=SECRET1" {
		t.Fatalf("unexpected cookie header: %q", cc.CookieHeader)
	}
	// localStorage only for the exact origin host
	if cc.LocalStorage["auth"] != "LS1" {
		t.Fatalf("missing target localStorage: %+v", cc.LocalStorage)
	}
	if _, ok := cc.LocalStorage["junk"]; ok {
		t.Fatal("must not capture other-origin localStorage")
	}
	if h := cc.Headers(); h["Cookie"] == "" {
		t.Fatal("Headers() must expose Cookie")
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := ParseStorageState([]byte(`{"cookies":[],"origins":[]}`), "https://app.example.com"); err == nil {
		t.Fatal("empty session material must error")
	}
	if _, err := ParseStorageState([]byte(`not json`), "https://x"); err == nil {
		t.Fatal("invalid json must error")
	}
}

func TestDomainMatches(t *testing.T) {
	cases := []struct {
		cd, host string
		want     bool
	}{
		{".example.com", "app.example.com", true},
		{"example.com", "app.example.com", true},
		{"app.example.com", "app.example.com", true},
		{"evil.com", "app.example.com", false},
		{"", "app.example.com", true},
	}
	for _, c := range cases {
		if got := domainMatches(c.cd, c.host); got != c.want {
			t.Errorf("domainMatches(%q,%q)=%v want %v", c.cd, c.host, got, c.want)
		}
	}
}
