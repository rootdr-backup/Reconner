package scanner

import (
	"strings"
	"testing"
)

func TestSQLiOOBPayloadsCoverEngines(t *testing.T) {
	cb := "http://oob.example.com:8080/oob/rcnoobABC"
	host := "oob.example.com:8080"
	ps := sqliOOBPayloads(cb, host, "")
	if len(ps) < 6 {
		t.Fatalf("expected a broad OOB SQLi set, got %d", len(ps))
	}
	joined := strings.Join(ps, "\n")

	// every payload must carry the reachable hostname. UNC paths cannot contain an
	// HTTP port, while Oracle HTTP payloads retain the full callback URL.
	for _, p := range ps {
		if !strings.Contains(p, "oob.example.com") {
			t.Errorf("payload missing callback host: %q", p)
		}
	}
	// Engine coverage stays DB-native and proof-only: no OS command execution.
	for _, want := range []string{"UTL_HTTP.REQUEST", "HTTPURITYPE", "xp_dirtree", "LOAD_FILE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("OOB SQLi set must cover %s", want)
		}
	}
	if strings.Contains(joined, "xp_cmdshell") || strings.Contains(joined, "TO PROGRAM") {
		t.Fatal("SQLi proof payloads must not escalate into OS command execution")
	}
	// breakout coverage: string-quote close, numeric, stacked.
	if !strings.Contains(joined, "'||") || !strings.Contains(joined, "';") {
		t.Error("must include string-context breakouts")
	}
	// double-quote string context (ANSI_QUOTES / hand-built "col"="$v" clauses)
	// and parenthesis-closing numeric context (WHERE id=($v)) must ALSO be
	// covered — a parameter injectable only in one of these contexts used to
	// get zero OOB/blind coverage at all.
	if !strings.Contains(joined, "\"||") {
		t.Error("must include a double-quote string-context breakout")
	}
	if !strings.Contains(joined, ") AND LOAD_FILE") {
		t.Error("must include a parenthesis-closing numeric-context breakout")
	}
}
