package scanner

import (
	"strings"
	"testing"
)

func TestSQLiOOBPayloadsCoverEngines(t *testing.T) {
	cb := "http://oob.example.com:8080/oob/rcnoobABC"
	host := "oob.example.com:8080"
	ps := sqliOOBPayloads(cb, host)
	if len(ps) < 6 {
		t.Fatalf("expected a broad OOB SQLi set, got %d", len(ps))
	}
	joined := strings.Join(ps, "\n")

	// every payload must carry our callback host so any DB hit attributes back.
	for _, p := range ps {
		if !strings.Contains(p, host) {
			t.Errorf("payload missing callback host: %q", p)
		}
	}
	// engine coverage: Oracle HTTP, MSSQL cmdshell, UNC/DNS exfil.
	for _, want := range []string{"UTL_HTTP.REQUEST", "HTTPURITYPE", "xp_cmdshell", "xp_dirtree", "LOAD_FILE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("OOB SQLi set must cover %s", want)
		}
	}
	// breakout coverage: string-quote close, numeric, stacked.
	if !strings.Contains(joined, "'||") || !strings.Contains(joined, "';") {
		t.Error("must include string-context breakouts")
	}
}
