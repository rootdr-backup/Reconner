package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestHandleMergeCorpusAcceptsBodyLargerThanOldTwoMebibyteCap proves an
// operator wordlist well above the OLD 2 MiB request-body ceiling (which
// http.MaxBytesReader would have rejected outright, surfacing as a decode
// error / 400) is now accepted end to end through the real HTTP handler. A
// full 500 MiB body would make this test needlessly slow; a body several
// times the OLD cap is enough to prove that specific limit is gone.
func TestHandleMergeCorpusAcceptsBodyLargerThanOldTwoMebibyteCap(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg.WordlistsDir = t.TempDir()

	const oldCapBytes = 2 << 20
	var sb strings.Builder
	for i := 0; sb.Len() < oldCapBytes*3; i++ {
		fmt.Fprintf(&sb, "word%d\n", i)
	}
	payload, err := json.Marshal(map[string]string{"text": sb.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= oldCapBytes {
		t.Fatalf("test fixture (%d bytes) must exceed the old %d-byte cap", len(payload), oldCapBytes)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/system/corpora/subdomain", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"category": "subdomain"})
	rec := httptest.NewRecorder()
	h.handleMergeCorpus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a %d-byte body (well above the old 2 MiB cap) must be accepted: status=%d body=%s",
			len(payload), rec.Code, rec.Body.String())
	}
}
