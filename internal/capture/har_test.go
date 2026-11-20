package capture

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// harFixture builds a minimal HAR 1.2 export with one entry per (method, url).
func harFixture(entries string) []byte {
	return []byte(`{"log":{"version":"1.2","creator":{"name":"pytest","version":"1"},"entries":[` + entries + `]}}`)
}

// harEntry builds one entry JSON with method substituted into the template.
func harEntryFor(method string) string {
	return fmt.Sprintf(harEntryTemplate, method)
}

const harEntryTemplate = `{
	"startedDateTime":"2026-11-20T10:00:00.000Z",
	"time":128.5,
	"request":{
		"method":"%s","url":"https://app.example.test/api/projects/42?view=full&token=secret",
		"httpVersion":"HTTP/1.1",
		"headers":[{"name":"Authorization","value":"Bearer abc.def.ghi"},{"name":"Content-Type","value":"application/json"}],
		"queryString":[{"name":"view","value":"full"},{"name":"token","value":"secret"}],
		"postData":{"mimeType":"application/json","text":"{\"name\":\"ok\"}"}
	},
	"response":{
		"status":200,"httpVersion":"HTTP/1.1",
		"headers":[{"name":"Content-Type","value":"application/json"},{"name":"Set-Cookie","value":"sid=secret"}],
		"content":{"size":11,"mimeType":"application/json","text":"{\"id\":\"42\"}"},
		"redirectURL":""
	}
}`

func TestParseHARProducesCanonicalExchanges(t *testing.T) {
	items, err := ParseHAR(harFixture(harEntryFor("get")))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(items))
	}
	ex := items[0]
	if ex.Source != "har" || ex.Sequence != 1 {
		t.Fatalf("unexpected source metadata: %+v", ex)
	}
	if ex.Request.Method != "GET" {
		t.Fatalf("method not canonicalized: %q", ex.Request.Method)
	}
	if ex.Request.URL != "https://app.example.test/api/projects/42?view=full&token=secret" {
		t.Fatalf("url not preserved: %q", ex.Request.URL)
	}
	if string(ex.Request.Body) != `{"name":"ok"}` || ex.Request.MimeType != "application/json" {
		t.Fatalf("request body lost: %+v", ex.Request)
	}
	if ex.Response.Status != 200 || string(ex.Response.Body) != `{"id":"42"}` {
		t.Fatalf("response lost: %+v", ex.Response)
	}
	if ex.Response.TimeMS != 128 {
		t.Fatalf("time (ms) not carried: %d", ex.Response.TimeMS)
	}
	if ex.StartedAt.IsZero() || ex.StartedAt.Year() != 2026 {
		t.Fatalf("startedDateTime not parsed: %v", ex.StartedAt)
	}
	if len(ex.Request.Headers) != 2 || ex.Request.Headers[0].Name != "Authorization" {
		t.Fatalf("headers lost: %+v", ex.Request.Headers)
	}
}

func TestParseHARDecodesBase64ResponseBodies(t *testing.T) {
	body := "binary\x00payload"
	entry := strings.Replace(harEntryFor("GET"),
		`"content":{"size":11,"mimeType":"application/json","text":"{\"id\":\"42\"}"}`,
		`"content":{"size":`+fmt.Sprint(len(body))+`,"mimeType":"application/octet-stream","text":"`+base64.StdEncoding.EncodeToString([]byte(body))+`","encoding":"base64"}`, 1)
	items, err := ParseHAR(harFixture(entry))
	if err != nil {
		t.Fatal(err)
	}
	if string(items[0].Response.Body) != body || items[0].Response.MimeType != "application/octet-stream" {
		t.Fatalf("base64 content lost: %+v", items[0].Response)
	}
}

func TestParseHARAcceptsSanitizedExportsWithEmptyBodies(t *testing.T) {
	// A sanitized export: no postData at all and an empty content object.
	entry := `{
	"startedDateTime":"2026-11-20T10:00:00.000Z","time":10,
	"request":{"method":"GET","url":"https://app.example.test/api/orders/77","httpVersion":"HTTP/1.1",
		"headers":[{"name":"Accept","value":"*/*"}],"queryString":[]},
	"response":{"status":204,"httpVersion":"HTTP/1.1","headers":[],"content":{"size":0,"mimeType":""},"redirectURL":""}
}`
	items, err := ParseHAR(harFixture(entry))
	if err != nil {
		t.Fatal(err)
	}
	if len(items[0].Request.Body) != 0 || len(items[0].Response.Body) != 0 {
		t.Fatal("sanitized export should import with empty bodies")
	}
	if items[0].Response.Status != 204 {
		t.Fatalf("sanitized status lost: %+v", items[0].Response)
	}
}

func TestParseHARRaisesCanonicalErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"wrong version", `{"log":{"version":"0.9","entries":[]}}`, "unsupported HAR version"},
		{"no entries", `{"log":{"version":"1.2","entries":[]}}`, "no entries"},
		{"trailing data", `{"log":{"version":"1.2","entries":[]}} {"x":1}`, "trailing data"},
		{"invalid json", `{"log":{"version":"1.2","entries":[`, "invalid HAR JSON"},
	}
	for _, tc := range cases {
		if _, err := ParseHAR([]byte(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
	}
}

func TestParseHARRejectsInvalidEntries(t *testing.T) {
	badURL := strings.Replace(harEntryFor("GET"), "https://app.example.test/api/projects/42?view=full&token=secret", "ftp://app.example.test/x", 1)
	if _, err := ParseHAR(harFixture(badURL)); err == nil || !strings.Contains(err.Error(), "HAR entry 1") {
		t.Fatalf("non-HTTP scheme accepted: %v", err)
	}
	noMethod := strings.Replace(harEntryFor("GET"), `"method":"GET"`, `"method":" "`, 1)
	if _, err := ParseHAR(harFixture(noMethod)); err == nil || !strings.Contains(err.Error(), "no request method") {
		t.Fatalf("missing method accepted: %v", err)
	}
	oversized := strings.Replace(harEntryFor("GET"), `\"name\":\"ok\"`, strings.Repeat("x", MaxMessageBytes+1), 1)
	if _, err := ParseHAR(harFixture(oversized)); err == nil || !strings.Contains(err.Error(), "body exceeds") {
		t.Fatalf("oversized body accepted: %v", err)
	}
}

func TestParseHAREnforcesItemAndImportLimits(t *testing.T) {
	// An import over the byte cap is rejected before any decoding work.
	big := append([]byte(`{"log":{"version":"1.2","entries":[{"x":`), make([]byte, MaxImportBytes+16)...)
	big = append(big, []byte(`}]}}`)...)
	if _, err := ParseHAR(big); err != ErrImportTooLarge {
		t.Fatalf("import cap not enforced: %v", err)
	}
}

func TestParseHARIsDeterministicForDuplicates(t *testing.T) {
	items, err := ParseHAR(harFixture(harEntryFor("GET") + "," + harEntryFor("GET")))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Sequence != 1 || items[1].Sequence != 2 {
		t.Fatalf("sequences not stable: %+v", items)
	}
	if string(RequestShapeBytes(items[0].Request)) != string(RequestShapeBytes(items[1].Request)) {
		t.Fatal("identical entries must produce identical dedup shapes")
	}
}

func TestParseHARIgnoresExtensionFields(t *testing.T) {
	// The HAR spec allows exporters to add custom fields; a Chrome/Firefox
	// export full of custom keys must still import.
	raw := strings.Replace(string(harFixture(harEntryFor("GET"))),
		`"creator":{"name":"pytest","version":"1"}`,
		`"creator":{"name":"pytest","version":"1","comment":"custom"},"browser":{"name":"x"},"pages":[],"_exporter":"firefox"`, 1)
	if _, err := ParseHAR([]byte(raw)); err != nil {
		t.Fatalf("spec-compliant extension fields rejected: %v", err)
	}
}
