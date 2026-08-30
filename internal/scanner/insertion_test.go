package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"
)

func reqBody(t *testing.T, ip insertionPoint, value string) string {
	t.Helper()
	req, err := buildInjectedRequest(context.Background(), ip, value, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(req.Body)
	return string(b)
}

func TestInjectedPOSTPreservesRequiredSiblingFields(t *testing.T) {
	formIP := insertionPoint{
		URL: "http://x.test/save", Param: "lookup", Method: "POST",
		Siblings: map[string]string{"csrf": "token-123", "mode": "strict", "lookup": "old"},
	}
	form, err := url.ParseQuery(reqBody(t, formIP, "1'"))
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("csrf") != "token-123" || form.Get("mode") != "strict" || form.Get("lookup") != "1'" {
		t.Fatalf("form replay lost/overwrote sibling fields: %#v", form)
	}

	jsonIP := insertionPoint{
		URL: "http://x.test/api", Param: "lookup", Method: "POST", ContentType: "application/json",
		Siblings: map[string]string{"csrf": "token-123", "tenant": "acme", "lookup": "old"},
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(reqBody(t, jsonIP, "x'")), &body); err != nil {
		t.Fatal(err)
	}
	if body["csrf"] != "token-123" || body["tenant"] != "acme" || body["lookup"] != "x'" {
		t.Fatalf("JSON replay lost/overwrote sibling fields: %#v", body)
	}
}

func TestInjectedRequestPreservesNonPOSTAPIMethodAndQueryPlacement(t *testing.T) {
	put := insertionPoint{URL: "http://x.test/api/item", Param: "name", Method: "PUT", ContentType: "application/json", Location: "query"}
	req, err := buildInjectedRequest(context.Background(), put, "probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "PUT" || req.Header.Get("Content-Type") != "application/json" || req.Body == nil {
		t.Fatalf("PUT JSON request contract lost: method=%s content-type=%s body=%v", req.Method, req.Header.Get("Content-Type"), req.Body)
	}

	postQuery := insertionPoint{URL: "http://x.test/search?page=1", Param: "page", Method: "POST", Location: "query"}
	req, err = buildInjectedRequest(context.Background(), postQuery, "2 OR 1=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.URL.Query().Get("page") != "2 OR 1=1" || req.Body != nil {
		t.Fatalf("explicit POST query parameter was moved into a body: method=%s url=%s body=%v", req.Method, req.URL, req.Body)
	}
}

func TestMultipartInjectionPreservesTextSiblings(t *testing.T) {
	ip := insertionPoint{
		URL: "http://x.test/upload", Param: "title", Value: "old", Method: "POST",
		ContentType: "multipart/form-data", Location: "multipart",
		Siblings: map[string]string{"csrf": "tok123", "folder": "reports"},
	}
	req, err := buildInjectedRequest(context.Background(), ip, "x' OR '1'='1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	if req.FormValue("csrf") != "tok123" || req.FormValue("folder") != "reports" || req.FormValue("title") != "x' OR '1'='1" {
		t.Fatalf("multipart mutation lost fields: %#v", req.MultipartForm.Value)
	}
}

func TestXMLInjectionPreservesDocumentAndEscapesSyntax(t *testing.T) {
	ip := insertionPoint{
		URL: "http://x.test/xml", Param: "lookup", Method: "POST", ContentType: "application/xml", Location: "xml",
		Siblings: map[string]string{"tenant": "acme", "csrf": "a&b"},
	}
	req, err := buildInjectedRequest(context.Background(), ip, "x' OR 1<2", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(req.Body)
	body := string(b)
	if req.Header.Get("Content-Type") != "application/xml" || !strings.Contains(body, "<tenant>acme</tenant>") ||
		!strings.Contains(body, "<csrf>a&amp;b</csrf>") || !strings.Contains(body, "1&lt;2") {
		t.Fatalf("XML request contract/value escaping failed: content-type=%q body=%s", req.Header.Get("Content-Type"), body)
	}
}

func TestNestedJSONInjectionPreservesObjectShape(t *testing.T) {
	ip := insertionPoint{
		URL: "http://x.test/api", Param: "user.id", Method: "PATCH", ContentType: "application/json", Location: "json",
		Siblings:     map[string]string{"user.id": "7", "user.tenant": "acme", "csrf": "tok", "qty": "2"},
		SiblingTypes: map[string]string{"user.id": "integer", "user.tenant": "string", "csrf": "string", "qty": "integer"},
	}
	req, err := buildInjectedRequest(context.Background(), ip, "7 OR 1=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(req.Body)
	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	user, ok := doc["user"].(map[string]interface{})
	if !ok || user["id"] != "7 OR 1=1" || user["tenant"] != "acme" || doc["csrf"] != "tok" || doc["qty"] != float64(2) || req.Method != "PATCH" {
		t.Fatalf("nested JSON request shape/method lost: method=%s body=%s", req.Method, b)
	}
}

// Regression: a pre-encoded bypass payload (%0a, ..%2f) injected into a POST form
// body must survive to the wire, NOT be double-encoded (%0a → %250a) by
// url.Values.Encode() into an inert literal — which silently defeated every
// injection detector's encoded WAF-bypass payloads on POST endpoints.
func TestPostBodyPreservesPreEncodedPayload(t *testing.T) {
	ip := insertionPoint{URL: "http://x.com/login?next=/home", Param: "user", Method: "POST"}
	req, err := buildInjectedRequest(context.Background(), ip, "x%0asleep 5", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(req.Body)
	body := string(b)

	if !strings.Contains(body, "user=x%0asleep%205") {
		t.Fatalf("pre-encoded payload was mangled in POST body: %q", body)
	}
	if strings.Contains(body, "%250a") {
		t.Fatalf("payload was double-encoded (%%0a -> %%250a): %q", body)
	}
	// A query parameter on the form action stays in the URL, not the form body.
	if req.URL.Query().Get("next") != "/home" || strings.Contains(body, "next=") {
		t.Fatalf("form action query placement changed: url=%s body=%q", req.URL, body)
	}
}

// A raw structural character in the value must still be escaped so it can't break
// out of its own field (preserving field boundaries).
func TestPostBodyEscapesFieldBoundaries(t *testing.T) {
	ip := insertionPoint{URL: "http://x.com/s", Param: "q", Method: "POST"}
	body := reqBody(t, ip, "a&admin=1")
	// The '&' in the value must be escaped, so it cannot inject a second field.
	if strings.Contains(body, "q=a&admin=1") {
		t.Fatalf("unescaped & let the value inject a new field: %q", body)
	}
	if !strings.Contains(body, "q=a%26admin=1") {
		t.Fatalf("value & not escaped as expected: %q", body)
	}
}

func TestQueryProbeEscapesRawSemicolonWithoutChangingDecodedValue(t *testing.T) {
	ip := insertionPoint{URL: "http://x.com/s?q=old", Param: "q", Method: "GET"}
	req, err := buildInjectedRequest(context.Background(), ip, `a;b`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req.URL.RawQuery, ";") || !strings.Contains(strings.ToLower(req.URL.RawQuery), "%3b") {
		t.Fatalf("raw semicolon can invalidate ParseQuery: %q", req.URL.RawQuery)
	}
	if got := req.URL.Query().Get("q"); got != "a;b" {
		t.Fatalf("application receives %q, want decoded semicolon", got)
	}
}

func TestXSSSurfaceDoesNotDropTrackingOrCMSParameters(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,content_type,cms)
		VALUES ('svc',?,'https://shop.test/',200,'text/html','wordpress')`, tid)
	_, _ = db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,method,content_type,location)
		VALUES ('p1',?,'https://shop.test/?utm_campaign=x','utm_campaign','GET','','query'),
		       ('p2',?,'https://shop.test/?search=x','search','GET','','query')`, tid, tid)
	if got := loadInsertionPoints(context.Background(), db, tid, 20); len(got) != 0 {
		t.Fatalf("shared noise-filtered loader unexpectedly kept CMS surface: %+v", got)
	}
	got := loadXSSInsertionPoints(context.Background(), db, tid, 20)
	if len(got) != 2 {
		t.Fatalf("XSS loader dropped renderable CMS/tracking parameters: %+v", got)
	}
}
