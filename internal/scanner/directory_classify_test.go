package scanner

import "testing"

func TestSoft404Classification(t *testing.T) {
	shell := []byte(`<!doctype html><html><head><title>My App</title></head><body>` +
		`<div id="root">loading…</div></body></html>`)
	base := soft404{active: true, statusCode: 200, bodyLen: len(shell),
		contentType: "text/html; charset=utf-8", title: "My App"}

	// 1. SPA route-echo: SAME title, very DIFFERENT length → still the catch-all,
	//    must be discarded (the old length-only check missed this).
	longShell := append([]byte(`<!doctype html><html><head><title>My App</title></head><body>`),
		make([]byte, 50000)...)
	if !base.matches(200, longShell, "text/html") {
		t.Error("SPA shell with same title but different length must be classified as soft-404")
	}

	// 2. A REAL file of a different content-type family (application/zip) that
	//    happens to be similar length must NOT be discarded.
	zip := make([]byte, len(shell)) // same length as baseline
	if base.matches(200, zip, "application/zip") {
		t.Error("a real non-HTML file must NOT be discarded as soft-404")
	}

	// 3. A genuinely different HTML page (different title) is kept.
	realPage := []byte(`<html><head><title>Admin Dashboard — Users</title></head><body>` +
		string(make([]byte, 4000)) + `</body></html>`)
	if base.matches(200, realPage, "text/html") {
		t.Error("a distinct HTML page (different title, different size) must be kept")
	}

	// 4. Inactive baseline never matches.
	if (soft404{}).matches(200, shell, "text/html") {
		t.Error("inactive baseline must not classify anything as soft-404")
	}
}

func TestCTFamily(t *testing.T) {
	cases := map[string]string{
		"text/html; charset=utf-8": "html",
		"application/json":         "json",
		"application/xml":          "xml",
		"text/javascript":          "js",
		"text/plain":               "text",
		"application/zip":          "other",
	}
	for ct, want := range cases {
		if got := ctFamily(ct); got != want {
			t.Errorf("ctFamily(%q)=%q want %q", ct, got, want)
		}
	}
}
