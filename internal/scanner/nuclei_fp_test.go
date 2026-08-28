package scanner

import "testing"

func TestBlockedNoisyTemplates(t *testing.T) {
	blocked := []struct{ id, name string }{
		{"brotli-compression-oracle-attack", "Brotli Compression Oracle Attack Detection"},
		{"web-cache-poisoning-real", "Web Cache Poisoning"},
		{"some-id", "Brotli Compression Oracle Attack Detection"}, // name-only backstop
		{"web-cache-poisoning", "Web Cache Poisoning (real)"},
	}
	for _, b := range blocked {
		if !nucleiBlockedTemplate(b.id, b.name) {
			t.Errorf("template %q/%q should be blocked", b.id, b.name)
		}
	}
	// A real template must NOT be blocked by the new patterns.
	if nucleiBlockedTemplate("CVE-2021-44228", "Apache Log4j RCE") {
		t.Error("log4shell must not be blocked")
	}
}

func TestNucleiURLReflectionFP(t *testing.T) {
	// The tirana-airport.com case: shellshock payload in the PATH is reflected
	// verbatim into an og:url meta tag → the "echo www-data" match is a reflection.
	req := "GET /at.php%28%29%20%7B%20:;%7D;%20echo%20www-data HTTP/1.1\r\nHost: x\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<meta property="og:url" content="https://x/at.php%28%29%20%7B%20:;%7D;%20echo%20www-data" >www-data`
	if !nucleiURLReflectionFP("cmd-injection", "OS Command Injection", []string{"cmdi"}, req, resp) {
		t.Error("reflected-URL command-injection must be flagged as FP")
	}

	// A genuine RCE where output (not the URL) appears must NOT be flagged.
	req2 := "GET /ping?host=127.0.0.1;id HTTP/1.1\r\nHost: x\r\n\r\n"
	resp2 := "HTTP/1.1 200 OK\r\n\r\nuid=0(root) gid=0(root) groups=0(root)"
	if nucleiURLReflectionFP("cmd-injection", "OS Command Injection", []string{"cmdi"}, req2, resp2) {
		t.Error("a real RCE (command output, no URL echo) must NOT be flagged")
	}

	// A non-injection template is never touched by this guard.
	if nucleiURLReflectionFP("tech-detect", "Tech Detect", []string{"tech"}, req, resp) {
		t.Error("non-injection template must not be affected")
	}

	// The real tirana /player case: shellshock payload in the PATH plus a ?query,
	// sent url-ENCODED on the wire (a request-target can't contain raw spaces), and
	// reflected ENCODED into og:url. Must be flagged as an FP.
	pReqEnc := "GET /player%28%29%20%7B%20:;%7D;%20echo%20www-data?autoplay=true HTTP/1.1\r\nHost: x\r\n\r\n"
	pRespEncoded := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<meta property="og:url" content="https://x/player%28%29%20%7B%20:;%7D;%20echo%20www-data?autoplay=true">www-data`
	if !nucleiURLReflectionFP("CVE-2014-6271", "Shellshock", []string{"cve", "shellshock", "rce"}, pReqEnc, pRespEncoded) {
		t.Error("shellshock reflected into og:url (encoded body) must be flagged as FP")
	}
	// The encode/decode-robust path: request ENCODED, body reflects DECODED.
	pReqEncoded := "GET /player%28%29%20%7B%20:;%7D;%20echo%20www-data?autoplay=true HTTP/1.1\r\nHost: x\r\n\r\n"
	pRespDecoded := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<link rel="canonical" href="https://x/player() { :;}; echo www-data?autoplay=true">www-data`
	if !nucleiURLReflectionFP("CVE-2014-6271", "Shellshock", []string{"shellshock"}, pReqEncoded, pRespDecoded) {
		t.Error("shellshock reflected into canonical (decoded body, encoded request) must be flagged as FP")
	}
}

func TestLenientURLDecode(t *testing.T) {
	cases := map[string]string{
		"%28%29%20%7B":     "() {",
		"a+b":              "a b",
		"100%discount":     "100%discount", // malformed % left as-is
		"/path/no-escapes": "/path/no-escapes",
	}
	for in, want := range cases {
		if got := lenientURLDecode(in); got != want {
			t.Errorf("lenientURLDecode(%q)=%q want %q", in, got, want)
		}
	}
}
