package scanner

import (
	"strings"
	"testing"
)

func TestInjectParamPreservesEncoding(t *testing.T) {
	cases := []struct{ url, param, val, wantContains string }{
		// pre-encoded traversal must NOT be double-encoded
		{"http://h/p?file=x", "file", "..%2f..%2fetc%2fpasswd", "file=..%2f..%2fetc%2fpasswd"},
		{"http://h/p?f=x", "f", "%c0%ae%c0%ae%c0%af", "f=%c0%ae%c0%ae%c0%af"},
		{"http://h/p?f=x", "f", "../../etc/passwd%00", "f=../../etc/passwd%00"},
		// raw traversal stays readable (slashes/dots verbatim, server-decodable)
		{"http://h/p?f=x", "f", "../../../etc/passwd", "f=../../../etc/passwd"},
		// gopher/ssrf %-encoding preserved
		{"http://h/p?u=x", "u", "gopher://127.0.0.1:6379/_%2A1%0D%0A", "u=gopher://127.0.0.1:6379/_%2A1%0D%0A"},
		// raw SQLi: space encoded, quote kept
		{"http://h/p?id=1", "id", "1' OR '1'='1", "id=1'%20OR%20'1'='1"},
		// & inside value must be escaped so it can't split into another param
		{"http://h/p?u=x", "u", "http://e/?a=1&b=2", "u=http://e/?a=1%26b=2"},
		// stray % (not a valid escape) gets escaped
		{"http://h/p?q=x", "q", "100%off", "q=100%25off"},
	}
	for _, c := range cases {
		got := injectParam(c.url, c.param, c.val)
		if !strings.Contains(got, c.wantContains) {
			t.Errorf("injectParam(%q,%q,%q)=%q; want it to contain %q", c.url, c.param, c.val, got, c.wantContains)
		}
	}
}
