package scanner

import "testing"

// The injected confirm element used by the DAST reflected-XSS proof.
const testEl = "rcnq2z"

func TestHtmlishResponse(t *testing.T) {
	cases := []struct {
		ct, body string
		want     bool
	}{
		{"text/html; charset=utf-8", "<html>..</html>", true},
		{"application/xhtml+xml", "<html/>", true},
		{"text/css", "<rcnq2z> body{}", false},                // static CSS w/ raw reflection
		{"application/javascript", "var x='<rcnq2z>'", false}, // JS asset
		{"text/javascript", "<rcnq2z>", false},                // push.js style
		{"application/json", `{"q":"<rcnq2z>"}`, false},       // JSON echo
		{"text/plain", "<rcnq2z>", false},                     // plain text
		{"", "<!doctype html><html><rcnq2z></html>", true},    // no CT but real HTML
		{"", "<rcnq2z> not a page", false},                    // no CT, not HTML
	}
	for _, c := range cases {
		if got := htmlishResponse(c.ct, c.body); got != c.want {
			t.Errorf("htmlishResponse(%q, …) = %v, want %v", c.ct, got, c.want)
		}
	}
}

func TestHtmlTagInjected(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		// TRUE positives — the element is a genuine start tag in HTML text.
		{"html-text breakout", `<div>hello</div><rcnq2z>`, true},
		{"unquoted-attr breakout", `<a href=x param=><rcnq2z> rest`, true},
		{"quoted-attr breakout", `<meta content="x"><rcnq2z>`, true},
		{"tag with attr", `<p>x</p><rcnq2z x=1>`, true},

		// FALSE positives that MUST be rejected — raw chars trapped in a value.
		{"inside quoted attr", `<meta property="og:url" content="https://s/?p=><rcnq2z>">`, false},
		{"inside single-quoted attr", `<a href='/x?q=><rcnq2z>'>link</a>`, false},
		{"inside script string", `<script>var u="/x?p=><rcnq2z>";</script>`, false},
		{"inside style block", `<style>/* <rcnq2z> */ body{}</style>`, false},
		{"not present", `<html><body>clean</body></html>`, false},
	}
	for _, c := range cases {
		if got := htmlTagInjected(c.body, testEl); got != c.want {
			t.Errorf("%s: htmlTagInjected = %v, want %v", c.name, got, c.want)
		}
	}
}
