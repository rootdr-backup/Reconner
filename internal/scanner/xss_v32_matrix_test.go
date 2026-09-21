package scanner

import (
	"fmt"
	"strings"
	"testing"
)

func TestXSSV32AttributeSemanticMatrix(t *testing.T) {
	tests := []struct {
		name, body, context, tag, attr string
		quote                          byte
		scheme                         bool
	}{
		{"ordinary-double", `<div data-value="%s">`, CtxQuotedAttr, "div", "data-value", '"', false},
		{"ordinary-single", `<input value='%s'>`, CtxQuotedAttr, "input", "value", '\'', false},
		{"ordinary-unquoted", `<input value=%s>`, CtxUnquotedAttr, "input", "value", 0, false},
		{"anchor-href", `<a href="%s">`, CtxURL, "a", "href", '"', true},
		{"stylesheet-href", `<link href="%s">`, CtxURL, "link", "href", '"', false},
		{"image-srcset", `<img srcset="%s 1x">`, CtxURL, "img", "srcset", '"', false},
		{"form-action", `<form action="%s">`, CtxURL, "form", "action", '"', true},
		{"script-src", `<script src="%s">`, CtxURL, "script", "src", '"', false},
		{"event-js-string", `<button onclick="show('%s')">`, CtxEventHandler, "button", "onclick", '"', false},
		{"nested-srcdoc", `<iframe srcdoc="%s">`, CtxSrcDoc, "iframe", "srcdoc", '"', false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(tc.body, xssProbe)
			a := AnalyzeReflection(body)
			if a.Context != tc.context || a.TagName != tc.tag || a.AttrName != tc.attr ||
				a.Quote != tc.quote || a.URLScheme != tc.scheme {
				t.Fatalf("semantic classification mismatch: %+v", a)
			}
		})
	}
}

func TestXSSV32TokenizerStateMatrix(t *testing.T) {
	for _, tc := range []struct {
		element, context string
	}{
		{"title", CtxRCDATA},
		{"textarea", CtxRCDATA},
		{"xmp", CtxRAWTEXT},
		{"noembed", CtxRAWTEXT},
		{"noframes", CtxRAWTEXT},
		{"iframe", CtxRAWTEXT},
	} {
		for _, spelling := range []string{tc.element, strings.ToUpper(tc.element)} {
			t.Run(spelling, func(t *testing.T) {
				a := AnalyzeReflection("<" + spelling + ">" + xssProbe + "</" + spelling + ">")
				if a.Context != tc.context || !strings.EqualFold(a.CloseTag, "</"+tc.element+">") {
					t.Fatalf("tokenizer state mismatch: %+v", a)
				}
			})
		}
	}
}

func TestXSSV32EncodingMutationMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		executable   bool
	}{
		{"raw", `'"<>` + "`" + `\\/();= ` + "\t", true},
		{"html-entities", `&#39;&quot;&lt;&gt;&#96;%5c%2f%28%29%3b%3d%20%09`, false},
		{"percent", `%27%22%3c%3e%60%5c%2f%28%29%3b%3d%20%09`, false},
		{"double-percent", `%2527%2522%253c%253e%2560%255c%252f%2528%2529%253b%253d%2520%2509`, false},
		{"js-escapes", `\x27\x22\x3c\x3e\x60\x5c%2f%28%29%3b%3d%20%09`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := analyzeReflectionProbe(`<div>`+"matrix"+tc.suffix+`</div>`, "matrix", xssProbeSuffix)
			if a.Executable != tc.executable {
				t.Fatalf("mutation executable=%t want %t: %+v", a.Executable, tc.executable, a)
			}
		})
	}
}

func FuzzAnalyzeReflectionV32(f *testing.F) {
	for _, seed := range []string{
		`<div>` + xssProbe + `</div>`,
		`<input value="` + xssProbe + `">`,
		`<script>const x='` + xssProbe + `'</script>`,
		`<!--` + xssProbe + `-->`,
		`<iframe srcdoc="` + xssProbe + `"></iframe>`,
		strings.Repeat(`<template data-x="`, 8) + xssProbe,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		all := AnalyzeReflectionsWithMarker(body, xssMarker)
		for _, a := range all {
			if !a.Reflected || a.Context == "" || a.Offset < 0 || a.Offset >= len(body) {
				t.Fatalf("invalid reflection result: %+v", a)
			}
		}
	})
}
