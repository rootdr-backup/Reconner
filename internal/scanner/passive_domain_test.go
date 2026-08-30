package scanner

import "testing"

func TestHostRootOf(t *testing.T) {
	cases := map[string]string{
		"https://x.com/a/b?c=1":  "https://x.com/",
		"http://y.com:8080/deep": "http://y.com:8080/",
		"https://z.com":          "https://z.com/",
	}
	for in, want := range cases {
		if got := hostRootOf(in); got != want {
			t.Errorf("hostRootOf(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCapURLsPerHost(t *testing.T) {
	urls := []string{
		"https://a.com/1", "https://a.com/2", "https://a.com/3",
		"https://b.com/1", "https://b.com/2",
		"https://a.com/4",
	}
	got := capURLsPerHost(urls, 2)
	// a.com capped to 2, b.com keeps 2 → total 4; distinct hosts preserved.
	if len(got) != 4 {
		t.Fatalf("expected 4 urls after cap, got %d: %v", len(got), got)
	}
	aCount := 0
	for _, u := range got {
		if u == "https://a.com/1" || u == "https://a.com/2" || u == "https://a.com/3" || u == "https://a.com/4" {
			aCount++
		}
	}
	if aCount != 2 {
		t.Errorf("expected a.com capped to 2, got %d", aCount)
	}
}
