package scanner

import (
	"context"
	"testing"

	"github.com/recon-platform/internal/config"
)

func TestParseDNSXResponseLine(t *testing.T) {
	cases := []struct {
		line string
		name string
		want []string
	}{
		{"www.example.com [34.117.59.50, 34.149.123.216]", "www.example.com", []string{"34.117.59.50", "34.149.123.216"}},
		{"www.example.com [157.240.1.35 2a03:2880:f142:83:face:b00c:0:25de]", "www.example.com", []string{"157.240.1.35", "2a03:2880:f142:83:face:b00c:0:25de"}},
		{"www.example.com [Example.Edge.Cdn.Net.]", "www.example.com", []string{"example.edge.cdn.net"}},
		{"mixed.example.com [1.2.3.4, something.example.net]", "mixed.example.com", []string{"1.2.3.4", "something.example.net"}},
		{"trailing.example.com. [ 1.2.3.4 ]", "trailing.example.com", []string{"1.2.3.4"}},
		{"no brackets here", "", nil},
		{"[1.2.3.4] alone", "", nil},
	}
	for i, tc := range cases {
		gotName, gotToks := parseDNSXResponseLine(tc.line)
		if gotName != tc.name {
			t.Errorf("case %d: name = %q, want %q", i, gotName, tc.name)
		}
		if len(gotToks) != len(tc.want) {
			t.Errorf("case %d: tokens = %v, want %v", i, gotToks, tc.want)
			continue
		}
		for j := range gotToks {
			if gotToks[j] != tc.want[j] {
				t.Errorf("case %d: token %d = %q, want %q", i, j, gotToks[j], tc.want[j])
			}
		}
	}
}

func TestDNSXResolveIPsNilWithoutExecutor(t *testing.T) {
	s := &SubdomainScanner{cfg: &config.Config{}}
	if got := s.dnsxResolveIPs(context.Background(), "target", []string{"a.example.com"}); got != nil {
		t.Fatalf("nil-executor scanner must signal fallback (nil map), got %v", got)
	}
}
