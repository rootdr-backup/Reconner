package scanner

import (
	"net"
	"reflect"
	"testing"
)

func TestNormalizeAndExpandNetworkScope(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"192.168.1.1", []string{"192.168.1.1"}},
		{"192.168.1.0/30", []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}},
		{"192.168.1.1-192.168.1.3", []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}},
	} {
		got, err := ExpandNetworkScope(tc.in, 32)
		if err != nil {
			t.Fatalf("ExpandNetworkScope(%q): %v", tc.in, err)
		}
		var text []string
		for _, ip := range got {
			text = append(text, ip.String())
		}
		if !reflect.DeepEqual(text, tc.want) {
			t.Fatalf("ExpandNetworkScope(%q)=%v, want %v", tc.in, text, tc.want)
		}
	}
}

func TestNetworkScopeRejectsHostnamesReversedAndOversize(t *testing.T) {
	for _, raw := range []string{"example.com", "192.168.1.9-192.168.1.1", "10.0.0.0/8"} {
		if _, err := ExpandNetworkScope(raw, 256); err == nil {
			t.Fatalf("scope %q unexpectedly accepted", raw)
		}
	}
}

func TestFilterCDNWAFBlocksKnownCloudflareRangeButKeepsPrivate(t *testing.T) {
	kept, blocked := FilterCDNWAF([]net.IP{net.ParseIP("173.245.48.12"), net.ParseIP("192.168.1.1")})
	if len(blocked) != 1 || blocked[0].IP != "173.245.48.12" || (blocked[0].Kind != "cdn" && blocked[0].Kind != "waf") {
		t.Fatalf("blocked=%+v", blocked)
	}
	if !reflect.DeepEqual(kept, []string{"192.168.1.1"}) {
		t.Fatalf("kept=%v", kept)
	}
}
