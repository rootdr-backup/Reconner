package scanner

import (
	"fmt"
	"reflect"
	"testing"
)

// TestMergeHistoricalIPsDedupsAcrossSourcesPreservingOrder is the regression
// test for the v4.9 origin-IP provider-fallback fix: SecurityTrails and OTX
// results must combine into one candidate list, never silently replace each
// other or double-count an IP both sources happen to report.
func TestMergeHistoricalIPsDedupsAcrossSourcesPreservingOrder(t *testing.T) {
	got := mergeHistoricalIPs(
		[]string{"1.1.1.1", "2.2.2.2"},
		[]string{"2.2.2.2", "3.3.3.3"},
	)
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeHistoricalIPs=%v, want %v", got, want)
	}
}

// TestMergeHistoricalIPsCapsCombinedTotal ensures two generous sources
// together still can't blow the downstream probe step's cost budget wide
// open.
func TestMergeHistoricalIPsCapsCombinedTotal(t *testing.T) {
	a := make([]string, 60)
	b := make([]string, 60)
	for i := 0; i < 60; i++ {
		a[i] = ipFromIndex(i)
		b[i] = ipFromIndex(i + 1000)
	}
	got := mergeHistoricalIPs(a, b)
	if len(got) != 80 {
		t.Fatalf("len(merged)=%d, want capped at 80", len(got))
	}
}

// TestMergeHistoricalIPsHandlesNoSourcesCleanly covers the case where every
// source legitimately found nothing — not an error, just an empty list.
func TestMergeHistoricalIPsHandlesNoSourcesCleanly(t *testing.T) {
	if got := mergeHistoricalIPs(nil, nil); len(got) != 0 {
		t.Fatalf("mergeHistoricalIPs(nil, nil)=%v, want empty", got)
	}
}

func ipFromIndex(i int) string {
	return fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
}

// TestParseOTXPassiveDNSAddressesFiltersToValidARecords is the regression
// test for the new free OTX origin-IP fallback source: only valid,
// deduplicated A-record addresses survive — AAAA/CNAME/NS noise and
// malformed addresses must never reach the origin probe step.
func TestParseOTXPassiveDNSAddressesFiltersToValidARecords(t *testing.T) {
	body := []byte(`{"passive_dns":[
		{"address":"93.184.216.34","record_type":"A"},
		{"address":"93.184.216.34","record_type":"A"},
		{"address":"2606:2800:220:1:248:1893:25c8:1946","record_type":"AAAA"},
		{"address":"not-an-ip","record_type":"A"},
		{"address":"","record_type":"A"},
		{"address":"198.51.100.7","record_type":"a"}
	]}`)
	got, err := parseOTXPassiveDNSAddresses(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"93.184.216.34", "198.51.100.7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseOTXPassiveDNSAddresses=%v, want %v", got, want)
	}
}

// TestParseOTXPassiveDNSAddressesRejectsNonJSON covers the same
// rate-limited/blocked-HTML-page failure mode the other passive sources in
// this package already guard against (see errSourceUnavailable).
func TestParseOTXPassiveDNSAddressesRejectsNonJSON(t *testing.T) {
	_, err := parseOTXPassiveDNSAddresses([]byte("<html>rate limited</html>"))
	if err != errSourceUnavailable {
		t.Fatalf("err=%v, want errSourceUnavailable", err)
	}
}

// TestParseOTXPassiveDNSAddressesCapsAtSixty bounds the candidate list from
// a single very active historical domain.
func TestParseOTXPassiveDNSAddressesCapsAtSixty(t *testing.T) {
	got, err := parseOTXPassiveDNSAddresses([]byte(buildOTXFixture(100)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 60 {
		t.Fatalf("len(got)=%d, want capped at 60", len(got))
	}
}

func buildOTXFixture(n int) string {
	out := `{"passive_dns":[`
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"address":"%s","record_type":"A"}`, ipFromIndex(i))
	}
	out += `]}`
	return out
}
