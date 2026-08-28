package scanner

import (
	"bytes"
	"testing"
)

// A dynamic catch-all whose size wobbles by more than the fixed 5%/128B tolerance
// must still be recognised as the soft-404 baseline (via the measured noise), so
// its varying pages are discarded instead of leaking as discovered files.
func TestSoft404NoiseTolerance(t *testing.T) {
	// Catch-all seen at 4600 and 5000 bytes across the two bogus probes.
	b := soft404{active: true, statusCode: 200, bodyLen: 5000, noise: 400, contentType: "text/html"}

	// A catch-all page at 4600 bytes: 400 below the anchor, within 2×noise (800).
	if !b.matches(200, bytes.Repeat([]byte("x"), 4600), "text/html") {
		t.Fatal("a dynamic catch-all page within the measured wobble must be discarded")
	}
	// Without the noise widening the fixed tolerance (250) would have missed it —
	// assert that a genuinely different-sized real file is still KEPT.
	if b.matches(200, bytes.Repeat([]byte("x"), 9000), "text/html") {
		t.Fatal("a real file far outside the catch-all size must NOT be treated as soft-404")
	}
	// A different content-type family is genuine content, never a soft-404 match.
	if b.matches(200, bytes.Repeat([]byte("x"), 5000), "application/zip") {
		t.Fatal("a different content-type family must not match the HTML catch-all")
	}
}
