package scheduler

import "testing"

// TestResourceTargetCeilingPreventsTinyHostThrash checks the hardware-envelope
// helper only. resourceTargetCeiling is now the DEEP envelope used by
// computeAdmissionCaps; it is no longer a general admission ceiling. For the
// full admission decision (configured values + pressure + lane reservation),
// see TestComputeAdmissionCaps* in admission_test.go.
func TestResourceTargetCeilingPreventsTinyHostThrash(t *testing.T) {
	cases := []struct {
		cpu, memory, configured, want int
	}{
		{1, 3072, 7, 1},
		{4, 3072, 7, 2},
		{16, 4096, 20, 4},
		{32, 65536, 20, 16},
		{32, 0, 7, 7},
	}
	for _, tc := range cases {
		if got := resourceTargetCeiling(tc.cpu, tc.memory, tc.configured); got != tc.want {
			t.Errorf("resourceTargetCeiling(%d,%d,%d)=%d want %d", tc.cpu, tc.memory, tc.configured, got, tc.want)
		}
	}
}
