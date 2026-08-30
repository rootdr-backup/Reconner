package scheduler

import "testing"

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
