package scheduler

import "testing"

func TestClassifyMemoryPressure(t *testing.T) {
	tests := []struct {
		percent float64
		want    int
	}{
		{0, 0}, {81.99, 0}, {82, 1}, {91.99, 1}, {92, 2}, {130, 2},
	}
	for _, tt := range tests {
		if got := classifyMemoryPressure(tt.percent); got != tt.want {
			t.Errorf("classifyMemoryPressure(%v)=%d want %d", tt.percent, got, tt.want)
		}
	}
}
