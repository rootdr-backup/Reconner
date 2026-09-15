package api

import "testing"

func TestClassifyProjectScopeDoesNotAdvertiseBareNetworksAsWeb(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"domain", []string{"example.com"}, "web"},
		{"ip hosted URL", []string{"http://192.0.2.10/app"}, "web"},
		{"bare IP", []string{"192.0.2.10"}, "network"},
		{"CIDR", []string{"192.0.2.0/24"}, "network"},
		{"mixed", []string{"example.com", "192.0.2.0/24"}, "mixed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyProjectScope(tc.values); got != tc.want {
				t.Fatalf("classifyProjectScope(%v)=%q, want %q", tc.values, got, tc.want)
			}
		})
	}
}
