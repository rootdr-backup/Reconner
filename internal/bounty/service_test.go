package bounty

import "testing"

func TestNormalizeAssetTypeAppStore(t *testing.T) {
	cases := []struct {
		provider   string
		typ        string
		identifier string
		want       string
	}{
		{"hackerone", "url", "https://play.google.com/store/apps/details?id=com.example", "app_store"},
		{"hackerone", "url", "https://apps.apple.com/us/app/example/id123456789", "app_store"},
		{"hackerone", "domain", "play.google.com", "app_store"},
		{"hackerone", "domain", "apps.apple.com", "app_store"},
		{"bugcrowd", "url", "https://apps.microsoft.com/detail/example", "app_store"},
		{"hackerone", "url", "https://example.com/app/login", "url"},
		{"hackerone", "domain", "example.com", "domain"},
		{"hackerone", "domain", "apple.com", "domain"},
		{"hackerone", "domain", "google.com", "domain"},
		{"intigriti", "intigriti:2", "com.example.app", "android"},
		{"intigriti", "intigriti:3", "com.example.app", "ios"},
	}

	for _, tc := range cases {
		got := normalizeAssetType(tc.provider, tc.typ, tc.identifier)
		if got != tc.want {
			t.Errorf("normalizeAssetType(%q,%q,%q)=%q, want %q", tc.provider, tc.typ, tc.identifier, got, tc.want)
		}
	}
}
