package assets

import "testing"

func TestIsAppStoreAsset(t *testing.T) {
	cases := map[string]bool{
		"https://play.google.com/store/apps/details?id=com.example": true,
		"https://apps.apple.com/us/app/example/id123456789":         true,
		"play.google.com": true,
		"apps.apple.com":  true,
		"https://apps.microsoft.com/detail/example":             true,
		"https://example.com/store/apps/details?id=com.example": true,
		"https://example.com/us/app/example/id123456789":        true,
		"apple.com":                     false,
		"google.com":                    false,
		"example.com":                   false,
		"https://example.com/app/login": false,
		"https://example.com/store/products/item": false,
		"https://example.com/app/identity":        false,
		"https://example.com/app/foo/identity":    false,
		"https://example.com/app/someid123":       false,
		"https://example.com/app/id123456789":     true,
		"https://example.com/app/foo/id123456789": true,
	}

	for identifier, want := range cases {
		if got := IsAppStoreAsset(identifier); got != want {
			t.Errorf("IsAppStoreAsset(%q)=%v, want %v", identifier, got, want)
		}
	}
}

func TestIsScannableWebAsset(t *testing.T) {
	cases := []struct {
		assetType  string
		identifier string
		want       bool
	}{
		{"domain", "example.com", true},
		{"url", "https://example.com/app/login", true},
		{"wildcard", "*.example.com", true},
		{"app_store", "https://play.google.com/store/apps/details?id=x", false},
		{"url", "https://play.google.com/store/apps/details?id=x", false},
		{"domain", "apps.apple.com", false},
		{"android", "com.example.app", false},
		{"ios", "com.example.app", false},
		{"cidr", "10.0.0.0/24", false},
		{"other", "reference", false},
		{"", "example.com", false},
	}

	for _, tc := range cases {
		if got := IsScannableWebAsset(tc.assetType, tc.identifier); got != tc.want {
			t.Errorf("IsScannableWebAsset(%q,%q)=%v, want %v", tc.assetType, tc.identifier, got, tc.want)
		}
	}
}
