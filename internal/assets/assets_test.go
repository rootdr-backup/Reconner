package assets

import "testing"

func TestIsAppStoreAsset(t *testing.T) {
	cases := map[string]bool{
		"https://play.google.com/store/apps/details?id=com.example": true,
		"https://apps.apple.com/us/app/example/id123456789":         true,
		"play.google.com": true,
		"apps.apple.com":  true,
		"https://apps.microsoft.com/detail/example":                         true,
		"https://chromewebstore.google.com/detail/loom/abcdef":              true,
		"https://marketplace.atlassian.com/apps/1212096/customfield-editor": true,
		"https://chrome.google.com/webstore/detail/loom/abcdef":             true,
		"https://itunes.apple.com/app/id123456789":                          true,
		"https://apps.apple.com/app/foo/id123456789":                        true,
		"play.google.com:443":                                               true,
		"apps.apple.com:443":                                                true,
		"https://play.google.com:443/store/apps/details?id=x":               true,
		"play.google.com:443/store/apps/details?id=x":                       true,
		"https://marketplace.atlassian.com:443/apps/1212096/x":              true,
		"apple.com":                                                         false,
		"google.com":                                                        false,
		"example.com":                                                       false,
		"https://marketplace.atlassian.com":                                 false,
		"https://marketplace.digitalocean.com":                              false,
		"https://example.com/apps/1212096/anything":                         false,
		"https://example.com/app/login":                                     false,
		"https://example.com/store/products/item":                           false,
		"https://example.com/app/identity":                                  false,
		"https://example.com/app/foo/identity":                              false,
		"https://example.com/app/someid123":                                 false,
		"https://example.com/store/apps/details?id=com.example":             false,
		"https://example.com/us/app/example/id123456789":                    false,
		"https://example.com/api/store/app/v1/users":                        false,
		"https://example.com/us/app/":                                       false,
		"https://shop.example.com/store/apps/":                              false,
		"https://example.com/app/id123456789":                               false,
		"https://example.com/app/foo/id123456789":                           false,
		"https://example.com/?next=play.google.com/store/apps/details?id=x": false,
		"https://example.com:443/api/store/app/v1/users":                    false,
	}

	for identifier, want := range cases {
		if got := IsAppStoreAsset(identifier); got != want {
			t.Errorf("IsAppStoreAsset(%q)=%v, want %v", identifier, got, want)
		}
	}
}

func TestIsWebShapedIdentifier(t *testing.T) {
	cases := map[string]bool{
		"example.com":                           true,
		"*.example.com":                         true,
		"example.com/app/login":                 true,
		"aiven.io/community":                    true,
		"https://example.com/app/login?a=b":     true,
		"example.com:8080":                      true,
		"cvrstreaming*.arlo.com":                true,
		"*dev*.arlo.com":                        true,
		"bugcrowd*.freshdesk.com":               true,
		"localhost":                             false,
		"Third Party Marketplace Apps":          false,
		"Trustwallet Chrome Extension":          false,
		"Any internal or development services.": false,
		"wss://socket.example.com":              false,
		"https://*/flat/*":                      false,
		"":                                      false,
	}

	for identifier, want := range cases {
		if got := IsWebShapedIdentifier(identifier); got != want {
			t.Errorf("IsWebShapedIdentifier(%q)=%v, want %v", identifier, got, want)
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
		{"domain", "cvrstreaming*.arlo.com", true},
		{"wildcard", "*dev*.arlo.com", true},
		{"domain", "bugcrowd*.freshdesk.com", true},
		{"app_store", "https://play.google.com/store/apps/details?id=x", false},
		{"url", "https://play.google.com/store/apps/details?id=x", false},
		{"url", "https://chromewebstore.google.com/detail/loom/abc", false},
		{"url", "https://marketplace.atlassian.com/apps/1212096/x", false},
		{"domain", "apps.apple.com", false},
		{"url", "play.google.com:443", false},
		{"url", "https://example.com/api/store/app/v1/users", true},
		{"domain", "Third Party Marketplace Apps", false},
		{"url", "Trustwallet Chrome Extension", false},
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

func TestIsTrackableScopeAsset(t *testing.T) {
	cases := []struct {
		assetType  string
		identifier string
		want       bool
	}{
		{"domain", "example.com", true},
		{"wildcard", "*.example.com", true},
		{"url", "https://example.com/app/login", true},
		{"domain", "cvrstreaming*.arlo.com", true},
		{"ip", "192.0.2.10", true},
		{"cidr", "10.0.0.0/24", true},
		{"network", "2001:db8::/32", true},
		{"ip_address", "198.51.100.7", true},
		{"ip", "2001:db8::1", true},
		{"ip", "192.0.2.10:8443", true},
		{"ip", "All IPs owned by Acme", false},
		{"cidr", "internal network range", false},
		{"network", "our corporate network", false},
		{"ip_address", "not an address", false},
		{"app_store", "https://play.google.com/store/apps/details?id=x", false},
		{"url", "https://play.google.com/store/apps/details?id=x", false},
		{"url", "play.google.com:443", false},
		{"url", "https://marketplace.atlassian.com/apps/1212096/x", false},
		{"domain", "apps.apple.com", false},
		{"domain", "Third Party Marketplace Apps", false},
		{"url", "Trustwallet Chrome Extension", false},
		{"android", "com.example.app", false},
		{"ios", "com.example.app", false},
		{"hardware", "Some device", false},
		{"source_code", "https://github.com/acme/repo", false},
		{"other", "reference", false},
		{"reference", "not a host", false},
	}

	for _, tc := range cases {
		if got := IsTrackableScopeAsset(tc.assetType, tc.identifier); got != tc.want {
			t.Errorf("IsTrackableScopeAsset(%q,%q)=%v, want %v", tc.assetType, tc.identifier, got, tc.want)
		}
	}
}
