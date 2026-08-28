package scanner

import "testing"

func TestIsStaticAssetURL(t *testing.T) {
	static := []string{
		"https://x.org/wp-includes/css/dashicons.min.css",
		"https://x.org/wp-includes/js/dist/a11y.min.js/api/user", // nonsense path on a .js
		"https://x.org/style.min.css/api/user",                   // the exact FP class
		"https://x.org/assets/logo.png",
		"https://x.org/fonts/font.woff2?v=3",
		"https://x.org/app.js.map",
		"https://x.org/a/b/c.svg/poc?__nextDataReq=1",
	}
	for _, u := range static {
		if !isStaticAssetURL(u) {
			t.Errorf("expected static: %s", u)
		}
	}
	dynamic := []string{
		"https://x.org/",
		"https://x.org/wp-login.php",
		"https://x.org/api/user",
		"https://x.org/eventi/eventi/?ical=1",
		"https://x.org/download/report.json", // .json is NOT treated as static
		"https://x.org/sitemap.xml",          // .xml kept
		"https://x.org/index.html",           // html page kept
	}
	for _, u := range dynamic {
		if isStaticAssetURL(u) {
			t.Errorf("expected NON-static: %s", u)
		}
	}
}
