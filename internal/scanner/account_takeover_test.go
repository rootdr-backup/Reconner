package scanner

import "testing"

func TestATOSensitiveAuthURL(t *testing.T) {
	// Sensitive by path.
	for _, u := range []string{
		"https://x.com/oauth/authorize?client_id=1",
		"https://x.com/login?next=/a",
		"https://x.com/sso/callback",
		"https://x.com/account/reset-password?token=abc",
		"https://x.com/user/verify-email",
	} {
		if !isSensitiveAuthURL(u, "next") {
			t.Errorf("expected %q to be a sensitive auth flow", u)
		}
	}
	// Sensitive by redirect-landing parameter even on a plain path.
	if !isSensitiveAuthURL("https://x.com/go", "redirect_uri") {
		t.Error("redirect_uri parameter must mark a sensitive redirect")
	}
	// Not sensitive: an ordinary content page with a non-auth parameter.
	if isSensitiveAuthURL("https://x.com/products/list", "sort") {
		t.Error("an ordinary content page must not be treated as an auth flow")
	}
}

func TestATOParamClassifiers(t *testing.T) {
	if !atoRedirectParams[normParam("returnUrl")] {
		t.Error("returnUrl must be a redirect-landing param")
	}
	if !atoAuthTokenParams[normParam("access_token")] {
		t.Error("access_token must be an auth-token param")
	}
	if atoAuthTokenParams[normParam("color")] {
		t.Error("color must not be an auth-token param")
	}
	if !isSessionCookie("PHPSESSID") || !isSessionCookie("auth_token") {
		t.Error("session/auth cookie names must be recognised")
	}
	if isSessionCookie("theme") {
		t.Error("a non-session cookie must not be recognised as session-bearing")
	}
}
