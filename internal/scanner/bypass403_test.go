package scanner

import "testing"

func TestLooksLike403AuthWallUsesSpecificSignals(t *testing.T) {
	for _, wall := range []string{
		"<h1>Login required</h1>",
		"<form><input type=\"password\"></form>",
		"403 Forbidden",
	} {
		if !looksLike403AuthWall(wall) {
			t.Errorf("auth wall not recognized: %q", wall)
		}
	}
	for _, content := range []string{
		`{"feature":"audit_login_events","admin":true}`,
		"The login audit dashboard contains authorized private data",
	} {
		if looksLike403AuthWall(content) {
			t.Errorf("real content containing a login-related word was rejected: %q", content)
		}
	}
}
