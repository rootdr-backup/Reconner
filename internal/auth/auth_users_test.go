package auth

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

func newTestAuth(t *testing.T) *Auth {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := &config.Config{AdminUsername: "admin", AdminPassword: config.DefaultAdminPassword}
	a := New(db, cfg)
	if err := a.EnsureAdminUser(); err != nil {
		t.Fatalf("ensure admin: %v", err)
	}
	return a
}

func TestSeededAdminHasAdminRole(t *testing.T) {
	a := newTestAuth(t)
	users, err := a.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Role != RoleAdmin || users[0].Disabled {
		t.Fatalf("expected one enabled admin, got %+v", users)
	}
}

func TestCreateAndLoginMember(t *testing.T) {
	a := newTestAuth(t)
	u, err := a.CreateUser("analyst", "supersecret", RoleMember)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Role != RoleMember {
		t.Fatalf("role = %q, want member", u.Role)
	}
	if _, err := a.Login("analyst", "supersecret"); err != nil {
		t.Fatalf("member login failed: %v", err)
	}
	// Duplicate username is rejected.
	if _, err := a.CreateUser("analyst", "another-one", RoleMember); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate create err = %v, want ErrUserExists", err)
	}
}

func TestInvalidRoleNeverDefaultsToAdministrator(t *testing.T) {
	a := newTestAuth(t)
	for _, role := range []string{"", "membber", "owner"} {
		if _, err := a.CreateUser("bad-"+role, "supersecret", role); !errors.Is(err, ErrInvalidRole) {
			t.Fatalf("CreateUser role=%q err=%v, want ErrInvalidRole", role, err)
		}
	}
	u, err := a.CreateUser("analyst", "supersecret", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bad := "super-admin"
	if _, err := a.UpdateUser(u.ID, &bad, nil); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("UpdateUser invalid role err=%v, want ErrInvalidRole", err)
	}
	got, err := a.GetUser(u.ID)
	if err != nil || got.Role != RoleMember {
		t.Fatalf("invalid update changed role: user=%+v err=%v", got, err)
	}
}

func TestDisabledUserCannotLogin(t *testing.T) {
	a := newTestAuth(t)
	u, _ := a.CreateUser("temp", "supersecret", RoleMember)
	oldSession, err := a.Login("temp", "supersecret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdateUser(u.ID, nil, boolPtr(true)); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := a.ValidateSession(oldSession); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("disabled account retained its pre-disable session: %v", err)
	}
	// Fail closed even if a stale session row appears after the explicit revoke
	// (for example due to a concurrent login finishing around the disable).
	if _, err := a.db.Exec(`INSERT INTO sessions(id,user_id,expires_at) VALUES('stale-disabled',?,datetime('now','+1 hour'))`, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession("stale-disabled"); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("ValidateSession accepted a disabled account: %v", err)
	}
	if _, err := a.Login("temp", "supersecret"); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("login err = %v, want ErrUserDisabled", err)
	}
	// Re-enable → login works again.
	if _, err := a.UpdateUser(u.ID, nil, boolPtr(false)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := a.Login("temp", "supersecret"); err != nil {
		t.Fatalf("re-enabled login failed: %v", err)
	}
}

func TestLastAdminCannotBeRemovedOrDemoted(t *testing.T) {
	a := newTestAuth(t)
	admin, _ := a.ListUsers()
	id := admin[0].ID

	if _, err := a.UpdateUser(id, strPtr(RoleMember), nil); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin err = %v, want ErrLastAdmin", err)
	}
	if _, err := a.UpdateUser(id, nil, boolPtr(true)); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin err = %v, want ErrLastAdmin", err)
	}
	if err := a.DeleteUser(id); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin err = %v, want ErrLastAdmin", err)
	}

	// With a SECOND admin present, the first can be demoted.
	second, err := a.CreateUser("admin2", "supersecret", RoleAdmin)
	if err != nil {
		t.Fatalf("create 2nd admin: %v", err)
	}
	if _, err := a.UpdateUser(id, strPtr(RoleMember), nil); err != nil {
		t.Fatalf("demote with backup admin failed: %v", err)
	}
	// Now admin2 is the last admin and is likewise protected.
	if err := a.DeleteUser(second.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete new last admin err = %v, want ErrLastAdmin", err)
	}
}

func TestAdminPasswordResetInvalidatesOld(t *testing.T) {
	a := newTestAuth(t)
	u, _ := a.CreateUser("rot", "oldpassword", RoleMember)
	oldSession, err := a.Login("rot", "oldpassword")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AdminSetPassword(u.ID, "newpassword"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := a.ValidateSession(oldSession); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("admin reset left an old session usable: %v", err)
	}
	if _, err := a.Login("rot", "oldpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password should fail, got %v", err)
	}
	if _, err := a.Login("rot", "newpassword"); err != nil {
		t.Fatalf("new password login failed: %v", err)
	}
}

func TestPasswordChangeKeepsCurrentSessionAndRevokesOthers(t *testing.T) {
	a := newTestAuth(t)
	u, _ := a.CreateUser("multi", "oldpassword", RoleMember)
	current, _ := a.Login("multi", "oldpassword")
	other, _ := a.Login("multi", "oldpassword")

	if err := a.ChangePassword(u.ID, current, "oldpassword", "newpassword"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateSession(current); err != nil {
		t.Fatalf("password change revoked its authorizing session: %v", err)
	}
	if _, err := a.ValidateSession(other); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("password change left another session usable: %v", err)
	}
}

func TestSessionCookieSecurityMatchesTransport(t *testing.T) {
	a := newTestAuth(t)
	tests := []struct {
		name       string
		request    func() *http.Request
		wantSecure bool
	}{
		{name: "local HTTP", request: func() *http.Request { return httptest.NewRequest("GET", "http://127.0.0.1/", nil) }},
		{name: "direct HTTPS", request: func() *http.Request {
			r := httptest.NewRequest("GET", "https://recon.example/", nil)
			r.TLS = &tls.ConnectionState{}
			return r
		}, wantSecure: true},
		{name: "reverse-proxy HTTPS", request: func() *http.Request {
			r := httptest.NewRequest("GET", "http://recon.internal/", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			return r
		}, wantSecure: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			a.SetSessionCookie(recorder, tc.request(), "session-id")
			cookies := recorder.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookies = %d, want 1", len(cookies))
			}
			cookie := cookies[0]
			if cookie.Secure != tc.wantSecure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("cookie security = Secure:%v HttpOnly:%v SameSite:%v", cookie.Secure, cookie.HttpOnly, cookie.SameSite)
			}
		})
	}
}

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }
