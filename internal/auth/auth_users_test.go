package auth

import (
	"errors"
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

func TestDisabledUserCannotLogin(t *testing.T) {
	a := newTestAuth(t)
	u, _ := a.CreateUser("temp", "supersecret", RoleMember)
	if _, err := a.UpdateUser(u.ID, nil, boolPtr(true)); err != nil {
		t.Fatalf("disable: %v", err)
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
	if err := a.AdminSetPassword(u.ID, "newpassword"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := a.Login("rot", "oldpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password should fail, got %v", err)
	}
	if _, err := a.Login("rot", "newpassword"); err != nil {
		t.Fatalf("new password login failed: %v", err)
	}
}

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }
