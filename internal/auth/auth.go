package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "recon_session"
const sessionDuration = 24 * time.Hour

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrSessionExpired = errors.New("session expired")
var ErrUserDisabled = errors.New("account disabled")
var ErrUserExists = errors.New("username already taken")
var ErrLastAdmin = errors.New("cannot remove or disable the last active administrator")
var ErrNotFound = errors.New("user not found")

// Role constants. 'admin' can manage users and settings; 'member' can run scans
// and read findings but not touch user administration.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// User is the account record surfaced to the admin user-management UI. The
// password hash is never included.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type Auth struct {
	db  *database.DB
	cfg *config.Config
}

func New(db *database.DB, cfg *config.Config) *Auth {
	return &Auth{db: db, cfg: cfg}
}

func (a *Auth) EnsureAdminUser() error {
	var count int
	err := a.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", a.cfg.AdminUsername).Scan(&count)
	if err != nil {
		return fmt.Errorf("check admin user: %w", err)
	}

	if count > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(a.cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = a.db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", a.cfg.AdminUsername, string(hash), RoleAdmin)
	return err
}

func (a *Auth) Login(username, password string) (string, error) {
	var userID int64
	var passwordHash string
	var disabled int

	err := a.db.QueryRow("SELECT id, password_hash, disabled FROM users WHERE username = ?", username).
		Scan(&userID, &passwordHash, &disabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("query user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	// A disabled account authenticates but is refused a session — verify the
	// password first so a disabled/enabled probe can't be used as an oracle.
	if disabled != 0 {
		return "", ErrUserDisabled
	}

	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(sessionDuration)

	_, err = a.db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID, userID, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	return sessionID, nil
}

func (a *Auth) Logout(sessionID string) error {
	_, err := a.db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
	return err
}

func (a *Auth) ValidateSession(sessionID string) (int64, error) {
	var userID int64
	var expiresAt time.Time

	err := a.db.QueryRow(
		"SELECT user_id, expires_at FROM sessions WHERE id = ?",
		sessionID,
	).Scan(&userID, &expiresAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrSessionExpired
		}
		return 0, fmt.Errorf("query session: %w", err)
	}

	if time.Now().After(expiresAt) {
		_, _ = a.db.Exec("DELETE FROM sessions WHERE id = ?", sessionID)
		return 0, ErrSessionExpired
	}

	_, _ = a.db.Exec(
		"UPDATE sessions SET expires_at = ? WHERE id = ?",
		time.Now().Add(sessionDuration), sessionID,
	)

	return userID, nil
}

func (a *Auth) GetSessionFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", ErrSessionExpired
	}
	return cookie.Value, nil
}

func (a *Auth) SetSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
}

func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (a *Auth) CleanExpiredSessions() error {
	_, err := a.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	return err
}

func (a *Auth) ChangePassword(userID int64, oldPassword, newPassword string) error {
	var passwordHash string
	err := a.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&passwordHash)
	if err != nil {
		return fmt.Errorf("query user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = a.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), userID)
	return err
}

// --- Multi-user administration (admin-only surface) ---------------------------

func normalizeRole(role string) string {
	if role == RoleMember {
		return RoleMember
	}
	return RoleAdmin
}

// GetUser returns the account by id (no password hash).
func (a *Auth) GetUser(id int64) (*User, error) {
	u := &User{}
	var disabled int
	err := a.db.QueryRow(
		"SELECT id, username, role, disabled, created_at, updated_at FROM users WHERE id = ?", id,
	).Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	return u, nil
}

// ListUsers returns every account, newest first.
func (a *Auth) ListUsers() ([]User, error) {
	rows, err := a.db.Query("SELECT id, username, role, disabled, created_at, updated_at FROM users ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var disabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// activeAdminCount counts enabled administrators, optionally excluding one id —
// used to refuse the operation that would remove the last way into the system.
func (a *Auth) activeAdminCount(excludeID int64) (int, error) {
	var n int
	err := a.db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0 AND id != ?", RoleAdmin, excludeID,
	).Scan(&n)
	return n, err
}

// CreateUser adds an account with the given role. Password must be >= 8 chars
// (enforced by the handler). Returns the created user.
func (a *Auth) CreateUser(username, password, role string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	res, err := a.db.Exec(
		"INSERT INTO users (username, password_hash, role, disabled) VALUES (?, ?, ?, 0)",
		username, string(hash), normalizeRole(role),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUserExists
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return a.GetUser(id)
}

// UpdateUser changes role and/or disabled state. Nil fields are left untouched.
// Refuses to strip admin from, or disable, the last active administrator.
func (a *Auth) UpdateUser(id int64, role *string, disabled *bool) (*User, error) {
	cur, err := a.GetUser(id)
	if err != nil {
		return nil, err
	}
	newRole := cur.Role
	if role != nil {
		newRole = normalizeRole(*role)
	}
	newDisabled := cur.Disabled
	if disabled != nil {
		newDisabled = *disabled
	}
	// If this change would demote or disable an admin, ensure another remains.
	losingAdmin := cur.Role == RoleAdmin && !cur.Disabled && (newRole != RoleAdmin || newDisabled)
	if losingAdmin {
		others, err := a.activeAdminCount(id)
		if err != nil {
			return nil, err
		}
		if others == 0 {
			return nil, ErrLastAdmin
		}
	}
	dis := 0
	if newDisabled {
		dis = 1
	}
	_, err = a.db.Exec(
		"UPDATE users SET role = ?, disabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		newRole, dis, id,
	)
	if err != nil {
		return nil, err
	}
	// Disabling an account kills its live sessions immediately.
	if newDisabled {
		_, _ = a.db.Exec("DELETE FROM sessions WHERE user_id = ?", id)
	}
	return a.GetUser(id)
}

// AdminSetPassword resets a user's password (no old-password check — admin action).
func (a *Auth) AdminSetPassword(id int64, newPassword string) error {
	if _, err := a.GetUser(id); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = a.db.Exec("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", string(hash), id)
	return err
}

// DeleteUser removes an account (and its sessions cascade). Refuses to delete
// the last active administrator.
func (a *Auth) DeleteUser(id int64) error {
	cur, err := a.GetUser(id)
	if err != nil {
		return err
	}
	if cur.Role == RoleAdmin && !cur.Disabled {
		others, err := a.activeAdminCount(id)
		if err != nil {
			return err
		}
		if others == 0 {
			return ErrLastAdmin
		}
	}
	_, err = a.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// UsingDefaultPassword reports whether the admin account still has the shipped
// default password (config.DefaultAdminPassword). The UI uses this to force a
// password change on first login. Compared against the stored bcrypt hash, so it
// stays correct however the password was set.
func (a *Auth) UsingDefaultPassword() bool {
	var passwordHash string
	err := a.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", a.cfg.AdminUsername).Scan(&passwordHash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(config.DefaultAdminPassword)) == nil
}
