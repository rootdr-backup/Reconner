package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/recon-platform/internal/auth"
)

// loginLimiter throttles failed login attempts per client IP to blunt brute-force
// against the single admin account. Successful logins clear the counter; only
// FAILED attempts count, so a legitimate user is never locked out by their own
// success. In-memory and best-effort (a restart resets it) — enough for a
// self-hosted single-admin tool without adding a storage dependency.
type loginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

const (
	loginMaxAttempts = 5
	loginWindow      = time.Minute
)

var loginRL = &loginLimiter{hits: make(map[string][]time.Time)}

// allowed reports whether ip may attempt a login now, pruning attempts older than
// the window as it goes.
func (l *loginLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := l.hits[ip][:0:0]
	for _, t := range l.hits[ip] {
		if now.Sub(t) < loginWindow {
			recent = append(recent, t)
		}
	}
	l.hits[ip] = recent
	return len(recent) < loginMaxAttempts
}

func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[ip] = append(l.hits[ip], time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, ip)
}

// peerIP returns the transport peer IP from RemoteAddr. Unlike the request's
// X-Forwarded-For (attacker-controlled), RemoteAddr can't be spoofed by the
// client, so a brute-forcer can't rotate a fake header to dodge the login limiter.
func peerIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := peerIP(r)
	if !loginRL.allowed(ip) {
		h.writeError(w, http.StatusTooManyRequests, "too many login attempts — wait a minute and try again")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "username and password required")
		return
	}

	sessionID, err := h.auth.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			loginRL.recordFailure(ip) // count only failures toward the limit
			h.writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if errors.Is(err, auth.ErrUserDisabled) {
			h.writeError(w, http.StatusForbidden, "this account has been disabled — contact an administrator")
			return
		}
		h.logger.Error("Login error", "error", err)
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	loginRL.reset(ip) // successful login clears this IP's failure count
	h.auth.SetSessionCookie(w, sessionID)
	h.writeSuccess(w, map[string]string{"message": "logged in"})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.auth.GetSessionFromRequest(r)
	if err == nil {
		_ = h.auth.Logout(sessionID)
	}
	h.auth.ClearSessionCookie(w)
	h.writeSuccess(w, map[string]string{"message": "logged out"})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := h.auth.GetUser(h.currentUserID(r))
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "session expired")
		return
	}
	// must_change_password only applies to the seeded admin still on the shipped
	// default password — never nags freshly-created accounts.
	mustChange := u.Username == h.cfg.AdminUsername && h.auth.UsingDefaultPassword()
	h.writeSuccess(w, map[string]any{
		"id":                   u.ID,
		"username":             u.Username,
		"role":                 u.Role,
		"must_change_password": mustChange,
	})
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.NewPassword) < 8 {
		h.writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	sessionID, _ := h.auth.GetSessionFromRequest(r)
	userID, _ := h.auth.ValidateSession(sessionID)

	if err := h.auth.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			h.writeError(w, http.StatusUnauthorized, "current password incorrect")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to change password")
		return
	}

	h.writeSuccess(w, map[string]string{"message": "password changed"})
}
