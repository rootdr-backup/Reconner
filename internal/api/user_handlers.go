package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/auth"
)

// handleListUsers returns every account (admin-only). No password material.
func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.auth.ListUsers()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	if users == nil {
		users = []auth.User{}
	}
	h.writeSuccess(w, users)
}

// handleCreateUser adds a new account with a role and initial password.
func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		h.writeError(w, http.StatusBadRequest, "username required")
		return
	}
	if len(req.Password) < 8 {
		h.writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	u, err := h.auth.CreateUser(req.Username, req.Password, req.Role)
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			h.writeError(w, http.StatusConflict, "username already taken")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	h.writeSuccess(w, u)
}

// handleUpdateUser edits role / disabled state / password of an account.
func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["uid"], 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// An admin editing their own row can't disable themselves — that would be an
	// immediate self-lockout even if other admins exist.
	if id == h.currentUserID(r) && req.Disabled != nil && *req.Disabled {
		h.writeError(w, http.StatusBadRequest, "you cannot disable your own account")
		return
	}

	if req.Password != nil {
		if len(*req.Password) < 8 {
			h.writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		if err := h.auth.AdminSetPassword(id, *req.Password); err != nil {
			if errors.Is(err, auth.ErrNotFound) {
				h.writeError(w, http.StatusNotFound, "user not found")
				return
			}
			h.writeError(w, http.StatusInternalServerError, "failed to reset password")
			return
		}
	}

	if req.Role != nil || req.Disabled != nil {
		u, err := h.auth.UpdateUser(id, req.Role, req.Disabled)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrNotFound):
				h.writeError(w, http.StatusNotFound, "user not found")
			case errors.Is(err, auth.ErrLastAdmin):
				h.writeError(w, http.StatusConflict, err.Error())
			default:
				h.writeError(w, http.StatusInternalServerError, "failed to update user")
			}
			return
		}
		h.writeSuccess(w, u)
		return
	}

	u, err := h.auth.GetUser(id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "user not found")
		return
	}
	h.writeSuccess(w, u)
}

// handleDeleteUser removes an account (guarded against last-admin removal).
func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(mux.Vars(r)["uid"], 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if id == h.currentUserID(r) {
		h.writeError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if err := h.auth.DeleteUser(id); err != nil {
		switch {
		case errors.Is(err, auth.ErrNotFound):
			h.writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, auth.ErrLastAdmin):
			h.writeError(w, http.StatusConflict, err.Error())
		default:
			h.writeError(w, http.StatusInternalServerError, "failed to delete user")
		}
		return
	}
	h.writeSuccess(w, map[string]string{"message": "user deleted"})
}
