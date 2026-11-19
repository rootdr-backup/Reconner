package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
)

func (h *Handler) telegramBot(w http.ResponseWriter) *TelegramBot {
	if h.telegram == nil {
		h.writeError(w, http.StatusServiceUnavailable, "Telegram runtime is unavailable")
		return nil
	}
	return h.telegram
}

func (h *Handler) handleGetTelegram(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	state, err := bot.State(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load Telegram settings")
		return
	}
	h.writeSuccess(w, state)
}

func (h *Handler) handleUpdateTelegram(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	var body struct {
		BotToken *string `json:"bot_token"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := bot.Configure(r.Context(), body.BotToken, body.Enabled); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := bot.State(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Telegram was saved but state could not be reloaded")
		return
	}
	h.writeSuccess(w, state)
}

func (h *Handler) handleAddTelegramChat(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	var chat TelegramChat
	if err := json.NewDecoder(r.Body).Decode(&chat); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if chat.Role == "" {
		chat.Role = "viewer"
	}
	saved, err := bot.AddChat(r.Context(), chat)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": saved})
}

func (h *Handler) handleUpdateTelegramChat(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	id := mux.Vars(r)["chat"]
	state, err := bot.State(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load chat")
		return
	}
	var current *TelegramChat
	for i := range state.Chats {
		if state.Chats[i].ID == id {
			current = &state.Chats[i]
			break
		}
	}
	if current == nil {
		h.writeError(w, http.StatusNotFound, "chat not found")
		return
	}
	var patch struct {
		Label                   *string `json:"label"`
		Role                    *string `json:"role"`
		Enabled                 *bool   `json:"enabled"`
		NotifyScanStarted       *bool   `json:"notify_scan_started"`
		NotifyPhaseFinished     *bool   `json:"notify_phase_finished"`
		NotifyScanFinished      *bool   `json:"notify_scan_finished"`
		NotifyFindings          *bool   `json:"notify_findings"`
		NotifyMonitoring        *bool   `json:"notify_monitoring"`
		NotifyWatchScanStarted  *bool   `json:"notify_watch_scan_started"`
		NotifyWatchScanFinished *bool   `json:"notify_watch_scan_finished"`
		NotifyScopeLanded       *bool   `json:"notify_scope_landed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if patch.Label != nil {
		current.Label = *patch.Label
	}
	if patch.Role != nil {
		current.Role = *patch.Role
	}
	if patch.Enabled != nil {
		current.Enabled = *patch.Enabled
	}
	if patch.NotifyScanStarted != nil {
		current.NotifyScanStarted = *patch.NotifyScanStarted
	}
	if patch.NotifyPhaseFinished != nil {
		current.NotifyPhaseFinished = *patch.NotifyPhaseFinished
	}
	if patch.NotifyScanFinished != nil {
		current.NotifyScanFinished = *patch.NotifyScanFinished
	}
	if patch.NotifyFindings != nil {
		current.NotifyFindings = *patch.NotifyFindings
	}
	if patch.NotifyMonitoring != nil {
		current.NotifyMonitoring = *patch.NotifyMonitoring
	}
	if patch.NotifyWatchScanStarted != nil {
		current.NotifyWatchScanStarted = *patch.NotifyWatchScanStarted
	}
	if patch.NotifyWatchScanFinished != nil {
		current.NotifyWatchScanFinished = *patch.NotifyWatchScanFinished
	}
	if patch.NotifyScopeLanded != nil {
		current.NotifyScopeLanded = *patch.NotifyScopeLanded
	}
	if err := bot.UpdateChat(r.Context(), id, *current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeError(w, http.StatusNotFound, "chat not found")
		} else {
			h.writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	state, _ = bot.State(r.Context())
	h.writeSuccess(w, state)
}

func (h *Handler) handleDeleteTelegramChat(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	if err := bot.DeleteChat(r.Context(), mux.Vars(r)["chat"]); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeError(w, http.StatusNotFound, "chat not found")
		} else {
			h.writeError(w, http.StatusInternalServerError, "failed to delete chat")
		}
		return
	}
	h.writeSuccess(w, map[string]string{"message": "deleted"})
}

func (h *Handler) handleTestTelegramChat(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	if err := bot.TestChat(r.Context(), mux.Vars(r)["chat"]); err != nil {
		h.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.writeSuccess(w, map[string]string{"message": "test message sent"})
}

func (h *Handler) handleRetryTelegram(w http.ResponseWriter, r *http.Request) {
	bot := h.telegramBot(w)
	if bot == nil {
		return
	}
	if err := bot.RetryFailed(r.Context()); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to retry Telegram messages")
		return
	}
	h.writeSuccess(w, map[string]string{"message": "failed messages queued for retry"})
}
