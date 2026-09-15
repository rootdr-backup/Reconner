package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/secret"
)

const telegramAPIBase = "https://api.telegram.org"

var telegramTokenRE = regexp.MustCompile(`^[0-9]{6,12}:[A-Za-z0-9_-]{20,}$`)
var telegramChatIDRE = regexp.MustCompile(`^-?[0-9]{1,20}$`)

type TelegramChat struct {
	ID                  string `json:"id"`
	ChatID              string `json:"chat_id"`
	Label               string `json:"label"`
	Role                string `json:"role"`
	Enabled             bool   `json:"enabled"`
	NotifyScanStarted   bool   `json:"notify_scan_started"`
	NotifyPhaseFinished bool   `json:"notify_phase_finished"`
	NotifyScanFinished  bool   `json:"notify_scan_finished"`
	NotifyFindings      bool   `json:"notify_findings"`
	NotifyMonitoring    bool   `json:"notify_monitoring"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type TelegramState struct {
	Configured      bool           `json:"configured"`
	Enabled         bool           `json:"enabled"`
	MaskedToken     string         `json:"masked_token"`
	BotUsername     string         `json:"bot_username"`
	Connected       bool           `json:"connected"`
	LastError       string         `json:"last_error"`
	LastConnectedAt string         `json:"last_connected_at"`
	Pending         int            `json:"pending"`
	Failed          int            `json:"failed"`
	Chats           []TelegramChat `json:"chats"`
}

type tgInlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
}

type tgInlineKeyboard struct {
	Rows [][]tgInlineButton `json:"inline_keyboard"`
}

type tgAPIResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

type tgUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type tgChat struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

type tgMessage struct {
	MessageID int64  `json:"message_id"`
	From      tgUser `json:"from"`
	Chat      tgChat `json:"chat"`
	Text      string `json:"text"`
}

type tgCallbackQuery struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message"`
	CallbackQuery *tgCallbackQuery `json:"callback_query"`
}

// TelegramBot is both a durable notification sink for the scheduler and a
// long-polling management bot. Long polling keeps self-hosted installations
// usable behind NAT; no public webhook URL is required.
type TelegramBot struct {
	h       *Handler
	client  *http.Client
	apiBase string
	wake    chan struct{}
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	start   sync.Once
	stop    sync.Once
	offset  atomic.Int64
	config  atomic.Uint64 // changes invalidate in-flight long polls from an old token
	scans   sync.Map      // task id -> scan start time; keeps phase finding sweeps lossless
}

func NewTelegramBot(h *Handler) *TelegramBot {
	return &TelegramBot{
		h: h, apiBase: telegramAPIBase, wake: make(chan struct{}, 1),
		client: &http.Client{Timeout: 40 * time.Second},
	}
}

func (b *TelegramBot) Start() {
	b.start.Do(func() {
		var lastUpdateID int64
		_ = b.h.db.QueryRow(`SELECT COALESCE(last_update_id,0) FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
		if lastUpdateID > 0 {
			b.offset.Store(lastUpdateID + 1)
		}
		ctx, cancel := context.WithCancel(context.Background())
		b.cancel = cancel
		b.wg.Add(2)
		go b.pollLoop(ctx)
		go b.outboxLoop(ctx)
	})
}

func (b *TelegramBot) Stop() {
	b.stop.Do(func() {
		if b.cancel != nil {
			b.cancel()
		}
		b.wg.Wait()
	})
}

func (b *TelegramBot) Wake() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *TelegramBot) botToken(ctx context.Context) (string, bool, error) {
	var encrypted string
	var enabled int
	err := b.h.db.QueryRowContext(ctx, `SELECT encrypted_bot_token,enabled FROM telegram_config WHERE id=1`).Scan(&encrypted, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return secret.New(b.h.cfg.SessionSecret).Decrypt(encrypted), enabled == 1, nil
}

func (b *TelegramBot) State(ctx context.Context) (TelegramState, error) {
	state := TelegramState{Chats: []TelegramChat{}}
	var encrypted string
	var enabled int
	var lastConnected sql.NullString
	err := b.h.db.QueryRowContext(ctx, `SELECT encrypted_bot_token,enabled,bot_username,last_error,last_connected_at
		FROM telegram_config WHERE id=1`).Scan(&encrypted, &enabled, &state.BotUsername, &state.LastError, &lastConnected)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return state, err
	}
	if err == nil {
		token := secret.New(b.h.cfg.SessionSecret).Decrypt(encrypted)
		state.Configured = token != ""
		state.Enabled = enabled == 1
		state.MaskedToken = maskKey(token)
		if lastConnected.Valid {
			state.LastConnectedAt = lastConnected.String
			if t, parseErr := time.Parse("2006-01-02 15:04:05", lastConnected.String); parseErr == nil {
				state.Connected = state.Enabled && state.LastError == "" && time.Since(t) < 2*time.Minute
			}
		}
	}

	rows, err := b.h.db.QueryContext(ctx, `SELECT id,chat_id,label,role,enabled,
		notify_scan_started,notify_phase_finished,notify_scan_finished,notify_findings,notify_monitoring,
		created_at,updated_at FROM telegram_chats ORDER BY created_at`)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var c TelegramChat
		var enabled, a, p, f, findings, monitoring int
		if err := rows.Scan(&c.ID, &c.ChatID, &c.Label, &c.Role, &enabled, &a, &p, &f, &findings, &monitoring, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return state, err
		}
		c.Enabled, c.NotifyScanStarted, c.NotifyPhaseFinished = enabled == 1, a == 1, p == 1
		c.NotifyScanFinished, c.NotifyFindings, c.NotifyMonitoring = f == 1, findings == 1, monitoring == 1
		state.Chats = append(state.Chats, c)
	}
	if err := rows.Err(); err != nil {
		return state, err
	}
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_outbox WHERE status='pending'`).Scan(&state.Pending)
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_outbox WHERE status='failed'`).Scan(&state.Failed)
	return state, nil
}

// Configure validates a replacement token with getMe before sealing it. A nil
// token preserves the current one; an explicit empty token disconnects the bot.
func (b *TelegramBot) Configure(ctx context.Context, token *string, enabled *bool) error {
	// Invalidate any long poll before validation or persistence starts. This
	// closes the narrow window where an old bot response could otherwise claim
	// an update cursor immediately after a replacement token is stored.
	b.config.Add(1)
	current, currentEnabled, err := b.botToken(ctx)
	if err != nil {
		return err
	}
	next, nextEnabled := current, currentEnabled
	username := ""
	if token != nil {
		next = strings.TrimSpace(*token)
		if next != "" {
			if !telegramTokenRE.MatchString(next) {
				return fmt.Errorf("invalid BotFather token format")
			}
			user, verifyErr := b.getMe(ctx, next)
			if verifyErr != nil {
				return fmt.Errorf("Telegram rejected the bot token: %w", verifyErr)
			}
			username = user.Username
		} else {
			nextEnabled = false
		}
	}
	if enabled != nil {
		nextEnabled = *enabled
	}
	if nextEnabled && next == "" {
		return fmt.Errorf("set a BotFather token before enabling Telegram")
	}
	if username == "" && next != "" {
		var saved string
		_ = b.h.db.QueryRowContext(ctx, `SELECT bot_username FROM telegram_config WHERE id=1`).Scan(&saved)
		username = saved
	}
	tokenChanged := token != nil && next != current
	sealed := secret.New(b.h.cfg.SessionSecret).Encrypt(next)
	_, err = b.h.db.ExecContext(ctx, `INSERT INTO telegram_config(id,encrypted_bot_token,enabled,bot_username,last_error,updated_at)
		VALUES(1,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET encrypted_bot_token=excluded.encrypted_bot_token,
		enabled=excluded.enabled,bot_username=excluded.bot_username,last_error='',
		last_update_id=CASE WHEN ?=1 THEN 0 ELSE telegram_config.last_update_id END,
		updated_at=CURRENT_TIMESTAMP`,
		sealed, boolInt(nextEnabled), username, "", boolInt(tokenChanged))
	if err == nil {
		var lastUpdateID int64
		_ = b.h.db.QueryRowContext(ctx, `SELECT COALESCE(last_update_id,0) FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
		if lastUpdateID > 0 {
			b.offset.Store(lastUpdateID + 1)
		} else {
			b.offset.Store(0)
		}
		if nextEnabled && next != "" {
			// Command registration is best-effort; polling and direct commands do
			// not depend on Telegram rendering the menu immediately.
			_, _ = b.call(ctx, next, "setMyCommands", map[string]any{"commands": []map[string]string{
				{"command": "status", "description": "Platform and scan status"},
				{"command": "targets", "description": "List targets"},
				{"command": "scans", "description": "Recent scans"},
				{"command": "findings", "description": "Latest verified findings"},
				{"command": "scan", "description": "Start a target scan"},
				{"command": "pause", "description": "Pause a target scan"},
				{"command": "resume", "description": "Resume a target scan"},
				{"command": "skip", "description": "Skip the current scan phase"},
				{"command": "cancel", "description": "Cancel a target scan"},
				{"command": "help", "description": "Show commands for this chat role"},
			}}, nil)
		}
		b.Wake()
	}
	return err
}

func (b *TelegramBot) AddChat(ctx context.Context, c TelegramChat) (TelegramChat, error) {
	c.ChatID = strings.TrimSpace(c.ChatID)
	c.Label = strings.TrimSpace(c.Label)
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	if !telegramChatIDRE.MatchString(c.ChatID) {
		return c, fmt.Errorf("chat id must be a signed numeric Telegram chat id")
	}
	if len(c.Label) > 80 {
		return c, fmt.Errorf("chat label is too long")
	}
	if roleRank(c.Role) < 0 {
		return c, fmt.Errorf("role must be viewer, operator or admin")
	}
	c.ID = uuid.NewString()
	// New chats receive all high-signal event types by default.
	c.Enabled, c.NotifyScanStarted, c.NotifyPhaseFinished = true, true, true
	c.NotifyScanFinished, c.NotifyFindings, c.NotifyMonitoring = true, true, true
	_, err := b.h.db.ExecContext(ctx, `INSERT INTO telegram_chats(id,chat_id,label,role,enabled,
		notify_scan_started,notify_phase_finished,notify_scan_finished,notify_findings,notify_monitoring)
		VALUES(?,?,?,?,1,1,1,1,1,1)`, c.ID, c.ChatID, c.Label, c.Role)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return c, fmt.Errorf("that chat id is already configured")
		}
		return c, err
	}
	b.Wake()
	state, err := b.State(ctx)
	if err == nil {
		for _, saved := range state.Chats {
			if saved.ID == c.ID {
				return saved, nil
			}
		}
	}
	return c, err
}

func (b *TelegramBot) UpdateChat(ctx context.Context, id string, c TelegramChat) error {
	c.Label = strings.TrimSpace(c.Label)
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	if len(c.Label) > 80 {
		return fmt.Errorf("chat label is too long")
	}
	if roleRank(c.Role) < 0 {
		return fmt.Errorf("role must be viewer, operator or admin")
	}
	res, err := b.h.db.ExecContext(ctx, `UPDATE telegram_chats SET label=?,role=?,enabled=?,
		notify_scan_started=?,notify_phase_finished=?,notify_scan_finished=?,notify_findings=?,notify_monitoring=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		c.Label, c.Role, boolInt(c.Enabled), boolInt(c.NotifyScanStarted), boolInt(c.NotifyPhaseFinished),
		boolInt(c.NotifyScanFinished), boolInt(c.NotifyFindings), boolInt(c.NotifyMonitoring), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	b.Wake()
	return nil
}

func (b *TelegramBot) DeleteChat(ctx context.Context, id string) error {
	res, err := b.h.db.ExecContext(ctx, `DELETE FROM telegram_chats WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (b *TelegramBot) TestChat(ctx context.Context, entryID string) error {
	token, enabled, err := b.botToken(ctx)
	if err != nil {
		return err
	}
	if token == "" || !enabled {
		return fmt.Errorf("Telegram bot is not enabled")
	}
	var chatID string
	if err := b.h.db.QueryRowContext(ctx, `SELECT chat_id FROM telegram_chats WHERE id=? AND enabled=1`, entryID).Scan(&chatID); err != nil {
		return fmt.Errorf("enabled chat not found")
	}
	return b.sendMessage(ctx, token, chatID, "✅ Reconner is connected. Scan, phase and verified-finding notifications are enabled for this chat.", nil)
}

func (b *TelegramBot) RetryFailed(ctx context.Context) error {
	_, err := b.h.db.ExecContext(ctx, `UPDATE telegram_outbox SET status='pending',attempts=0,last_error='',next_attempt_at=CURRENT_TIMESTAMP WHERE status='failed'`)
	b.Wake()
	return err
}

func (b *TelegramBot) getMe(ctx context.Context, token string) (tgUser, error) {
	var user tgUser
	resp, err := b.call(ctx, token, "getMe", map[string]any{}, &user)
	if err != nil {
		return user, err
	}
	if !resp.OK {
		return user, fmt.Errorf("%s", resp.Description)
	}
	return user, nil
}

func (b *TelegramBot) call(ctx context.Context, token, method string, payload any, result any) (tgAPIResponse, error) {
	var envelope tgAPIResponse
	body, err := json.Marshal(payload)
	if err != nil {
		return envelope, err
	}
	endpoint := strings.TrimRight(b.apiBase, "/") + "/bot" + token + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return envelope, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Reconner-Telegram/1")
	res, err := b.client.Do(req)
	if err != nil {
		return envelope, fmt.Errorf("%s", redactTelegramError(err.Error(), token))
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return envelope, err
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return envelope, fmt.Errorf("Telegram returned HTTP %d with an invalid response", res.StatusCode)
	}
	if result != nil && len(envelope.Result) > 0 && string(envelope.Result) != "null" {
		if err := json.Unmarshal(envelope.Result, result); err != nil {
			return envelope, err
		}
	}
	if !envelope.OK {
		return envelope, fmt.Errorf("Telegram API: %s", envelope.Description)
	}
	return envelope, nil
}

func redactTelegramError(message, token string) string {
	if token != "" {
		message = strings.ReplaceAll(message, token, "<redacted-bot-token>")
	}
	return message
}

func (b *TelegramBot) sendMessage(ctx context.Context, token, chatID, text string, keyboard *tgInlineKeyboard) error {
	if len([]rune(text)) > 4000 {
		text = string([]rune(text)[:3990]) + "\n…"
	}
	payload := map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true}
	if keyboard != nil && len(keyboard.Rows) > 0 {
		payload["reply_markup"] = keyboard
	}
	_, err := b.call(ctx, token, "sendMessage", payload, nil)
	return err
}

func (b *TelegramBot) answerCallback(ctx context.Context, token, id, text string) {
	_, _ = b.call(ctx, token, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

func (b *TelegramBot) setConnection(errorText string, connected bool) {
	errorText = redactTelegramError(errorText, "")
	if len(errorText) > 1000 {
		errorText = errorText[:1000]
	}
	if connected {
		_, _ = b.h.db.Exec(`UPDATE telegram_config SET last_error='',last_connected_at=CURRENT_TIMESTAMP WHERE id=1`)
	} else {
		_, _ = b.h.db.Exec(`UPDATE telegram_config SET last_error=? WHERE id=1`, errorText)
	}
}

func (b *TelegramBot) pollLoop(ctx context.Context) {
	defer b.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		token, enabled, err := b.botToken(ctx)
		if err != nil || !enabled || token == "" {
			b.wait(ctx, 15*time.Second)
			continue
		}
		var updates []tgUpdate
		generation := b.config.Load()
		payload := map[string]any{
			"offset": b.offset.Load(), "timeout": 25,
			"allowed_updates": []string{"message", "callback_query"},
		}
		_, err = b.call(ctx, token, "getUpdates", payload, &updates)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			b.setConnection(redactTelegramError(err.Error(), token), false)
			b.wait(ctx, 5*time.Second)
			continue
		}
		// A settings change can finish while getUpdates is blocked. Never execute
		// a late response obtained with a disabled or replaced bot token.
		activeToken, activeEnabled, activeErr := b.botToken(ctx)
		if activeErr != nil || !activeEnabled || activeToken != token || generation != b.config.Load() {
			continue
		}
		b.setConnection("", true)
		for _, update := range updates {
			if generation != b.config.Load() {
				break
			}
			if update.UpdateID < b.offset.Load() {
				continue
			}
			// Claim the update before executing it. Scan/target commands are safer
			// at-most-once than duplicated after a crash (especially /scan).
			claim, err := b.h.db.ExecContext(ctx, `UPDATE telegram_config SET last_update_id=?,updated_at=CURRENT_TIMESTAMP
				WHERE id=1 AND last_update_id<?`, update.UpdateID, update.UpdateID)
			if err != nil {
				b.setConnection(err.Error(), false)
				break
			}
			b.offset.Store(update.UpdateID + 1)
			if claimed, _ := claim.RowsAffected(); claimed == 0 {
				continue
			}
			b.handleUpdate(ctx, token, update)
		}
	}
}

func (b *TelegramBot) wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-b.wake:
	case <-t.C:
	}
}

func (b *TelegramBot) outboxLoop(ctx context.Context) {
	defer b.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
			b.drainOutbox(ctx)
		case <-ticker.C:
			b.drainOutbox(ctx)
		}
	}
}

func (b *TelegramBot) drainOutbox(ctx context.Context) {
	token, enabled, err := b.botToken(ctx)
	if err != nil || !enabled || token == "" {
		return
	}
	type item struct {
		id, chatID, message, keyboard string
		attempts                      int
	}
	rows, err := b.h.db.QueryContext(ctx, `SELECT o.id,c.chat_id,o.message,o.keyboard_json,o.attempts
		FROM telegram_outbox o JOIN telegram_chats c ON c.id=o.chat_entry_id
		WHERE o.status='pending' AND o.next_attempt_at<=CURRENT_TIMESTAMP AND c.enabled=1
		ORDER BY o.created_at LIMIT 20`)
	if err != nil {
		return
	}
	var items []item
	for rows.Next() {
		var v item
		if rows.Scan(&v.id, &v.chatID, &v.message, &v.keyboard, &v.attempts) == nil {
			items = append(items, v)
		}
	}
	rows.Close()
	for _, v := range items {
		var keyboard *tgInlineKeyboard
		if v.keyboard != "" {
			var k tgInlineKeyboard
			if json.Unmarshal([]byte(v.keyboard), &k) == nil {
				keyboard = &k
			}
		}
		sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := b.sendMessage(sendCtx, token, v.chatID, v.message, keyboard)
		cancel()
		if err == nil {
			_, _ = b.h.db.ExecContext(ctx, `UPDATE telegram_outbox SET status='sent',sent_at=CURRENT_TIMESTAMP,last_error='' WHERE id=?`, v.id)
			continue
		}
		attempts := v.attempts + 1
		status := "pending"
		if attempts >= 8 {
			status = "failed"
		}
		backoff := 1 << minInt(attempts, 8)
		message := redactTelegramError(err.Error(), token)
		_, _ = b.h.db.ExecContext(ctx, `UPDATE telegram_outbox SET status=?,attempts=?,last_error=?,
			next_attempt_at=datetime('now', ?) WHERE id=?`, status, attempts, message, "+"+strconv.Itoa(backoff)+" seconds", v.id)
	}
}

func (b *TelegramBot) enqueue(category, eventKey, text string, keyboard *tgInlineKeyboard) {
	preference := map[string]string{
		"scan_started": "notify_scan_started", "phase_finished": "notify_phase_finished",
		"scan_finished": "notify_scan_finished", "finding": "notify_findings", "monitoring": "notify_monitoring",
	}[category]
	if preference == "" {
		return
	}
	keyboardJSON := ""
	if keyboard != nil {
		if raw, err := json.Marshal(keyboard); err == nil {
			keyboardJSON = string(raw)
		}
	}
	query := `INSERT OR IGNORE INTO telegram_outbox(id,chat_entry_id,event_key,category,message,keyboard_json)
		SELECT lower(hex(randomblob(16))),id,?,?,?,? FROM telegram_chats
		WHERE enabled=1 AND ` + preference + `=1
		  AND EXISTS (SELECT 1 FROM telegram_config WHERE id=1 AND enabled=1 AND encrypted_bot_token<>'')`
	_, _ = b.h.db.Exec(query, eventKey, category, text, keyboardJSON)
	b.Wake()
}

func (b *TelegramBot) NotifyScanStarted(taskID, targetID, domain string) {
	b.scans.Store(taskID, time.Now())
	text := "🚀 Scan started\nTarget: " + displayDomain(domain) + "\nTask: " + shortBotID(taskID)
	b.enqueue("scan_started", "scan:start:"+taskID, text, b.scanKeyboard(targetID))
}

func (b *TelegramBot) NotifyPhaseFinished(taskID, targetID, domain, phase, status string, duration time.Duration, progress, total int) {
	icon := map[string]string{"completed": "✅", "blocked": "🚫", "failed": "❌", "timed_out": "⏱", "skipped": "⏭", "cancelled": "🛑"}[status]
	if icon == "" {
		icon = "ℹ️"
	}
	text := fmt.Sprintf("%s Scan phase %s\nTarget: %s\nPhase: %s\nProgress: %d/%d\nDuration: %s",
		icon, strings.ReplaceAll(status, "_", " "), displayDomain(domain), phase, progress, total, shortDuration(duration))
	b.enqueue("phase_finished", "scan:phase:"+taskID+":"+phase+":"+status, text, b.scanKeyboard(targetID))
	b.enqueueValidFindingsSince(targetID, b.findingSweepStart(taskID, duration))
}

func (b *TelegramBot) NotifyScanFinished(taskID, targetID, domain, status string, duration time.Duration, stats map[string]int) {
	icon := "✅"
	if status == "failed" {
		icon = "❌"
	} else if status == "cancelled" {
		icon = "🛑"
	}
	text := fmt.Sprintf("%s Scan %s\nTarget: %s\nDuration: %s\nSubdomains: %d · Alive: %d\nVerified findings: %d\nNative: %d · Nuclei: %d · Backups: %d · Redirects: %d · JS: %d",
		icon, status, displayDomain(domain), shortDuration(duration), stats["subdomains"], stats["alive"], stats["verified"],
		stats["vulns"], stats["nuclei"], stats["backups"], stats["redirects"], stats["js"])
	b.enqueue("scan_finished", "scan:finish:"+taskID+":"+status, text, b.scanKeyboard(targetID))
	b.enqueueValidFindingsSince(targetID, b.findingSweepStart(taskID, duration))
	b.scans.Delete(taskID)
}

func (b *TelegramBot) findingSweepStart(taskID string, fallbackDuration time.Duration) time.Time {
	if started, ok := b.scans.Load(taskID); ok {
		if value, valid := started.(time.Time); valid {
			return value.Add(-2 * time.Second)
		}
	}
	return time.Now().Add(-fallbackDuration - 2*time.Second)
}

func (b *TelegramBot) NotifyNewVuln(findingID, targetID, domain, vulnType, severity, rawURL, parameter string) {
	text := "🚨 Verified finding\nTarget: " + displayDomain(domain) + "\nSeverity: " + strings.ToUpper(severity) +
		"\nType: " + vulnType + "\nURL: " + rawURL
	if parameter != "" {
		text += "\nParameter: " + parameter
	}
	b.enqueue("finding", "finding:"+findingID, text, b.findingKeyboard(targetID))
}

func (b *TelegramBot) NotifyMonitorChange(targetID, domain, changeType, rawURL, oldVal, newVal string) {
	text := "🔭 Monitor change\nTarget: " + displayDomain(domain) + "\nType: " + changeType + "\n" + rawURL
	if oldVal != "" {
		text += "\nOld: " + oldVal
	}
	if newVal != "" {
		text += "\nNew: " + newVal
	}
	b.enqueue("monitoring", "monitor:"+targetID+":"+changeType+":"+strconv.FormatInt(time.Now().UnixNano(), 10), text, b.scanKeyboard(targetID))
}

// Some first-class finding stores (verified Nuclei, backup exposure and open
// redirect) predate new_vuln_finding broadcasts. Sweep only the just-finished
// phase window and rely on the outbox's row-id event key for exact-once delivery.
func (b *TelegramBot) enqueueValidFindingsSince(targetID string, since time.Time) {
	sinceSQL := since.UTC().Format("2006-01-02 15:04:05")
	var domain string
	_ = b.h.db.QueryRow(`SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)
	type found struct{ id, typ, severity, rawURL, param, qualifier string }
	var all []found
	queries := []struct {
		query string
		args  []any
	}{
		{`SELECT id,type,severity,url,COALESCE(parameter,''),'verified' FROM vuln_findings
			WHERE target_id=? AND COALESCE(status,'finding')='finding' AND COALESCE(triage,'')<>'false_positive' AND created_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,template_name,severity,matched_url,'',COALESCE(verification,'unverified') FROM nuclei_findings
			WHERE target_id=? AND verification='verified' AND verified_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,'open_redirect','medium',url,COALESCE(parameter,''),'verified' FROM open_redirect_findings
			WHERE target_id=? AND verified=1 AND COALESCE(status,'finding')='finding' AND created_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,'backup_exposure','high',url,'','content-validated' FROM backup_findings
			WHERE target_id=? AND created_at>=?`, []any{targetID, sinceSQL}},
		{`SELECT id,type,severity,COALESCE((SELECT url FROM js_files WHERE id=js_findings.js_file_id),''),'','verified' FROM js_findings
			WHERE target_id=? AND verified=1 AND created_at>=?`, []any{targetID, sinceSQL}},
	}
	for _, q := range queries {
		rows, err := b.h.db.Query(q.query, q.args...)
		if err != nil {
			continue
		}
		for rows.Next() {
			var f found
			if rows.Scan(&f.id, &f.typ, &f.severity, &f.rawURL, &f.param, &f.qualifier) == nil {
				all = append(all, f)
			}
		}
		rows.Close()
	}
	for _, f := range all {
		text := "🚨 Verified finding\nTarget: " + displayDomain(domain) + "\nSeverity: " + strings.ToUpper(f.severity) +
			"\nType: " + f.typ + "\nURL: " + f.rawURL + "\nProof: " + f.qualifier
		if f.param != "" {
			text += "\nParameter: " + f.param
		}
		b.enqueue("finding", "finding:"+f.id, text, b.findingKeyboard(targetID))
	}
}

func (b *TelegramBot) scanKeyboard(targetID string) *tgInlineKeyboard {
	return &tgInlineKeyboard{Rows: [][]tgInlineButton{
		{{Text: "📊 Target", CallbackData: "target:" + targetID}, {Text: "⏭ Skip phase", CallbackData: "skip:" + targetID}},
		{{Text: "⏸ Pause", CallbackData: "pause:" + targetID}, {Text: "▶ Resume", CallbackData: "resume:" + targetID}, {Text: "🛑 Cancel", CallbackData: "cancel:" + targetID}},
	}}
}

func (b *TelegramBot) findingKeyboard(targetID string) *tgInlineKeyboard {
	return &tgInlineKeyboard{Rows: [][]tgInlineButton{{{Text: "🔎 Latest findings", CallbackData: "findings:" + targetID}, {Text: "📊 Target", CallbackData: "target:" + targetID}}}}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func minInt(a, c int) int {
	if a < c {
		return a
	}
	return c
}

func shortBotID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func shortDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func displayDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if len([]rune(domain)) > 180 {
		return string([]rune(domain)[:177]) + "…"
	}
	return domain
}
