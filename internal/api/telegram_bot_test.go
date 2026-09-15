package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
)

func telegramAPIMock(t *testing.T, messages *[]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			_, _ = w.Write([]byte(`{"ok":true,"result":{"id":42,"username":"reconner_test_bot"}}`))
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			*messages = append(*messages, payload)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		}
	}))
}

func TestTelegramTokenIsValidatedMaskedAndEncrypted(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg.SessionSecret = "unit-test-session-secret"
	bot := NewTelegramBot(h)
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	defer server.Close()
	bot.apiBase = server.URL

	token := "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	enabled := true
	if err := bot.Configure(context.Background(), &token, &enabled); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := h.db.QueryRow(`SELECT encrypted_bot_token FROM telegram_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("bot token was not encrypted at rest: %q", stored)
	}
	state, err := bot.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Configured || !state.Enabled || state.BotUsername != "reconner_test_bot" || state.MaskedToken == token {
		t.Fatalf("unsafe or incomplete state: %+v", state)
	}
	if _, err := h.db.Exec(`UPDATE telegram_config SET last_update_id=77 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	disabled := false
	if err := bot.Configure(context.Background(), nil, &disabled); err != nil {
		t.Fatal(err)
	}
	var lastUpdateID int64
	_ = h.db.QueryRow(`SELECT last_update_id FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
	if lastUpdateID != 77 {
		t.Fatalf("toggling the existing bot reset its update cursor: %d", lastUpdateID)
	}
	replacement := "987654321:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	if err := bot.Configure(context.Background(), &replacement, &enabled); err != nil {
		t.Fatal(err)
	}
	_ = h.db.QueryRow(`SELECT last_update_id FROM telegram_config WHERE id=1`).Scan(&lastUpdateID)
	if lastUpdateID != 0 {
		t.Fatalf("a replacement bot inherited the previous bot's update cursor: %d", lastUpdateID)
	}
}

func TestTelegramOutboxFansOutAndHonorsPerChatPreferences(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	if _, err := h.db.Exec(`INSERT INTO telegram_config(id,encrypted_bot_token,enabled) VALUES(1,'test-token',1)`); err != nil {
		t.Fatal(err)
	}
	first, err := bot.AddChat(context.Background(), TelegramChat{ChatID: "1001", Label: "viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := bot.AddChat(context.Background(), TelegramChat{ChatID: "-1002002", Label: "ops", Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	second.NotifyFindings = false
	if err := bot.UpdateChat(context.Background(), second.ID, second); err != nil {
		t.Fatal(err)
	}

	bot.NotifyNewVuln("finding-1", "target-1", "example.com", "sqli", "medium", "https://example.com/?id=1", "id")
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "sqli", "completed", 0, 3, 5)
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "origin_ip", "blocked", 0, 4, 5)
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "nuclei", "skipped", 0, 5, 5)

	var findingRows, phaseRows int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='finding'`).Scan(&findingRows)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='phase_finished'`).Scan(&phaseRows)
	if findingRows != 1 || phaseRows != 6 {
		t.Fatalf("preference fanout wrong: findings=%d phases=%d", findingRows, phaseRows)
	}
	// Exact-once per chat/event: replaying the same callbacks cannot duplicate.
	bot.NotifyNewVuln("finding-1", "target-1", "example.com", "sqli", "medium", "https://example.com/?id=1", "id")
	bot.NotifyPhaseFinished("task-1", "target-1", "example.com", "sqli", "completed", 0, 3, 5)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='finding'`).Scan(&findingRows)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='phase_finished'`).Scan(&phaseRows)
	if findingRows != 1 || phaseRows != 6 {
		t.Fatalf("outbox dedup failed: findings=%d phases=%d", findingRows, phaseRows)
	}
	var blockedMessage, skippedMessage string
	_ = h.db.QueryRow(`SELECT message FROM telegram_outbox WHERE event_key='scan:phase:task-1:origin_ip:blocked' LIMIT 1`).Scan(&blockedMessage)
	_ = h.db.QueryRow(`SELECT message FROM telegram_outbox WHERE event_key='scan:phase:task-1:nuclei:skipped' LIMIT 1`).Scan(&skippedMessage)
	if !strings.Contains(blockedMessage, "🚫 Scan phase blocked") || !strings.Contains(skippedMessage, "⏭ Scan phase skipped") {
		t.Fatalf("terminal phase notifications lost status: blocked=%q skipped=%q", blockedMessage, skippedMessage)
	}
	_, _ = h.db.Exec(`UPDATE telegram_config SET enabled=0 WHERE id=1`)
	bot.NotifyNewVuln("finding-while-disabled", "target-1", "example.com", "xss", "high", "https://example.com/x", "q")
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE category='finding'`).Scan(&findingRows)
	if findingRows != 1 {
		t.Fatalf("disabled bot accumulated a surprise delivery backlog: findings=%d", findingRows)
	}
	if first.Role != "viewer" {
		t.Fatalf("chat role changed unexpectedly: %+v", first)
	}
}

func TestTelegramOutboxDeliversToEveryConfiguredChat(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg.SessionSecret = "unit-test-session-secret"
	bot := NewTelegramBot(h)
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	defer server.Close()
	bot.apiBase = server.URL
	token := "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
	enabled := true
	if err := bot.Configure(context.Background(), &token, &enabled); err != nil {
		t.Fatal(err)
	}
	for _, chatID := range []string{"1001", "-1002002"} {
		if _, err := bot.AddChat(context.Background(), TelegramChat{ChatID: chatID, Role: "viewer"}); err != nil {
			t.Fatal(err)
		}
	}
	bot.NotifyNewVuln("finding-1", "target-1", "example.com", "sqli", "critical", "https://example.com/?id=1", "id")
	bot.drainOutbox(context.Background())
	if len(messages) != 2 {
		t.Fatalf("expected one delivery per chat, got %d", len(messages))
	}
	var sent, pending int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='sent'`).Scan(&sent)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM telegram_outbox WHERE status='pending'`).Scan(&pending)
	if sent != 2 || pending != 0 {
		t.Fatalf("unexpected delivery state: sent=%d pending=%d", sent, pending)
	}
}

func TestTelegramAdminCanCreateAndEditTarget(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg = &config.Config{SessionSecret: "test"}
	bot := NewTelegramBot(h)
	target, err := bot.createTelegramTarget(context.Background(), "https://example.com/app", "Example")
	if err != nil {
		t.Fatal(err)
	}
	if target.Name != "Example" || target.Kind != "web" || target.Domain != "https://example.com/app" {
		t.Fatalf("unexpected target: %+v", target)
	}
	if err := bot.editTelegramTarget(context.Background(), target, []string{"name=Renamed", "priority=high", "notes=telegram"}); err != nil {
		t.Fatal(err)
	}
	updated, err := bot.resolveTelegramTarget(context.Background(), target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Renamed" || updated.Priority != "high" {
		t.Fatalf("target edit did not persist: %+v", updated)
	}
}

func TestTelegramTargetManagementRejectsUnsupportedNetworkScopes(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.cfg = &config.Config{SessionSecret: "test"}
	bot := NewTelegramBot(h)
	ctx := context.Background()

	for _, scope := range []string{"10.0.0.0/24", "example.com,10.0.0.1"} {
		if _, err := bot.createTelegramTarget(ctx, scope, "unsupported"); err == nil || !strings.Contains(err.Error(), "network/CIDR") {
			t.Fatalf("create scope %q error=%v, want explicit network rejection", scope, err)
		}
	}
	var count int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unsupported Telegram create persisted %d target(s)", count)
	}

	target, err := bot.createTelegramTarget(ctx, "example.org", "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := bot.editTelegramTarget(ctx, target, []string{"name=must-not-commit", "scope=192.0.2.0/24"}); err == nil || !strings.Contains(err.Error(), "network/CIDR") {
		t.Fatalf("network edit error=%v, want explicit rejection", err)
	}
	unchanged, err := bot.resolveTelegramTarget(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Domain != "example.org" || unchanged.Name != "web" || unchanged.Kind != "web" {
		t.Fatalf("rejected edit was not atomic: %+v", unchanged)
	}

	if _, err := bot.startTelegramScan(ctx, telegramTarget{Kind: "network"}, "deep"); err == nil || !strings.Contains(err.Error(), "network/CIDR") {
		t.Fatalf("legacy network scan error=%v, want explicit rejection", err)
	}
}

func TestTelegramViewerCannotMutateAndSkipPhaseAliasIsAudited(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	var messages []map[string]any
	server := telegramAPIMock(t, &messages)
	defer server.Close()
	bot.apiBase = server.URL
	ctx := context.Background()

	bot.handleCommand(ctx, "token", TelegramChat{ChatID: "1001", Role: "viewer"}, "/addtarget example.org | denied")
	bot.handleCommand(ctx, "token", TelegramChat{ChatID: "1001", Role: "viewer"}, "/scan example.org")
	var targets, tasks int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&targets)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&tasks)
	if targets != 0 || tasks != 0 {
		t.Fatalf("viewer mutation escaped RBAC: targets=%d tasks=%d", targets, tasks)
	}

	target, err := bot.createTelegramTarget(ctx, "example.org", "web")
	if err != nil {
		t.Fatal(err)
	}
	bot.handleCommand(ctx, "token", TelegramChat{ChatID: "2002", Role: "operator"}, "/skipphase "+target.ID)
	var action, status string
	if err := h.db.QueryRow(`SELECT action,status FROM telegram_audit_log WHERE chat_id='2002' ORDER BY created_at DESC LIMIT 1`).Scan(&action, &status); err != nil {
		t.Fatal(err)
	}
	if action != "scan_skip" || status != "failed" {
		t.Fatalf("skipphase alias audit=(%q,%q), want (scan_skip,failed)", action, status)
	}
}

func TestTelegramHelpIncludesSkipForOperatorsOnly(t *testing.T) {
	bot := &TelegramBot{}
	if strings.Contains(bot.helpText("viewer"), "/skip") {
		t.Fatal("viewer help exposed scan controls")
	}
	if !strings.Contains(bot.helpText("operator"), "/skip <target>") {
		t.Fatal("operator help is missing skip phase")
	}
	foundButton := false
	for _, row := range bot.scanKeyboard("target-id").Rows {
		for _, button := range row {
			if button.CallbackData == "skip:target-id" {
				foundButton = true
			}
		}
	}
	if !foundButton {
		t.Fatal("scan notification keyboard is missing skip phase")
	}
}

func TestTelegramFindingsListsOnlyValidatedResultsAcrossStores(t *testing.T) {
	h, _ := newIsoHandler(t)
	bot := NewTelegramBot(h)
	target, err := bot.createTelegramTarget(context.Background(), "example.org", "Example")
	if err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO vuln_findings(id,target_id,type,severity,url,parameter,status,triage) VALUES('vf',?,'sqli','critical','https://example.org/a','id','finding','')`, []any{target.ID}},
		{`INSERT INTO vuln_findings(id,target_id,type,severity,url,parameter,status,triage) VALUES('fp',?,'false_noise','high','https://example.org/noise','','finding','false_positive')`, []any{target.ID}},
		{`INSERT INTO nuclei_findings(id,target_id,template_id,template_name,severity,matched_url,verification,verified_at) VALUES('nf',?,'cve','verified_cve','high','https://example.org/cve','verified',CURRENT_TIMESTAMP)`, []any{target.ID}},
		{`INSERT INTO open_redirect_findings(id,target_id,url,parameter,verified,status) VALUES('or',?,'https://example.org/redirect','next',1,'finding')`, []any{target.ID}},
		{`INSERT INTO backup_findings(id,target_id,url,file_type) VALUES('bf',?,'https://example.org/.env','env')`, []any{target.ID}},
		{`INSERT INTO js_files(id,target_id,url) VALUES('js',?,'https://example.org/app.js')`, []any{target.ID}},
		{`INSERT INTO js_findings(id,target_id,js_file_id,type,value,severity,verified) VALUES('jf',?,'js','secret_exposure','token','medium',1)`, []any{target.ID}},
	}
	for _, stmt := range statements {
		if _, err := h.db.Exec(stmt.query, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	text := bot.findingsText(context.Background(), target.ID)
	for _, expected := range []string{"sqli", "verified_cve", "open_redirect", "backup_exposure", "secret_exposure"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q from findings output:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "false_noise") {
		t.Fatalf("false-positive result leaked into verified findings:\n%s", text)
	}
	status := bot.statusText(context.Background())
	if !strings.Contains(status, "Verified findings: 5 (1 critical)") {
		t.Fatalf("cross-store finding totals are wrong: %s", status)
	}
}
