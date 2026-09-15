package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scheduler"
)

type telegramTarget struct {
	ID             string
	Domain         string
	Name           string
	Kind           string
	Priority       string
	ScanStatus     string
	FindingCount   int
	EnabledModules []string
}

func roleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "viewer":
		return 0
	case "operator":
		return 1
	case "admin":
		return 2
	default:
		return -1
	}
}

func (b *TelegramBot) handleUpdate(ctx context.Context, token string, update tgUpdate) {
	if update.Message != nil {
		chatID := strconv.FormatInt(update.Message.Chat.ID, 10)
		chat, ok := b.authorizedChat(ctx, chatID)
		if !ok {
			_ = b.sendMessage(ctx, token, chatID, "This chat is not authorized in Reconner.\nChat ID: "+chatID+"\nAsk a Reconner administrator to add it in System → Integrations → Telegram.", nil)
			return
		}
		b.handleCommand(ctx, token, chat, update.Message.Text)
		return
	}
	if update.CallbackQuery != nil && update.CallbackQuery.Message != nil {
		chatID := strconv.FormatInt(update.CallbackQuery.Message.Chat.ID, 10)
		chat, ok := b.authorizedChat(ctx, chatID)
		if !ok {
			b.answerCallback(ctx, token, update.CallbackQuery.ID, "Unauthorized chat")
			return
		}
		b.handleCallback(ctx, token, chat, update.CallbackQuery)
	}
}

func (b *TelegramBot) authorizedChat(ctx context.Context, chatID string) (TelegramChat, bool) {
	var c TelegramChat
	var enabled, a, p, f, findings, monitoring int
	err := b.h.db.QueryRowContext(ctx, `SELECT id,chat_id,label,role,enabled,
		notify_scan_started,notify_phase_finished,notify_scan_finished,notify_findings,notify_monitoring,
		created_at,updated_at FROM telegram_chats WHERE chat_id=?`, chatID).
		Scan(&c.ID, &c.ChatID, &c.Label, &c.Role, &enabled, &a, &p, &f, &findings, &monitoring, &c.CreatedAt, &c.UpdatedAt)
	if err != nil || enabled != 1 {
		return c, false
	}
	c.Enabled, c.NotifyScanStarted, c.NotifyPhaseFinished = true, a == 1, p == 1
	c.NotifyScanFinished, c.NotifyFindings, c.NotifyMonitoring = f == 1, findings == 1, monitoring == 1
	return c, true
}

func (b *TelegramBot) handleCommand(ctx context.Context, token string, chat TelegramChat, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return
	}
	fields := strings.Fields(raw)
	command := strings.TrimPrefix(fields[0], "/")
	commandParts := strings.SplitN(command, "@", 2)
	if len(commandParts) == 2 {
		var username string
		_ = b.h.db.QueryRowContext(ctx, `SELECT bot_username FROM telegram_config WHERE id=1`).Scan(&username)
		if username == "" || !strings.EqualFold(commandParts[1], username) {
			return
		}
	}
	name := strings.ToLower(commandParts[0])
	args := fields[1:]
	reply := func(text string, keyboard *tgInlineKeyboard) {
		_ = b.sendMessage(ctx, token, chat.ChatID, text, keyboard)
	}

	switch name {
	case "start", "help":
		reply(b.helpText(chat.Role), nil)
	case "chatid":
		reply("Chat ID: "+chat.ChatID+"\nRole: "+chat.Role, nil)
	case "status":
		reply(b.statusText(ctx), nil)
	case "targets":
		text, keyboard := b.targetsText(ctx, chat.Role)
		reply(text, keyboard)
	case "target":
		if len(args) == 0 {
			reply("Usage: /target <id, name or domain>", nil)
			return
		}
		t, err := b.resolveTelegramTarget(ctx, strings.Join(args, " "))
		if err != nil {
			reply("Target: "+err.Error(), nil)
			return
		}
		reply(b.targetText(t), b.targetKeyboard(t.ID, chat.Role))
	case "scans":
		reply(b.scansText(ctx), nil)
	case "findings":
		ref := strings.Join(args, " ")
		reply(b.findingsText(ctx, ref), nil)
	case "scan":
		if !b.requireRole(chat, "operator", reply) {
			return
		}
		if len(args) == 0 {
			reply("Usage: /scan <target> [safe|standard|deep]", nil)
			return
		}
		profile := "standard"
		if last := strings.ToLower(args[len(args)-1]); last == "safe" || last == "standard" || last == "deep" {
			profile = last
			args = args[:len(args)-1]
		}
		t, err := b.resolveTelegramTarget(ctx, strings.Join(args, " "))
		if err == nil {
			var task *models.Task
			task, err = b.startTelegramScan(ctx, t, profile)
			if err == nil {
				b.audit(chat.ChatID, "scan_start", t.ID, "ok", profile)
				reply("✅ Scan queued for "+displayDomain(t.Domain)+"\nProfile: "+profile+"\nTask: "+shortBotID(task.ID), b.scanKeyboard(t.ID))
				return
			}
		}
		b.audit(chat.ChatID, "scan_start", strings.Join(args, " "), "failed", errorText(err))
		reply("Could not start scan: "+errorText(err), nil)
	case "pause", "resume", "skip", "skipphase", "cancel":
		if !b.requireRole(chat, "operator", reply) {
			return
		}
		if len(args) == 0 {
			reply("Usage: /"+name+" <target>", nil)
			return
		}
		t, err := b.resolveTelegramTarget(ctx, strings.Join(args, " "))
		controlAction := name
		if controlAction == "skipphase" {
			controlAction = "skip"
		}
		if err == nil {
			err = b.controlScan(controlAction, t.ID)
		}
		b.audit(chat.ChatID, "scan_"+controlAction, targetResource(t), statusFor(err), errorText(err))
		if err != nil {
			reply("Scan control failed: "+err.Error(), nil)
		} else {
			reply("✅ Scan "+name+" requested for "+displayDomain(t.Domain), b.scanKeyboard(t.ID))
		}
	case "addtarget":
		if !b.requireRole(chat, "admin", reply) {
			return
		}
		payload := strings.TrimSpace(strings.TrimPrefix(raw, fields[0]))
		parts := splitBotPipes(payload)
		if len(parts) == 0 || parts[0] == "" {
			reply("Usage: /addtarget <scope> | <optional name>", nil)
			return
		}
		nameValue := ""
		if len(parts) > 1 {
			nameValue = parts[1]
		}
		t, err := b.createTelegramTarget(ctx, parts[0], nameValue)
		b.audit(chat.ChatID, "target_add", parts[0], statusFor(err), errorText(err))
		if err != nil {
			reply("Could not add target: "+err.Error(), nil)
		} else {
			reply("✅ Target added\n"+b.targetText(t), b.targetKeyboard(t.ID, chat.Role))
		}
	case "edittarget":
		if !b.requireRole(chat, "admin", reply) {
			return
		}
		payload := strings.TrimSpace(strings.TrimPrefix(raw, fields[0]))
		parts := splitBotPipes(payload)
		if len(parts) < 2 {
			reply("Usage: /edittarget <target> | name=... | priority=low|medium|high|critical | scope=... | exclude=... | notes=...", nil)
			return
		}
		t, err := b.resolveTelegramTarget(ctx, parts[0])
		if err == nil {
			err = b.editTelegramTarget(ctx, t, parts[1:])
		}
		b.audit(chat.ChatID, "target_edit", targetResource(t), statusFor(err), errorText(err))
		if err != nil {
			reply("Could not edit target: "+err.Error(), nil)
		} else {
			t, _ = b.resolveTelegramTarget(ctx, t.ID)
			reply("✅ Target updated\n"+b.targetText(t), b.targetKeyboard(t.ID, chat.Role))
		}
	case "deletetarget":
		if !b.requireRole(chat, "admin", reply) {
			return
		}
		if len(args) == 0 {
			reply("Usage: /deletetarget <target>", nil)
			return
		}
		t, err := b.resolveTelegramTarget(ctx, strings.Join(args, " "))
		if err != nil {
			reply("Target: "+err.Error(), nil)
			return
		}
		keyboard := &tgInlineKeyboard{Rows: [][]tgInlineButton{{
			{Text: "Delete permanently", CallbackData: "delete_confirm:" + t.ID},
			{Text: "Keep target", CallbackData: "delete_cancel:" + t.ID},
		}}}
		reply("⚠️ Delete target?\n"+displayDomain(t.Domain)+"\nRunning scans and all results will be removed.", keyboard)
	default:
		reply("Unknown command. Use /help.", nil)
	}
}

func (b *TelegramBot) handleCallback(ctx context.Context, token string, chat TelegramChat, q *tgCallbackQuery) {
	parts := strings.SplitN(q.Data, ":", 2)
	if len(parts) != 2 {
		b.answerCallback(ctx, token, q.ID, "Invalid action")
		return
	}
	action, targetID := parts[0], parts[1]
	reply := func(text string, keyboard *tgInlineKeyboard) {
		_ = b.sendMessage(ctx, token, chat.ChatID, text, keyboard)
	}
	t, err := b.resolveTelegramTarget(ctx, targetID)
	if err != nil && action != "delete_cancel" {
		b.answerCallback(ctx, token, q.ID, "Target not found")
		return
	}
	switch action {
	case "target":
		b.answerCallback(ctx, token, q.ID, "Target loaded")
		reply(b.targetText(t), b.targetKeyboard(t.ID, chat.Role))
	case "findings":
		b.answerCallback(ctx, token, q.ID, "Findings loaded")
		reply(b.findingsText(ctx, t.ID), nil)
	case "scan":
		if roleRank(chat.Role) < roleRank("operator") {
			b.answerCallback(ctx, token, q.ID, "Operator role required")
			return
		}
		task, runErr := b.startTelegramScan(ctx, t, "standard")
		b.audit(chat.ChatID, "scan_start", t.ID, statusFor(runErr), "standard; "+errorText(runErr))
		if runErr != nil {
			b.answerCallback(ctx, token, q.ID, "Scan could not start")
			reply("Could not start scan: "+runErr.Error(), nil)
		} else {
			b.answerCallback(ctx, token, q.ID, "Scan queued")
			reply("✅ Scan queued for "+displayDomain(t.Domain)+"\nTask: "+shortBotID(task.ID), b.scanKeyboard(t.ID))
		}
	case "pause", "resume", "skip", "cancel":
		if roleRank(chat.Role) < roleRank("operator") {
			b.answerCallback(ctx, token, q.ID, "Operator role required")
			return
		}
		runErr := b.controlScan(action, t.ID)
		b.audit(chat.ChatID, "scan_"+action, t.ID, statusFor(runErr), errorText(runErr))
		if runErr != nil {
			b.answerCallback(ctx, token, q.ID, "Action failed")
			reply("Scan control failed: "+runErr.Error(), nil)
		} else {
			b.answerCallback(ctx, token, q.ID, "Action accepted")
		}
	case "delete_confirm":
		if roleRank(chat.Role) < roleRank("admin") {
			b.answerCallback(ctx, token, q.ID, "Admin role required")
			return
		}
		runErr := b.h.deleteTargetByID(t.ID)
		b.audit(chat.ChatID, "target_delete", t.ID, statusFor(runErr), errorText(runErr))
		if runErr != nil {
			b.answerCallback(ctx, token, q.ID, "Delete failed")
			reply("Could not delete target: "+runErr.Error(), nil)
		} else {
			b.answerCallback(ctx, token, q.ID, "Target deleted")
			reply("🗑 Target deleted: "+displayDomain(t.Domain), nil)
		}
	case "delete_cancel":
		b.answerCallback(ctx, token, q.ID, "Deletion cancelled")
	default:
		b.answerCallback(ctx, token, q.ID, "Unknown action")
	}
}

func (b *TelegramBot) requireRole(chat TelegramChat, required string, reply func(string, *tgInlineKeyboard)) bool {
	if roleRank(chat.Role) >= roleRank(required) {
		return true
	}
	reply(strings.ToUpper(required[:1])+required[1:]+" role required for this command.", nil)
	return false
}

func (b *TelegramBot) helpText(role string) string {
	text := "Reconner Telegram control\n\nView:\n/status — platform summary\n/targets — list targets\n/target <id|name|domain> — target details\n/scans — recent scans\n/findings [target] — latest findings\n/chatid — this chat and role"
	if roleRank(role) >= roleRank("operator") {
		text += "\n\nScan control:\n/scan <target> [safe|standard|deep]\n/pause <target>\n/resume <target>\n/skip <target> — skip current phase\n/cancel <target>"
	}
	if roleRank(role) >= roleRank("admin") {
		text += "\n\nTarget management:\n/addtarget <scope> | <name>\n/edittarget <target> | name=... | priority=... | scope=... | exclude=... | notes=...\n/deletetarget <target>"
	}
	return text
}

func (b *TelegramBot) statusText(ctx context.Context) string {
	var targets, running, pending, findings, critical int
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM targets`).Scan(&targets)
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tasks WHERE status='running'`).Scan(&running)
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tasks WHERE status='pending'`).Scan(&pending)
	_ = b.h.db.QueryRowContext(ctx, `WITH verified(severity) AS (
		SELECT severity FROM vuln_findings WHERE COALESCE(status,'finding')='finding' AND COALESCE(triage,'')<>'false_positive'
		UNION ALL SELECT severity FROM nuclei_findings WHERE verification='verified'
		UNION ALL SELECT 'medium' FROM open_redirect_findings WHERE verified=1 AND COALESCE(status,'finding')='finding'
		UNION ALL SELECT 'high' FROM backup_findings
		UNION ALL SELECT severity FROM js_findings WHERE verified=1
	) SELECT COUNT(*),COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0) FROM verified`).Scan(&findings, &critical)
	return fmt.Sprintf("Reconner status\nTargets: %d\nScans: %d running · %d queued\nVerified findings: %d (%d critical)", targets, running, pending, findings, critical)
}

func (b *TelegramBot) targetsText(ctx context.Context, role string) (string, *tgInlineKeyboard) {
	rows, err := b.h.db.QueryContext(ctx, `SELECT id,domain,COALESCE(name,''),COALESCE(scan_status,'idle'),COALESCE(finding_count,0)
		FROM targets ORDER BY updated_at DESC LIMIT 20`)
	if err != nil {
		return "Could not load targets.", nil
	}
	defer rows.Close()
	lines := []string{"Targets (latest 20)"}
	keyboard := &tgInlineKeyboard{}
	for rows.Next() {
		var id, domain, name, status string
		var findings int
		if rows.Scan(&id, &domain, &name, &status, &findings) != nil {
			continue
		}
		label := name
		if label == "" {
			label = displayDomain(domain)
		}
		lines = append(lines, fmt.Sprintf("%s · %s · %d findings · #%s", label, status, findings, shortBotID(id)))
		buttons := []tgInlineButton{{Text: trimButton(label), CallbackData: "target:" + id}}
		if roleRank(role) >= roleRank("operator") {
			buttons = append(buttons, tgInlineButton{Text: "Scan", CallbackData: "scan:" + id})
		}
		keyboard.Rows = append(keyboard.Rows, buttons)
	}
	if len(lines) == 1 {
		return "No targets yet.", nil
	}
	return strings.Join(lines, "\n"), keyboard
}

func (b *TelegramBot) targetText(t telegramTarget) string {
	label := t.Name
	if label == "" {
		label = displayDomain(t.Domain)
	}
	return fmt.Sprintf("Target: %s\nScope: %s\nID: %s\nKind: %s · Priority: %s\nScan: %s\nFindings: %d",
		label, displayDomain(t.Domain), t.ID, t.Kind, t.Priority, t.ScanStatus, t.FindingCount)
}

func (b *TelegramBot) targetKeyboard(id, role string) *tgInlineKeyboard {
	rows := [][]tgInlineButton{{{Text: "🔎 Findings", CallbackData: "findings:" + id}}}
	if roleRank(role) >= roleRank("operator") {
		rows = append(rows,
			[]tgInlineButton{{Text: "🚀 Standard scan", CallbackData: "scan:" + id}},
			[]tgInlineButton{{Text: "⏭ Skip phase", CallbackData: "skip:" + id}},
			[]tgInlineButton{{Text: "⏸ Pause", CallbackData: "pause:" + id}, {Text: "▶ Resume", CallbackData: "resume:" + id}, {Text: "🛑 Cancel", CallbackData: "cancel:" + id}},
		)
	}
	return &tgInlineKeyboard{Rows: rows}
}

func (b *TelegramBot) scansText(ctx context.Context) string {
	rows, err := b.h.db.QueryContext(ctx, `SELECT t.id,COALESCE(g.name,''),g.domain,t.status,t.progress,t.total,COALESCE(t.current_module,'')
		FROM tasks t JOIN targets g ON g.id=t.target_id ORDER BY t.created_at DESC LIMIT 15`)
	if err != nil {
		return "Could not load scans."
	}
	defer rows.Close()
	lines := []string{"Recent scans"}
	for rows.Next() {
		var id, name, domain, status, module string
		var progress, total int
		if rows.Scan(&id, &name, &domain, &status, &progress, &total, &module) != nil {
			continue
		}
		if name == "" {
			name = displayDomain(domain)
		}
		line := fmt.Sprintf("%s · %s · %d/%d · #%s", name, status, progress, total, shortBotID(id))
		if module != "" {
			line += " · " + module
		}
		lines = append(lines, line)
	}
	if len(lines) == 1 {
		return "No scans yet."
	}
	return strings.Join(lines, "\n")
}

func (b *TelegramBot) findingsText(ctx context.Context, targetRef string) string {
	targetID, title := "", "Latest verified findings"
	if strings.TrimSpace(targetRef) != "" {
		t, err := b.resolveTelegramTarget(ctx, targetRef)
		if err != nil {
			return "Target: " + err.Error()
		}
		targetID, title = t.ID, "Latest findings · "+displayDomain(t.Domain)
	}
	query := `WITH verified(target_id,type,severity,url,parameter,created_at) AS (
		SELECT target_id,type,severity,url,COALESCE(parameter,''),created_at FROM vuln_findings
		 WHERE COALESCE(status,'finding')='finding' AND COALESCE(triage,'')<>'false_positive'
		UNION ALL SELECT target_id,template_name,severity,matched_url,'',created_at FROM nuclei_findings WHERE verification='verified'
		UNION ALL SELECT target_id,'open_redirect','medium',url,COALESCE(parameter,''),created_at FROM open_redirect_findings
		 WHERE verified=1 AND COALESCE(status,'finding')='finding'
		UNION ALL SELECT target_id,'backup_exposure','high',url,'',created_at FROM backup_findings
		UNION ALL SELECT j.target_id,j.type,j.severity,COALESCE(f.url,''),'',j.created_at FROM js_findings j
		 LEFT JOIN js_files f ON f.id=j.js_file_id WHERE j.verified=1
	) SELECT type,severity,url,parameter,created_at FROM verified
	  WHERE (?='' OR target_id=?) ORDER BY created_at DESC LIMIT 12`
	rows, err := b.h.db.QueryContext(ctx, query, targetID, targetID)
	if err != nil {
		return "Could not load findings."
	}
	defer rows.Close()
	lines := []string{title}
	for rows.Next() {
		var typ, severity, rawURL, param, created string
		if rows.Scan(&typ, &severity, &rawURL, &param, &created) != nil {
			continue
		}
		line := "[" + strings.ToUpper(severity) + "] " + typ + "\n" + rawURL
		if param != "" {
			line += " · " + param
		}
		lines = append(lines, line)
	}
	if len(lines) == 1 {
		return title + "\nNo verified findings."
	}
	return strings.Join(lines, "\n\n")
}

func (b *TelegramBot) resolveTelegramTarget(ctx context.Context, ref string) (telegramTarget, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return telegramTarget{}, fmt.Errorf("target reference is empty")
	}
	rows, err := b.h.db.QueryContext(ctx, `SELECT id,domain,COALESCE(name,''),COALESCE(kind,'web'),COALESCE(priority,'medium'),
		COALESCE(scan_status,'idle'),COALESCE(finding_count,0),COALESCE(enabled_modules,'[]')
		FROM targets WHERE id=? OR id LIKE ? OR lower(COALESCE(name,''))=lower(?) OR lower(domain)=lower(?)
		ORDER BY CASE WHEN id=? THEN 0 WHEN lower(COALESCE(name,''))=lower(?) THEN 1 ELSE 2 END LIMIT 3`,
		ref, ref+"%", ref, ref, ref, ref)
	if err != nil {
		return telegramTarget{}, err
	}
	defer rows.Close()
	var found []telegramTarget
	for rows.Next() {
		var t telegramTarget
		var modules string
		if rows.Scan(&t.ID, &t.Domain, &t.Name, &t.Kind, &t.Priority, &t.ScanStatus, &t.FindingCount, &modules) == nil {
			t.EnabledModules = models.JSONToStringSlice(modules)
			found = append(found, t)
		}
	}
	if len(found) == 0 {
		return telegramTarget{}, fmt.Errorf("not found")
	}
	if len(found) > 1 {
		return telegramTarget{}, fmt.Errorf("reference is ambiguous; use the target id")
	}
	return found[0], nil
}

func (b *TelegramBot) startTelegramScan(ctx context.Context, target telegramTarget, profile string) (*models.Task, error) {
	if target.Kind == "network" || target.Kind == "mixed" {
		return nil, fmt.Errorf("network/CIDR scanning is unavailable in this build; use a web-only project")
	}
	if b.h.sched == nil {
		return nil, fmt.Errorf("scheduler is unavailable")
	}
	var modules []string
	webSafe := []string{scheduler.ModuleHTTPProbe, scheduler.ModuleJSAnalysis, scheduler.ModuleJSEndpoints,
		scheduler.ModuleParamDiscovery, scheduler.ModulePassive, scheduler.ModuleExposure, scheduler.ModuleIntel}
	webStandard := append(append([]string{}, webSafe...), scheduler.ModuleParamReflection, scheduler.ModuleBackupDiscovery,
		scheduler.ModuleOpenRedirect, scheduler.ModuleXSS, scheduler.ModuleSQLi, scheduler.ModuleCORS, scheduler.ModuleJWT)
	switch profile {
	case "safe":
		modules = webSafe
	case "deep":
		modules = append([]string{}, scheduler.AllModules...)
	default:
		modules = webStandard
	}
	// Access-control proof is useful only with two identities. A Telegram deep
	// scan remains runnable on a fresh target but does not pretend IDOR was tested.
	var identityCount int
	_ = b.h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identities WHERE target_id=?`, target.ID).Scan(&identityCount)
	if identityCount < 2 {
		filtered := modules[:0]
		for _, module := range modules {
			if module != scheduler.ModuleIDOR && module != scheduler.ModuleAuthz {
				filtered = append(filtered, module)
			}
		}
		modules = filtered
	}
	return b.h.sched.CreateTask(target.ID, modules, 5)
}

func (b *TelegramBot) controlScan(action, targetID string) error {
	if b.h.sched == nil {
		return fmt.Errorf("scheduler is unavailable")
	}
	switch action {
	case "pause":
		return b.h.sched.PauseTarget(targetID)
	case "resume":
		return b.h.sched.ResumeTarget(targetID)
	case "skip":
		return b.h.sched.SkipCurrentPhase(targetID)
	case "cancel":
		return b.h.sched.CancelTasksForTarget(targetID)
	default:
		return fmt.Errorf("unsupported scan action")
	}
}

func (b *TelegramBot) createTelegramTarget(ctx context.Context, rawScope, name string) (telegramTarget, error) {
	values, err := normalizeScopeValues(rawScope)
	if err != nil {
		return telegramTarget{}, err
	}
	domain := strings.Join(values, ",")
	if classifyProjectScope(values) != "web" {
		return telegramTarget{}, fmt.Errorf("network/CIDR targets are unavailable in this build; add web domains or URLs only")
	}
	kind := "web"
	var ownerID int64
	if err := b.h.db.QueryRowContext(ctx, `SELECT id FROM users WHERE role='admin' AND disabled=0 ORDER BY id LIMIT 1`).Scan(&ownerID); err != nil {
		return telegramTarget{}, fmt.Errorf("no active Reconner administrator owns bot-created targets")
	}
	id := uuid.NewString()
	tx, err := b.h.db.BeginTx(ctx, nil)
	if err != nil {
		return telegramTarget{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO targets(id,domain,name,description,tags,priority,notes,kind,exclude_scope,owner_id,scan_headers)
		VALUES(?,?,?,'','[]','medium','',?,'',?,'{}')`, id, domain, strings.TrimSpace(name), kind, ownerID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return telegramTarget{}, fmt.Errorf("target already exists")
		}
		return telegramTarget{}, err
	}
	if err := reconcileManualAssetsTx(tx, id, values); err != nil {
		return telegramTarget{}, err
	}
	if err := tx.Commit(); err != nil {
		return telegramTarget{}, err
	}
	if b.h.hub != nil {
		b.h.hub.Broadcast("target_created", map[string]any{"id": id, "domain": domain, "name": strings.TrimSpace(name), "kind": kind})
	}
	return b.resolveTelegramTarget(ctx, id)
}

func (b *TelegramBot) editTelegramTarget(ctx context.Context, target telegramTarget, edits []string) error {
	updates := map[string]string{}
	for _, edit := range edits {
		pair := strings.SplitN(strings.TrimSpace(edit), "=", 2)
		if len(pair) != 2 {
			return fmt.Errorf("invalid edit %q; use field=value", edit)
		}
		key, value := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		switch key {
		case "name", "priority", "scope", "exclude", "notes":
			updates[key] = value
		default:
			return fmt.Errorf("unsupported field %q", key)
		}
	}
	if priority, ok := updates["priority"]; ok {
		switch strings.ToLower(priority) {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("priority must be low, medium, high or critical")
		}
	}
	tx, err := b.h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if value, ok := updates["name"]; ok {
		if _, err = tx.ExecContext(ctx, `UPDATE targets SET name=? WHERE id=?`, value, target.ID); err != nil {
			return err
		}
	}
	if value, ok := updates["priority"]; ok {
		if _, err = tx.ExecContext(ctx, `UPDATE targets SET priority=? WHERE id=?`, strings.ToLower(value), target.ID); err != nil {
			return err
		}
	}
	if value, ok := updates["exclude"]; ok {
		if _, err = tx.ExecContext(ctx, `UPDATE targets SET exclude_scope=? WHERE id=?`, value, target.ID); err != nil {
			return err
		}
	}
	if value, ok := updates["notes"]; ok {
		if _, err = tx.ExecContext(ctx, `UPDATE targets SET notes=? WHERE id=?`, value, target.ID); err != nil {
			return err
		}
	}
	if value, ok := updates["scope"]; ok {
		values, scopeErr := normalizeScopeValues(value)
		if scopeErr != nil {
			return scopeErr
		}
		domain := strings.Join(values, ",")
		if classifyProjectScope(values) != "web" {
			return fmt.Errorf("network/CIDR targets are unavailable in this build; use web domains or URLs only")
		}
		kind := "web"
		if _, err = tx.ExecContext(ctx, `UPDATE targets SET domain=?,kind=? WHERE id=?`, domain, kind, target.ID); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return fmt.Errorf("another target already uses that scope")
			}
			return err
		}
		if err := reconcileManualAssetsTx(tx, target.ID, values); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE targets SET updated_at=CURRENT_TIMESTAMP WHERE id=?`, target.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if b.h.hub != nil {
		b.h.hub.Broadcast("target_updated", map[string]string{"id": target.ID})
	}
	return nil
}

func (b *TelegramBot) audit(chatID, action, resource, status, detail string) {
	if len(detail) > 1000 {
		detail = detail[:1000]
	}
	_, _ = b.h.db.Exec(`INSERT INTO telegram_audit_log(id,chat_id,action,resource,status,detail) VALUES(?,?,?,?,?,?)`,
		uuid.NewString(), chatID, action, resource, status, detail)
}

func splitBotPipes(s string) []string {
	raw := strings.Split(s, "|")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, strings.TrimSpace(v))
	}
	return out
}

func trimButton(s string) string {
	r := []rune(s)
	if len(r) > 28 {
		return string(r[:27]) + "…"
	}
	return s
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func statusFor(err error) string {
	if err == nil {
		return "ok"
	}
	return "failed"
}

func targetResource(t telegramTarget) string {
	if t.ID != "" {
		return t.ID
	}
	return t.Domain
}
