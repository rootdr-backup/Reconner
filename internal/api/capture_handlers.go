package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/secret"
)

const captureMultipartOverhead = 1 << 20

func (h *Handler) handlePreviewCapture(w http.ResponseWriter, r *http.Request) {
	exchanges, identityID, identityLabel, label, err := h.readCaptureUpload(w, r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.validateCaptureIdentity(mux.Vars(r)["id"], identityID); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for i := range exchanges {
		exchanges[i].IdentityLabel = identityLabel
	}
	preview := capture.BuildPreview(exchanges, func(u string) bool {
		return scanner.GuidedURLInScope(r.Context(), h.db, mux.Vars(r)["id"], u)
	})
	h.writeSuccess(w, map[string]any{
		"preview": preview, "identity_id": identityID, "identity_label": identityLabel,
		"label": label, "passive": true, "traffic_sent": 0,
	})
}

// handleImportCapture seals accepted request/response pairs at rest. It does not
// replay, crawl, mutate, or otherwise contact the target.
func (h *Handler) handleImportCapture(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	exchanges, identityID, identityLabel, label, err := h.readCaptureUpload(w, r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.validateCaptureIdentity(targetID, identityID); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for i := range exchanges {
		exchanges[i].IdentityLabel = identityLabel
	}
	preview := capture.BuildPreview(exchanges, func(u string) bool { return scanner.GuidedURLInScope(r.Context(), h.db, targetID, u) })
	if preview.Accepted == 0 {
		h.writeError(w, http.StatusBadRequest, "capture has no in-scope HTTP exchanges")
		return
	}

	box := secret.New(h.cfg.SessionSecret)
	captureID := uuid.New().String()
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to start capture import")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO capture_sessions
		(id,target_id,source,identity_id,identity_label,label,status,imported_count,accepted_count,rejected_count,expires_at)
		VALUES (?,?,?,?,?,?,'imported',?,?,?,datetime('now','+7 days'))`,
		captureID, targetID, preview.Source, identityID, identityLabel, label,
		preview.Total, preview.Accepted, preview.Rejected)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save capture session")
		return
	}

	stored := 0
	acceptedForMaterialization := make([]capture.Exchange, 0, preview.Accepted)
	for i, ex := range exchanges {
		if !preview.Items[i].Accepted {
			continue
		}
		reqJSON, _ := json.Marshal(ex.Request)
		respJSON, _ := json.Marshal(ex.Response)
		previewJSON, _ := json.Marshal(preview.Items[i])
		templateID := uuid.New().String()
		policy := "manual_only"
		if preview.Items[i].OperationKind == "read_only" || preview.Items[i].OperationKind == "query_like" {
			policy = "proof_only"
		}
		// Different credentials or business values are distinct contracts. Only
		// byte-identical decoded requests may collapse inside this import.
		shapeHash := keyedCaptureHash(h.cfg.SessionSecret, reqJSON)
		sealedReq, sealedResp := box.Encrypt(string(reqJSON)), box.Encrypt(string(respJSON))
		if !strings.HasPrefix(sealedReq, "enc:v1:") || !strings.HasPrefix(sealedResp, "enc:v1:") {
			h.writeError(w, http.StatusInternalServerError, "capture encryption failed")
			return
		}
		res, execErr := tx.ExecContext(r.Context(), `INSERT OR IGNORE INTO request_templates
			(id,target_id,capture_session_id,identity_id,method,norm_url,content_type,operation_kind,
			 request_shape_hash,encrypted_request,redacted_preview,replay_policy,source,sequence)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			templateID, targetID, captureID, identityID, ex.Request.Method,
			scanner.NormalizeURL(capture.SafeDisplayURL(ex.Request.URL)), ex.Request.MimeType, preview.Items[i].OperationKind,
			shapeHash, sealedReq, string(previewJSON), policy, ex.Source, ex.Sequence)
		if execErr != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to seal request template")
			return
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			continue
		}
		respPreview, _ := json.Marshal(map[string]any{
			"status": ex.Response.Status, "content_type": ex.Response.MimeType, "length": len(ex.Response.Body),
		})
		_, execErr = tx.ExecContext(r.Context(), `INSERT INTO captured_responses
			(id,request_template_id,status,content_type,body_hash,encrypted_response,redacted_preview,response_len,timing_ms)
			VALUES (?,?,?,?,?,?,?,?,?)`, uuid.New().String(), templateID, ex.Response.Status,
			ex.Response.MimeType, keyedCaptureHash(h.cfg.SessionSecret, ex.Response.Body),
			sealedResp, string(respPreview), len(ex.Response.Body), ex.Response.TimeMS)
		if execErr != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to seal captured response")
			return
		}
		stored++
		acceptedForMaterialization = append(acceptedForMaterialization, ex)
	}
	if err := tx.Commit(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to commit capture import")
		return
	}

	// Populate only non-secret request intelligence. Full URLs, headers and bodies
	// remain confined to the encrypted template layer above.
	for _, ex := range acceptedForMaterialization {
		safeURL := capture.SafeDisplayURL(ex.Request.URL)
		scanner.RecordInteraction(r.Context(), h.db, targetID,
			scanner.CanonRequest{Method: ex.Request.Method, URL: safeURL, IdentityLabel: identityLabel, Scanner: "guided-capture"},
			scanner.CanonResponse{Status: ex.Response.Status, CT: ex.Response.MimeType, Len: len(ex.Response.Body)})
		a := scanner.ClassifyAction(ex.Request.Method, safeURL, "", ex.Response.Status)
		scanner.StoreAction(r.Context(), h.db, targetID, identityID, identityLabel, "guided-capture", a)
	}

	h.writeSuccess(w, map[string]any{
		"capture_id": captureID, "preview": preview, "templates_stored": stored,
		"passive": true, "traffic_sent": 0, "full_messages": "encrypted",
	})
}

func (h *Handler) handleListCaptures(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `SELECT id,source,identity_id,identity_label,label,status,
		imported_count,accepted_count,rejected_count,created_at,COALESCE(expires_at,'')
		FROM capture_sessions WHERE target_id=? ORDER BY created_at DESC`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to list captures")
		return
	}
	defer rows.Close()
	type item struct {
		ID            string `json:"id"`
		Source        string `json:"source"`
		IdentityID    string `json:"identity_id"`
		IdentityLabel string `json:"identity_label"`
		Label         string `json:"label"`
		Status        string `json:"status"`
		Imported      int    `json:"imported"`
		Accepted      int    `json:"accepted"`
		Rejected      int    `json:"rejected"`
		CreatedAt     string `json:"created_at"`
		ExpiresAt     string `json:"expires_at"`
	}
	out := []item{}
	for rows.Next() {
		var v item
		if rows.Scan(&v.ID, &v.Source, &v.IdentityID, &v.IdentityLabel, &v.Label, &v.Status,
			&v.Imported, &v.Accepted, &v.Rejected, &v.CreatedAt, &v.ExpiresAt) == nil {
			out = append(out, v)
		}
	}
	h.writeSuccess(w, out)
}

type capturePreflightResult struct {
	TemplateID     string `json:"template_id"`
	Method         string `json:"method"`
	Route          string `json:"route"`
	Status         string `json:"status"`
	HTTPStatus     int    `json:"http_status"`
	CapturedStatus int    `json:"captured_status"`
	BaselineMatch  bool   `json:"baseline_match"`
	Reason         string `json:"reason"`
	TimingMS       int64  `json:"timing_ms"`
}

// handlePreflightCapture explicitly replays only imported GET/HEAD/OPTIONS
// templates. It performs no mutation and stops credentials at the existing
// scope + resolve/validate/pin transport boundary.
func (h *Handler) handlePreflightCapture(w http.ResponseWriter, r *http.Request) {
	targetID, captureID := mux.Vars(r)["id"], mux.Vars(r)["cid"]
	var request struct {
		TemplateIDs []string `json:"template_ids"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&request); err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid preflight request")
			return
		}
	}
	selected := map[string]bool{}
	for _, id := range request.TemplateIDs {
		if id = strings.TrimSpace(id); id != "" {
			selected[id] = true
		}
	}

	rows, err := h.db.QueryContext(r.Context(), `SELECT rt.id,rt.method,rt.encrypted_request,
		cr.status,cr.content_type,cr.encrypted_response,COALESCE(rt.identity_id,'')
		FROM request_templates rt JOIN capture_sessions cs ON cs.id=rt.capture_session_id
		LEFT JOIN captured_responses cr ON cr.request_template_id=rt.id
		WHERE rt.capture_session_id=? AND rt.target_id=? AND cs.target_id=?
		AND (cs.expires_at IS NULL OR cs.expires_at>datetime('now'))
		ORDER BY rt.sequence`, captureID, targetID, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load capture templates")
		return
	}
	defer rows.Close()
	type sealedTemplate struct {
		id, method, encRequest, capturedCT, encResponse, identityID string
		capturedStatus                                              int
	}
	templates := []sealedTemplate{}
	for rows.Next() {
		var t sealedTemplate
		if err := rows.Scan(&t.id, &t.method, &t.encRequest, &t.capturedStatus, &t.capturedCT, &t.encResponse, &t.identityID); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to decode capture templates")
			return
		}
		if len(selected) == 0 || selected[t.id] {
			templates = append(templates, t)
		}
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load capture templates")
		return
	}
	if len(templates) == 0 {
		h.writeError(w, http.StatusNotFound, "capture or selected templates not found")
		return
	}
	rows.Close()
	if len(templates) > 100 {
		h.writeError(w, http.StatusBadRequest, "preflight is limited to 100 templates per run")
		return
	}

	box := secret.New(h.cfg.SessionSecret)
	scanCtx := r.Context()
	identities := scanner.LoadIdentities(scanCtx, h.db, targetID, box)
	identityByID := map[string]*scanner.Identity{}
	for i := range identities {
		identityByID[identities[i].ID] = &identities[i]
	}
	results := make([]capturePreflightResult, 0, len(templates))
	matched, blocked, failed, sent := 0, 0, 0, 0
	for _, t := range templates {
		var capturedRequest capture.Request
		if err := json.Unmarshal([]byte(box.Decrypt(t.encRequest)), &capturedRequest); err != nil {
			results = append(results, capturePreflightResult{TemplateID: t.id, Method: t.method, Status: "failed", Reason: "sealed request could not be decoded"})
			failed++
			continue
		}
		result := capturePreflightResult{TemplateID: t.id, Method: t.method, Route: capture.SafeDisplayURL(capturedRequest.URL), CapturedStatus: t.capturedStatus}
		method := strings.ToUpper(strings.TrimSpace(capturedRequest.Method))
		if !capture.SafeAutomaticReplay(capturedRequest) {
			result.Status, result.Reason = "blocked", "preflight permits only non-sensitive GET, HEAD and OPTIONS"
			results = append(results, result)
			blocked++
			continue
		}
		if !scanner.GuidedURLInScope(r.Context(), h.db, targetID, capturedRequest.URL) {
			result.Status, result.Reason = "blocked", "request is no longer in target scope"
			results = append(results, result)
			blocked++
			continue
		}
		if t.identityID != "" && identityByID[t.identityID] == nil {
			result.Status, result.Reason = "blocked", "bound identity is unavailable"
			results = append(results, result)
			blocked++
			continue
		}
		headers := map[string][]string{}
		for _, header := range capturedRequest.Headers {
			headers[header.Name] = append(headers[header.Name], header.Value)
		}
		replayed := scanner.Replay(scanCtx, scanner.ReplaySpec{
			Method: method, URL: capturedRequest.URL, Body: string(capturedRequest.Body),
			ContentType: capturedRequest.MimeType, Headers: headers,
		}, identityByID[t.identityID])
		sent++
		result.HTTPStatus, result.TimingMS = replayed.Status, replayed.TimingMs
		if replayed.Verdict == "error" {
			result.Status, result.Reason = "failed", "baseline request failed or destination policy blocked it"
			failed++
		} else {
			var capturedResponse capture.Response
			_ = json.Unmarshal([]byte(box.Decrypt(t.encResponse)), &capturedResponse)
			statusMatch := t.capturedStatus == 0 || replayed.Status == t.capturedStatus
			ctMatch := mediaTypeBase(replayed.CT) == mediaTypeBase(t.capturedCT) || t.capturedCT == ""
			bodyMatch := len(capturedResponse.Body) == 0 || scanner.BodyHash(replayed.Response.Body) == scanner.BodyHash(string(capturedResponse.Body))
			result.BaselineMatch = statusMatch && ctMatch && bodyMatch
			if result.BaselineMatch && replayed.Status >= 200 && replayed.Status < 300 {
				result.Status, result.Reason = "ready", "status, content type and stable body fingerprint match"
				matched++
			} else {
				result.Status = "stale"
				result.Reason = "baseline changed (status=" + strconv.FormatBool(statusMatch) + ", content_type=" + strconv.FormatBool(ctMatch) + ", body=" + strconv.FormatBool(bodyMatch) + ")"
				failed++
			}
		}
		results = append(results, result)
	}
	for _, result := range results {
		_, _ = h.db.ExecContext(r.Context(), `UPDATE request_templates SET preflight_status=?,preflight_http_status=?,preflight_reason=?,preflight_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`, result.Status, result.HTTPStatus, result.Reason, result.TemplateID, targetID)
	}
	h.writeSuccess(w, map[string]any{
		"capture_id": captureID, "results": results, "ready": matched, "blocked": blocked,
		"failed_or_stale": failed, "requests_sent": sent,
		"mode": "baseline_only", "mutations_sent": 0,
	})
}

func mediaTypeBase(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func (h *Handler) readCaptureUpload(w http.ResponseWriter, r *http.Request) ([]capture.Exchange, string, string, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, capture.MaxImportBytes+captureMultipartOverhead)
	if err := r.ParseMultipartForm(capture.MaxImportBytes); err != nil {
		return nil, "", "", "", fmt.Errorf("capture upload is invalid or too large")
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, "", "", "", fmt.Errorf("multipart field 'file' is required")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, capture.MaxImportBytes+1))
	if err != nil || len(raw) > capture.MaxImportBytes {
		return nil, "", "", "", capture.ErrImportTooLarge
	}
	source := strings.TrimSpace(r.FormValue("source"))
	if source == "" {
		source = "burp_xml"
	}
	var exchanges []capture.Exchange
	switch source {
	case "burp_xml", "burp-xml":
		exchanges, err = capture.ParseBurpXML(raw)
	case "reconner_json", "chrome", "chrome-devtools":
		exchanges, err = capture.ParseReconnerJSON(raw)
	case "har", "har12":
		exchanges, err = capture.ParseHAR(raw)
	default:
		return nil, "", "", "", fmt.Errorf("unsupported capture source %q", source)
	}
	if err != nil {
		return nil, "", "", "", err
	}
	return exchanges, strings.TrimSpace(r.FormValue("identity_id")),
		strings.TrimSpace(r.FormValue("identity_label")), strings.TrimSpace(r.FormValue("label")), nil
}

func (h *Handler) validateCaptureIdentity(targetID, identityID string) error {
	if identityID == "" {
		return nil
	}
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM identities WHERE id=? AND target_id=?`, identityID, targetID).Scan(&n); err != nil || n != 1 {
		return fmt.Errorf("identity does not belong to this target")
	}
	return nil
}

func keyedCaptureHash(key string, value []byte) string {
	h := hmac.New(sha256.New, []byte("reconner-capture-v1|"+key))
	_, _ = h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}
