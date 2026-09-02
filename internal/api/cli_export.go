package api

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/scheduler"
	"github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

// NewHandler builds an API Handler without wiring an HTTP server. It exists so
// the CLI can reuse the exact same report generators (HTML / Markdown / PDF)
// that the web UI uses — no duplicated report code, no running server.
func NewHandler(db *database.DB, hub *websocket.Hub, sched *scheduler.Scheduler, cfg *config.Config, log *logger.Logger) *Handler {
	return &Handler{
		db:      db,
		hub:     hub,
		sched:   sched,
		cfg:     cfg,
		logger:  log,
		updates: newReleaseChecker(),
		bounty:  sched.BountyCatalog(),
	}
}

// renderReport invokes an internal report handler against an in-memory recorder
// and returns the produced bytes — the trick that lets the CLI reuse the web
// report code verbatim.
func (h *Handler) renderReport(targetID string, fn func(http.ResponseWriter, *http.Request)) ([]byte, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/report", nil)
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	fn(rec, req)
	return rec.Body.Bytes(), rec.Header().Get("Content-Type")
}

// ReportHTML returns the full self-contained HTML report for a target.
func (h *Handler) ReportHTML(targetID string) []byte {
	b, _ := h.renderReport(targetID, h.handleGenerateReportHTML)
	return b
}

// ReportMarkdown returns the HackerOne-style Markdown report for a target.
func (h *Handler) ReportMarkdown(targetID string) []byte {
	b, _ := h.renderReport(targetID, h.handleGenerateReport)
	return b
}

// ReportPDF returns the PDF report bytes for a target.
func (h *Handler) ReportPDF(targetID string) []byte {
	b, _ := h.renderReport(targetID, h.handleGenerateReportPDF)
	return b
}
