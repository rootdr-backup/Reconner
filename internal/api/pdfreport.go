package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// This file implements a dependency-free PDF report. It uses the three built-in
// PDF base-14 fonts (Helvetica family) so nothing needs embedding, and lays out
// wrapped, paginated text by hand. No external library, no API key, no network —
// which matters given the project's "take nothing from me" constraint and the
// sanctioned-network environment where `go get` of a new module can fail.

type pdfStyle int

const (
	styleH1 pdfStyle = iota
	styleH2
	styleH3
	styleBody
	styleMono
	styleRule
)

type pdfLineItem struct {
	style pdfStyle
	text  string
}

// pdfBuilder accumulates styled lines then renders a multi-page PDF.
type pdfBuilder struct {
	lines []pdfLineItem
}

func (p *pdfBuilder) add(style pdfStyle, text string) {
	p.lines = append(p.lines, pdfLineItem{style, text})
}
func (p *pdfBuilder) h1(t string)   { p.add(styleH1, t) }
func (p *pdfBuilder) h2(t string)   { p.add(styleH2, t) }
func (p *pdfBuilder) h3(t string)   { p.add(styleH3, t) }
func (p *pdfBuilder) body(t string) { p.add(styleBody, t) }
func (p *pdfBuilder) mono(t string) { p.add(styleMono, t) }
func (p *pdfBuilder) rule()         { p.add(styleRule, "") }

// style parameters: font resource name, size, leading, approx chars/line at
// 540pt usable width.
func styleParams(s pdfStyle) (font string, size float64, leading float64, wrap int) {
	switch s {
	case styleH1:
		return "F2", 22, 30, 46
	case styleH2:
		return "F2", 15, 22, 68
	case styleH3:
		return "F2", 12, 18, 84
	case styleMono:
		return "F3", 9, 13, 108
	case styleRule:
		return "F1", 10, 10, 120
	default:
		return "F1", 10, 15, 100
	}
}

// pdfEscape escapes the characters that are special inside a PDF string literal
// and drops non-ASCII (the base-14 fonts are WinAnsi; keep it simple/robust).
func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r > 126 {
			if r == '\t' {
				b.WriteString("    ")
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		default:
			b.WriteByte(byte(r))
		}
	}
	return b.String()
}

func wrapText(s string, width int) []string {
	s = strings.ReplaceAll(s, "\t", "    ")
	if width < 8 {
		width = 8
	}
	var out []string
	for len(s) > width {
		// try to break on a space near the wrap boundary
		cut := width
		if idx := strings.LastIndexByte(s[:width], ' '); idx > width/2 {
			cut = idx
		}
		out = append(out, strings.TrimRight(s[:cut], " "))
		s = strings.TrimLeft(s[cut:], " ")
	}
	out = append(out, s)
	return out
}

// render produces the full PDF byte stream.
func (p *pdfBuilder) render() []byte {
	const (
		pageW  = 612.0
		pageH  = 792.0
		left   = 54.0
		top    = 748.0
		bottom = 54.0
	)

	// Build content streams, paginating as we go.
	var pages []string
	var cur bytes.Buffer
	y := top

	newPage := func() {
		pages = append(pages, cur.String())
		cur.Reset()
		y = top
	}
	cur.WriteString("0.15 0.16 0.20 rg\n") // default dark text

	for _, ln := range p.lines {
		font, size, leading, wrap := styleParams(ln.style)

		if ln.style == styleRule {
			if y-leading < bottom {
				newPage()
			}
			y -= leading * 0.6
			fmt.Fprintf(&cur, "0.80 0.80 0.85 RG 0.5 w %g %g m %g %g l S\n", left, y, pageW-left, y)
			y -= leading * 0.4
			continue
		}

		segments := wrapText(ln.text, wrap)
		for _, seg := range segments {
			if y-leading < bottom {
				newPage()
			}
			// heading color accent
			switch ln.style {
			case styleH1:
				cur.WriteString("0.06 0.09 0.16 rg\n")
			case styleH2:
				cur.WriteString("0.10 0.30 0.55 rg\n")
			case styleH3:
				cur.WriteString("0.15 0.16 0.20 rg\n")
			case styleMono:
				cur.WriteString("0.20 0.22 0.28 rg\n")
			default:
				cur.WriteString("0.20 0.22 0.28 rg\n")
			}
			fmt.Fprintf(&cur, "BT /%s %g Tf %g %g Td (%s) Tj ET\n", font, size, left, y, pdfEscape(seg))
			y -= leading
		}
		if ln.style == styleH1 || ln.style == styleH2 {
			y -= 4
		}
	}
	pages = append(pages, cur.String())

	// Assemble objects.
	// 1 catalog, 2 pages, 3 font Helvetica, 4 Helvetica-Bold, 5 Courier,
	// then per page: a page object + a content object.
	var objs []string
	objs = append(objs, "<< /Type /Catalog /Pages 2 0 R >>") // 1

	pageObjStart := 6
	var kids []string
	for i := range pages {
		pageObjNum := pageObjStart + i*2
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObjNum))
	}
	objs = append(objs, fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pages), strings.Join(kids, " "))) // 2
	objs = append(objs, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")         // 3
	objs = append(objs, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")    // 4
	objs = append(objs, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")           // 5

	for i, content := range pages {
		pageObjNum := pageObjStart + i*2
		contentObjNum := pageObjNum + 1
		pageObj := fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %g %g] "+
				"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			pageW, pageH, contentObjNum)
		objs = append(objs, pageObj)
		contentObj := fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content)
		objs = append(objs, contentObj)
	}

	// Serialize with xref.
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs)+1)
	for i, o := range objs {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xrefPos := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", len(objs)+1)
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xrefPos)
	return out.Bytes()
}

// handleGenerateReportPDF renders the same intelligence-driven report as the
// Markdown export, but as a downloadable PDF.
func (h *Handler) handleGenerateReportPDF(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var domain string
	h.db.QueryRowContext(r.Context(), "SELECT domain FROM targets WHERE id = ?", id).Scan(&domain)
	if domain == "" {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}

	p := &pdfBuilder{}
	p.h1("Recon Report — " + domain)
	p.body("Generated by Reconner · offensive-security recon & vulnerability platform · crafted by RootDR")
	p.rule()

	// Attack paths (correlated intelligence layer).
	_, _, paths := h.buildGraph(r, id)
	if len(paths) > 0 {
		p.h2("Attack Paths (correlated, ranked)")
		for i, path := range paths {
			if i >= 15 {
				break
			}
			p.h3(fmt.Sprintf("%d. [%s] %s (%d%% confidence)", i+1, strings.ToUpper(path.Severity), path.Summary, path.Confidence))
			if len(path.Tech) > 0 {
				p.body("Stack: " + strings.Join(path.Tech, ", "))
			}
			for _, step := range path.Steps {
				p.body("• " + step)
			}
		}
		p.rule()
	}

	// Vuln findings, severity-ordered, with confidence/priority if present.
	p.h2("All Findings")
	vrows, _ := h.db.QueryContext(r.Context(), `
		SELECT type, severity, url, parameter, payload, evidence,
		       COALESCE(confidence,0), COALESCE(priority,0)
		FROM vuln_findings
		WHERE target_id = ? AND COALESCE(status,'finding')='finding'
		ORDER BY priority DESC, CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
	`, id)
	count := 0
	if vrows != nil {
		for vrows.Next() {
			var typ, sev, url, param, payload, evidence string
			var confidence, priority int
			if vrows.Scan(&typ, &sev, &url, &param, &payload, &evidence, &confidence, &priority) != nil {
				continue
			}
			count++
			title := fmt.Sprintf("[%s] %s", strings.ToUpper(sev), strings.ToUpper(typ))
			if confidence > 0 {
				title += fmt.Sprintf("  (confidence %d%%, priority %d)", confidence, priority)
			}
			p.h3(title)
			p.body("Target: " + url)
			if param != "" {
				p.body("Parameter: " + param)
			}
			if payload != "" {
				p.mono("Payload: " + payload)
			}
			if evidence != "" {
				p.mono("Evidence: " + evidence)
			}
			p.rule()
		}
		vrows.Close()
	}

	// Nuclei findings.
	nrows, _ := h.db.QueryContext(r.Context(), `
		SELECT template_name, severity, matched_url, description FROM (
			SELECT template_name || CASE WHEN COUNT(*) OVER (PARTITION BY template_id) > 1
			         THEN ' (×' || COUNT(*) OVER (PARTITION BY template_id) || ' URLs)' ELSE '' END AS template_name,
			       severity, matched_url, COALESCE(description,'') AS description,
			       ROW_NUMBER() OVER (PARTITION BY template_id ORDER BY LENGTH(matched_url) ASC, created_at DESC) AS rn
			FROM nuclei_findings
			WHERE target_id = ? AND severity IN ('critical','high','medium')
			  AND COALESCE(verification,'unverified') != 'rejected'
		) WHERE rn=1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END
	`, id)
	if nrows != nil {
		for nrows.Next() {
			var name, sev, url, desc string
			if nrows.Scan(&name, &sev, &url, &desc) != nil {
				continue
			}
			count++
			p.h3(fmt.Sprintf("[%s] %s", strings.ToUpper(sev), name))
			p.body("URL: " + url)
			if desc != "" {
				p.body(desc)
			}
			p.rule()
		}
		nrows.Close()
	}

	if count == 0 {
		p.body("No vulnerabilities recorded for this target yet.")
	}

	// ── Recon sections (parity with the HTML/Markdown reports) ───────────────
	h.pdfReconSections(r, p, id)

	pdf := p.render()
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-report.pdf", domain))
	w.Write(pdf)
}

// pdfReconSections appends recon data to the PDF (capped per section so the file
// stays reasonable), matching the HTML/Markdown reports.
func (h *Handler) pdfReconSections(r *http.Request, p *pdfBuilder, id string) {
	ctx := r.Context()

	// JS findings grouped by (type, value) with x N.
	if jrows, err := h.db.QueryContext(ctx, `
		SELECT type, value, COUNT(*) FROM js_findings WHERE target_id=?
		GROUP BY type, value ORDER BY COUNT(*) DESC LIMIT 400`, id); err == nil {
		p.h2("JS Findings (grouped)")
		n := 0
		for jrows.Next() {
			var typ, val string
			var cnt int
			if jrows.Scan(&typ, &val, &cnt) != nil {
				continue
			}
			line := "[" + typ + "] " + val
			if cnt > 1 {
				line += fmt.Sprintf("  x%d", cnt)
			}
			p.body(line)
			n++
		}
		jrows.Close()
		if n == 0 {
			p.body("none")
		}
		p.rule()
	}

	section := func(title, query string, cols int) {
		rows, err := h.db.QueryContext(ctx, query, id)
		if err != nil {
			return
		}
		defer rows.Close()
		p.h2(title)
		n := 0
		for rows.Next() {
			vals := make([]any, cols)
			ptrs := make([]any, cols)
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if rows.Scan(ptrs...) != nil {
				continue
			}
			parts := make([]string, cols)
			for i := range vals {
				parts[i] = mdCell(vals[i])
			}
			p.body(strings.Join(parts, "  |  "))
			n++
		}
		if n == 0 {
			p.body("none")
		}
		p.rule()
	}

	section("Subdomains", `SELECT subdomain, CASE is_alive WHEN 1 THEN 'alive' ELSE '' END, COALESCE(ip,'') FROM subdomains WHERE target_id=? ORDER BY subdomain LIMIT 1500`, 3)
	section("Live HTTP Hosts", `SELECT url, status_code, COALESCE(title,'') FROM http_services WHERE target_id=? AND COALESCE(source,'probe')='probe' ORDER BY url LIMIT 1000`, 3)
	section("Reflected Parameters", `SELECT url, parameter FROM parameters WHERE target_id=? AND is_reflected=1 ORDER BY url LIMIT 800`, 2)
	section("Open Redirects", `SELECT url, redirect_to FROM open_redirect_findings WHERE target_id=? AND COALESCE(status,'finding')='finding' ORDER BY url LIMIT 500`, 2)
	section("Directories", `SELECT url, status_code FROM directory_findings WHERE target_id=? ORDER BY url LIMIT 1000`, 2)
	section("Backups / Config Files", `SELECT url, COALESCE(file_type,'') FROM backup_findings WHERE target_id=? ORDER BY url LIMIT 800`, 2)
}
