package api

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
)

// handleGenerateReportHTML renders a single, self-contained, offline HTML report
// covering EVERY recon section — not just vulnerabilities. Every URL is a
// clickable link, and every vulnerability carries a ready-to-submit bug-bounty
// PoC (curl reproduction + steps + a fill-in report block) with a one-click Copy
// button. No external assets, so it opens anywhere.
func (h *Handler) handleGenerateReportHTML(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	ctx := r.Context()

	var domain, kind string
	h.db.QueryRowContext(ctx, "SELECT domain, COALESCE(kind,'web') FROM targets WHERE id = ?", id).Scan(&domain, &kind)
	if domain == "" {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}

	// A network target's results live in a different set of tables (network hosts/
	// services, Ingram camera findings, network-CVE nuclei) than the web recon
	// pipeline — render a dedicated report instead of a page full of empty web
	// sections. Retroactive: reads whatever is already in the DB.
	if kind == "network" {
		h.networkReportHTML(ctx, w, id, domain)
		return
	}

	var b strings.Builder
	b.WriteString(reportHead(domain))

	// ── summary counts ──────────────────────────────────────────────────────
	counts := map[string]int{}
	countInto := func(key, q string) {
		var n int
		h.db.QueryRowContext(ctx, q, id).Scan(&n)
		counts[key] = n
	}
	countInto("subs", "SELECT COUNT(*) FROM subdomains WHERE target_id=?")
	countInto("alive", "SELECT COUNT(*) FROM subdomains WHERE target_id=? AND is_alive=1")
	countInto("hosts", "SELECT COUNT(*) FROM http_services WHERE target_id=? AND COALESCE(source,'probe')='probe'")
	countInto("js", "SELECT COUNT(*) FROM js_findings WHERE target_id=?")
	countInto("params", "SELECT COUNT(*) FROM parameters WHERE target_id=? AND is_reflected=1")
	countInto("redirects", "SELECT COUNT(*) FROM open_redirect_findings WHERE target_id=? AND COALESCE(status,'finding')='finding'")
	countInto("nuclei", "SELECT COUNT(*) FROM nuclei_findings WHERE target_id=? AND COALESCE(verification,'unverified') != 'rejected'")
	countInto("vulns", "SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding'")
	countInto("dirs", "SELECT COUNT(*) FROM directory_findings WHERE target_id=?")
	countInto("backups", "SELECT COUNT(*) FROM backup_findings WHERE target_id=?")

	fmt.Fprintf(&b, `<header><h1>Recon Report — %s</h1>`, html.EscapeString(domain))
	b.WriteString(`<div class="stats">`)
	for _, s := range []struct{ label, key string }{
		{"Subdomains", "subs"}, {"Alive", "alive"}, {"HTTP Hosts", "hosts"},
		{"JS Findings", "js"}, {"Reflected Params", "params"}, {"Open Redirects", "redirects"},
		{"Nuclei", "nuclei"}, {"Vulns", "vulns"}, {"Directories", "dirs"}, {"Backups", "backups"},
	} {
		fmt.Fprintf(&b, `<div class="stat"><span class="n">%d</span><span class="l">%s</span></div>`, counts[s.key], s.label)
	}
	b.WriteString(`</div></header>`)

	// table of contents
	b.WriteString(`<nav class="toc">`)
	for _, t := range []struct{ id, label string }{
		{"vulns", "Vulnerabilities (with PoC)"}, {"nuclei", "Nuclei"},
		{"redirects", "Open Redirects"}, {"params", "Reflected Parameters"},
		{"js", "JS Findings"}, {"dirs", "Directories"}, {"backups", "Backups"},
		{"hosts", "Live Hosts"}, {"subs", "Subdomains"},
	} {
		fmt.Fprintf(&b, `<a href="#sec-%s">%s</a>`, t.id, html.EscapeString(t.label))
	}
	b.WriteString(`</nav>`)

	// ── Vulnerabilities (with PoC) ──────────────────────────────────────────
	h.sectionVulns(ctx, &b, id, domain)

	// generic sections: {colIndex that is a URL to linkify, or -1}
	h.section(ctx, &b, id, "nuclei", "Nuclei Findings", `
		SELECT template_name, severity, matched_url, description FROM (
			SELECT template_name || CASE WHEN COUNT(*) OVER (PARTITION BY template_id) > 1
			         THEN ' (×' || COUNT(*) OVER (PARTITION BY template_id) || ' URLs)' ELSE '' END AS template_name,
			       severity, matched_url, COALESCE(description,'') AS description,
			       ROW_NUMBER() OVER (PARTITION BY template_id ORDER BY LENGTH(matched_url) ASC, created_at DESC) AS rn
			FROM nuclei_findings WHERE target_id=? AND COALESCE(verification,'unverified') != 'rejected'
		) WHERE rn=1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
		[]string{"Template", "Severity", "URL", "Description"}, 2)

	h.section(ctx, &b, id, "redirects", "Open Redirects", `
		SELECT url, parameter, redirect_to, CASE verified WHEN 1 THEN 'verified' ELSE '' END
		FROM open_redirect_findings WHERE target_id=? AND COALESCE(status,'finding')='finding' ORDER BY url`,
		[]string{"URL", "Param", "Redirects To", "Status"}, 0)

	h.section(ctx, &b, id, "params", "Reflected Parameters", `
		SELECT DISTINCT url, parameter, COALESCE(value,''), COALESCE(source,'')
		FROM parameters WHERE target_id=? AND is_reflected=1 ORDER BY url LIMIT 2000`,
		[]string{"URL", "Param", "Value", "Source"}, 0)

	h.sectionJSGrouped(ctx, &b, id)

	h.section(ctx, &b, id, "dirs", "Directories", `
		SELECT url, status_code, COALESCE(content_type,''), content_length
		FROM directory_findings WHERE target_id=? ORDER BY status_code, url LIMIT 3000`,
		[]string{"URL", "Status", "Type", "Size"}, 0)

	h.section(ctx, &b, id, "backups", "Backup / Config Files", `
		SELECT url, status_code, COALESCE(file_type,''), content_length
		FROM backup_findings WHERE target_id=? ORDER BY url LIMIT 2000`,
		[]string{"URL", "Status", "Type", "Size"}, 0)

	h.section(ctx, &b, id, "hosts", "Live HTTP Hosts", `
		SELECT url, status_code, COALESCE(title,''), COALESCE(server,'')
		FROM http_services WHERE target_id=? AND COALESCE(source,'probe')='probe' ORDER BY url LIMIT 3000`,
		[]string{"URL", "Status", "Title", "Server"}, 0)

	h.section(ctx, &b, id, "subs", "All Subdomains", `
		SELECT subdomain, CASE is_alive WHEN 1 THEN 'alive' ELSE '' END, COALESCE(ip,''), COALESCE(server,'')
		FROM subdomains WHERE target_id=? ORDER BY is_alive DESC, subdomain LIMIT 5000`,
		[]string{"Subdomain", "Alive", "IP", "Server"}, -1)

	b.WriteString(reportFoot())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%s-report.html", domain))
	w.Write([]byte(b.String()))
}

// section renders a generic 4-column table. linkCol is the column index to render
// as a clickable link (URL), or -1 for none. If the value in a link column is a
// bare subdomain (no scheme) it is still linked with https://.
func (h *Handler) section(ctx context.Context, b *strings.Builder, id, secID, title, query string, headers []string, linkCol int) {
	rows, err := h.db.QueryContext(ctx, query, id)
	fmt.Fprintf(b, `<section id="sec-%s"><h2>%s</h2>`, secID, html.EscapeString(title))
	if err != nil {
		b.WriteString(`<p class="empty">query error</p></section>`)
		return
	}
	defer rows.Close()

	b.WriteString(`<div class="tbl"><table><thead><tr>`)
	for _, hd := range headers {
		fmt.Fprintf(b, `<th>%s</th>`, html.EscapeString(hd))
	}
	b.WriteString(`</tr></thead><tbody>`)

	n := 0
	for rows.Next() {
		cols := make([]any, len(headers))
		ptrs := make([]any, len(headers))
		for i := range cols {
			ptrs[i] = &cols[i]
		}
		if rows.Scan(ptrs...) != nil {
			continue
		}
		b.WriteString(`<tr>`)
		for i := range headers {
			val := asString(cols[i])
			if i == linkCol && val != "" {
				fmt.Fprintf(b, `<td>%s</td>`, linkify(val))
			} else if i == 1 && isSeverityHeader(headers) {
				fmt.Fprintf(b, `<td>%s</td>`, sevBadge(val))
			} else {
				fmt.Fprintf(b, `<td>%s</td>`, html.EscapeString(val))
			}
		}
		b.WriteString(`</tr>`)
		n++
	}
	b.WriteString(`</tbody></table></div>`)
	if n == 0 {
		b.WriteString(`<p class="empty">— none —</p>`)
	}
	b.WriteString(`</section>`)
}

// sectionJSGrouped renders JS findings GROUPED by (type, value): identical
// findings (e.g. the same internal_url http://localhost:8080 seen in 30 JS
// files) collapse to ONE row showing "×N" and an expandable list of the source
// files — instead of flooding the report with dozens of identical rows.
func (h *Handler) sectionJSGrouped(ctx context.Context, b *strings.Builder, id string) {
	b.WriteString(`<section id="sec-js"><h2>JS Findings (secrets / endpoints)</h2>`)
	rows, err := h.db.QueryContext(ctx, `
		SELECT jf.type, jf.severity, COALESCE(jf.value,''), COALESCE(js.url,'')
		FROM js_findings jf LEFT JOIN js_files js ON js.id = jf.js_file_id
		WHERE jf.target_id=?
		ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT 20000`, id)
	if err != nil {
		b.WriteString(`<p class="empty">query error</p></section>`)
		return
	}
	defer rows.Close()

	type group struct {
		typ, sev, value string
		sources         []string
	}
	order := []string{}
	groups := map[string]*group{}
	for rows.Next() {
		var typ, sev, value, src string
		if rows.Scan(&typ, &sev, &value, &src) != nil {
			continue
		}
		key := typ + "\x00" + value
		g := groups[key]
		if g == nil {
			g = &group{typ: typ, sev: sev, value: value}
			groups[key] = g
			order = append(order, key)
		}
		if src != "" {
			g.sources = append(g.sources, src)
		}
	}
	if len(order) == 0 {
		b.WriteString(`<p class="empty">— none —</p></section>`)
		return
	}

	b.WriteString(`<div class="tbl"><table><thead><tr><th>Type</th><th>Severity</th><th>Value</th><th>Seen in</th></tr></thead><tbody>`)
	for _, key := range order {
		g := groups[key]
		fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>`,
			html.EscapeString(g.typ), sevBadge(g.sev), html.EscapeString(truncateStr(g.value, 200)))
		n := len(g.sources)
		if n <= 1 {
			if n == 1 {
				b.WriteString(linkify(g.sources[0]))
			} else {
				b.WriteString(`<span class="empty">—</span>`)
			}
		} else {
			// count badge + expandable source list
			fmt.Fprintf(b, `<details><summary><b>×%d</b> files (expand)</summary><div class="srclist">`, n)
			for _, src := range g.sources {
				fmt.Fprintf(b, `%s<br>`, linkify(src))
			}
			b.WriteString(`</div></details>`)
		}
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table></div></section>`)
}

// sectionVulns renders each vulnerability as a card with a collapsible, copyable
// bug-bounty PoC.
func (h *Handler) sectionVulns(ctx context.Context, b *strings.Builder, id, domain string) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT type, severity, url, COALESCE(parameter,''), COALESCE(payload,''),
		       COALESCE(evidence,''), COALESCE(confidence,0), COALESCE(priority,0),
		       COALESCE(lifecycle,'LEGACY')
		FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding'
		ORDER BY priority DESC,
		         CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
		id)
	b.WriteString(`<section id="sec-vulns"><h2>Vulnerabilities (with PoC)</h2>`)
	b.WriteString(`<p class="empty" style="opacity:.7">Confirmed / surfaced findings. Rejected and duplicate results are excluded; inconclusive/unverified candidates are listed in the analyst section below.</p>`)
	if err != nil {
		b.WriteString(`<p class="empty">query error</p></section>`)
		return
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var typ, sev, u, param, payload, evidence, lifecycle string
		var confidence, priority int
		if rows.Scan(&typ, &sev, &u, &param, &payload, &evidence, &confidence, &priority, &lifecycle) != nil {
			continue
		}
		n++
		curl, steps := pocFor(typ, u, param, payload)
		report := bugReport(typ, sev, u, param, payload, evidence, curl, steps, domain)

		fmt.Fprintf(b, `<div class="vuln %s">`, sevClass(sev))
		fmt.Fprintf(b, `<div class="vh">%s <span class="vtype">%s</span> <span class="conf">%s</span>`,
			sevBadge(sev), html.EscapeString(strings.ToUpper(strings.ReplaceAll(typ, "_", " "))), lifecycleLabel(lifecycle))
		if confidence > 0 {
			fmt.Fprintf(b, ` <span class="conf">confidence %d%% · priority %d</span>`, confidence, priority)
		}
		b.WriteString(`</div>`)
		fmt.Fprintf(b, `<div class="vurl">%s</div>`, linkify(u))
		if param != "" {
			fmt.Fprintf(b, `<div class="vmeta">Parameter: <code>%s</code></div>`, html.EscapeString(param))
		}
		if payload != "" {
			fmt.Fprintf(b, `<div class="vmeta">Payload: <code>%s</code></div>`, html.EscapeString(payload))
		}
		if evidence != "" {
			fmt.Fprintf(b, `<div class="vev">%s</div>`, html.EscapeString(evidence))
		}
		// PoC block (collapsible + copy)
		b.WriteString(`<details class="poc"><summary>▸ PoC &amp; bug-bounty report (click to expand)</summary>`)
		b.WriteString(`<button class="copy" onclick="copyPoc(this)">Copy report</button>`)
		fmt.Fprintf(b, `<pre class="pocbody">%s</pre>`, html.EscapeString(report))
		b.WriteString(`</details></div>`)
	}
	if n == 0 {
		b.WriteString(`<p class="empty">— no confirmed vulnerabilities —</p>`)
	}
	// Analyst section: unverified/inconclusive candidates. Surfaced but clearly
	// NOT presented as confirmed vulnerabilities (nothing is silently hidden).
	h.sectionCandidates(ctx, b, id)
	b.WriteString(`</section>`)
}

// lifecycleLabel renders a compact lifecycle tag for a finding.
func lifecycleLabel(lc string) string {
	switch lc {
	case "CONFIRMED":
		return `<span style="color:#86efac">CONFIRMED</span>`
	case "VERIFIED":
		return `<span style="color:#86efac">VERIFIED</span>`
	case "INCONCLUSIVE":
		return `<span style="color:#fde047">INCONCLUSIVE</span>`
	case "LEGACY", "":
		return `<span style="color:#9ca3af">unverified (legacy)</span>`
	default:
		return `<span style="color:#9ca3af">` + html.EscapeString(lc) + `</span>`
	}
}

// sectionCandidates lists analyst-only detected/inconclusive candidates (status
// 'candidate') so the report is transparent without inflating the confirmed set.
func (h *Handler) sectionCandidates(ctx context.Context, b *strings.Builder, id string) {
	rows, err := h.db.QueryContext(ctx, `
		SELECT type, severity, url, COALESCE(parameter,''), COALESCE(confidence,0), COALESCE(lifecycle,'LEGACY')
		FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='candidate'
		ORDER BY confidence DESC LIMIT 200`, id)
	if err != nil {
		return
	}
	defer rows.Close()
	var body strings.Builder
	n := 0
	for rows.Next() {
		var typ, sev, u, param, lc string
		var conf int
		if rows.Scan(&typ, &sev, &u, &param, &conf, &lc) != nil {
			continue
		}
		n++
		fmt.Fprintf(&body, `<div class="vmeta">%s <code>%s</code> %s conf %d%% — %s%s</div>`,
			html.EscapeString(strings.ToUpper(strings.ReplaceAll(typ, "_", " "))),
			html.EscapeString(param), lifecycleLabel(lc), conf, linkify(u), "")
	}
	if n == 0 {
		return
	}
	b.WriteString(`<details class="poc"><summary>▸ Analyst: detected / inconclusive candidates (not confirmed) — ` + fmt.Sprintf("%d", n) + `</summary>`)
	b.WriteString(body.String())
	b.WriteString(`</details>`)
}

// ── PoC generation ──────────────────────────────────────────────────────────

// pocFor returns a curl reproduction command and step list tuned to the vuln type.
func pocFor(typ, u, param, payload string) (string, []string) {
	switch typ {
	case "xss", "stored_xss", "dom_xss":
		// A working XSS PoC must contain a payload that actually pops alert().
		// If dalfox already gave a full "poc=<url>", use it verbatim; otherwise
		// inject a canonical, guaranteed-visible payload.
		if i := strings.Index(payload, "poc="); i >= 0 {
			pocURL := strings.TrimSpace(strings.Fields(payload[i+4:])[0])
			return pocURL,
				[]string{"Open the PoC URL below in a browser", "Observe alert(document.domain) firing — JavaScript executed", "PoC URL: " + pocURL}
		}
		xp := payload
		if !containsXSSMarker(xp) {
			xp = `"><svg onload=alert(document.domain)>`
		}
		test := injectInto(u, param, xp)
		return test,
			[]string{"Open the URL below in a browser (it pops alert(document.domain))",
				"Payload: " + xp,
				"URL: " + test}
	case "sqli":
		return "curl -sk '" + injectInto(u, param, payload) + "'",
			[]string{"Send the request with the SQL payload in the parameter", "Observe the database error / boolean-time difference in the response"}
	case "blind_sqli":
		return "curl -sk '" + injectInto(u, param, payload) + "'",
			[]string{"Send the request with the out-of-band SQL payload in the parameter (Oracle UTL_HTTP / MSSQL xp_cmdshell / UNC exfil)", "Observe the database engine call back to the OAST endpoint — proof of injection with no in-band signal"}
	case "ssrf", "blind_ssrf":
		return "curl -sk '" + injectInto(u, param, payload) + "'",
			[]string{"Set the URL parameter to an internal/metadata address (or the OAST callback)", "Observe the server-side fetch (in-band metadata leak, or an out-of-band callback hit)"}
	case "lfi":
		return "curl -sk '" + injectInto(u, param, payload) + "'",
			[]string{"Send the path-traversal payload in the parameter", "Observe file contents (e.g. root:x:0:0) in the response"}
	case "ssti":
		return "curl -sk '" + injectInto(u, param, payload) + "'",
			[]string{"Inject the template expression (e.g. {{7*7}})", "Observe the evaluated result (49) reflected in the response"}
	case "cmdi", "blind_rce":
		return "curl -sk '" + injectInto(u, param, payload) + "'",
			[]string{"Inject the OS-command payload in the parameter", "Observe the command output / timing delay / out-of-band callback"}
	case "xxe":
		body := payload
		if body == "" {
			body = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`
		}
		return "curl -sk -X POST '" + u + "' -H 'Content-Type: application/xml' --data '" + body + "'",
			[]string{"POST the XML body containing the external entity", "Observe file contents in the response (in-band) or an OAST callback (blind)"}
	case "idor":
		return "curl -sk '" + u + "'   # then repeat with neighbouring IDs (id-1, id+1)",
			[]string{"Request the resource with your session", "Change the object ID to a neighbouring value", "Observe another user's object returned (or access with no auth)"}
	case "open_redirect":
		return "curl -skI '" + injectInto(u, param, payload) + "'",
			[]string{"Send the request with the crafted redirect parameter", "Observe the Location header pointing to the attacker-controlled destination"}
	case "cors":
		return "curl -sk '" + u + "' -H 'Origin: https://evil.example'  -I",
			[]string{"Send the request with an attacker Origin header", "Observe Access-Control-Allow-Origin reflecting it with Allow-Credentials: true"}
	case "request_smuggling":
		return "# time-based test — see evidence; reproduce with a raw socket / Turbo Intruder",
			[]string{"Send the CL.TE/TE.CL probe with conflicting framing over a raw connection", "Observe the back-end blocking (long delay) vs a fast normal request"}
	case "race_condition":
		return "# fire the request below ~20x in parallel (single-packet / Turbo Intruder)",
			[]string{"Prepare N identical requests", "Release them simultaneously", "Observe the limit/uniqueness check being bypassed (multiple successes)"}
	default:
		test := injectInto(u, param, payload)
		return "curl -sk '" + test + "'", []string{"Reproduce with the request below", "URL: " + test}
	}
}

// containsXSSMarker reports whether a payload already carries a JS-executing
// XSS vector (so we don't overwrite a real one with the canonical fallback).
func containsXSSMarker(p string) bool {
	l := strings.ToLower(p)
	return strings.Contains(l, "alert(") || strings.Contains(l, "onerror") ||
		strings.Contains(l, "onload") || strings.Contains(l, "<script") ||
		strings.Contains(l, "<svg") || strings.Contains(l, "javascript:") ||
		strings.Contains(l, "<img")
}

// injectInto puts the payload into the given query param (or appends it) for a
// copy-paste reproduction URL. The value is percent-encoded so the URL is VALID in
// a browser address bar — an XSS payload carrying spaces/quotes/angle-brackets
// pasted raw would otherwise be a malformed URL that never reaches the app (the
// "PoC doesn't pop" trap). The server percent-decodes it back to the raw payload,
// so execution is unaffected; the human still sees the raw payload on the Payload line.
func injectInto(u, param, payload string) string {
	if payload == "" {
		return u
	}
	if param == "" {
		return u
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + param + "=" + url.QueryEscape(payload)
}

// bugReport builds a fill-in HackerOne-style report block.
func bugReport(typ, sev, u, param, payload, evidence, curl string, steps []string, domain string) string {
	var b strings.Builder
	title := strings.ToUpper(strings.ReplaceAll(typ, "_", " "))
	fmt.Fprintf(&b, "# %s on %s\n\n", title, domain)
	fmt.Fprintf(&b, "**Severity:** %s\n", strings.ToUpper(sev))
	fmt.Fprintf(&b, "**Affected URL:** %s\n", u)
	if param != "" {
		fmt.Fprintf(&b, "**Parameter:** %s\n", param)
	}
	if payload != "" {
		fmt.Fprintf(&b, "**Payload:** %s\n", payload)
	}
	b.WriteString("\n## Steps to Reproduce\n")
	for i, s := range steps {
		fmt.Fprintf(&b, "%d. %s\n", i+1, s)
	}
	b.WriteString("\n## Proof of Concept\n```\n" + curl + "\n```\n")
	if evidence != "" {
		b.WriteString("\n## Evidence\n" + evidence + "\n")
	}
	b.WriteString("\n## Impact\n_<describe the concrete security impact — data access, account takeover, etc.>_\n")
	b.WriteString("\n## Remediation\n_<recommended fix>_\n")
	return b.String()
}

// ── small HTML helpers ──────────────────────────────────────────────────────

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%g", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func linkify(u string) string {
	href := u
	if !strings.HasPrefix(href, "http://") && !strings.HasPrefix(href, "https://") {
		href = "https://" + href
	}
	return fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`,
		html.EscapeString(href), html.EscapeString(u))
}

func isSeverityHeader(headers []string) bool {
	return len(headers) > 1 && (headers[1] == "Severity")
}

func sevClass(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "s-crit"
	case "high":
		return "s-high"
	case "medium":
		return "s-med"
	case "low":
		return "s-low"
	}
	return "s-info"
}

func sevBadge(sev string) string {
	if sev == "" {
		return ""
	}
	return fmt.Sprintf(`<span class="badge %s">%s</span>`, sevClass(sev), html.EscapeString(strings.ToUpper(sev)))
}

func reportHead(domain string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — ` + html.EscapeString(domain) + `</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--card2:#1d2129;--bd:#2a2f3a;--tx:#e6e8ec;--mut:#8b93a1;--acc:#4c8dff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc);text-decoration:none;word-break:break-all}a:hover{text-decoration:underline}
header{padding:28px 22px 10px}h1{margin:0 0 14px;font-size:24px}
.stats{display:flex;flex-wrap:wrap;gap:10px}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 14px;min-width:96px}
.stat .n{display:block;font-size:22px;font-weight:700}.stat .l{color:var(--mut);font-size:12px}
.toc{display:flex;flex-wrap:wrap;gap:8px;padding:14px 22px;position:sticky;top:0;background:rgba(15,17,21,.92);backdrop-filter:blur(6px);border-bottom:1px solid var(--bd);z-index:5}
.toc a{background:var(--card2);border:1px solid var(--bd);border-radius:20px;padding:5px 12px;font-size:12px}
section{padding:18px 22px;border-bottom:1px solid var(--bd)}
h2{font-size:18px;margin:0 0 12px}
.tbl{overflow-x:auto;border:1px solid var(--bd);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
th{background:var(--card2);color:var(--mut);font-weight:600;position:sticky;top:0}
th.sortable{cursor:pointer;user-select:none;white-space:nowrap}
th.sortable:hover{color:var(--tx)}
th.sortable::after{content:'\2195';opacity:.3;margin-left:6px;font-size:11px}
th.sorted-asc::after{content:'\2191';opacity:.95}
th.sorted-desc::after{content:'\2193';opacity:.95}
tr:hover td{background:#141821}
.empty{color:var(--mut);padding:8px 2px}
td details summary{cursor:pointer;color:var(--acc)}
.srclist{margin-top:6px;max-height:260px;overflow:auto;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700}
.s-crit{color:#ef4444}.s-high{color:#f97316}.s-med{color:#eab308}.s-low{color:#22c55e}.s-info{color:#f8fafc}
.badge.s-crit{background:#3a1417;color:#ef4444}.badge.s-high{background:#3a2410;color:#f97316}
.badge.s-med{background:#3a3410;color:#eab308}.badge.s-low{background:#0f2e1a;color:#22c55e}.badge.s-info{background:#20242c;color:#f8fafc}
.vuln{background:var(--card);border:1px solid var(--bd);border-left:4px solid var(--mut);border-radius:8px;padding:14px;margin-bottom:12px}
.vuln.s-crit{border-left-color:#ef4444}.vuln.s-high{border-left-color:#f97316}.vuln.s-med{border-left-color:#eab308}.vuln.s-low{border-left-color:#22c55e}.vuln.s-info{border-left-color:#f8fafc}
.vh{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.vtype{font-weight:700;font-size:15px}.conf{color:var(--mut);font-size:12px}
.vurl{margin:4px 0}.vmeta{color:var(--mut);font-size:13px;margin:2px 0}
code{background:#0b0d11;border:1px solid var(--bd);border-radius:4px;padding:1px 5px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.vev{margin:8px 0;padding:8px 10px;background:#0b0d11;border:1px solid var(--bd);border-radius:6px;font-size:12.5px;color:#cdd3dc}
.poc{margin-top:10px}.poc summary{cursor:pointer;color:var(--acc);font-weight:600}
.copy{margin:8px 0;background:var(--acc);color:#fff;border:0;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px}
.copy:hover{opacity:.9}.copy.done{background:#22b573}
.pocbody{background:#0b0d11;border:1px solid var(--bd);border-radius:6px;padding:12px;overflow-x:auto;white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
footer{padding:20px 22px;color:var(--mut);font-size:12px}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.cam{background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.cam img{width:100%;height:190px;object-fit:contain;background:#000;display:block}
.cam .noimg{width:100%;height:190px;display:flex;align-items:center;justify-content:center;background:#0b0d11;color:var(--mut);font-size:13px}
.cam .cb{padding:10px 12px;display:flex;flex-direction:column;gap:5px}
.cam .caddr{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:700;font-size:14px}
.cam .cprod{font-size:12px;color:var(--tx);text-transform:capitalize}
.cam .cdesc{font-size:12px;color:var(--mut)}
</style></head><body>`
}

// networkReportHTML renders the self-contained HTML report for a NETWORK target:
// Ingram camera/DVR findings (with snapshots), confirmed vulnerabilities/creds,
// network-CVE nuclei hits, and the discovered services/hosts. Reads existing DB
// rows, so it covers scans that already finished.
func (h *Handler) networkReportHTML(ctx context.Context, w http.ResponseWriter, id, domain string) {
	var b strings.Builder
	b.WriteString(reportHead(domain))

	count := func(q string) int {
		var n int
		h.db.QueryRowContext(ctx, q, id).Scan(&n)
		return n
	}
	stats := []struct {
		label string
		n     int
	}{
		{"Live Hosts", count("SELECT COUNT(*) FROM network_hosts WHERE target_id=? AND is_alive=1")},
		{"Services", count("SELECT COUNT(*) FROM network_services WHERE target_id=?")},
		{"Cameras/DVRs", count("SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type LIKE 'ingram_%' AND COALESCE(status,'finding')='finding'")},
		{"Vulnerabilities", count("SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND COALESCE(status,'finding')='finding'")},
		{"Nuclei", count("SELECT COUNT(*) FROM nuclei_findings WHERE target_id=? AND COALESCE(verification,'unverified') != 'rejected'")},
	}

	fmt.Fprintf(&b, `<header><h1>Network Report — %s</h1>`, html.EscapeString(domain))
	b.WriteString(`<div class="stats">`)
	for _, s := range stats {
		fmt.Fprintf(&b, `<div class="stat"><span class="n">%d</span><span class="l">%s</span></div>`, s.n, html.EscapeString(s.label))
	}
	b.WriteString(`</div></header>`)

	b.WriteString(`<nav class="toc">`)
	for _, t := range []struct{ id, label string }{
		{"cameras", "Cameras / DVRs"}, {"creds", "Recovered Access"},
		{"vulns", "Vulnerabilities (with PoC)"}, {"nuclei", "Nuclei"},
		{"hostdetail", "Per-Host Detail"}, {"services", "Services"},
		{"backups", "Backups / Config"}, {"hosts", "Live Hosts"},
	} {
		fmt.Fprintf(&b, `<a href="#sec-%s">%s</a>`, t.id, html.EscapeString(t.label))
	}
	b.WriteString(`</nav>`)

	// Camera / DVR gallery (Ingram).
	h.sectionNetworkCameras(ctx, &b, id)

	// Recovered access / credentials (brute-force + camera/DVR default logins).
	h.section(ctx, &b, id, "creds", "Recovered Access / Credentials", `
		SELECT url,
		       CASE WHEN type LIKE 'ingram_%' THEN REPLACE(SUBSTR(type,8),'_',' ') ELSE REPLACE(type,'_',' ') END,
		       severity, evidence
		FROM vuln_findings
		WHERE target_id=? AND (type LIKE '%weak_credentials%' OR type LIKE 'ingram_%')
		  AND COALESCE(status,'finding')='finding'
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, url`,
		[]string{"Host:Port", "Kind", "Severity", "Detail (credentials shown inline)"}, -1)

	// Confirmed vulnerabilities & recovered credentials (includes brute-force,
	// exposed-service and initial-access findings) with ready-to-file PoC blocks.
	h.sectionVulns(ctx, &b, id, domain)

	h.section(ctx, &b, id, "nuclei", "Nuclei Findings", `
		SELECT template_name, severity, matched_url, COALESCE(description,'') FROM (
			SELECT template_name, severity, matched_url, description,
			       ROW_NUMBER() OVER (PARTITION BY template_id ORDER BY LENGTH(matched_url) ASC, created_at DESC) AS rn
			FROM nuclei_findings WHERE target_id=? AND COALESCE(verification,'unverified') != 'rejected'
		) WHERE rn=1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
		[]string{"Template", "Severity", "URL", "Description"}, 2)

	// Per-host detail: every open service grouped under its IP.
	h.sectionNetworkHostDetail(ctx, &b, id)

	h.section(ctx, &b, id, "services", "Discovered Services", `
		SELECT ip || ':' || port, COALESCE(NULLIF(service,''),'?'),
		       TRIM(COALESCE(product,'') || ' ' || COALESCE(version,'')),
		       COALESCE(NULLIF(web_title,''), SUBSTR(COALESCE(banner,''),1,120))
		FROM network_services WHERE target_id=? ORDER BY ip, port LIMIT 5000`,
		[]string{"Host:Port", "Service", "Product", "Title / Banner"}, -1)

	h.section(ctx, &b, id, "backups", "Backups / Config Files", `
		SELECT url, status_code, COALESCE(file_type,''), content_length
		FROM backup_findings WHERE target_id=? ORDER BY url LIMIT 2000`,
		[]string{"URL", "Status", "Type", "Size"}, 0)

	h.section(ctx, &b, id, "hosts", "Live Hosts", `
		SELECT ip, open_ports, COALESCE(last_seen,'') FROM network_hosts
		WHERE target_id=? AND is_alive=1 ORDER BY ip LIMIT 20000`,
		[]string{"IP", "Open Ports", "Last Seen"}, -1)

	b.WriteString(reportFoot())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%s-network-report.html", domain))
	w.Write([]byte(b.String()))
}

// sectionNetworkHostDetail renders one block per live host: its IP followed by a
// compact table of every open port with the detected service / product / version
// / title, so a reader can see each machine's full footprint at a glance instead
// of scanning a flat services list.
func (h *Handler) sectionNetworkHostDetail(ctx context.Context, b *strings.Builder, id string) {
	b.WriteString(`<section id="sec-hostdetail"><h2>Per-Host Detail</h2>`)
	rows, err := h.db.QueryContext(ctx, `
		SELECT ip, port, COALESCE(NULLIF(service,''),'?'),
		       TRIM(COALESCE(product,'') || ' ' || COALESCE(version,'')),
		       COALESCE(NULLIF(web_title,''), SUBSTR(COALESCE(banner,''),1,120)),
		       COALESCE(web_url,'')
		FROM network_services WHERE target_id=? ORDER BY ip, port LIMIT 20000`, id)
	if err != nil {
		b.WriteString(`<p class="empty">query error</p></section>`)
		return
	}
	defer rows.Close()

	type row struct{ port, service, product, title, weburl string }
	byHost := map[string][]row{}
	order := []string{}
	for rows.Next() {
		var ip, service, product, title, weburl string
		var port int
		if rows.Scan(&ip, &port, &service, &product, &title, &weburl) != nil {
			continue
		}
		if _, seen := byHost[ip]; !seen {
			order = append(order, ip)
		}
		byHost[ip] = append(byHost[ip], row{fmt.Sprintf("%d", port), service, product, title, weburl})
	}

	if len(order) == 0 {
		b.WriteString(`<p class="empty">— no discovered services —</p></section>`)
		return
	}
	for _, ip := range order {
		fmt.Fprintf(b, `<h3 style="margin:14px 0 6px;font-size:15px"><a href="http://%s/" target="_blank">%s</a> <span style="color:var(--mut);font-weight:400">(%d service%s)</span></h3>`,
			html.EscapeString(ip), html.EscapeString(ip), len(byHost[ip]), plural(len(byHost[ip])))
		b.WriteString(`<div class="tbl"><table><thead><tr><th>Port</th><th>Service</th><th>Product / Version</th><th>Title / Banner</th></tr></thead><tbody>`)
		for _, sv := range byHost[ip] {
			portCell := html.EscapeString(sv.port)
			if sv.weburl != "" {
				portCell = fmt.Sprintf(`<a href="%s" target="_blank">%s</a>`, html.EscapeString(sv.weburl), html.EscapeString(sv.port))
			}
			fmt.Fprintf(b, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				portCell, html.EscapeString(sv.service), html.EscapeString(sv.product), html.EscapeString(sv.title))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</section>`)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// sectionNetworkCameras renders the Ingram camera/DVR findings as an image
// gallery: each device's captured snapshot (served at /screenshots/{id}) above
// its address, product, the PoC that confirmed it, and the human description
// (which includes any recovered credentials).
func (h *Handler) sectionNetworkCameras(ctx context.Context, b *strings.Builder, id string) {
	b.WriteString(`<section id="sec-cameras"><h2>Cameras / DVRs (Ingram)</h2>`)
	rows, err := h.db.QueryContext(ctx, `
		SELECT v.url, v.type, v.severity, COALESCE(v.evidence,''), COALESCE(v.parameter,''), COALESCE(e.image,'')
		FROM vuln_findings v
		LEFT JOIN evidence e ON e.finding_id = v.id AND e.kind = 'camera_poc'
		WHERE v.target_id = ? AND v.type LIKE 'ingram_%' AND COALESCE(v.status,'finding') = 'finding'
		ORDER BY (COALESCE(e.image,'') = '') ASC,
		         CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         v.url`, id)
	if err != nil {
		b.WriteString(`<p class="empty">query error</p></section>`)
		return
	}
	defer rows.Close()

	b.WriteString(`<div class="gallery">`)
	n := 0
	for rows.Next() {
		var addr, typ, sev, desc, poc, image string
		if rows.Scan(&addr, &typ, &sev, &desc, &poc, &image) != nil {
			continue
		}
		product := strings.TrimSpace(strings.ReplaceAll(strings.TrimPrefix(typ, "ingram_"), "_", " "))
		if product == "" {
			product = "device"
		}
		b.WriteString(`<div class="cam">`)
		if image != "" {
			fmt.Fprintf(b, `<a href="%s" target="_blank"><img src="%s" loading="lazy" alt="%s"></a>`,
				html.EscapeString(image), html.EscapeString(image), html.EscapeString(addr))
		} else {
			b.WriteString(`<div class="noimg">no snapshot</div>`)
		}
		b.WriteString(`<div class="cb">`)
		fmt.Fprintf(b, `<a class="caddr" href="http://%s/" target="_blank">%s</a>`, html.EscapeString(addr), html.EscapeString(addr))
		fmt.Fprintf(b, `<div class="cprod">%s %s`, sevBadge(sev), html.EscapeString(product))
		if poc != "" {
			fmt.Fprintf(b, ` · <code>%s</code>`, html.EscapeString(poc))
		}
		b.WriteString(`</div>`)
		if desc != "" {
			fmt.Fprintf(b, `<div class="cdesc">%s</div>`, html.EscapeString(desc))
		}
		b.WriteString(`</div></div>`)
		n++
	}
	b.WriteString(`</div>`)
	if n == 0 {
		b.WriteString(`<p class="empty">— no camera/DVR findings (run a scan with Ingram enabled) —</p>`)
	}
	b.WriteString(`</section>`)
}

func reportFoot() string {
	return `<footer>Generated by Reconner — offensive-security recon &amp; vulnerability platform · crafted by <strong>RootDR</strong>. All findings require manual verification before submission.</footer>
<script>
function copyPoc(btn){
  var pre = btn.parentElement.querySelector('.pocbody');
  var txt = pre ? pre.textContent : '';
  function done(){ btn.textContent='Copied'; btn.classList.add('done'); setTimeout(function(){btn.textContent='Copy report';btn.classList.remove('done')},1600); }
  if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done, function(){fallback(txt);done();}); }
  else { fallback(txt); done(); }
}
function fallback(t){ var ta=document.createElement('textarea'); ta.value=t; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy')}catch(e){} document.body.removeChild(ta); }

// Click-to-sort on every report table. Columns auto-detect their type: a
// severity column sorts by CRITICAL>HIGH>MEDIUM>LOW>INFO, a numeric column
// (status code, size) sorts numerically, everything else alphabetically.
// Clicking a header toggles ascending/descending.
var SEV={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};
function cellKey(td){
  if(!td) return {s:''};
  var t=(td.textContent||'').trim();
  var up=t.toUpperCase();
  if(SEV[up]!==undefined) return {n:SEV[up]};
  if(t!=='' && /^[0-9][0-9.,]*$/.test(t)) return {n:parseFloat(t.replace(/,/g,''))};
  return {s:t.toLowerCase()};
}
function sortTable(table,idx,th){
  var tb=table.tBodies[0]; if(!tb) return;
  var rows=Array.prototype.slice.call(tb.rows);
  var dir=th.getAttribute('data-dir')==='asc'?'desc':'asc';
  table.querySelectorAll('thead th').forEach(function(o){ if(o!==th){o.removeAttribute('data-dir');o.classList.remove('sorted-asc','sorted-desc');} });
  th.setAttribute('data-dir',dir);
  th.classList.toggle('sorted-asc',dir==='asc');
  th.classList.toggle('sorted-desc',dir==='desc');
  rows.sort(function(a,b){
    var av=cellKey(a.cells[idx]),bv=cellKey(b.cells[idx]),r;
    if('n' in av && 'n' in bv) r=av.n-bv.n;
    else r=String('n' in av?av.n:av.s).localeCompare(String('n' in bv?bv.n:bv.s));
    return dir==='asc'?r:-r;
  });
  rows.forEach(function(r){ tb.appendChild(r); });
}
document.querySelectorAll('.tbl table').forEach(function(table){
  var ths=table.querySelectorAll('thead th');
  ths.forEach(function(th,idx){
    th.classList.add('sortable');
    th.title='Click to sort';
    th.addEventListener('click',function(){ sortTable(table,idx,th); });
  });
});
</script></body></html>`
}
