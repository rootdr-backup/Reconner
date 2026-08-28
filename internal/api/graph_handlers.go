package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// ── Asset graph + correlation ─────────────────────────────────────────────────
//
// The intelligence layer. Instead of a flat list of findings, it correlates the
// stored data into an asset graph (subdomain ↔ IP ↔ service ↔ finding) and
// derives attack paths: which host, what it runs, what's wrong with it, and what
// that chains into. This is what turns raw output into something an operator can
// act on.

type graphNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // subdomain | ip | finding
	Label string `json:"label"`
	Meta  string `json:"meta,omitempty"`
	Sev   string `json:"severity,omitempty"`
}

type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type attackPath struct {
	Host       string   `json:"host"`
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
	Summary    string   `json:"summary"`
	Steps      []string `json:"steps"`
	Tech       []string `json:"tech,omitempty"`
}

func (h *Handler) handleAssetGraph(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	nodes, edges, paths := h.buildGraph(r, id)
	h.writeSuccess(w, map[string]any{
		"nodes":        nodes,
		"edges":        edges,
		"attack_paths": paths,
	})
}

// buildGraph reads subdomains, http_services and vuln_findings and correlates
// them. Returns graph nodes/edges plus ranked attack paths.
func (h *Handler) buildGraph(r *http.Request, targetID string) ([]graphNode, []graphEdge, []attackPath) {
	ctx := r.Context()
	var nodes []graphNode
	var edges []graphEdge
	seenNode := map[string]bool{}
	addNode := func(n graphNode) {
		if !seenNode[n.ID] {
			seenNode[n.ID] = true
			nodes = append(nodes, n)
		}
	}

	// Subdomains ↔ IPs (co-location reveals pivot opportunities).
	ipHosts := map[string][]string{}
	subTech := map[string]string{}
	rows, err := h.db.QueryContext(ctx, `SELECT subdomain, ip, technologies FROM subdomains WHERE target_id = ? AND is_alive = 1`, targetID)
	if err == nil {
		for rows.Next() {
			var sub, ip, techs string
			if rows.Scan(&sub, &ip, &techs) != nil {
				continue
			}
			addNode(graphNode{ID: "sub:" + sub, Type: "subdomain", Label: sub})
			if ip != "" {
				addNode(graphNode{ID: "ip:" + ip, Type: "ip", Label: ip})
				edges = append(edges, graphEdge{From: "sub:" + sub, To: "ip:" + ip, Kind: "resolves"})
				ipHosts[ip] = append(ipHosts[ip], sub)
			}
			subTech[sub] = techs
		}
		rows.Close()
	}

	// Findings ↔ host.
	type f struct {
		typ, sev, url, evidence string
		confidence, priority    int
	}
	hostFindings := map[string][]f{}
	frows, err := h.db.QueryContext(ctx, `
		SELECT type, severity, url, evidence, COALESCE(confidence,0), COALESCE(priority,0)
		FROM vuln_findings WHERE target_id = ?
		AND COALESCE(status,'finding') = 'finding'
		ORDER BY priority DESC
	`, targetID)
	if err == nil {
		for frows.Next() {
			var it f
			if frows.Scan(&it.typ, &it.sev, &it.url, &it.evidence, &it.confidence, &it.priority) != nil {
				continue
			}
			host := hostOf(it.url)
			hostFindings[host] = append(hostFindings[host], it)
			fid := "find:" + it.typ + ":" + it.url
			addNode(graphNode{ID: fid, Type: "finding", Label: it.typ, Sev: it.sev, Meta: fmt.Sprintf("%d%%", it.confidence)})
			if host != "" {
				addNode(graphNode{ID: "sub:" + host, Type: "subdomain", Label: host})
				edges = append(edges, graphEdge{From: "sub:" + host, To: fid, Kind: "has_finding"})
			}
		}
		frows.Close()
	}

	// Attack paths: one per host that has a meaningful finding, enriched with
	// co-located hosts and tech, and chained where findings reinforce each other.
	var paths []attackPath
	for host, fs := range hostFindings {
		if host == "" || len(fs) == 0 {
			continue
		}
		top := fs[0]
		if top.priority < 25 { // skip pure info noise
			continue
		}
		steps := []string{
			fmt.Sprintf("Host `%s` exposes **%s** (%s, %d%% confidence).", host, strings.ReplaceAll(top.typ, "_", " "), top.sev, top.confidence),
		}
		// chain: other findings on the same host
		if len(fs) > 1 {
			var others []string
			for _, o := range fs[1:] {
				others = append(others, strings.ReplaceAll(o.typ, "_", " "))
				if len(others) >= 4 {
					break
				}
			}
			steps = append(steps, "Same host also has: "+strings.Join(others, ", ")+" — chainable for greater impact.")
		}
		// co-location pivot
		for ip, hosts := range ipHosts {
			if contains(hosts, host) && len(hosts) > 1 {
				steps = append(steps, fmt.Sprintf("Shares IP `%s` with %d other hosts — potential lateral pivot.", ip, len(hosts)-1))
				break
			}
		}
		var tech []string
		if t := subTech[host]; t != "" && t != "[]" {
			tech = splitTech(t)
		}
		paths = append(paths, attackPath{
			Host:       host,
			Severity:   top.sev,
			Confidence: top.confidence,
			Summary:    fmt.Sprintf("%s on %s", strings.ReplaceAll(top.typ, "_", " "), host),
			Steps:      steps,
			Tech:       tech,
		})
	}
	sort.Slice(paths, func(i, j int) bool {
		return sevRank(paths[i].Severity) < sevRank(paths[j].Severity)
	})
	return nodes, edges, paths
}

func hostOf(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#:"); i >= 0 {
		s = s[:i]
	}
	return s
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func splitTech(j string) []string {
	j = strings.Trim(j, "[]")
	if j == "" {
		return nil
	}
	parts := strings.Split(j, ",")
	var out []string
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
