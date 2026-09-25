package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// panelSignature is deliberately evidence-heavy: a generic 200 on /admin is
// not enough. Product fingerprints, authentication responses, or an admin-ish
// title plus a credential form are required to keep this inventory low-noise.
type panelSignature struct {
	Product   string
	PanelType string
	Evidence  string
}

var panelProducts = []struct {
	name    string
	needles []string
}{
	{"Grafana", []string{"grafana", "grafana-app"}},
	{"Kibana", []string{"kibana", "kbn-injected-metadata"}},
	{"Prometheus", []string{"prometheus time series", "prometheus"}},
	{"Jenkins", []string{"jenkins", "x-jenkins"}},
	{"Argo CD", []string{"argo cd", "argocd"}},
	{"Kubernetes Dashboard", []string{"kubernetes dashboard"}},
	{"HashiCorp Vault", []string{"vault ui", "hashicorp vault"}},
	{"HashiCorp Consul", []string{"consul by hashicorp", "consul ui"}},
	{"Portainer", []string{"portainer"}},
	{"RabbitMQ Management", []string{"rabbitmq management"}},
	{"phpMyAdmin", []string{"phpmyadmin"}},
	{"Adminer", []string{"adminer"}},
	{"pgAdmin", []string{"pgadmin"}},
	{"SonarQube", []string{"sonarqube"}},
	{"Nexus Repository", []string{"nexus repository", "nexus repository manager"}},
	{"JFrog Artifactory", []string{"jfrog", "artifactory"}},
	{"Harbor", []string{"harbor portal", "harbor"}},
	{"Traefik Dashboard", []string{"traefik dashboard"}},
	{"Jaeger", []string{"jaeger ui", "jaeger"}},
	{"Zipkin", []string{"zipkin"}},
	{"Netdata", []string{"netdata dashboard", "netdata"}},
	{"Zabbix", []string{"zabbix"}},
	{"Nagios", []string{"nagios"}},
	{"Swagger UI", []string{"swagger ui", "swagger-ui"}},
	{"GraphQL Console", []string{"graphiql", "graphql playground", "apollo sandbox"}},
}

var (
	panelSpaceRE     = regexp.MustCompile(`\s+`)
	panelVolatileRE  = regexp.MustCompile(`(?i)(csrf|nonce|token|request[_-]?id)["'=:\s]+[a-z0-9_./+:-]{8,}`)
	panelAttrValueRE = regexp.MustCompile(`(?i)(value=["'])[a-z0-9_./+:-]{12,}(["'])`)
	panelHostRE      = regexp.MustCompile(`(?i)https?://[a-z0-9._:-]+`)
	panelLongIDRE    = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{16,}|\d{10,})\b`)
	panelTagSpaceRE  = regexp.MustCompile(`>\s+<`)
)

func classifyAdminPanel(rawURL string, status int, title string, body []byte, extra string) (panelSignature, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return panelSignature{}, false
	}
	path := strings.ToLower(strings.TrimRight(u.Path, "/"))
	text := strings.ToLower(title + " " + string(body) + " " + extra)
	for _, p := range panelProducts {
		for _, needle := range p.needles {
			if strings.Contains(text, needle) {
				return panelSignature{Product: p.name, PanelType: "management console", Evidence: "product fingerprint: " + needle}, true
			}
		}
	}
	cleanTitle := strings.TrimSpace(strings.ToLower(title))
	if cleanTitle == "admin login" || cleanTitle == "administrator login" || cleanTitle == "control panel" || cleanTitle == "management console" {
		return panelSignature{Product: "Administrative login", PanelType: "admin login", Evidence: "high-signal administrative page title"}, true
	}

	adminPath := path == "/admin" || path == "/administrator" || path == "/dashboard" ||
		path == "/manage" || path == "/management" || path == "/backend" || path == "/console" ||
		strings.Contains(path, "/admin/") || strings.HasSuffix(path, "/admin/login") ||
		strings.HasSuffix(path, "/users/sign_in") || strings.HasSuffix(path, "/auth/login")
	if !adminPath {
		return panelSignature{}, false
	}
	if status == 401 || status == 403 {
		return panelSignature{Product: "Restricted interface", PanelType: "admin or restricted panel", Evidence: "admin path with HTTP authentication/authorization response"}, true
	}
	if status >= 300 && status < 400 && (strings.Contains(text, "login") || strings.Contains(text, "sign-in") || strings.Contains(text, "signin")) {
		return panelSignature{Product: "Administrative login", PanelType: "admin login", Evidence: "administrative path redirects to authentication"}, true
	}
	adminWords := strings.Contains(text, "admin") || strings.Contains(text, "dashboard") ||
		strings.Contains(text, "control panel") || strings.Contains(text, "management console")
	passwordForm := strings.Contains(text, `type="password"`) || strings.Contains(text, `type='password'`) ||
		(strings.Contains(text, "password") && strings.Contains(text, "<form"))
	if status >= 200 && status < 400 && adminWords && passwordForm {
		return panelSignature{Product: "Administrative login", PanelType: "admin login", Evidence: "admin title/content plus credential form"}, true
	}
	return panelSignature{}, false
}

func normalizePanelContent(body []byte) string {
	s := strings.ToLower(string(body))
	s = panelHostRE.ReplaceAllString(s, "http://<host>")
	s = panelVolatileRE.ReplaceAllString(s, "$1=<volatile>")
	s = panelAttrValueRE.ReplaceAllString(s, "$1<volatile>$2")
	s = panelLongIDRE.ReplaceAllString(s, "<id>")
	s = panelSpaceRE.ReplaceAllString(s, " ")
	s = panelTagSpaceRE.ReplaceAllString(s, "><")
	return strings.TrimSpace(s)
}

func panelContentHash(body []byte) string {
	normalized := normalizePanelContent(body)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func canonicalPanelDestination(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	u.Fragment = ""
	u.RawQuery = ""
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.EscapedPath(), "/")
	return u.String()
}

func adminPanelGroupKey(sig panelSignature, rawURL, redirectURL, contentHash, title string) string {
	if contentHash != "" {
		return "content:" + contentHash
	}
	if dst := canonicalPanelDestination(redirectURL); dst != "" {
		return "redirect:" + dst
	}
	u, _ := url.Parse(rawURL)
	path := "/"
	if u != nil && u.Path != "" {
		path = strings.ToLower(strings.TrimRight(u.Path, "/"))
	}
	return "identity:" + strings.ToLower(sig.Product) + ":" + strings.ToLower(strings.TrimSpace(title)) + ":" + path
}

func (s *DirScanner) storeAdminPanel(targetID, rawURL string, status int, title string, body []byte, redirectURL, extra string) bool {
	sig, ok := classifyAdminPanel(rawURL, status, title, body, extra)
	if !ok {
		return false
	}
	hash := panelContentHash(body)
	group := adminPanelGroupKey(sig, rawURL, redirectURL, hash, title)
	_, err := s.db.Exec(`
		INSERT INTO admin_panel_findings
			(id,target_id,url,status_code,panel_type,product,title,redirect_url,content_hash,group_key,evidence)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id,url) DO UPDATE SET status_code=excluded.status_code,
			panel_type=excluded.panel_type,product=excluded.product,title=excluded.title,
			redirect_url=excluded.redirect_url,content_hash=excluded.content_hash,
			group_key=excluded.group_key,evidence=excluded.evidence,updated_at=CURRENT_TIMESTAMP`,
		uuid.New().String(), targetID, rawURL, status, sig.PanelType, sig.Product, title,
		redirectURL, hash, group, sig.Evidence)
	return err == nil
}

// classifyStoredServicePanels catches panels mounted at / on dedicated hosts
// without sending another request; HTTP probing has already stored their title,
// server and technology fingerprint.
func (s *DirScanner) classifyStoredServicePanels(targetID string) {
	rows, err := s.db.Query(`SELECT url,status_code,COALESCE(title,''),COALESCE(server,''),COALESCE(technologies,'')
		FROM http_services WHERE target_id=? AND status_code BETWEEN 200 AND 403`, targetID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rawURL, title, server, technologies string
		var status int
		if rows.Scan(&rawURL, &status, &title, &server, &technologies) == nil {
			s.storeAdminPanel(targetID, rawURL, status, title, nil, "", server+" "+technologies)
		}
	}
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				out = append(out, value)
			}
		}
	}
	sort.Strings(out)
	return out
}
