package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// devToolWords targets names humans commonly choose after the product or
// infrastructure they deploy. These are intentionally separate from the generic
// top-word list so they can also lead wildcard/vhost prioritisation.
var devToolWords = []string{
	"argocd", "argo", "argoworkflows", "vault", "nomad", "consul", "harbor",
	"nexus", "artifactory", "sonarqube", "sonar", "sentry", "rabbitmq", "rabbit",
	"kafka", "zookeeper", "minio", "rancher", "traefik", "airflow", "temporal",
	"keycloak", "oauth2-proxy", "loki", "tempo", "jaeger", "zipkin", "graylog",
	"splunk", "elk", "opensearch", "elasticsearch", "logstash", "fluentd",
	"fluentbit", "kibana", "grafana", "prometheus", "alertmanager", "thanos",
	"victoriametrics", "datadog", "newrelic", "jenkins", "teamcity", "bamboo",
	"buildkite", "circleci", "drone", "gitea", "gogs", "bitbucket", "gitlab",
	"registry", "docker-registry", "kubernetes", "k8s", "kube", "openshift",
	"istio", "kiali", "linkerd", "kong", "tyk", "apisix", "nginx", "haproxy",
	"rabbitmq-management", "phpmyadmin", "pgadmin", "adminer", "redis-commander",
	"mongo-express", "kafdrop", "akhq", "schema-registry", "swagger", "swagger-ui",
	"openapi", "graphql", "graphiql", "playground", "storybook", "backstage",
	"mattermost", "rocket", "rocketchat", "slack", "wiki", "confluence", "jira",
	"sftp", "bastion", "jump", "jumpbox", "vpn", "openvpn", "wireguard",
	"mailhog", "mailcatcher", "smtp", "webmail", "roundcube", "autodiscover",
	"exchange", "owa", "adfs", "ldap", "auth", "sso", "iam", "identity",
}

var dnsEnvironments = []string{
	"dev", "development", "stage", "staging", "test", "testing", "qa", "uat",
	"preprod", "sandbox", "demo", "internal", "int", "corp", "private", "prod",
}

// deepDNSWords creates a large but bounded and deterministic wordlist. Operators
// may drop additional .txt/.lst files containing "subdomain", "dns" or "vhost"
// in data/wordlists; those are merged without requiring a rebuild.
func (s *SubdomainScanner) deepDNSWords(ctx context.Context, domain string, known []string) []string {
	capWords := 50000
	switch webSpeedFromCtx(ctx) {
	case SpeedSlow:
		capWords = 20000
	case SpeedFast:
		capWords = 100000
	}
	seen := map[string]bool{}
	words := make([]string, 0, 12000)
	add := func(raw string) {
		if len(words) >= capWords {
			return
		}
		w := strings.ToLower(strings.TrimSpace(raw))
		w = strings.TrimPrefix(w, "*.")
		w = strings.TrimSuffix(w, ".")
		w = strings.TrimSuffix(w, "."+strings.ToLower(strings.TrimSuffix(domain, ".")))
		if w == "" || seen[w] || !validDNSPrefix(w) {
			return
		}
		seen[w] = true
		words = append(words, w)
	}

	for _, w := range bruteWords {
		add(w)
	}
	for _, w := range devToolWords {
		add(w)
		for _, env := range dnsEnvironments {
			add(w + "-" + env)
			add(env + "-" + w)
		}
	}
	// Numeric variants cover the common api1/node03/jenkins2 convention without
	// multiplying every generic dictionary entry.
	for _, w := range append([]string{"api", "app", "web", "node", "server", "ns", "mail", "vpn", "git", "jenkins"}, devToolWords...) {
		for i := 1; i <= 10; i++ {
			add(w + itoaSmall(i))
			add(w + "-" + itoaSmall(i))
		}
	}

	for _, host := range known {
		label := strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), "."+strings.ToLower(domain))
		if label == "" || !validDNSPrefix(label) {
			continue
		}
		add(label)
		for _, env := range dnsEnvironments {
			add(env + "-" + label)
			add(label + "-" + env)
			add(env + "." + label)
		}
	}
	if s.cfg != nil {
		for _, word := range loadAdaptiveWordlist(s.cfg.WordlistsDir, domain, 400) {
			add(word)
		}
	}

	if s.cfg != nil && s.cfg.WordlistsDir != "" {
		entries, _ := os.ReadDir(s.cfg.WordlistsDir)
		for _, entry := range entries {
			if ctx.Err() != nil || len(words) >= capWords || entry.IsDir() {
				break
			}
			name := strings.ToLower(entry.Name())
			ext := strings.ToLower(filepath.Ext(name))
			if ext != ".txt" && ext != ".lst" && ext != ".wordlist" {
				continue
			}
			if !strings.Contains(name, "subdomain") && !strings.Contains(name, "dns") && !strings.Contains(name, "vhost") {
				continue
			}
			f, err := os.Open(filepath.Join(s.cfg.WordlistsDir, entry.Name()))
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 4096), 1024*1024)
			for sc.Scan() && len(words) < capWords {
				if ctx.Err() != nil {
					break
				}
				line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
				add(line)
			}
			_ = f.Close()
		}
	}

	// Stable order means identical scans produce identical resolver batches.
	sort.Strings(words)
	return words
}

func validDNSPrefix(prefix string) bool {
	if prefix == "" || len(prefix) > 240 || strings.ContainsAny(prefix, "/:@?#[] ") {
		return false
	}
	for _, label := range strings.Split(prefix, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func itoaSmall(n int) string {
	if n == 10 {
		return "10"
	}
	return string(rune('0' + n))
}
