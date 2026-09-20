package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// CorpusCategory describes one operator-extensible scanner dictionary. Built-in
// entries remain compiled into Reconner; custom entries are stored separately so
// upgrades and "restore defaults" are both lossless and predictable.
type CorpusCategory struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Kind         string   `json:"kind"`
	Description  string   `json:"description"`
	DefaultCount int      `json:"default_count"`
	CustomCount  int      `json:"custom_count"`
	TotalCount   int      `json:"total_count"`
	Preview      []string `json:"preview"`
}

// CorpusMergeResult is intentionally explicit: the UI can tell an operator how
// much of a pasted/uploaded list was useful instead of silently dropping rows.
type CorpusMergeResult struct {
	Input      int `json:"input"`
	Added      int `json:"added"`
	Duplicates int `json:"duplicates"`
	Invalid    int `json:"invalid"`
	Total      int `json:"total"`
}

type corpusSpec struct {
	label, kind, description string
	defaults                 func() []string
}

var corpusSpecs = map[string]corpusSpec{
	"subdomain": {"Subdomains", "wordlist", "DNS brute-force and permutation seeds.", func() []string { return append([]string{}, bruteWords...) }},
	"vhost":     {"Virtual hosts", "wordlist", "Host-header discovery prefixes.", func() []string { return append([]string{}, vhostWordlist...) }},
	"directory": {"Directories & files", "wordlist", "Paths used by built-in content discovery.", func() []string { return append([]string{}, builtinWordlist...) }},
	"backup":    {"Backups & secrets", "wordlist", "Sensitive files, archives, dumps and configuration paths.", func() []string { return append([]string{}, backupPatterns...) }},
	"exposure":  {"Exposure paths", "wordlist", "High-signal configuration and secret paths checked by exposure scanning.", func() []string { return append([]string{}, exposureConfigPaths...) }},
	"graphql":   {"GraphQL paths", "wordlist", "Endpoint paths used by GraphQL discovery and introspection checks.", func() []string { return append([]string{}, graphqlPaths...) }},
	"api_spec":  {"API specification paths", "wordlist", "Swagger and OpenAPI document paths checked by exposure scanning.", func() []string { return append([]string{}, apiSpecPaths...) }},
	"extensions": {"File extensions", "wordlist", "Extensions supplied to directory fuzzers.", func() []string {
		return strings.Split("php,asp,aspx,jsp,html,txt,bak,backup,old,zip,sql,tar,gz,rar,7z,xml,json,yaml,yml,env,js,map,pdf,cfg,conf,swp,inc", ",")
	}},
	"parameters": {"Hidden parameters", "wordlist", "Names tested by hidden-parameter mining.", func() []string { return append([]string{}, paramFuzzWords...) }},
	"jwt_secrets": {"JWT weak secrets", "wordlist", "HMAC secrets used by the bounded JWT dictionary check.", func() []string {
		return append([]string{}, jwtWeakSecrets...)
	}},
	"xss":  {"XSS", "payload", "Browser-proof templates. Each template must set top.document.title to the single %s nonce.", xssBrowserPayloads},
	"sqli": {"SQL injection", "payload", "Supplemental error-based SQL injection probes, replayed before a finding is accepted.", func() []string { return []string{"'", `"`, "' OR '1'='1'-- -", "1 AND 1=1", "1 AND 1=2"} }},
	"lfi":  {"LFI / traversal", "payload", "Local-file inclusion and traversal probes.", func() []string { return append([]string{}, lfiPayloads...) }},
	"ssrf": {"SSRF", "payload", "In-band internal and metadata URLs.", func() []string {
		out := make([]string, 0, len(ssrfInbandPayloads))
		for _, p := range ssrfInbandPayloads {
			out = append(out, p.url)
		}
		return out
	}},
	"ssti": {"SSTI", "payload", "Arithmetic expression templates. Use exactly two %d placeholders for independently verified operands.", func() []string {
		return []string{"{{%d*%d}}", "${%d*%d}", "#{%d*%d}", "<%%=%d*%d%%>", "@(%d*%d)", "{%d*%d}"}
	}},
	"csti":     {"CSTI", "payload", "Client-template arithmetic expressions. Use exactly two %d placeholders.", func() []string { return []string{"{{%d*%d}}"} }},
	"nosqli":   {"NoSQL injection", "payload", "Supplemental document-database operator probes.", func() []string { return []string{"[$ne]=1", "[$regex]=.*", `{"$ne":null}`, `{"$where":"1==1"}`} }},
	"cmdi":     {"Command injection", "payload", "Reflection-safe command probes. Custom entries must retain Reconner's computed proof marker.", func() []string { return append([]string{}, cmdiEchoPayloads...) }},
	"redirect": {"Open redirect", "payload", "External redirect bypass forms using Reconner's controlled evil.com proof host.", func() []string { return append([]string{}, openRedirectPayloads...) }},
}

var corpusMu sync.Mutex

var extensionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$`)

func corpusPath(dir, id string) string {
	return filepath.Join(dir, "reconner-custom-"+id+".txt")
}

func corpusKey(id, value string) string {
	value = normalizeCorpusValue(id, value)
	switch id {
	case "subdomain", "vhost", "extensions", "parameters":
		return strings.ToLower(value)
	default:
		return value
	}
}

func normalizeCorpusValue(id, value string) string {
	value = strings.TrimSpace(value)
	switch id {
	case "subdomain", "vhost":
		value = strings.ToLower(value)
		value = strings.TrimPrefix(value, "*.")
		value = strings.TrimPrefix(value, ".")
	case "extensions":
		value = strings.TrimLeft(value, ".")
	case "directory", "backup", "exposure", "graphql", "api_spec":
		if value != "" && !strings.HasPrefix(value, "/") {
			value = "/" + value
		}
	}
	return value
}

func validCorpusValue(id, value string) bool {
	value = normalizeCorpusValue(id, value)
	if value == "" || len(value) > 8192 || strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n") {
		return false
	}
	switch id {
	case "subdomain", "vhost":
		return validDNSPrefix(value)
	case "extensions":
		return extensionPattern.MatchString(value)
	case "parameters":
		return usableParamName(value)
	case "directory", "backup", "exposure", "graphql", "api_spec":
		return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") &&
			!strings.Contains(value, "://") && !strings.Contains(value, "..")
	case "xss":
		// A custom XSS vector may only become a finding when the real browser
		// observes Reconner's random title nonce. Requiring the proof sink and one
		// formatting slot prevents an arbitrary alert/reflection string from being
		// mistaken for an execution-capable template.
		return strings.Count(value, "%s") == 1 && strings.Contains(value, "top.document.title")
	case "ssti", "csti":
		return strings.Count(value, "%d") == 2
	case "cmdi":
		return strings.Contains(value, "RCNZZ$((1000+337))ZZ")
	case "redirect":
		return strings.Contains(strings.ToLower(value), evilRedirectHost)
	default:
		return true
	}
}

func readCustomCorpus(dir, id string) []string {
	if dir == "" {
		return nil
	}
	f, err := os.Open(corpusPath(dir, id))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		if value := normalizeCorpusValue(id, s.Text()); validCorpusValue(id, value) {
			out = append(out, value)
		}
	}
	return out
}

// CustomCorpus returns only operator-managed values. Scanners use this when
// their built-in probes have richer metadata than a flat string (for example,
// SQLi verification pairs) and custom payloads must be added as a supplemental
// proof stage rather than replacing the native detector.
func CustomCorpus(dir, id string) []string {
	spec, ok := corpusSpecs[id]
	if !ok {
		return nil
	}
	return customOnlyCorpus(id, uniqueCorpus(id, spec.defaults()), readCustomCorpus(dir, id))
}

func uniqueCorpus(id string, values ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range values {
		for _, raw := range list {
			value := normalizeCorpusValue(id, raw)
			key := corpusKey(id, value)
			if !validCorpusValue(id, value) || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

// LoadCorpus merges a scanner's authoritative defaults with operator additions.
func LoadCorpus(dir, id string, defaults []string) []string {
	return uniqueCorpus(id, defaults, readCustomCorpus(dir, id))
}

func CorpusCatalog(dir string) []CorpusCategory {
	ids := make([]string, 0, len(corpusSpecs))
	for id := range corpusSpecs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]CorpusCategory, 0, len(ids))
	for _, id := range ids {
		spec := corpusSpecs[id]
		defaults := uniqueCorpus(id, spec.defaults())
		custom := customOnlyCorpus(id, defaults, readCustomCorpus(dir, id))
		all := uniqueCorpus(id, defaults, custom)
		// Show operator additions first so a successful import is immediately
		// visible even when a category has thousands of compiled defaults.
		preview := uniqueCorpus(id, custom, defaults)
		if len(preview) > 8 {
			preview = preview[:8]
		}
		out = append(out, CorpusCategory{ID: id, Label: spec.label, Kind: spec.kind, Description: spec.description, DefaultCount: len(defaults), CustomCount: len(uniqueCorpus(id, custom)), TotalCount: len(all), Preview: append([]string{}, preview...)})
	}
	return out
}

func customOnlyCorpus(id string, defaults, values []string) []string {
	seen := make(map[string]bool, len(defaults)+len(values))
	for _, value := range defaults {
		seen[corpusKey(id, value)] = true
	}
	var out []string
	for _, value := range uniqueCorpus(id, values) {
		key := corpusKey(id, value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func MergeCorpus(dir, id string, input []string) (CorpusMergeResult, error) {
	corpusMu.Lock()
	defer corpusMu.Unlock()
	spec, ok := corpusSpecs[id]
	if !ok {
		return CorpusMergeResult{}, fmt.Errorf("unknown corpus category %q", id)
	}
	if len(input) > 20000 {
		return CorpusMergeResult{}, fmt.Errorf("at most 20000 entries may be added at once")
	}
	defaults := uniqueCorpus(id, spec.defaults())
	custom := customOnlyCorpus(id, defaults, readCustomCorpus(dir, id))
	seen := map[string]bool{}
	for _, value := range append(append([]string{}, defaults...), custom...) {
		seen[corpusKey(id, value)] = true
	}
	result := CorpusMergeResult{}
	for _, raw := range input {
		value := normalizeCorpusValue(id, raw)
		if value == "" {
			continue
		}
		result.Input++
		if !validCorpusValue(id, value) {
			result.Invalid++
			continue
		}
		key := corpusKey(id, value)
		if seen[key] {
			result.Duplicates++
			continue
		}
		seen[key] = true
		custom = append(custom, value)
		result.Added++
	}
	if err := writeCustomCorpus(dir, id, custom); err != nil {
		return CorpusMergeResult{}, err
	}
	result.Total = len(defaults) + len(custom)
	return result, nil
}

func writeCustomCorpus(dir, id string, values []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".corpus-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintln(tmp, value); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, corpusPath(dir, id))
}

func RestoreCorpus(dir, id string) (int, error) {
	corpusMu.Lock()
	defer corpusMu.Unlock()
	if _, ok := corpusSpecs[id]; !ok {
		return 0, fmt.Errorf("unknown corpus category %q", id)
	}
	defaults := uniqueCorpus(id, corpusSpecs[id].defaults())
	removed := len(customOnlyCorpus(id, defaults, readCustomCorpus(dir, id)))
	err := os.Remove(corpusPath(dir, id))
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	return removed, nil
}
