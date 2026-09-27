package scanner

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// JavaScript request-contract mining deliberately stays narrow. Extracting every
// object key from a bundle creates an enormous, low-quality wordlist; these
// patterns only inspect objects attached to fetch/axios request primitives and
// URLSearchParams/FormData setters.
var (
	apiSetterParamRE = regexp.MustCompile(`(?i)(?:\.append|\.set)\s*\(\s*["']([a-z_$][a-z0-9_$.-]{1,63})["']`)
	apiObjectStartRE = regexp.MustCompile(`(?is)(?:JSON\.stringify\s*\(|new\s+URLSearchParams\s*\(|\b(?:params|data|body)\s*:\s*|(?:axios\.)?(?:post|put)\s*\([^,]{0,500},\s*)\{`)
	apiObjectKeyRE   = regexp.MustCompile(`(?m)(?:^|[,{\s])(?:["']?)([a-zA-Z_$][a-zA-Z0-9_$.-]{1,63})(?:["']?)\s*:`)
)

var apiContractNoiseKeys = map[string]bool{
	"method": true, "headers": true, "body": true, "mode": true,
	"credentials": true, "cache": true, "redirect": true, "referrer": true,
	"referrerpolicy": true, "integrity": true, "keepalive": true, "signal": true,
	"timeout": true, "baseurl": true, "url": true, "transformrequest": true,
	"transformresponse": true, "adapter": true, "responsetype": true,
}

type apiParamHint struct {
	name    string
	context string
}

func extractAPIParamHints(content string) []apiParamHint {
	seen := map[string]apiParamHint{}
	add := func(name, source string) {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if len(name) < 2 || len(name) > 64 || apiContractNoiseKeys[key] || !safeParameterName(name) {
			return
		}
		if _, ok := seen[key]; !ok {
			seen[key] = apiParamHint{name: name, context: source}
		}
	}

	for _, match := range apiSetterParamRE.FindAllStringSubmatch(content, 1000) {
		if len(match) > 1 {
			add(match[1], "js-request-parameter")
		}
	}

	for _, loc := range apiObjectStartRE.FindAllStringIndex(content, 1000) {
		if len(loc) < 2 {
			continue
		}
		braceOffset := strings.LastIndex(content[loc[0]:loc[1]], "{")
		if braceOffset < 0 {
			continue
		}
		block, ok := balancedJSObject(content, loc[0]+braceOffset, 4096)
		if !ok {
			continue
		}
		// params:/data: are common in unrelated configuration objects. Require a
		// nearby request primitive unless JSON.stringify itself provided the bound.
		start := loc[0] - 600
		if start < 0 {
			start = 0
		}
		window := strings.ToLower(content[start:loc[1]])
		whole := strings.ToLower(content[loc[0]:loc[1]])
		if !strings.Contains(whole, "json.stringify") && !strings.Contains(whole, "urlsearchparams") &&
			!strings.Contains(whole, ".post(") && !strings.HasPrefix(strings.TrimSpace(whole), "post(") &&
			!strings.Contains(whole, ".put(") && !strings.HasPrefix(strings.TrimSpace(whole), "put(") &&
			!strings.Contains(window, "fetch(") &&
			!strings.Contains(window, "axios") &&
			!strings.Contains(window, ".request(") &&
			!strings.Contains(window, ".post(") &&
			!strings.Contains(window, ".get(") {
			continue
		}
		for _, key := range apiObjectKeyRE.FindAllStringSubmatch(block, 100) {
			if len(key) > 1 {
				add(key[1], "js-request-body")
			}
		}
	}

	out := make([]apiParamHint, 0, len(seen))
	for _, hint := range seen {
		out = append(out, hint)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].name) < strings.ToLower(out[j].name) })
	return out
}

func balancedJSObject(content string, brace, maxBytes int) (string, bool) {
	if brace < 0 || brace >= len(content) || content[brace] != '{' {
		return "", false
	}
	end := brace + maxBytes
	if end > len(content) {
		end = len(content)
	}
	depth := 0
	var quote byte
	escaped := false
	for i := brace; i < end; i++ {
		ch := content[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[brace+1 : i], true
			}
		}
	}
	return "", false
}

func safeParameterName(name string) bool {
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("_$.-", r) {
			continue
		}
		return false
	}
	return true
}

func (s *JSScanner) storeAPIParamHints(ctx context.Context, targetID, jsFileID, content string) int {
	stored := 0
	for _, hint := range extractAPIParamHints(content) {
		res, err := s.db.ExecContext(ctx, `INSERT INTO js_findings
			(id,target_id,js_file_id,type,value,context,severity)
			SELECT ?,?,?, 'api_param',?,?, 'info'
			WHERE NOT EXISTS (
				SELECT 1 FROM js_findings
				WHERE target_id=? AND js_file_id=? AND type='api_param' AND lower(value)=lower(?)
			)`, uuid.New().String(), targetID, jsFileID, hint.name, hint.context,
			targetID, jsFileID, hint.name)
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				stored++
			}
		}
	}
	return stored
}
