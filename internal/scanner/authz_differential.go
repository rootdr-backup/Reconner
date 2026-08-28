package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Two-identity authorization DIFFERENTIAL engine (BOLA/IDOR/BFLA). Built on
// identity.go (fetchAs/looksLikeAuthObject/deniesAccess) and idor.go.

type AuthzProfile int

const (
	AuthzSafe AuthzProfile = iota
	AuthzBalanced
	AuthzDeep
)

func (p AuthzProfile) allowsWrite() bool { return p >= AuthzBalanced }
func (p AuthzProfile) allowsDelete(destructiveEnabled bool) bool {
	return p >= AuthzDeep && destructiveEnabled
}

func ParseAuthzProfile(s string) AuthzProfile {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "safe":
		return AuthzSafe
	case "deep", "aggressive":
		return AuthzDeep
	default:
		return AuthzBalanced
	}
}

type AuthzRef struct {
	Location string
	Name     string
	Value    string
	Kind     string
	JSONPath string
}

var (
	reInt    = regexp.MustCompile(`^\d{1,19}$`)
	reAzUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reULID   = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	reMongo  = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
	reEmail  = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reSlug   = regexp.MustCompile(`^[a-z0-9]+(?:[-_][a-z0-9]+)+$`)
)

func classifyIDKind(v string) string {
	switch {
	case reInt.MatchString(v):
		return "int"
	case reAzUUID.MatchString(v):
		return "uuid"
	case reULID.MatchString(v):
		return "ulid"
	case reMongo.MatchString(v):
		return "mongo"
	case reEmail.MatchString(v):
		return "email"
	case reSlug.MatchString(v):
		return "slug"
	default:
		return "opaque"
	}
}

var idNameHints = []string{
	"id", "uid", "guid", "uuid", "ref", "key", "slug", "token", "item", "object",
	"user", "userid", "account", "accountid", "customer", "customerid",
	"order", "orderid", "document", "documentid", "file", "fileid",
	"project", "projectid", "tenant", "tenantid", "organization", "organizationid",
	"org", "orgid", "workspace", "company", "invoice", "message", "resource", "entity",
	"member", "owner", "created", "createdby",
}

func looksLikeObjectRef(name, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || v == "true" || v == "false" || v == "null" {
		return false
	}
	kind := classifyIDKind(v)
	structural := kind != "opaque" && kind != "slug" || (kind == "slug" && nameHintMatch(name))
	if kind == "int" {
		if (v == "0" || v == "1") && !nameHintMatch(name) {
			return false
		}
	}
	if nameHintMatch(name) {
		return len(v) >= 1
	}
	return structural && len(v) >= 2
}

func nameHintMatch(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	n = strings.NewReplacer("-", "", "_", "").Replace(n)
	for _, h := range idNameHints {
		hh := strings.ReplaceAll(h, "_", "")
		if n == hh || strings.HasSuffix(n, hh) {
			return true
		}
	}
	return false
}

func extractObjectRefs(rawURL, contentType, body string, headers map[string]string) []AuthzRef {
	var out []AuthzRef
	seen := map[string]bool{}
	add := func(r AuthzRef) {
		k := r.Location + "|" + r.Name + "|" + r.JSONPath + "|" + r.Value
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, r)
	}
	if u, err := url.Parse(rawURL); err == nil {
		segs := strings.Split(strings.Trim(u.Path, "/"), "/")
		for i, seg := range segs {
			if seg == "" {
				continue
			}
			name := ""
			if i > 0 {
				name = strings.TrimSuffix(segs[i-1], "s")
			}
			if looksLikeObjectRef(name, seg) || classifyIDKind(seg) != "opaque" && classifyIDKind(seg) != "slug" {
				if classifyIDKind(seg) != "opaque" || nameHintMatch(name) {
					add(AuthzRef{Location: "path", Name: name, Value: seg, Kind: classifyIDKind(seg)})
				}
			}
		}
		for k, vs := range u.Query() {
			for _, v := range vs {
				if looksLikeObjectRef(k, v) {
					add(AuthzRef{Location: "query", Name: k, Value: v, Kind: classifyIDKind(v)})
				}
			}
		}
	}
	if strings.Contains(strings.ToLower(contentType), "json") && strings.TrimSpace(body) != "" {
		var v any
		if json.Unmarshal([]byte(body), &v) == nil {
			walkJSONRefs("", v, add)
		}
	}
	for k, v := range headers {
		if isAuthHeaderName(k) {
			continue
		}
		if looksLikeObjectRef(k, v) {
			add(AuthzRef{Location: "header", Name: k, Value: v, Kind: classifyIDKind(v)})
		}
	}
	return out
}

func walkJSONRefs(path string, v any, add func(AuthzRef)) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			switch cv := child.(type) {
			case string:
				if looksLikeObjectRef(k, cv) {
					add(AuthzRef{Location: "json", Name: k, Value: cv, Kind: classifyIDKind(cv), JSONPath: p})
				}
			case float64:
				s := strconv.FormatFloat(cv, 'f', -1, 64)
				if looksLikeObjectRef(k, s) {
					add(AuthzRef{Location: "json", Name: k, Value: s, Kind: classifyIDKind(s), JSONPath: p})
				}
			default:
				walkJSONRefs(p, child, add)
			}
		}
	case []any:
		for i, child := range t {
			walkJSONRefs(fmt.Sprintf("%s[%d]", path, i), child, add)
		}
	}
}

func isAuthHeaderName(name string) bool {
	n := strings.ToLower(name)
	for _, a := range []string{"authorization", "cookie", "x-csrf", "csrf", "x-xsrf",
		"x-auth", "x-session", "x-api-key", "api-key", "token", "bearer"} {
		if strings.Contains(n, a) {
			return true
		}
	}
	return false
}

func typeConfusionVariants(kind, value string) []string {
	var out []string
	switch kind {
	case "int":
		out = append(out, strconv.Quote(value))
		out = append(out, "["+value+"]")
		out = append(out, "["+strconv.Quote(value)+"]")
	default:
		if _, err := strconv.Atoi(value); err == nil {
			out = append(out, value)
		}
		out = append(out, "["+strconv.Quote(value)+"]")
	}
	return out
}

func duplicateParamVariants(rawURL, name, ownValue, otherValue string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	base := u.Query()
	base.Del(name)
	prefix := base.Encode()
	if prefix != "" {
		prefix += "&"
	}
	mk := func(a, b string) string {
		q := prefix + url.QueryEscape(name) + "=" + url.QueryEscape(a) + "&" +
			url.QueryEscape(name) + "=" + url.QueryEscape(b)
		u2 := *u
		u2.RawQuery = q
		return u2.String()
	}
	return []string{mk(ownValue, otherValue), mk(otherValue, ownValue)}
}

func pathNormalizationVariants(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return nil
	}
	p := u.Path
	var paths []string
	if strings.HasSuffix(p, "/") {
		paths = append(paths, strings.TrimRight(p, "/"))
	} else {
		paths = append(paths, p+"/")
	}
	paths = append(paths, p+"/.")
	paths = append(paths, p+"/./")
	paths = append(paths, strings.Replace(p, "/", "//", 1))
	var out []string
	for _, np := range paths {
		u2 := *u
		u2.Path = np
		out = append(out, u2.String())
	}
	return out
}

func attackerLeakedOwnerRef(ownerRefs []AuthzRef, attackerBody string) (string, bool) {
	for _, r := range ownerRefs {
		switch r.Kind {
		case "uuid", "ulid", "mongo", "email":
			if len(r.Value) >= 12 && strings.Contains(attackerBody, r.Value) {
				return r.Value, true
			}
		}
	}
	return "", false
}

type authzSignals struct {
	unauthDenied       bool
	ownerHasObject     bool
	attackerGotObject  bool
	bodiesMatch        bool
	leakedOwnerUnique  bool
	writeVerified      bool
	methodDifferential bool
}

func authzConfidence(s authzSignals) int {
	if !s.unauthDenied || !s.ownerHasObject || !s.attackerGotObject {
		return 0
	}
	c := 55
	if s.bodiesMatch {
		c = 90
	}
	if s.methodDifferential && !s.writeVerified && c < 70 {
		c = 70
	}
	if s.leakedOwnerUnique {
		c = 96
	}
	if s.writeVerified {
		c = 99
	}
	if c > 100 {
		c = 100
	}
	return c
}

func publicResourceLikely(owner, unauth IdentityResponse) bool {
	if unauth.Err != nil {
		return false
	}
	if unauth.Status == 200 && looksLikeAuthObject(unauth) && bodiesSameObject(owner.Body, unauth.Body) {
		return true
	}
	return false
}

func authzReproSteps(method, url, ownerLabel, attackerLabel, objectRef string, write bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Reproduction (authorization boundary: %s owns the object, %s must not access it):\n", ownerLabel, attackerLabel)
	if write {
		fmt.Fprintf(&b, "  1. As <%s_AUTH>, capture the current state:  curl -i -sk %s\n", strings.ToUpper(ownerLabel), url)
		fmt.Fprintf(&b, "  2. As <%s_AUTH>, replay the mutation:        curl -i -sk -X %s %s\n", strings.ToUpper(attackerLabel), method, url)
		fmt.Fprintf(&b, "  3. As <%s_AUTH>, re-read the object and observe the state changed (unauthorized write).\n", strings.ToUpper(ownerLabel))
	} else {
		fmt.Fprintf(&b, "  1. As <%s_AUTH>, confirm ownership:          curl -i -sk %s\n", strings.ToUpper(ownerLabel), url)
		fmt.Fprintf(&b, "  2. Unauthenticated control (must be denied): curl -i -sk %s\n", url)
		fmt.Fprintf(&b, "  3. As <%s_AUTH> (a DIFFERENT user), replay:  curl -i -sk -X %s %s\n", strings.ToUpper(attackerLabel), method, url)
		fmt.Fprintf(&b, "  4. Observe the attacker received the owner's object (object ref %q present).\n", objectRef)
	}
	b.WriteString("  (Add each identity's session header, e.g. -H 'Cookie: <session>' / -H 'Authorization: Bearer <token>'.)")
	return b.String()
}

func fetchAsMethod(ctx context.Context, method, rawURL, body, contentType string, id *Identity) IdentityResponse {
	var who Identity
	if id != nil {
		who = *id
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), rawURL, rdr)
	if err != nil {
		return IdentityResponse{Identity: who, Err: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if id != nil {
		if id.UserAgent != "" {
			req.Header.Set("User-Agent", id.UserAgent)
		}
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := identityHTTPClient.Do(req)
	if err != nil {
		return IdentityResponse{Identity: who, Err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return IdentityResponse{Identity: who, Status: resp.StatusCode, CT: resp.Header.Get("Content-Type"),
		Body: string(b), Len: len(b)}
}

type MethodDiffResult struct {
	Method        string
	Vulnerable    bool
	WriteVerified bool
	Confidence    int
	Evidence      string
}

func crossUserMethodDifferential(ctx context.Context, url string, owner, attacker Identity,
	methods []string, prof AuthzProfile, destructive bool, ownerRefs []AuthzRef, safeBody, contentType string) []MethodDiffResult {
	var results []MethodDiffResult
	for _, m := range methods {
		m = strings.ToUpper(m)
		switch m {
		case "GET", "HEAD", "OPTIONS":
			continue
		case "DELETE":
			if !prof.allowsDelete(destructive) {
				continue
			}
		case "PUT", "PATCH", "POST":
			if !prof.allowsWrite() {
				continue
			}
		default:
			continue
		}
		pre := fetchAs(ctx, url, &owner)
		if !looksLikeAuthObject(pre) {
			continue
		}
		body := safeBody
		if m == "DELETE" {
			body = ""
		}
		att := fetchAsMethod(ctx, m, url, body, contentType, &attacker)
		if deniesAccess(att) || att.Status >= 400 {
			continue
		}
		post := fetchAs(ctx, url, &owner)
		writeVerified := false
		switch m {
		case "DELETE":
			writeVerified = looksLikeAuthObject(pre) && (deniesAccess(post) || post.Status == 404)
		default:
			writeVerified = looksLikeAuthObject(post) && !bodiesSameObject(pre.Body, post.Body)
		}
		sig := authzSignals{unauthDenied: true, ownerHasObject: true, attackerGotObject: att.Status < 300,
			writeVerified: writeVerified, methodDifferential: true}
		conf := authzConfidence(sig)
		if conf < 60 && !writeVerified {
			continue
		}
		results = append(results, MethodDiffResult{
			Method: m, Vulnerable: true, WriteVerified: writeVerified, Confidence: conf,
			Evidence: fmt.Sprintf("cross-user %s on %s by %q succeeded (HTTP %d); owner-side post-condition %s.",
				m, url, attacker.Label, att.Status,
				map[bool]string{true: "CONFIRMS the unauthorized effect", false: "inconclusive"}[writeVerified]),
		})
	}
	return results
}

func sortedRefNames(refs []AuthzRef) []string {
	var n []string
	for _, r := range refs {
		n = append(n, r.Location+":"+r.Name+"="+r.Value)
	}
	sort.Strings(n)
	return n
}
