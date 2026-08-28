package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Authorization hardening: mutation-escalation ladder, authorization-aware
// controlled race, and extra discovery (OpenAPI/Swagger, GraphQL detection,
// POST-body object refs). Each mutation requires SEMANTIC authorization impact.

type grantResult struct {
	resp    IdentityResponse
	granted bool
	leak    bool
}

func attackerGrantedOwnerObject(ctx context.Context, method, url, body, ct string,
	attacker Identity, ownerBody string, ownerRefs []AuthzRef) grantResult {
	att := fetchAsMethod(ctx, method, url, body, ct, &attacker)
	if att.Err != nil || deniesAccess(att) || !looksLikeAuthObject(att) {
		return grantResult{resp: att}
	}
	same := bodiesSameObject(ownerBody, att.Body)
	_, leak := attackerLeakedOwnerRef(ownerRefs, att.Body)
	return grantResult{resp: att, granted: same || leak, leak: leak}
}

func mutationEscalation(ctx context.Context, c AuthzCandidate, owner, attacker Identity,
	ownerResp IdentityResponse, prof AuthzProfile, log func(stage, msg string)) []AuthzFinding {
	if prof < AuthzBalanced {
		return nil
	}
	ownerRefs := extractObjectRefs(c.TargetURL, ownerResp.CT, ownerResp.Body, nil)
	var out []AuthzFinding
	seen := map[string]bool{}
	emit := func(strategy, method, url, body, ct string, gr grantResult) {
		key := strategy + "|" + method + "|" + url
		if seen[key] || !gr.granted {
			return
		}
		seen[key] = true
		conf := 80
		if gr.leak {
			conf = 90
		}
		out = append(out, AuthzFinding{
			Type: "idor", Severity: sevFor(conf), URL: url, Method: method,
			OwnerLabel: owner.Label, AttackerLabel: attacker.Label, VictimObject: c.ObjectValue,
			Confidence: conf, Status: pick(conf >= ConfEvidence, StatusFinding, StatusCandidate),
			Evidence:        fmt.Sprintf("Mutation (%s): attacker %q was granted owner %q's object at %s (%s).", strategy, attacker.Label, owner.Label, url, pick(gr.leak, "leaked the owner's unique id", "bodies match")),
			Repro:           authzReproSteps(method, url, owner.Label, attacker.Label, c.ObjectValue, method != "GET"),
			DiscoverySource: "mutation:" + strategy})
		log("verify", fmt.Sprintf("CANDIDATE mutation:%s %s %s → %s [conf %d]", strategy, method, url, attacker.Label, conf))
	}
	switch c.Location {
	case "path":
		for _, peer := range c.PeerObjects {
			mu := substituteObjectValue(c.TargetURL, "path", c.ObjectName, c.ObjectValue, peer)
			if mu != "" && mu != c.TargetURL {
				emit("id-substitution", "GET", mu, "", "", attackerGrantedOwnerObject(ctx, "GET", mu, "", "", attacker, peerOwnerBody(ctx, mu, owner), peerRefs(ctx, mu, owner)))
			}
		}
		for _, nu := range pathNormalizationVariants(c.TargetURL) {
			emit("path-normalization", "GET", nu, "", "", attackerGrantedOwnerObject(ctx, "GET", nu, "", "", attacker, ownerResp.Body, ownerRefs))
		}
		for _, peer := range c.PeerObjects {
			cu := injectParam(c.TargetURL, orDefault(c.ObjectName, "id"), peer)
			if cu != c.TargetURL {
				emit("location-conflict", "GET", cu, "", "", attackerGrantedOwnerObject(ctx, "GET", cu, "", "", attacker, ownerResp.Body, ownerRefs))
			}
		}
	case "query":
		for _, peer := range c.PeerObjects {
			for _, du := range duplicateParamVariants(c.TargetURL, c.ObjectName, c.ObjectValue, peer) {
				emit("duplicate-parameter", "GET", du, "", "", attackerGrantedOwnerObject(ctx, "GET", du, "", "", attacker, ownerResp.Body, ownerRefs))
			}
		}
		for _, peer := range c.PeerObjects {
			mu := substituteObjectValue(c.TargetURL, "query", c.ObjectName, c.ObjectValue, peer)
			if mu != "" && mu != c.TargetURL {
				emit("id-substitution", "GET", mu, "", "", attackerGrantedOwnerObject(ctx, "GET", mu, "", "", attacker, peerOwnerBody(ctx, mu, owner), peerRefs(ctx, mu, owner)))
			}
		}
	}
	return out
}

func peerOwnerBody(ctx context.Context, url string, owner Identity) string {
	r := fetchAs(ctx, url, &owner)
	if looksLikeAuthObject(r) {
		return r.Body
	}
	return ""
}
func peerRefs(ctx context.Context, url string, owner Identity) []AuthzRef {
	r := fetchAs(ctx, url, &owner)
	return extractObjectRefs(url, r.CT, r.Body, nil)
}

func bodyTypeConfusionFindings(ctx context.Context, method, url, jsonBody string,
	owner, attacker Identity, prof AuthzProfile, log func(stage, msg string)) []AuthzFinding {
	if prof < AuthzBalanced || !isJSONObjectBody(jsonBody) {
		return nil
	}
	ownerResp := fetchAsMethod(ctx, method, url, jsonBody, "application/json", &owner)
	if !looksLikeAuthObject(ownerResp) {
		return nil
	}
	ownerRefs := extractObjectRefs(url, "application/json", ownerResp.Body, nil)
	var out []AuthzFinding
	seen := map[string]bool{}
	for _, r := range extractObjectRefs(url, "application/json", jsonBody, nil) {
		if r.Location != "json" {
			continue
		}
		variants := []string{jsonBody}
		for _, tv := range typeConfusionVariants(r.Kind, r.Value) {
			variants = append(variants, replaceJSONScalar(jsonBody, r.Name, r.Value, tv))
		}
		for _, v := range variants {
			if seen[v] {
				continue
			}
			seen[v] = true
			gr := attackerGrantedOwnerObject(ctx, method, url, v, "application/json", attacker, ownerResp.Body, ownerRefs)
			if !gr.granted {
				continue
			}
			strategy := "body-replay"
			if v != jsonBody {
				strategy = "type-confusion"
			}
			conf := 82
			if gr.leak {
				conf = 90
			}
			out = append(out, AuthzFinding{
				Type: "idor", Severity: sevFor(conf), URL: url, Method: method,
				OwnerLabel: owner.Label, AttackerLabel: attacker.Label, VictimObject: r.Value,
				Confidence: conf, Status: pick(conf >= ConfEvidence, StatusFinding, StatusCandidate),
				Evidence:        fmt.Sprintf("Cross-user %s body (%s): attacker %q retrieved owner %q's data via %s", method, strategy, attacker.Label, owner.Label, url),
				Repro:           authzReproSteps(method, url, owner.Label, attacker.Label, r.Value, false),
				DiscoverySource: "mutation:" + strategy})
			log("verify", fmt.Sprintf("%s cross-user %s body %s → %s [conf %d]", strings.ToUpper(pick(conf >= ConfEvidence, "FINDING", "CANDIDATE")), method, url, attacker.Label, conf))
			break
		}
	}
	return out
}

type RaceOutcome struct {
	Attempts     int
	Successes    int
	Rounds       int
	RateLimited  bool
	Reproducible bool
}

func authorizationRace(ctx context.Context, method, url, body, ct string, owner, attacker Identity,
	ownerRefs []AuthzRef, ownerBody string, concurrency int, log func(stage, msg string)) (AuthzFinding, RaceOutcome, bool) {
	if concurrency < 4 {
		concurrency = 6
	}
	if concurrency > 8 {
		concurrency = 8
	}
	outcome := RaceOutcome{}
	roundGrants := 0
	const rounds = 2
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]grantResult, concurrency)
		var rl int32
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				att := fetchAsMethod(ctx, method, url, body, ct, &attacker)
				if att.Status == http.StatusTooManyRequests {
					rl = 1
				}
				same := looksLikeAuthObject(att) && bodiesSameObject(ownerBody, att.Body)
				_, leak := attackerLeakedOwnerRef(ownerRefs, att.Body)
				results[idx] = grantResult{resp: att, granted: same || leak, leak: leak}
			}(i)
		}
		close(start)
		wg.Wait()
		outcome.Rounds++
		outcome.Attempts += concurrency
		g := 0
		for _, r := range results {
			if r.granted {
				g++
			}
		}
		outcome.Successes += g
		if rl == 1 {
			outcome.RateLimited = true
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return AuthzFinding{}, outcome, false
			}
		}
		if g > 0 {
			roundGrants++
		}
	}
	outcome.Reproducible = roundGrants == rounds && outcome.Successes >= rounds
	if !outcome.Reproducible {
		return AuthzFinding{}, outcome, false
	}
	f := AuthzFinding{
		Type: "idor", Severity: "high", URL: url, Method: method,
		OwnerLabel: owner.Label, AttackerLabel: attacker.Label, Confidence: 85, Status: StatusCandidate,
		Evidence: fmt.Sprintf("Controlled authorization race: attacker %q obtained owner %q's object under %d-way concurrency, reproduced across %d rounds (%d/%d successes).",
			attacker.Label, owner.Label, concurrency, outcome.Rounds, outcome.Successes, outcome.Attempts),
		DiscoverySource: "authorization-race"}
	log("verify", fmt.Sprintf("CANDIDATE authorization-race %s %s (reproduced %d/%d)", method, url, outcome.Successes, outcome.Attempts))
	return f, outcome, true
}

type openAPIDoc struct {
	OpenAPI string                                `json:"openapi"`
	Swagger string                                `json:"swagger"`
	Paths   map[string]map[string]json.RawMessage `json:"paths"`
}

func looksLikeOpenAPI(body string) bool {
	t := strings.TrimSpace(body)
	if !strings.HasPrefix(t, "{") {
		return false
	}
	return strings.Contains(t, `"openapi"`) || strings.Contains(t, `"swagger"`) ||
		(strings.Contains(t, `"paths"`) && strings.Contains(t, `"/`))
}

func discoverOpenAPI(fromURL, body string, depth int) []crawlItem {
	var doc openAPIDoc
	if json.Unmarshal([]byte(body), &doc) != nil || len(doc.Paths) == 0 {
		return nil
	}
	base := originOf(fromURL)
	var out []crawlItem
	for p, methods := range doc.Paths {
		full := base + p
		hasTemplate := strings.Contains(p, "{")
		for origM, op := range methods {
			m := strings.ToUpper(origM)
			switch m {
			case "GET":
				if !hasTemplate {
					out = append(out, crawlItem{method: "GET", url: full, source: "openapi", parent: fromURL, depth: depth})
				}
			case "POST", "PUT", "PATCH", "DELETE":
				if !hasTemplate {
					out = append(out, crawlItem{method: m, url: full, source: "openapi", parent: fromURL,
						depth: depth, ct: "application/json", body: openAPIExampleBody(op)})
				}
			}
		}
	}
	return out
}

func openAPIExampleBody(op json.RawMessage) string {
	var o struct {
		RequestBody struct {
			Content map[string]struct {
				Example json.RawMessage `json:"example"`
			} `json:"content"`
		} `json:"requestBody"`
	}
	if json.Unmarshal(op, &o) != nil {
		return "{}"
	}
	for ctype, c := range o.RequestBody.Content {
		if strings.Contains(strings.ToLower(ctype), "json") && len(c.Example) > 0 {
			var v any
			if json.Unmarshal(c.Example, &v) == nil {
				if b, err := json.Marshal(v); err == nil {
					return string(b)
				}
			}
		}
	}
	return "{}"
}

func valueOwnerMap(rg *ResourceGraph) map[string]string {
	out := map[string]string{}
	if rg == nil {
		return out
	}
	for _, o := range rg.Objects {
		if !o.Shared && o.Owner != "" {
			if _, ok := out[o.Value]; !ok {
				out[o.Value] = o.Owner
			}
		}
	}
	return out
}

func generateBodyCandidates(rg *ResourceGraph, graphs []*IdentityGraph, identityLabels []string) []AuthzCandidate {
	owners := valueOwnerMap(rg)
	var out []AuthzCandidate
	seen := map[string]bool{}
	for _, g := range graphs {
		for _, n := range g.Nodes {
			if n.External || n.Body == "" || !isJSONObjectBody(n.Body) {
				continue
			}
			if n.Method != "POST" && n.Method != "PUT" && n.Method != "PATCH" {
				continue
			}
			for _, r := range extractObjectRefs(n.URL, "application/json", n.Body, nil) {
				if r.Location != "json" {
					continue
				}
				ownerLabel := owners[r.Value]
				if ownerLabel == "" {
					continue
				}
				for _, attacker := range identityLabels {
					if attacker == ownerLabel {
						continue
					}
					key := n.Method + "|" + n.NormURL + "|" + r.Value + "|" + attacker
					if seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, AuthzCandidate{
						Template: n.NormURL, TargetURL: n.URL, Method: n.Method,
						ContentType: "application/json", Body: n.Body,
						OwnerLabel: ownerLabel, AttackerLabel: attacker,
						ObjectValue: r.Value, ObjectName: r.Name, ObjectKind: r.Kind, Location: "json",
						Source: "openapi/body", OriginalNode: n})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetURL != out[j].TargetURL {
			return out[i].TargetURL < out[j].TargetURL
		}
		return out[i].AttackerLabel < out[j].AttackerLabel
	})
	return out
}

func looksLikeGraphQL(url, body string) bool {
	lu := strings.ToLower(url)
	if strings.HasSuffix(lu, "/graphql") || strings.HasSuffix(lu, "/gql") || strings.Contains(lu, "/graphql?") {
		return true
	}
	lb := strings.ToLower(body)
	return strings.Contains(lb, `"data"`) && strings.Contains(lb, `"__typename"`)
}

func isJSONObjectBody(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") && len(t) > 2
}

func replaceJSONScalar(jsonBody, name, oldVal, newRaw string) string {
	for _, oldTok := range []string{`"` + oldVal + `"`, oldVal} {
		needle := `"` + name + `":` + oldTok
		compact := strings.ReplaceAll(jsonBody, " ", "")
		if strings.Contains(compact, needle) {
			return strings.Replace(compact, needle, `"`+name+`":`+newRaw, 1)
		}
	}
	return jsonBody
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func originOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rawURL[:i+3+j]
		}
		return rawURL
	}
	return rawURL
}
