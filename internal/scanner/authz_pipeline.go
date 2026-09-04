package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Deep Two-Identity Authorization PIPELINE.

type AuthzPipelineInput struct {
	TargetDomain string
	Origins      []string
	Seeds        []string
	IdentityA    *Identity
	IdentityB    *Identity
	Profile      AuthzProfile
	Destructive  bool
	Log          func(stage, msg string)
}

type AuthzFinding struct {
	Type            string
	Severity        string
	URL             string
	Method          string
	OwnerLabel      string
	AttackerLabel   string
	VictimObject    string
	AttackerObject  string
	Confidence      int
	Status          string
	Evidence        string
	Repro           string
	DiscoverySource string
}

type AuthzStats struct {
	ACrawled, BCrawled   int
	AOnly, BOnly, Shared int
	JSDiscovered         int
	Objects, Ownerships  int
	PairsGenerated       int
	TestsExecuted        int
	Findings, Candidates int
	FPSuppressed         int
}

type AuthzPipelineResult struct {
	Findings  []AuthzFinding
	Stats     AuthzStats
	Logs      []string
	GraphA    *IdentityGraph
	GraphB    *IdentityGraph
	Resources *ResourceGraph
}

func RunAuthzPipeline(ctx context.Context, in AuthzPipelineInput) AuthzPipelineResult {
	res := AuthzPipelineResult{}
	var logMu sync.Mutex
	log := func(stage, msg string) {
		logMu.Lock()
		res.Logs = append(res.Logs, "["+stage+"] "+msg)
		logMu.Unlock()
		if in.Log != nil {
			in.Log(stage, msg)
		}
	}
	if in.IdentityA == nil || in.IdentityB == nil {
		log("abort", "two identities are required")
		return res
	}
	labelA, labelB := in.IdentityA.Label, in.IdentityB.Label
	for _, id := range []*Identity{in.IdentityA, in.IdentityB} {
		if id.ValidationURL == "" {
			log("validate", fmt.Sprintf("%s: no validation endpoint — proceeding (session assumed live)", id.Label))
			continue
		}
		st := ValidateSession(ctx, *id)
		log("validate", fmt.Sprintf("%s: session %s", id.Label, st))
		if st != "authenticated" {
			log("abort", fmt.Sprintf("%s session is %s — cannot build a trustworthy graph", id.Label, st))
			return res
		}
	}
	seeds := dedupeSeeds(append(append([]string{}, in.Seeds...), in.Origins...))
	pol := crawlDepthPolicy(in.Profile)
	log("crawl", fmt.Sprintf("policy: maxDepth=%d maxRequests=%d maxPerHost=%d pages/list=%d", pol.MaxDepth, pol.MaxRequests, pol.MaxPerHost, pol.MaxPagesPerList))

	graphA := NewAuthenticatedCrawler(in.IdentityA, in.TargetDomain, in.Origins, pol, log).Crawl(ctx, seeds)
	log("crawl", fmt.Sprintf("Identity A crawl (%s): %d requests captured%s", labelA, len(graphA.Nodes), partialNote(graphA)))
	graphB := NewAuthenticatedCrawler(in.IdentityB, in.TargetDomain, in.Origins, pol, log).Crawl(ctx, seeds)
	log("crawl", fmt.Sprintf("Identity B crawl (%s): %d requests captured%s", labelB, len(graphB.Nodes), partialNote(graphB)))

	res.GraphA, res.GraphB = graphA, graphB
	res.Stats.ACrawled, res.Stats.BCrawled = countFetched(graphA), countFetched(graphB)
	res.Stats.JSDiscovered = countSource(graphA, "javascript") + countSource(graphB, "javascript")

	aOnly, bOnly, shared := surfaceDifferential(graphA, graphB)
	res.Stats.AOnly, res.Stats.BOnly, res.Stats.Shared = len(aOnly), len(bOnly), len(shared)
	log("merge", fmt.Sprintf("surfaces: %d shared, %d A-only, %d B-only", len(shared), len(aOnly), len(bOnly)))
	for _, e := range aOnly {
		log("merge", "A-only surface: "+e)
	}
	for _, e := range bOnly {
		log("merge", "B-only surface: "+e)
	}
	log("objects", fmt.Sprintf("object references extracted: %d under A, %d under B", countObjectRefs(graphA), countObjectRefs(graphB)))

	rg := BuildResourceGraph(graphA, graphB)
	res.Resources = rg
	owned := 0
	for _, o := range rg.Objects {
		if !o.Shared {
			owned++
		}
	}
	res.Stats.Objects = len(rg.Objects)
	res.Stats.Ownerships = owned
	log("ownership", fmt.Sprintf("resource graph: %d objects, %d with an inferred owner", len(rg.Objects), owned))
	for _, o := range rg.Objects {
		if o.Shared {
			log("ownership", fmt.Sprintf("SHARED/public %s=%s at %s (%s)", o.Name, o.Value, o.Template, o.Evidence))
			continue
		}
		log("ownership", fmt.Sprintf("%s owns %s=%s at %s [conf %d] (%s)", o.Owner, o.Name, o.Value, o.Template, o.Confidence, o.Evidence))
	}

	cands := GenerateCrossUserCandidates(rg, []*IdentityGraph{graphA, graphB}, []string{labelA, labelB})
	bodyCands := generateBodyCandidates(rg, []*IdentityGraph{graphA, graphB}, []string{labelA, labelB})
	cands = append(cands, bodyCands...)
	res.Stats.PairsGenerated = len(cands)
	log("pairing", fmt.Sprintf("generated %d cross-user test candidate(s) (A→B and B→A; %d via write-body)", len(cands), len(bodyCands)))
	for _, c := range cands {
		log("pairing", fmt.Sprintf("%s → %s's object %s=%s (%s %s) [from %s]", c.AttackerLabel, c.OwnerLabel, c.ObjectName, c.ObjectValue, c.Method, c.TargetURL, c.Source))
	}

	idByLabel := map[string]*Identity{labelA: in.IdentityA, labelB: in.IdentityB}
	seenFinding := map[string]bool{}
	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		owner := idByLabel[c.OwnerLabel]
		attacker := idByLabel[c.AttackerLabel]
		if owner == nil || attacker == nil {
			continue
		}
		res.Stats.TestsExecuted++
		var fs []AuthzFinding
		var fp bool
		if c.Location == "json" && c.Method != "GET" {
			fs = testBodyCandidate(ctx, c, *owner, *attacker, in.Profile, log)
		} else {
			fs, fp = testAuthzCandidate(ctx, c, *owner, *attacker, in.Profile, in.Destructive, log)
		}
		if fp {
			res.Stats.FPSuppressed++
		}
		for _, f := range fs {
			key := f.Type + "|" + f.Method + "|" + f.URL + "|" + f.AttackerLabel
			if seenFinding[key] {
				continue
			}
			seenFinding[key] = true
			res.Findings = append(res.Findings, f)
		}
	}
	for _, f := range res.Findings {
		if f.Status == StatusFinding {
			res.Stats.Findings++
		} else if f.Status == StatusCandidate {
			res.Stats.Candidates++
		}
	}
	sort.Slice(res.Findings, func(i, j int) bool { return res.Findings[i].Confidence > res.Findings[j].Confidence })
	log("verify", fmt.Sprintf("done: %d finding(s), %d candidate(s), %d false-positive(s) suppressed, %d test(s) executed",
		res.Stats.Findings, res.Stats.Candidates, res.Stats.FPSuppressed, res.Stats.TestsExecuted))
	return res
}

func testAuthzCandidate(ctx context.Context, c AuthzCandidate, owner, attacker Identity,
	prof AuthzProfile, destructive bool, log func(stage, msg string)) ([]AuthzFinding, bool) {
	url := c.TargetURL
	ownerResp := fetchAs(ctx, url, &owner)
	if !looksLikeAuthObject(ownerResp) {
		return nil, false
	}
	unauth := fetchAs(ctx, url, nil)
	if !deniesAccess(unauth) {
		return nil, false
	}
	if publicResourceLikely(ownerResp, unauth) {
		log("verify", fmt.Sprintf("FP suppressed: %s is public", url))
		return nil, true
	}
	ownerRefs := extractObjectRefs(url, ownerResp.CT, ownerResp.Body, nil)
	var findings []AuthzFinding

	att := fetchAs(ctx, url, &attacker)
	if looksLikeAuthObject(att) {
		leaked, leakOK := attackerLeakedOwnerRef(ownerRefs, att.Body)
		same := bodiesSameObject(ownerResp.Body, att.Body)
		if same || leakOK {
			sig := authzSignals{unauthDenied: true, ownerHasObject: true, attackerGotObject: att.Status < 300, bodiesMatch: same, leakedOwnerUnique: leakOK}
			conf := authzConfidence(sig)
			status := StatusCandidate
			if conf >= ConfEvidence {
				status = StatusFinding
			}
			ev := fmt.Sprintf("Cross-user READ: owner %q holds the object at %s; unauthenticated is denied; attacker %q received %s.",
				owner.Label, url, attacker.Label, pick(same, "the OWNER'S object (bodies match)", "an object leaking the owner's unique id "+leaked))
			findings = append(findings, AuthzFinding{
				Type: "idor", Severity: sevFor(conf), URL: url, Method: "GET",
				OwnerLabel: owner.Label, AttackerLabel: attacker.Label, VictimObject: c.ObjectValue,
				Confidence: conf, Status: status, Evidence: ev,
				Repro: authzReproSteps("GET", url, owner.Label, attacker.Label, c.ObjectValue, false), DiscoverySource: c.Source})
			log("verify", fmt.Sprintf("%s cross-user READ %s → %s [conf %d]", strings.ToUpper(status), url, attacker.Label, conf))
		}
	}

	safeBody, ct := "", ""
	if strings.Contains(strings.ToLower(ownerResp.CT), "json") && len(ownerResp.Body) > 0 && len(ownerResp.Body) < 64*1024 {
		safeBody, ct = ownerResp.Body, "application/json"
	}
	for _, r := range crossUserMethodDifferential(ctx, url, owner, attacker,
		[]string{"PUT", "PATCH", "POST", "DELETE"}, prof, destructive, ownerRefs, safeBody, ct) {
		if !r.Vulnerable {
			continue
		}
		status := StatusCandidate
		if r.Confidence >= ConfEvidence {
			status = StatusFinding
		}
		findings = append(findings, AuthzFinding{
			Type: "bfla", Severity: pick(r.WriteVerified, "critical", "high"), URL: url, Method: r.Method,
			OwnerLabel: owner.Label, AttackerLabel: attacker.Label, VictimObject: c.ObjectValue,
			Confidence: r.Confidence, Status: status,
			Evidence: fmt.Sprintf("Cross-user %s by %q on %q's object at %s. %s", r.Method, attacker.Label, owner.Label, url, r.Evidence),
			Repro:    authzReproSteps(r.Method, url, owner.Label, attacker.Label, c.ObjectValue, true), DiscoverySource: c.Source})
		log("verify", fmt.Sprintf("%s cross-user %s %s → %s [conf %d]", strings.ToUpper(status), r.Method, url, attacker.Label, r.Confidence))
	}

	if len(findings) == 0 {
		findings = append(findings, mutationEscalation(ctx, c, owner, attacker, ownerResp, prof, log)...)
	}
	if prof >= AuthzDeep && len(findings) == 0 {
		if f, ok := protocolDifferential(ctx, url, owner, attacker); ok {
			findings = append(findings, f)
			log("verify", "CANDIDATE protocol-differential "+url)
		}
	}
	if prof >= AuthzDeep && len(findings) == 0 {
		if f, _, ok := authorizationRace(ctx, "GET", url, "", "", owner, attacker, ownerRefs, ownerResp.Body, 6, log); ok {
			findings = append(findings, f)
		}
	}
	return findings, false
}

func testBodyCandidate(ctx context.Context, c AuthzCandidate, owner, attacker Identity, prof AuthzProfile, log func(stage, msg string)) []AuthzFinding {
	return bodyTypeConfusionFindings(ctx, c.Method, c.TargetURL, c.Body, owner, attacker, prof, log)
}

func surfaceDifferential(a, b *IdentityGraph) (aOnly, bOnly, shared []string) {
	as, bs := surfaceSet(a), surfaceSet(b)
	for s := range as {
		if bs[s] {
			shared = append(shared, s)
		} else {
			aOnly = append(aOnly, s)
		}
	}
	for s := range bs {
		if !as[s] {
			bOnly = append(bOnly, s)
		}
	}
	sort.Strings(aOnly)
	sort.Strings(bOnly)
	sort.Strings(shared)
	return
}

func surfaceSet(g *IdentityGraph) map[string]bool {
	out := map[string]bool{}
	if g == nil {
		return out
	}
	for _, n := range g.Nodes {
		if n.External {
			continue
		}
		out[n.Method+" "+n.NormURL] = true
	}
	return out
}

func countFetched(g *IdentityGraph) int {
	n := 0
	for _, x := range g.Nodes {
		if !x.External && x.Status > 0 {
			n++
		}
	}
	return n
}
func countSource(g *IdentityGraph, src string) int {
	n := 0
	for _, x := range g.Nodes {
		if x.Source == src {
			n++
		}
	}
	return n
}
func countObjectRefs(g *IdentityGraph) int {
	n := 0
	for _, x := range g.Nodes {
		n += len(x.ObjectRefs)
	}
	return n
}
func partialNote(g *IdentityGraph) string {
	if g.Partial {
		return " (PARTIAL: " + g.StopReason + ")"
	}
	return ""
}
func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
func sevFor(conf int) string {
	if conf >= 96 {
		return "critical"
	}
	if conf >= ConfEvidence {
		return "high"
	}
	return "medium"
}
func dedupeSeeds(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func substituteObjectValue(rawURL, location, name, oldVal, newVal string) string {
	switch location {
	case "path":
		return strings.Replace(rawURL, "/"+oldVal, "/"+newVal, 1)
	case "query":
		return injectParam(rawURL, name, newVal)
	}
	return ""
}

func protocolDifferential(ctx context.Context, url string, owner, attacker Identity) (AuthzFinding, bool) {
	h1 := fetchAsForceHTTP1(ctx, url, &attacker)
	def := fetchAs(ctx, url, &attacker)
	ownerResp := fetchAs(ctx, url, &owner)
	grantH1 := looksLikeAuthObject(h1) && bodiesSameObject(ownerResp.Body, h1.Body)
	grantDef := looksLikeAuthObject(def) && bodiesSameObject(ownerResp.Body, def.Body)
	if grantH1 == grantDef {
		return AuthzFinding{}, false
	}
	h1b := fetchAsForceHTTP1(ctx, url, &attacker)
	if (looksLikeAuthObject(h1b) && bodiesSameObject(ownerResp.Body, h1b.Body)) != grantH1 {
		return AuthzFinding{}, false
	}
	proto := pick(grantH1, "HTTP/1.1", "HTTP/2")
	return AuthzFinding{
		Type: "idor", Severity: "high", URL: url, Method: "GET",
		OwnerLabel: owner.Label, AttackerLabel: attacker.Label, Confidence: 82, Status: StatusCandidate,
		Evidence:        fmt.Sprintf("Protocol differential: attacker %q is granted the owner's object over %s but denied over the other protocol (reproduced).", attacker.Label, proto),
		DiscoverySource: "protocol-differential"}, true
}

var identityHTTP1Client = func() *http.Client {
	t := guardedCredentialTransport.Clone()
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	return &http.Client{Transport: identityRoundTripper{base: t}, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

func fetchAsForceHTTP1(ctx context.Context, url string, id *Identity) IdentityResponse {
	var who Identity
	if id != nil {
		who = *id
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return IdentityResponse{Identity: who, Err: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	if id != nil {
		if id.UserAgent != "" {
			req.Header.Set("User-Agent", id.UserAgent)
		}
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := identityHTTP1Client.Do(req)
	if err != nil {
		return IdentityResponse{Identity: who, Err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return IdentityResponse{Identity: who, Status: resp.StatusCode, CT: resp.Header.Get("Content-Type"), Body: string(b), Len: len(b)}
}
