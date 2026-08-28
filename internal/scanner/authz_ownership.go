package scanner

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Ownership / Resource graph + automatic cross-user object pairing.

type OwnedObject struct {
	Template   string
	Location   string
	Name       string
	Value      string
	Kind       string
	Owner      string
	Evidence   string
	Confidence int
	Shared     bool
}

type ResourceGraph struct {
	Objects    []OwnedObject
	byTemplate map[string][]OwnedObject
}

var selfEndpointRe = regexp.MustCompile(`(?i)/(me|profile|account|whoami|current[-_]?user|self|users?/me|session)(/|$|\?)`)

func isSelfEndpoint(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return selfEndpointRe.MatchString(u.Path)
}

func BuildResourceGraph(graphs ...*IdentityGraph) *ResourceGraph {
	rg := &ResourceGraph{byTemplate: map[string][]OwnedObject{}}
	type acc struct {
		obj      OwnedObject
		accessBy map[string]bool
		selfBy   map[string]bool
	}
	index := map[string]*acc{}
	keyOf := func(tmpl, loc, name, val string) string { return tmpl + "|" + loc + "|" + name + "|" + val }
	for _, g := range graphs {
		if g == nil {
			continue
		}
		for _, n := range g.Nodes {
			if n.External || n.Status < 200 || n.Status >= 300 {
				continue
			}
			isObj := looksLikeAuthObject(IdentityResponse{Status: n.Status, CT: n.RespCT, Body: n.RespBody, Len: len(n.RespBody)})
			self := isSelfEndpoint(n.URL)
			for _, r := range n.ObjectRefs {
				if r.Location != "path" && r.Location != "query" {
					continue
				}
				if !isObj && !self {
					continue
				}
				k := keyOf(n.NormURL, r.Location, r.Name, r.Value)
				a := index[k]
				if a == nil {
					a = &acc{obj: OwnedObject{Template: n.NormURL, Location: r.Location, Name: r.Name, Value: r.Value, Kind: r.Kind},
						accessBy: map[string]bool{}, selfBy: map[string]bool{}}
					index[k] = a
				}
				a.accessBy[g.IdentityLabel] = true
			}
			if self || isObj {
				for _, r := range bodyOwnerRefs(n.RespCT, n.RespBody) {
					tmpl := detailTemplateFor(n.URL, r.Name, r.Value)
					k := keyOf(tmpl, r.Location, r.Name, r.Value)
					a := index[k]
					if a == nil {
						a = &acc{obj: OwnedObject{Template: tmpl, Location: r.Location, Name: r.Name, Value: r.Value, Kind: r.Kind},
							accessBy: map[string]bool{}, selfBy: map[string]bool{}}
						index[k] = a
					}
					if self || isOwnerFieldName(r.Name) {
						a.selfBy[g.IdentityLabel] = true
					}
				}
			}
		}
	}
	for _, a := range index {
		labels := sortedKeys(a.accessBy)
		selfLabels := sortedKeys(a.selfBy)
		o := a.obj
		switch {
		case len(selfLabels) == 1 && len(a.accessBy) <= 1:
			o.Owner = selfLabels[0]
			o.Confidence = 92
			o.Evidence = "surfaced in " + o.Owner + "'s self/owner context"
		case len(labels) == 1:
			o.Owner = labels[0]
			o.Confidence = 80
			o.Evidence = o.Owner + " retrieved this object (200) and the other identity did not — exclusive access"
		case len(labels) >= 2:
			o.Owner = labels[0]
			o.Shared = true
			o.Confidence = 30
			o.Evidence = "retrieved by multiple identities — likely public/shared"
		default:
			continue
		}
		rg.Objects = append(rg.Objects, o)
		rg.byTemplate[o.Template] = append(rg.byTemplate[o.Template], o)
	}
	sort.Slice(rg.Objects, func(i, j int) bool {
		if rg.Objects[i].Template != rg.Objects[j].Template {
			return rg.Objects[i].Template < rg.Objects[j].Template
		}
		return rg.Objects[i].Value < rg.Objects[j].Value
	})
	return rg
}

type AuthzCandidate struct {
	Template      string
	TargetURL     string
	Method        string
	ContentType   string
	Body          string
	OwnerLabel    string
	AttackerLabel string
	ObjectValue   string
	ObjectName    string
	ObjectKind    string
	Location      string
	Source        string
	OriginalNode  *RequestNode
	PeerObjects   []string
}

func GenerateCrossUserCandidates(rg *ResourceGraph, graphs []*IdentityGraph, identityLabels []string) []AuthzCandidate {
	nodeByOwnerObj := map[string]*RequestNode{}
	for _, g := range graphs {
		for _, n := range g.Nodes {
			if n.External {
				continue
			}
			for _, r := range n.ObjectRefs {
				if r.Location == "path" || r.Location == "query" {
					nodeByOwnerObj[g.IdentityLabel+"|"+n.NormURL+"|"+r.Value] = n
				}
			}
		}
	}
	var out []AuthzCandidate
	for tmpl, objs := range rg.byTemplate {
		var peers []string
		for _, o := range objs {
			if !o.Shared {
				peers = append(peers, o.Value)
			}
		}
		for _, o := range objs {
			if o.Shared || o.Owner == "" {
				continue
			}
			node := nodeByOwnerObj[o.Owner+"|"+tmpl+"|"+o.Value]
			targetURL, method, ct, body := o.instantiate(node)
			if targetURL == "" {
				continue
			}
			for _, attacker := range identityLabels {
				if attacker == o.Owner {
					continue
				}
				out = append(out, AuthzCandidate{
					Template: tmpl, TargetURL: targetURL, Method: method, ContentType: ct, Body: body,
					OwnerLabel: o.Owner, AttackerLabel: attacker,
					ObjectValue: o.Value, ObjectName: o.Name, ObjectKind: o.Kind, Location: o.Location,
					Source: sourceOf(node), OriginalNode: node, PeerObjects: peersExcept(peers, o.Value)})
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

func (o OwnedObject) instantiate(node *RequestNode) (targetURL, method, ct, body string) {
	if node != nil {
		return node.URL, node.Method, node.ContentType, node.Body
	}
	return "", "GET", "", ""
}

func sourceOf(n *RequestNode) string {
	if n == nil {
		return "resource-graph"
	}
	return n.Source
}

var ownerFieldRe = regexp.MustCompile(`(?i)^(owner_?id|created_?by|user_?id|account_?id|tenant_?id|organization_?id|org_?id|customer_?id|member_?id|id)$`)

func isOwnerFieldName(name string) bool { return ownerFieldRe.MatchString(strings.TrimSpace(name)) }

func bodyOwnerRefs(ct, body string) []AuthzRef {
	if !strings.Contains(strings.ToLower(ct), "json") {
		return nil
	}
	return extractObjectRefs("", "application/json", body, nil)
}

func detailTemplateFor(fromURL, name, value string) string {
	if strings.Contains(fromURL, "/"+value) {
		return NormalizeURL(fromURL)
	}
	base := ""
	if u, err := url.Parse(fromURL); err == nil {
		base = u.Scheme + "://" + u.Host
	}
	coll := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "_id")
	coll = strings.TrimSuffix(coll, "id")
	if coll == "" {
		coll = "object"
	}
	return base + "/" + coll + "s/{id}"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func peersExcept(peers []string, self string) []string {
	var out []string
	for _, p := range peers {
		if p != self {
			out = append(out, p)
		}
	}
	return out
}
