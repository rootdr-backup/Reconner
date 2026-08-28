package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GraphQL introspection harvesting.
//
// A GraphQL endpoint with introspection enabled hands you its entire schema —
// every query, mutation, and argument — in one request. That's both a finding in
// its own right (introspection should be off in production) and the richest
// possible source of testable inputs: each operation's arguments become insertion
// points for injection / IDOR / access-control testing.

var graphqlPaths = []string{
	"/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1",
	"/query", "/api/query", "/gql", "/api/gql", "/graphql/console",
}

// A minimal introspection query — enough to enumerate operations + their args
// without pulling the full (huge) type system.
const gqlIntrospectionBody = `{"query":"query{__schema{queryType{name} mutationType{name} types{name fields{name args{name}}}}}"}`

// harvestGraphQL probes each in-scope origin for a GraphQL endpoint with
// introspection enabled and stores each operation's arguments as JSON-body
// parameters. Returns the number of operations discovered.
func (s *ParamScanner) harvestGraphQL(ctx context.Context, targetID string, targetURLs []string, logFn LogFunc) int {
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: sharedHTTPTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	origins := map[string]bool{}
	for _, u := range targetURLs {
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			origins[p.Scheme+"://"+p.Host] = true
		}
	}

	ops, stored := 0, 0
	for origin := range origins {
		if ctx.Err() != nil {
			break
		}
		for _, gp := range graphqlPaths {
			endpoint := origin + gp
			body := s.introspect(ctx, client, endpoint)
			if body == nil {
				continue
			}
			operations := parseGraphQLOperations(body)
			if len(operations) == 0 {
				continue
			}
			logFn("warn", "param_discovery", fmt.Sprintf(
				"GraphQL introspection ENABLED at %s — %d operation(s) exposed (introspection should be disabled in production).",
				endpoint, len(operations)))
			for _, op := range operations {
				ops++
				// Store the operation name + each argument as testable JSON-body
				// params on the GraphQL endpoint.
				if s.storeFormParameter(targetID, endpoint, op.Name, "POST", "application/json") {
					stored++
				}
				for _, arg := range op.Args {
					if s.storeFormParameter(targetID, endpoint, op.Name+"."+arg, "POST", "application/json") {
						stored++
					}
				}
			}
			break // one live GraphQL endpoint per origin is enough
		}
	}
	if ops > 0 {
		logFn("info", "param_discovery", fmt.Sprintf("GraphQL harvest: %d operation(s) → %d parameter(s) stored.", ops, stored))
	}
	return ops
}

// introspect POSTs the introspection query and returns the body only if the
// response is a GraphQL introspection result (has data.__schema).
func (s *ParamScanner) introspect(ctx context.Context, client *http.Client, endpoint string) []byte {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", endpoint, strings.NewReader(gqlIntrospectionBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if !bytes.Contains(b, []byte("__schema")) {
		return nil
	}
	return b
}

type gqlOperation struct {
	Name string
	Args []string
}

// parseGraphQLOperations extracts the root query + mutation operations (and their
// argument names) from an introspection response.
func parseGraphQLOperations(body []byte) []gqlOperation {
	var doc struct {
		Data struct {
			Schema struct {
				QueryType    struct{ Name string } `json:"queryType"`
				MutationType struct{ Name string } `json:"mutationType"`
				Types        []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	roots := map[string]bool{}
	if n := doc.Data.Schema.QueryType.Name; n != "" {
		roots[n] = true
	}
	if n := doc.Data.Schema.MutationType.Name; n != "" {
		roots[n] = true
	}
	if len(roots) == 0 {
		return nil
	}
	var ops []gqlOperation
	for _, t := range doc.Data.Schema.Types {
		if !roots[t.Name] {
			continue
		}
		for _, f := range t.Fields {
			if f.Name == "" || strings.HasPrefix(f.Name, "__") {
				continue
			}
			op := gqlOperation{Name: f.Name}
			for _, a := range f.Args {
				if a.Name != "" {
					op.Args = append(op.Args, a.Name)
				}
			}
			ops = append(ops, op)
		}
	}
	return ops
}
