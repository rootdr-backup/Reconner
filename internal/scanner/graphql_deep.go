package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// runGraphQLDeep goes beyond the introspection on/off check. Once a live
// GraphQL endpoint is found it probes the class of GraphQL-specific bugs that
// actually pay out on bounty programs:
//
//   - introspection enabled (full schema leak) — already flagged elsewhere but
//     confirmed here with the endpoint recorded for the deeper tests.
//   - field-suggestion schema leak: even with introspection disabled, a typo'd
//     field makes the server reply "Did you mean X?" — leaking the schema.
//   - query batching: the server accepts a JSON array of queries in one request,
//     enabling auth/rate-limit bypass and brute-force amplification.
//   - alias-based amplification: many aliases of the same field in one query are
//     answered, enabling denial-of-wallet / brute force without batching.
//   - GET-based / CSRF-able queries: a state-changing endpoint reachable via GET.
//
// It reuses ExposureScanner's store/notify so findings land in the same table.
func (s *ExposureScanner) runGraphQLDeep(ctx context.Context, targetID string, logFn LogFunc) error {
	endpoints := s.discoverGraphQLEndpoints(ctx, targetID)
	if len(endpoints) == 0 {
		return nil
	}
	logFn("info", "exposure", fmt.Sprintf("Deep-analysing %d live GraphQL endpoint(s)...", len(endpoints)))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 1. Field-suggestion schema leak (works even without introspection).
			if body, ok := s.gqlPost(ctx, u, `{"query":"query{__typ3name}"}`); ok {
				lb := strings.ToLower(body)
				if strings.Contains(lb, "did you mean") {
					s.store(targetID, "graphql_field_suggestion", "low", u, "",
						"GraphQL field-suggestion enabled — schema inferable via error hints even if introspection is disabled")
					found.Add(1)
					s.notify(targetID, "graphql_field_suggestion", u)
				}
			}

			// 2. Query batching (array form) — one request, N operations.
			batch := `[{"query":"{__typename}"},{"query":"{__typename}"}]`
			if body, ok := s.gqlPost(ctx, u, batch); ok {
				// A batched response is a JSON array with two results.
				trimmed := strings.TrimSpace(body)
				if strings.HasPrefix(trimmed, "[") && strings.Count(trimmed, "__typename") >= 2 ||
					strings.Count(trimmed, `"data"`) >= 2 {
					s.store(targetID, "graphql_batching", "medium", u, "",
						"GraphQL query batching accepted — enables auth/rate-limit bypass and brute-force amplification (send N login/OTP attempts in one request)")
					found.Add(1)
					s.notify(targetID, "graphql_batching", u)
				}
			}

			// 3. Alias-based amplification — many aliases of one field per query.
			var sb strings.Builder
			sb.WriteString(`{"query":"{`)
			for i := 0; i < 100; i++ {
				sb.WriteString(fmt.Sprintf("a%d:__typename ", i))
			}
			sb.WriteString(`}"}`)
			if body, ok := s.gqlPost(ctx, u, sb.String()); ok {
				if strings.Count(body, "__typename") >= 50 || strings.Count(body, `"a99"`) > 0 {
					s.store(targetID, "graphql_alias_amplification", "medium", u, "",
						"GraphQL resolves 100+ field aliases in a single query with no cost limit — denial-of-wallet / brute-force amplification")
					found.Add(1)
					s.notify(targetID, "graphql_alias_amplification", u)
				}
			}

			// 4. GET-based query (CSRF-able / cache-poisonable).
			if s.gqlGetExecutes(ctx, u) {
				s.store(targetID, "graphql_get_query", "medium", u, "",
					"GraphQL executes queries over GET — CSRF-able and cache-poisonable; mutations may be triggerable cross-site")
				found.Add(1)
				s.notify(targetID, "graphql_get_query", u)
			}
		}(ep)
	}
	wg.Wait()
	logFn("info", "exposure", fmt.Sprintf("GraphQL deep analysis done. %d issue(s) found.", found.Load()))
	return nil
}

// discoverGraphQLEndpoints probes common GraphQL paths and returns those that
// respond like a real GraphQL server (valid __typename query yields data).
func (s *ExposureScanner) discoverGraphQLEndpoints(ctx context.Context, targetID string) []string {
	bases := s.loadServiceBases(ctx, targetID, 200)
	paths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql", "/graphiql", "/api/graphql/v1"}

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	var out []string

	for _, base := range bases {
		for _, p := range paths {
			u := strings.TrimRight(base, "/") + p
			mu.Lock()
			if seen[u] {
				mu.Unlock()
				continue
			}
			seen[u] = true
			mu.Unlock()
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-sem }()
				if body, ok := s.gqlPost(ctx, u, `{"query":"{__typename}"}`); ok {
					if strings.Contains(body, "__typename") || strings.Contains(body, `"data"`) {
						mu.Lock()
						out = append(out, u)
						mu.Unlock()
					}
				}
			}(u)
		}
	}
	wg.Wait()
	return out
}

func (s *ExposureScanner) gqlPost(ctx context.Context, u, payload string) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", u, strings.NewReader(payload))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := exposureHTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return "", false
	}
	return string(body), true
}

func (s *ExposureScanner) gqlGetExecutes(ctx context.Context, u string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(reqCtx, "GET", u+sep+"query=%7B__typename%7D", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := exposureHTTPClient.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "json") && strings.Contains(string(body), "__typename")
}
