package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const introspectionResponse = `{"data":{"__schema":{
  "queryType":{"name":"Query"},
  "mutationType":{"name":"Mutation"},
  "types":[
    {"name":"Query","fields":[
      {"name":"user","args":[{"name":"id"}]},
      {"name":"__typename","args":[]}
    ]},
    {"name":"Mutation","fields":[
      {"name":"login","args":[{"name":"email"},{"name":"password"}]}
    ]},
    {"name":"User","fields":[{"name":"name","args":[]}]}
  ]
}}}`

func TestParseGraphQLOperations(t *testing.T) {
	ops := parseGraphQLOperations([]byte(introspectionResponse))
	got := map[string][]string{}
	for _, o := range ops {
		got[o.Name] = o.Args
	}
	if _, ok := got["user"]; !ok {
		t.Fatalf("root query operation 'user' missing: %v", got)
	}
	if _, ok := got["login"]; !ok {
		t.Fatalf("root mutation operation 'login' missing: %v", got)
	}
	if _, ok := got["name"]; ok {
		t.Fatal("non-root type field 'name' must NOT be treated as an operation")
	}
	if _, ok := got["__typename"]; ok {
		t.Fatal("introspection meta field '__typename' must be skipped")
	}
	if strings.Join(got["login"], ",") != "email,password" {
		t.Fatalf("mutation args not extracted: %v", got["login"])
	}
}

func TestHarvestGraphQLEndToEnd(t *testing.T) {
	withLoopbackAllowed(t)
	db, tid := testDB(t)
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(introspectionResponse))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &ParamScanner{db: db}
	n := s.harvestGraphQL(context.Background(), tid, []string{srv.URL}, func(_, _, _ string) {})
	if n < 2 {
		t.Fatalf("expected at least the user+login operations, got %d", n)
	}
	var params []string
	rows, _ := db.Query(`SELECT parameter FROM parameters WHERE target_id=?`, tid)
	defer rows.Close()
	for rows.Next() {
		var p string
		rows.Scan(&p)
		params = append(params, p)
	}
	joined := strings.Join(params, ",")
	if !strings.Contains(joined, "login.email") || !strings.Contains(joined, "user.id") {
		t.Fatalf("expected operation args stored as params, got %v", params)
	}
}
