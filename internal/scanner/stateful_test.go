package scanner

import "testing"

func TestClassifyAction(t *testing.T) {
	cases := []struct {
		method, url string
		status      int
		wantVerb    string
		wantObjID   string
	}{
		{"POST", "https://x.com/api/projects", 201, VerbCreate, ""},
		{"GET", "https://x.com/api/projects/42", 200, VerbRead, "42"},
		{"PATCH", "https://x.com/api/projects/42", 200, VerbUpdate, "42"},
		{"DELETE", "https://x.com/api/projects/42", 204, VerbDelete, "42"},
		{"POST", "https://x.com/api/projects/42/share", 200, VerbShare, "42"},
		{"POST", "https://x.com/api/invitations/7/accept", 200, VerbApprove, "7"},
		{"POST", "https://x.com/api/users/9/role", 200, VerbChangeRole, "9"},
	}
	for _, c := range cases {
		a := ClassifyAction(c.method, c.url, "", c.status)
		if a.Verb != c.wantVerb {
			t.Errorf("%s %s → verb %q want %q", c.method, c.url, a.Verb, c.wantVerb)
		}
		if a.ObjectID != c.wantObjID {
			t.Errorf("%s %s → objID %q want %q", c.method, c.url, a.ObjectID, c.wantObjID)
		}
	}
}

func TestDeriveOwnershipCreateVsAccess(t *testing.T) {
	// CREATE → creator + owner (strong)
	create := ClassifyAction("POST", "https://x.com/api/projects", `{"id":"77","owner":"user-a"}`, 201)
	create.ObjectID = "77" // creation response id (normally linked via variables)
	rels := DeriveRelationships(create, `{"id":"77","owner":"user-a"}`, "user-a")
	var gotCreator, gotOwner bool
	for _, r := range rels {
		if r.Role == RoleCreator {
			gotCreator = true
		}
		if r.Role == RoleOwner {
			gotOwner = true
		}
	}
	if !gotCreator || !gotOwner {
		t.Fatalf("CREATE must yield creator+owner: %+v", rels)
	}

	// Mere READ by a different user must NOT confer ownership (this is the BOLA
	// false-positive trap): attacker reading owner's object → ACCESSOR only.
	read := ClassifyAction("GET", "https://x.com/api/projects/77", "", 200)
	attackerRels := DeriveRelationships(read, `{"id":"77","owner":"user-a"}`, "user-b")
	for _, r := range attackerRels {
		if r.Role == RoleOwner || r.Role == RoleCreator {
			t.Fatalf("access must not confer ownership to user-b: %+v", r)
		}
	}
	// The legitimate owner reading their object → OWNER via ownership field.
	ownerRels := DeriveRelationships(read, `{"id":"77","owner":"user-a"}`, "user-a")
	foundOwner := false
	for _, r := range ownerRels {
		if r.Role == RoleOwner {
			foundOwner = true
		}
	}
	if !foundOwner {
		t.Fatalf("owner reading own object must be OWNER via response field: %+v", ownerRels)
	}
}

func TestDataflowExtractAndResolve(t *testing.T) {
	vars := ExtractVariables(`{"id":"123","slug":"acme","nested":{"x":1}}`, "project", "user-a", "https://x/api/projects")
	m := map[string]string{}
	for _, v := range vars {
		m[v.Name] = v.Value
	}
	if m["project.id"] != "123" {
		t.Fatalf("expected project.id=123, got %v", m)
	}
	resolved, missing := ResolveRefs("/api/projects/${project.id}/members?ref=${project.slug}", m)
	if resolved != "/api/projects/123/members?ref=acme" {
		t.Fatalf("bad resolve: %q", resolved)
	}
	if len(missing) != 0 {
		t.Fatalf("unexpected missing: %v", missing)
	}
	// Unknown refs are preserved AND reported (prerequisite detection).
	r2, miss2 := ResolveRefs("/x/${unknown.id}", m)
	if r2 != "/x/${unknown.id}" || len(miss2) != 1 {
		t.Fatalf("missing ref must be preserved+reported: %q %v", r2, miss2)
	}
}

func TestStateChanging(t *testing.T) {
	if isStateChanging(VerbRead) || isStateChanging(VerbDownload) {
		t.Error("read/download are not state-changing")
	}
	for _, v := range []string{VerbCreate, VerbUpdate, VerbDelete, VerbShare, VerbChangeRole} {
		if !isStateChanging(v) {
			t.Errorf("%s must be state-changing", v)
		}
	}
}
