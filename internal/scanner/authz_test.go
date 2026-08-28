package scanner

import (
	"testing"
)

func TestInterpretResponse(t *testing.T) {
	obj := IdentityResponse{Status: 200, Len: 300, CT: "application/json", Body: `{"id":"77","owner":"user-a"}` + pad(300)}
	if InterpretResponse(obj, "77") != VerdictAuthorized {
		t.Error("200 with the object id must be AUTHORIZED")
	}
	if InterpretResponse(obj, "999") != VerdictAmbiguous {
		t.Error("200 without the requested object id must be AMBIGUOUS, not AUTHORIZED")
	}
	if InterpretResponse(IdentityResponse{Status: 403}, "77") != VerdictForbidden {
		t.Error("403 → FORBIDDEN")
	}
	if InterpretResponse(IdentityResponse{Status: 401}, "77") != VerdictUnauthenticated {
		t.Error("401 → UNAUTHENTICATED")
	}
	if InterpretResponse(IdentityResponse{Status: 404}, "77") != VerdictNotFound {
		t.Error("404 → NOT_FOUND")
	}
	if InterpretResponse(IdentityResponse{Status: 302}, "77") != VerdictDenied {
		t.Error("redirect → DENIED")
	}
	notFound := IdentityResponse{Status: 200, Len: 300, CT: "application/json", Body: "object not found" + pad(300)}
	if InterpretResponse(notFound, "77") != VerdictNotFound {
		t.Error("200 body 'not found' → NOT_FOUND, not AUTHORIZED")
	}
}

func TestExpectedVerdictRelationshipAware(t *testing.T) {
	if ExpectedVerdict(RoleOwner, VerbRead) != ExpectAuthorized {
		t.Error("owner read → authorized")
	}
	if ExpectedVerdict("", VerbRead) != ExpectDenied {
		t.Error("no relationship → denied")
	}
	if ExpectedVerdict(RoleViewer, VerbUpdate) != ExpectDenied {
		t.Error("viewer write → denied")
	}
	if ExpectedVerdict(RoleMember, VerbDelete) != ExpectUnknown {
		t.Error("member delete → unknown (app-specific), must NOT auto-flag")
	}
}

func TestIsAuthzFlaw(t *testing.T) {
	if !IsAuthzFlaw(ExpectDenied, VerdictAuthorized) {
		t.Error("expected denied + observed authorized = flaw")
	}
	if !IsAuthzFlaw(ExpectDenied, VerdictSideEffect) {
		t.Error("expected denied + side effect = flaw")
	}
	if IsAuthzFlaw(ExpectAuthorized, VerdictAuthorized) {
		t.Error("expected authorized is never a flaw")
	}
	if IsAuthzFlaw(ExpectUnknown, VerdictAuthorized) {
		t.Error("UNKNOWN expected must never produce a flaw (anti-FP)")
	}
	if IsAuthzFlaw(ExpectDenied, VerdictNotFound) {
		t.Error("denied+not-found is NOT a flaw")
	}
}

func pad(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
