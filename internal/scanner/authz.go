package scanner

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Authorization Observation model (Phase 1/2). Separates the RAW HTTP response
// (authoritative, kept in evidence) from the SEMANTIC verdict (an interpretation)
// and, crucially, keeps EXPECTED authorization separate from OBSERVED. A finding
// requires expected=DENIED and observed=AUTHORIZED/SIDE_EFFECT — never "different
// identity ⇒ expected denied".

// Observed verdicts (semantic interpretation of a response).
const (
	VerdictAuthorized      = "AUTHORIZED"      // object accessible / action succeeded for this identity
	VerdictDenied          = "DENIED"          // access denied (403/redirect-to-login/empty)
	VerdictUnauthenticated = "UNAUTHENTICATED" // 401 / login required
	VerdictForbidden       = "FORBIDDEN"       // explicit 403
	VerdictNotFound        = "NOT_FOUND"       // 404 / object-not-found body
	VerdictAmbiguous       = "AMBIGUOUS"       // can't tell
	VerdictSideEffect      = "SIDE_EFFECT_DETECTED"
	VerdictUnknown         = "UNKNOWN"
)

// Expected verdicts.
const (
	ExpectAuthorized = "AUTHORIZED"
	ExpectDenied     = "DENIED"
	ExpectUnknown    = "UNKNOWN"
)

// InterpretResponse maps a raw response to a SEMANTIC verdict for a specific
// target object. It does NOT collapse status→verdict: a 200 that is really an
// object-not-found or a login page is not AUTHORIZED. When targetObjectID is
// given, the body must plausibly contain that object to count as AUTHORIZED.
func InterpretResponse(r IdentityResponse, targetObjectID string) string {
	switch r.Status {
	case 401:
		return VerdictUnauthenticated
	case 403:
		return VerdictForbidden
	case 404:
		return VerdictNotFound
	}
	if r.Status >= 300 && r.Status < 400 {
		return VerdictDenied // redirect (typically to login)
	}
	// NOT_FOUND is more specific than DENIED — check it first so a 200 "not found"
	// body isn't collapsed into a generic denial.
	low := strings.ToLower(r.Body)
	if strings.Contains(low, "not found") || strings.Contains(low, "does not exist") || strings.Contains(low, "no such") {
		return VerdictNotFound
	}
	if deniesAccess(r) {
		return VerdictDenied
	}
	if !looksLikeAuthObject(r) {
		return VerdictAmbiguous
	}
	// If we know which object we asked for, require the body to reference it,
	// otherwise we might be looking at a generic page — that's ambiguous, not proof.
	if targetObjectID != "" && !strings.Contains(r.Body, targetObjectID) {
		return VerdictAmbiguous
	}
	return VerdictAuthorized
}

// ExpectedVerdict derives EXPECTED authorization from the identity's relationship
// to the object and the action semantics. Conservative: anything it can't justify
// returns UNKNOWN (→ no finding). role is "" when the identity has NO known
// relationship to the object.
func ExpectedVerdict(role, verb string) string {
	switch role {
	case RoleOwner, RoleCreator, RoleAdmin:
		return ExpectAuthorized
	case RoleEditor:
		if verb == VerbDelete {
			return ExpectUnknown // editors may or may not delete
		}
		return ExpectAuthorized
	case RoleMember:
		if verb == VerbRead {
			return ExpectAuthorized
		}
		return ExpectUnknown // member write/delete is app-specific
	case RoleViewer:
		if verb == VerbRead || verb == VerbDownload {
			return ExpectAuthorized
		}
		return ExpectDenied // viewer performing a write is expected to be denied
	case "", RoleAccessor:
		// No legitimate relationship. A cross-identity access to someone else's
		// object is expected to be DENIED — but ONLY the caller establishes that
		// the object belongs to a DIFFERENT identity (done in candidate gen).
		return ExpectDenied
	}
	return ExpectUnknown
}

// AuthorizationObservation is one recorded (identity × object × action) result.
type AuthorizationObservation struct {
	IdentityLabel    string
	ObjectType       string
	ObjectID         string
	ActionVerb       string
	EndpointTemplate string
	Expected         string
	Observed         string
	Confidence       int
	Source           string
}

// StoreObservation upserts an observation.
func StoreObservation(ctx context.Context, db *database.DB, targetID string, o AuthorizationObservation) {
	_, _ = db.ExecContext(ctx, `
		INSERT INTO authorization_observations
		 (id, target_id, identity_label, object_type, object_id, action_verb, endpoint_template, expected, observed, confidence, source)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, identity_label, object_type, object_id, action_verb) DO UPDATE SET
		 expected=excluded.expected, observed=excluded.observed, confidence=excluded.confidence, source=excluded.source`,
		uuid.New().String(), targetID, o.IdentityLabel, o.ObjectType, o.ObjectID, o.ActionVerb,
		o.EndpointTemplate, o.Expected, o.Observed, o.Confidence, o.Source)
}

// IsAuthzFlaw reports whether an (expected, observed) pair constitutes a
// confirmed authorization flaw. Strong signal only.
func IsAuthzFlaw(expected, observed string) bool {
	if expected != ExpectDenied {
		return false
	}
	return observed == VerdictAuthorized || observed == VerdictSideEffect
}
