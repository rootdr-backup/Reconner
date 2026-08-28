package scanner

import (
	"context"

	"github.com/recon-platform/internal/database"
)

// Generic Test-Plan primitives (Phase 5) + Candidate generation (Phase 6). We do
// NOT write a separate scanner per authorization bug: one relationship-aware
// generator produces ranked (identity × object × action) candidates, each with a
// human-readable REASON, and one executor verifies them.

// Test-plan names.
const (
	PlanCrossIdentityRead   = "CrossIdentityRead"
	PlanCrossIdentityWrite  = "CrossIdentityWrite"
	PlanCrossIdentityDelete = "CrossIdentityDelete"
	PlanCrossIdentityShare  = "CrossIdentityShare"
	PlanCrossIdentityInvite = "CrossIdentityInvite"
	PlanPrivilegeBoundary   = "PrivilegeBoundary"
	PlanRoleBoundary        = "RoleBoundary"
	PlanTenantBoundary      = "TenantBoundary"
)

// verbToPlan maps an action verb to the cross-identity plan that tests it.
func verbToPlan(verb string) string {
	switch verb {
	case VerbRead, VerbDownload:
		return PlanCrossIdentityRead
	case VerbDelete:
		return PlanCrossIdentityDelete
	case VerbShare:
		return PlanCrossIdentityShare
	case VerbInvite:
		return PlanCrossIdentityInvite
	case VerbChangeRole, VerbChangePerm:
		return PlanPrivilegeBoundary
	default:
		return PlanCrossIdentityWrite
	}
}

// Candidate is a ranked authorization test to run: attacker (no relationship)
// against victim's object via action.
type Candidate struct {
	Plan             string
	AttackerLabel    string
	VictimLabel      string
	ObjectType       string
	ObjectID         string
	EndpointTemplate string
	URL              string
	Action           string
	Reason           string
	Score            int
	AutoVerify       bool // READ candidates are safe to auto-execute; writes are not
}

// GenerateCandidates inspects owned objects + relationships + observed actions and
// emits ranked cross-identity candidates. It is relationship-driven, NOT N×M×K:
// only objects with a STRONG owner (CREATOR/OWNER) and an attacker identity with
// NO relationship to that object become candidates.
func GenerateCandidates(ctx context.Context, db *database.DB, targetID string, identityLabels []string) []Candidate {
	// owned objects (strong ownership) + the endpoint/url to reach them
	rows, err := db.QueryContext(ctx, `
		SELECT r.object_type, r.object_id, r.identity_label, r.role, r.endpoint_template,
		       COALESCE((SELECT source_url FROM objects o WHERE o.target_id=r.target_id
		                 AND o.identifier=r.object_id AND o.endpoint_template=r.endpoint_template LIMIT 1),'')
		FROM object_relationships r
		WHERE r.target_id=? AND r.role IN ('CREATOR','OWNER','ADMIN')`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type owned struct{ objType, objID, owner, role, endpoint, url string }
	var owns []owned
	for rows.Next() {
		var o owned
		if rows.Scan(&o.objType, &o.objID, &o.owner, &o.role, &o.endpoint, &o.url) == nil {
			owns = append(owns, o)
		}
	}

	var out []Candidate
	for _, o := range owns {
		// which actions have been observed on this object's endpoint?
		verbs := observedVerbs(ctx, db, targetID, o.endpoint)
		if len(verbs) == 0 {
			verbs = []string{VerbRead}
		}
		for _, attacker := range identityLabels {
			if attacker == o.owner {
				continue
			}
			if hasStrongRelationship(ctx, db, targetID, o.objType, o.objID, attacker) {
				continue // attacker legitimately relates to the object → not a candidate
			}
			for _, verb := range verbs {
				plan := verbToPlan(verb)
				score := candidateScore(o.role, verb)
				out = append(out, Candidate{
					Plan: plan, AttackerLabel: attacker, VictimLabel: o.owner,
					ObjectType: o.objType, ObjectID: o.objID, EndpointTemplate: o.endpoint, URL: o.url,
					Action: verb, Score: score, AutoVerify: verb == VerbRead && o.url != "",
					Reason: attacker + " has NO relationship to " + o.objType + "#" + o.objID +
						" (owned by " + o.owner + " as " + o.role + "); " + verb + " should be DENIED.",
				})
			}
		}
	}
	rankCandidates(out)
	return out
}

// candidateScore ranks by impact: state-changing > read; stronger victim
// ownership (CREATOR/OWNER) > weaker.
func candidateScore(victimRole, verb string) int {
	s := 40
	if isStateChanging(verb) {
		s += 40
	}
	switch verb {
	case VerbDelete, VerbChangeRole, VerbChangePerm, VerbTransfer:
		s += 15
	}
	if victimRole == RoleCreator || victimRole == RoleOwner {
		s += 10
	}
	return s
}

func rankCandidates(c []Candidate) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j].Score > c[j-1].Score; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

func observedVerbs(ctx context.Context, db *database.DB, targetID, endpoint string) []string {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT verb FROM actions WHERE target_id=? AND endpoint_template=?`, targetID, endpoint)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var v []string
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			v = append(v, s)
		}
	}
	return v
}

func hasStrongRelationship(ctx context.Context, db *database.DB, targetID, objType, objID, label string) bool {
	var n int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM object_relationships
		WHERE target_id=? AND object_type=? AND object_id=? AND identity_label=?
		  AND role IN ('CREATOR','OWNER','ADMIN','EDITOR','MEMBER','VIEWER')`,
		targetID, objType, objID, label).Scan(&n)
	return n > 0
}
