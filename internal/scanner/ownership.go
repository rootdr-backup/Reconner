package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Object Ownership 2.0 (Phase 6). An object has MANY relationships to identities,
// each with provenance — not a single "owner" column that conflates access with
// ownership. Ownership is derived from OBSERVED signals (a CREATE action, or an
// explicit ownership field in the response that names this identity), never from
// mere access — which is exactly what a BOLA lets an attacker do.

// Relationship roles.
const (
	RoleCreator  = "CREATOR"
	RoleOwner    = "OWNER"
	RoleAdmin    = "ADMIN"
	RoleEditor   = "EDITOR"
	RoleMember   = "MEMBER"
	RoleViewer   = "VIEWER"
	RoleAccessor = "ACCESSOR" // merely accessed it — the WEAKEST signal
)

// Relationship is one identity's relationship to an object.
type Relationship struct {
	ObjectType       string
	ObjectID         string
	EndpointTemplate string
	IdentityLabel    string
	Role             string
	Provenance       string
}

// reOwnerField finds explicit ownership fields in a response body.
var reOwnerField = regexp.MustCompile(`(?i)"(owner|owner_id|owned_by|created_by|creator|user|user_id|user_name|username|account|account_id|belongs_to)"\s*:\s*"?([A-Za-z0-9_.@\-]{1,64})"?`)

// ownerValuesFromBody returns the distinct ownership-field values in a body.
func ownerValuesFromBody(body string) []string {
	if len(body) > 200*1024 {
		body = body[:200*1024]
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range reOwnerField.FindAllStringSubmatch(body, 64) {
		v := strings.ToLower(strings.TrimSpace(m[2]))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// DeriveRelationships infers an identity's relationships to the action's object
// from strong signals only. respBody is the (already size-bounded) response.
func DeriveRelationships(a Action, respBody, identityLabel string) []Relationship {
	if a.ObjectID == "" {
		return nil
	}
	base := Relationship{ObjectType: a.ObjectType, ObjectID: a.ObjectID, EndpointTemplate: a.EndpointTemplate, IdentityLabel: identityLabel}
	var out []Relationship

	// CREATE by this identity (2xx) → creator + owner. Strongest signal.
	if a.Verb == VerbCreate && a.Status >= 200 && a.Status < 300 {
		c := base
		c.Role, c.Provenance = RoleCreator, "created via "+a.Method+" "+a.EndpointTemplate
		o := base
		o.Role, o.Provenance = RoleOwner, "creator of the resource"
		return []Relationship{c, o}
	}

	// Explicit ownership field in the response naming this identity → owner.
	idl := strings.ToLower(identityLabel)
	for _, v := range ownerValuesFromBody(respBody) {
		if v == idl || strings.Contains(idl, v) || strings.Contains(v, idl) {
			o := base
			o.Role, o.Provenance = RoleOwner, "response ownership field matches identity ("+v+")"
			out = append(out, o)
			break
		}
	}

	// Role/permission-changing actions imply an ADMIN/privileged relationship.
	if a.Verb == VerbChangeRole || a.Verb == VerbChangePerm {
		r := base
		r.Role, r.Provenance = RoleAdmin, "performed "+a.Verb
		out = append(out, r)
	}

	// Otherwise this identity merely accessed the object (weak signal).
	if len(out) == 0 {
		acc := base
		acc.Role, acc.Provenance = RoleAccessor, "accessed via "+a.Method
		out = append(out, acc)
	}
	return out
}

// StoreRelationship upserts a relationship (dedup by object+identity+role).
func StoreRelationship(ctx context.Context, db *database.DB, targetID string, r Relationship) {
	_, _ = db.ExecContext(ctx, `
		INSERT INTO object_relationships (id, target_id, object_type, object_id, endpoint_template, identity_label, role, provenance)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, object_type, object_id, identity_label, role) DO NOTHING`,
		uuid.New().String(), targetID, r.ObjectType, r.ObjectID, r.EndpointTemplate, r.IdentityLabel, r.Role, r.Provenance)
}

// OwnerOf returns the identity label with the strongest ownership claim on an
// object (CREATOR/OWNER preferred), or "" if only accessors are known. This is
// what BOLA testing uses to pick the baseline owner reliably.
func OwnerOf(ctx context.Context, db *database.DB, targetID, objType, objID string) string {
	var label string
	_ = db.QueryRowContext(ctx, `
		SELECT identity_label FROM object_relationships
		WHERE target_id=? AND object_type=? AND object_id=?
		ORDER BY CASE role WHEN 'CREATOR' THEN 0 WHEN 'OWNER' THEN 1 WHEN 'ADMIN' THEN 2
		         WHEN 'EDITOR' THEN 3 WHEN 'MEMBER' THEN 4 WHEN 'VIEWER' THEN 5 ELSE 9 END
		LIMIT 1`, targetID, objType, objID).Scan(&label)
	return label
}
