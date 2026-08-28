package scanner

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Object/Resource model (Phase 8). Extracts candidate object identifiers from
// authenticated traffic using CONTEXTUAL signals — not "every number is an ID".
// This is the foundation for reliable, ownership-aware BOLA testing.

// ObjectRef is one discovered resource identifier.
type ObjectRef struct {
	Type             string // uuid | numeric-id | opaque
	Identifier       string
	SourceURL        string
	EndpointTemplate string // normalized (/api/orders/{id})
	Param            string // "" for path ids, else the query/param name
	Owner            string // identity label that accessed it
}

var (
	reObjUUID   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reNumeric   = regexp.MustCompile(`^\d{1,19}$`)
	reIDSegment = regexp.MustCompile(`^\d+$|^[0-9a-fA-F-]{16,}$`)
	// param names that connote an object identifier
	idParamName = regexp.MustCompile(`(?i)(^|_)(id|uid|uuid|gid|pid|oid|order|account|user|invoice|doc|document|file|project|org|organization|customer|ticket|record|item)s?(_?id)?$`)
	// path segments that precede an id and connote a collection
	collectionWords = map[string]bool{
		"users": true, "user": true, "orders": true, "order": true, "accounts": true, "account": true,
		"invoices": true, "invoice": true, "documents": true, "document": true, "files": true, "file": true,
		"projects": true, "project": true, "orgs": true, "organizations": true, "organization": true,
		"customers": true, "customer": true, "tickets": true, "ticket": true, "records": true, "items": true,
		"invitations": true, "invitation": true, "invites": true, "invite": true, "teams": true, "team": true,
		"groups": true, "group": true, "workspaces": true, "workspace": true, "tenants": true, "tenant": true,
		"api": true, "v1": true, "v2": true, "profile": true,
	}
)

func classifyID(s string) string {
	switch {
	case reObjUUID.MatchString(s):
		return "uuid"
	case reNumeric.MatchString(s):
		return "numeric-id"
	default:
		return "opaque"
	}
}

// ExtractObjects finds object identifiers in a single URL accessed by `owner`.
// Path ids are accepted only when the PRECEDING segment looks like a collection
// (so /v2/2024 date-ish paths aren't treated as objects); query ids only when
// the parameter NAME connotes an identifier.
func ExtractObjects(rawURL, owner string) []ObjectRef {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var out []ObjectRef
	tmpl := NormalizeURL(rawURL)

	// path ids
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, s := range segs {
		if i == 0 {
			continue
		}
		if reIDSegment.MatchString(s) && collectionWords[strings.ToLower(segs[i-1])] {
			out = append(out, ObjectRef{
				Type: classifyID(s), Identifier: s, SourceURL: rawURL,
				EndpointTemplate: tmpl, Owner: owner,
			})
		}
	}
	// query ids
	for k, vals := range u.Query() {
		if !idParamName.MatchString(k) || len(vals) == 0 {
			continue
		}
		v := vals[0]
		if reIDSegment.MatchString(v) {
			out = append(out, ObjectRef{
				Type: classifyID(v), Identifier: v, SourceURL: rawURL,
				EndpointTemplate: tmpl, Param: k, Owner: owner,
			})
		}
	}
	return out
}

// StoreObject upserts a discovered object (dedup by endpoint+id+param).
func StoreObject(ctx context.Context, db *database.DB, targetID string, o ObjectRef) {
	_, _ = db.ExecContext(ctx, `
		INSERT INTO objects (id, target_id, obj_type, identifier, source_url, endpoint_template, param, owner_identity)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, endpoint_template, identifier, param) DO UPDATE SET
			owner_identity = CASE WHEN objects.owner_identity='' THEN excluded.owner_identity ELSE objects.owner_identity END`,
		uuid.New().String(), targetID, o.Type, o.Identifier, o.SourceURL, o.EndpointTemplate, o.Param, o.Owner)
}

// DiscoverObjectsFromTraffic scans the recorded interactions for a target and
// persists the objects each identity accessed (their ownership footprint).
func DiscoverObjectsFromTraffic(ctx context.Context, db *database.DB, targetID string) int {
	rows, err := db.QueryContext(ctx,
		`SELECT url, COALESCE(identity_label,'') FROM http_interactions WHERE target_id=?`, targetID)
	if err != nil {
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var u, owner string
		if rows.Scan(&u, &owner) != nil {
			continue
		}
		for _, o := range ExtractObjects(u, owner) {
			StoreObject(ctx, db, targetID, o)
			n++
		}
	}
	return n
}
