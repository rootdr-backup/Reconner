package scanner

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Action semantics (Phase 2). A meaningful application operation classified from
// an interaction — NOT inferred from HTTP method alone. The raw interaction stays
// authoritative; the verb is metadata with provenance.

// Action verbs.
const (
	VerbCreate     = "CREATE"
	VerbRead       = "READ"
	VerbUpdate     = "UPDATE"
	VerbDelete     = "DELETE"
	VerbShare      = "SHARE"
	VerbInvite     = "INVITE"
	VerbTransfer   = "TRANSFER"
	VerbApprove    = "APPROVE"
	VerbReject     = "REJECT"
	VerbChangeRole = "CHANGE_ROLE"
	VerbChangePerm = "CHANGE_PERMISSION"
	VerbUpload     = "UPLOAD"
	VerbDownload   = "DOWNLOAD"
)

// verbWords maps a trailing path/action segment to a semantic verb. These beat
// the method-based default because they describe the real operation.
var verbWords = map[string]string{
	"share": VerbShare, "invite": VerbInvite, "invitation": VerbInvite,
	"transfer": VerbTransfer, "approve": VerbApprove, "accept": VerbApprove,
	"reject": VerbReject, "deny": VerbReject, "cancel": VerbDelete,
	"role": VerbChangeRole, "roles": VerbChangeRole, "permission": VerbChangePerm,
	"permissions": VerbChangePerm, "upload": VerbUpload, "download": VerbDownload,
	"delete": VerbDelete, "remove": VerbDelete,
}

// Action is a classified operation.
type Action struct {
	Verb             string
	Method           string
	URL              string
	EndpointTemplate string
	ObjectType       string
	ObjectID         string
	Status           int
}

// ClassifyAction derives the semantic verb + object for an interaction. body is
// optional (used only to disambiguate). It uses method + endpoint semantics +
// trailing action words, and reuses object extraction for the object id.
func ClassifyAction(method, rawURL, body string, status int) Action {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	a := Action{Method: method, URL: rawURL, Status: status, EndpointTemplate: NormalizeURL(rawURL)}

	u, err := url.Parse(rawURL)
	if err == nil {
		segs := splitPath(u.Path)
		// object id = last id-looking segment whose predecessor is a collection
		for i := 1; i < len(segs); i++ {
			if reIDSegment.MatchString(segs[i]) && collectionWords[strings.ToLower(segs[i-1])] {
				a.ObjectID = segs[i]
				a.ObjectType = strings.ToLower(strings.TrimSuffix(segs[i-1], "s"))
			}
		}
		// trailing verb word (e.g. /projects/1/share, /invitations/2/accept)
		if len(segs) > 0 {
			if v, ok := verbWords[strings.ToLower(segs[len(segs)-1])]; ok {
				a.Verb = v
			}
		}
	}

	if a.Verb == "" {
		switch method {
		case "POST":
			if a.ObjectID == "" {
				a.Verb = VerbCreate // POST to a collection creates
			} else {
				a.Verb = VerbUpdate
			}
		case "PUT", "PATCH":
			a.Verb = VerbUpdate
		case "DELETE":
			a.Verb = VerbDelete
		default:
			a.Verb = VerbRead
		}
	}
	return a
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// isStateChanging reports whether a verb mutates server state (drives which
// operations deserve cross-identity / BFLA testing first).
func isStateChanging(verb string) bool {
	switch verb {
	case VerbRead, VerbDownload:
		return false
	default:
		return true
	}
}

// StoreAction persists a classified action with provenance.
func StoreAction(ctx context.Context, db *database.DB, targetID, identityID, identityLabel, source string, a Action) {
	_, _ = db.ExecContext(ctx, `
		INSERT INTO actions (id, target_id, identity_id, identity_label, verb, method, url, endpoint_template, object_type, object_id, status, source)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, identityID, identityLabel, a.Verb, a.Method, a.URL, a.EndpointTemplate, a.ObjectType, a.ObjectID, a.Status, source)
}
