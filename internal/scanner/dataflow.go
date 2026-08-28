package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Variable & object dataflow (Phase 4). A value produced by one interaction
// (e.g. a created project's id) can be referenced by later actions via
// ${object.field}. Every variable carries provenance.

// Variable is an extracted, reusable value.
type Variable struct {
	Name       string // e.g. "project.id"
	Value      string
	ObjectType string
	SourceID   string // source identity label
	SourceURL  string
}

// reIDField pulls id-like fields out of a JSON response body.
var reIDField = regexp.MustCompile(`(?i)"(id|_id|uuid|guid|token|slug|number|reference|ref)"\s*:\s*"?([A-Za-z0-9_.\-]{1,80})"?`)

// reVarRef matches ${object.field} references.
var reVarRef = regexp.MustCompile(`\$\{([a-zA-Z0-9_.\-]+)\}`)

// ExtractVariables pulls reusable variables from a response body for an object
// type. `objectType` (e.g. "project") namespaces the variable: project.id, etc.
func ExtractVariables(respBody, objectType, sourceIdentity, sourceURL string) []Variable {
	if len(respBody) > 200*1024 {
		respBody = respBody[:200*1024]
	}
	prefix := objectType
	if prefix == "" {
		prefix = "object"
	}
	seen := map[string]bool{}
	var out []Variable
	for _, m := range reIDField.FindAllStringSubmatch(respBody, 64) {
		field := strings.ToLower(strings.TrimLeft(m[1], "_"))
		name := prefix + "." + field
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, Variable{Name: name, Value: m[2], ObjectType: objectType, SourceID: sourceIdentity, SourceURL: sourceURL})
	}
	return out
}

// ResolveRefs substitutes ${object.field} references in a template using the
// provided variables. Unknown references are left intact (so a caller can detect
// missing prerequisites) — this is NOT blind string substitution: only known,
// provenance-tracked variables are injected.
func ResolveRefs(template string, vars map[string]string) (resolved string, missing []string) {
	resolved = reVarRef.ReplaceAllStringFunc(template, func(ref string) string {
		key := reVarRef.FindStringSubmatch(ref)[1]
		if v, ok := vars[key]; ok {
			return v
		}
		missing = append(missing, key)
		return ref
	})
	return
}

// StoreVariable persists a variable with provenance.
func StoreVariable(ctx context.Context, db *database.DB, targetID, workflowID string, v Variable) {
	_, _ = db.ExecContext(ctx, `
		INSERT INTO workflow_variables (id, target_id, workflow_id, name, value, object_type, source_identity, source_url)
		VALUES (?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, workflowID, v.Name, v.Value, v.ObjectType, v.SourceID, v.SourceURL)
}
