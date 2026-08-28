package scanner

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// State snapshots (P2). Verify WRITE/DELETE/BFLA by an observable SIDE EFFECT
// instead of a status code: snapshot the object (via an OWNER read) before and
// after the tested action, then diff. HTTP 200 ≠ state changed; HTTP 403 ≠ no
// side effect — the snapshot is authoritative.

// StateSnapshot is an object's observable state at one moment.
type StateSnapshot struct {
	ObjectType    string
	ObjectID      string
	Phase         string // before | after
	ObserverLabel string
	Status        int
	Fingerprint   string
	Fields        map[string]string
}

// reStateField extracts salient, comparable fields (role/status/permission/state/
// name/owner/enabled…) whose change signals a real side effect.
var reStateField = regexp.MustCompile(`(?i)"(role|roles|status|state|permission|permissions|access|owner|owner_id|enabled|active|is_admin|admin|deleted|archived|member|members|title|name|amount|balance|price)"\s*:\s*"?([A-Za-z0-9_.@\- ]{0,64})"?`)

// SnapshotState reads the object as `observer` (normally the OWNER) and captures
// a stable fingerprint + salient field values. Redacted; no secrets stored.
func SnapshotState(ctx context.Context, url string, observer *Identity, objType, objID, phase string) StateSnapshot {
	r := Replay(ctx, ReplaySpec{Method: "GET", URL: url}, observer)
	label := "unauthenticated"
	if observer != nil {
		label = observer.Label
	}
	fields := map[string]string{}
	for _, m := range reStateField.FindAllStringSubmatch(r.Response.Body, 64) {
		fields[strings.ToLower(m[1])] = strings.TrimSpace(m[2])
	}
	return StateSnapshot{
		ObjectType: objType, ObjectID: objID, Phase: phase, ObserverLabel: label,
		Status: r.Response.Status, Fingerprint: BodyHash(r.Response.Body), Fields: fields,
	}
}

// SnapshotDiff describes what changed between two snapshots.
type SnapshotDiff struct {
	Changed   bool
	Existence string // "unchanged" | "deleted" | "created"
	Fields    map[string][2]string
	Summary   string
}

// DiffSnapshots compares before/after and reports whether an observable side
// effect occurred (the core of WRITE/DELETE verification).
func DiffSnapshots(before, after StateSnapshot) SnapshotDiff {
	d := SnapshotDiff{Fields: map[string][2]string{}, Existence: "unchanged"}

	beforeExists := before.Status >= 200 && before.Status < 300
	afterExists := after.Status >= 200 && after.Status < 300
	if beforeExists && !afterExists {
		d.Changed, d.Existence, d.Summary = true, "deleted", "object became inaccessible to its owner after the test (DELETE side effect)"
		return d
	}
	if !beforeExists && afterExists {
		d.Changed, d.Existence, d.Summary = true, "created", "object became accessible after the test (CREATE side effect)"
		return d
	}
	// Field-level changes (role escalation, status flip, ownership change…).
	var parts []string
	for k, av := range after.Fields {
		if bv, ok := before.Fields[k]; ok && bv != av {
			d.Fields[k] = [2]string{bv, av}
			parts = append(parts, k+": "+bv+"→"+av)
		}
	}
	if len(parts) > 0 {
		d.Changed = true
		d.Summary = "field change(s): " + strings.Join(parts, ", ")
		return d
	}
	// Fall back to a whole-object fingerprint change (nonce-stable).
	if before.Fingerprint != after.Fingerprint {
		d.Changed = true
		d.Summary = "object content changed after the test (fingerprint differs)"
	}
	return d
}

// StoreSnapshot persists a snapshot (redacted fields).
func StoreSnapshot(ctx context.Context, db *database.DB, targetID, source string, s StateSnapshot) {
	fj, _ := json.Marshal(s.Fields)
	_, _ = db.ExecContext(ctx, `
		INSERT INTO state_snapshots (id, target_id, object_type, object_id, phase, observer_label, status, fingerprint, fields_json, source)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, s.ObjectType, s.ObjectID, s.Phase, s.ObserverLabel, s.Status,
		s.Fingerprint, RedactText(string(fj)), source)
}
