package scanner

import (
	"context"

	"github.com/recon-platform/internal/database"
)

// Workflow graph (multi-step, analyst-oriented). Built from the already-persisted
// actions + object relationships, it answers: which identity created/owns an
// object, which identities touched it, and the ordered actions (state
// transitions) applied to it. Not a decorative graph — it drives authorization
// reasoning ("who has access without a relationship?").

// GraphNode / GraphEdge are the serialisable graph.
type GraphNode struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // identity | object
	Label string `json:"label"`
	Sub   string `json:"sub"` // role summary / object type
}
type GraphEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"` // role or action verb
	Kind  string `json:"kind"`  // ownership | action
}
type WorkflowGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// BuildWorkflowGraph assembles the graph for a target.
func BuildWorkflowGraph(ctx context.Context, db *database.DB, targetID string) WorkflowGraph {
	g := WorkflowGraph{Nodes: []GraphNode{}, Edges: []GraphEdge{}}
	haveNode := map[string]bool{}
	addNode := func(id, typ, label, sub string) {
		if id == "" || haveNode[id] {
			return
		}
		haveNode[id] = true
		g.Nodes = append(g.Nodes, GraphNode{ID: id, Type: typ, Label: label, Sub: sub})
	}

	// identities
	if rows, err := db.QueryContext(ctx, `SELECT DISTINCT label FROM identities WHERE target_id=?`, targetID); err == nil {
		for rows.Next() {
			var l string
			if rows.Scan(&l) == nil {
				addNode("id:"+l, "identity", l, "identity")
			}
		}
		rows.Close()
	}

	// ownership edges (identity → object, labeled role)
	if rows, err := db.QueryContext(ctx,
		`SELECT object_type, object_id, identity_label, role FROM object_relationships WHERE target_id=? LIMIT 3000`, targetID); err == nil {
		for rows.Next() {
			var ot, oid, lbl, role string
			if rows.Scan(&ot, &oid, &lbl, &role) != nil {
				continue
			}
			onode := "obj:" + ot + "#" + oid
			addNode(onode, "object", ot+"#"+oid, ot)
			if lbl != "" {
				addNode("id:"+lbl, "identity", lbl, "identity")
				g.Edges = append(g.Edges, GraphEdge{From: "id:" + lbl, To: onode, Label: role, Kind: "ownership"})
			}
		}
		rows.Close()
	}

	// action edges (identity → object, labeled verb), ordered — the transitions
	if rows, err := db.QueryContext(ctx,
		`SELECT identity_label, verb, object_type, object_id FROM actions
		 WHERE target_id=? AND object_id<>'' ORDER BY created_at ASC LIMIT 5000`, targetID); err == nil {
		for rows.Next() {
			var lbl, verb, ot, oid string
			if rows.Scan(&lbl, &verb, &ot, &oid) != nil {
				continue
			}
			onode := "obj:" + ot + "#" + oid
			addNode(onode, "object", ot+"#"+oid, ot)
			if lbl != "" {
				addNode("id:"+lbl, "identity", lbl, "identity")
				g.Edges = append(g.Edges, GraphEdge{From: "id:" + lbl, To: onode, Label: verb, Kind: "action"})
			}
		}
		rows.Close()
	}
	return g
}
