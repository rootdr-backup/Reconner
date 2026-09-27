package websocket

import (
	"testing"
	"time"
)

// TestBroadcastScopesToTargetOwner proves the cross-tenant leak this test
// guards against: before the owner-aware filtering in canReceive/Broadcast/
// Run, every authenticated client (any member, not just admins) received
// EVERY broadcast event regardless of which target it referenced — including
// new_vuln_finding events carrying a victim's URL/parameter/evidence. A
// non-owning member must not receive a message scoped to a target_id they
// don't own; the owning member and an admin must.
func TestBroadcastScopesToTargetOwner(t *testing.T) {
	h := NewHub()
	go h.Run()

	h.SetOwnerLookup(func(targetID string) (int64, bool) {
		switch targetID {
		case "t1":
			return 1, true
		case "t2":
			return 2, true
		default:
			return 0, false
		}
	})

	owner := &Client{hub: h, send: make(chan []byte, 4), userID: 1, isAdmin: false}
	other := &Client{hub: h, send: make(chan []byte, 4), userID: 2, isAdmin: false}
	admin := &Client{hub: h, send: make(chan []byte, 4), userID: 99, isAdmin: true}

	h.register <- owner
	h.register <- other
	h.register <- admin
	// Give Run() a moment to install all three registrations before broadcasting,
	// since register/broadcast are two independent channels with no ordering
	// guarantee between separate sends from this goroutine.
	time.Sleep(20 * time.Millisecond)

	h.Broadcast("new_vuln_finding", map[string]any{
		"target_id": "t1",
		"type":      "sqli",
		"url":       "https://victim.example/secret",
	})

	assertReceives(t, "owner", owner.send, true)
	assertReceives(t, "other-tenant member", other.send, false)
	assertReceives(t, "admin", admin.send, true)
}

// TestBroadcastWithoutTargetReachesEveryone confirms unscoped events (no
// target_id at all, e.g. a future system-wide notice) keep the original
// broadcast-to-everyone behavior — the fix only restricts target-scoped data.
func TestBroadcastWithoutTargetReachesEveryone(t *testing.T) {
	h := NewHub()
	go h.Run()

	member := &Client{hub: h, send: make(chan []byte, 4), userID: 1, isAdmin: false}
	h.register <- member
	time.Sleep(20 * time.Millisecond)

	h.Broadcast("system_notice", map[string]any{"message": "maintenance"})

	assertReceives(t, "member", member.send, true)
}

func assertReceives(t *testing.T, who string, ch chan []byte, want bool) {
	t.Helper()
	select {
	case <-ch:
		if !want {
			t.Errorf("%s: received a message scoped to a target it does not own", who)
		}
	case <-time.After(200 * time.Millisecond):
		if want {
			t.Errorf("%s: expected to receive the broadcast but got nothing", who)
		}
	}
}
