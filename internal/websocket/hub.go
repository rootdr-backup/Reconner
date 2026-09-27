package websocket

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Message struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

type Client struct {
	hub     *Hub
	conn    *websocket.Conn
	send    chan []byte
	mu      sync.Mutex
	closed  bool
	userID  int64
	isAdmin bool
}

// envelope pairs an already-serialized message with the target it is scoped
// to, so Run() can filter delivery per-connection without re-parsing JSON per
// client. targetID is "" for messages that carry no target reference at all
// (delivered to everyone, matching the pre-existing behavior for genuinely
// global events); any non-empty targetID is delivered only to that target's
// owner or an admin.
type envelope struct {
	data     []byte
	targetID string
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan envelope
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex

	// ownerLookup resolves a target id to its owning user id, guarded by its own
	// mutex (never taken while h.mu is held, avoiding any reentrancy). Set once
	// at construction (SetOwnerLookup) by the API layer, which owns the database
	// handle; the websocket package itself has no DB access. A nil lookup (e.g.
	// in a unit test that never calls SetOwnerLookup) falls back to admin-only
	// delivery for any target-scoped message, which is the fail-closed default.
	ownerMu     sync.RWMutex
	ownerLookup func(targetID string) (int64, bool)
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan envelope, 512),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// SetOwnerLookup wires the target-ownership resolver used to scope broadcast
// delivery. Called once from api.NewHandler, which holds the database handle.
func (h *Hub) SetOwnerLookup(fn func(targetID string) (int64, bool)) {
	h.ownerMu.Lock()
	h.ownerLookup = fn
	h.ownerMu.Unlock()
}

// canReceive reports whether client c may see a message scoped to targetID.
// An empty targetID means the message carries no target reference at all
// (delivered to everyone, matching the pre-existing broadcast behavior); a
// non-empty targetID is delivered only to that target's owner or an admin —
// this is the per-connection isolation the REST API already enforces via
// targetScopeMiddleware but the websocket hub previously lacked entirely,
// letting any authenticated member observe every other user's live scan
// findings, evidence, and task activity.
func (h *Hub) canReceive(c *Client, targetID string) bool {
	if targetID == "" || c.isAdmin {
		return true
	}
	h.ownerMu.RLock()
	fn := h.ownerLookup
	h.ownerMu.RUnlock()
	if fn == nil {
		return false
	}
	owner, ok := fn(targetID)
	return ok && owner == c.userID
}

func (h *Hub) Run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.mu.Lock()
				if !client.closed {
					client.closed = true
					close(client.send)
				}
				client.mu.Unlock()
			}
			h.mu.Unlock()

		case env := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				if !h.canReceive(client, env.targetID) {
					continue
				}
				select {
				case client.send <- env.data:
				default:
					h.mu.RUnlock()
					h.mu.Lock()
					delete(h.clients, client)
					client.mu.Lock()
					if !client.closed {
						client.closed = true
						close(client.send)
					}
					client.mu.Unlock()
					h.mu.Unlock()
					h.mu.RLock()
				}
			}
			h.mu.RUnlock()

		case <-ticker.C:
			ping, _ := json.Marshal(Message{Type: "ping"})
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- ping:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}
}

// targetScopedPayload extracts the "target_id" field a broadcast payload may
// carry, regardless of whether the payload was a map[string]string,
// map[string]any, or a struct (e.g. models.Task) — all of them serialize a
// target reference under the same JSON key, so a single generic unmarshal
// covers every call site without per-type reflection.
type targetScopedPayload struct {
	Payload struct {
		TargetID string `json:"target_id"`
	} `json:"payload"`
}

func (h *Hub) Broadcast(msgType string, payload any) {
	msg := Message{Type: msgType, Payload: payload}
	data, err := json.Marshal(msg)
	if err != nil {
		slog.Error("Failed to marshal websocket message", "error", err)
		return
	}

	var scoped targetScopedPayload
	_ = json.Unmarshal(data, &scoped)

	select {
	case h.broadcast <- envelope{data: data, targetID: scoped.Payload.TargetID}:
	default:
		slog.Warn("WebSocket broadcast channel full, dropping message")
	}
}

// ServeWS upgrades the connection and registers a client scoped to the caller's
// identity. userID/isAdmin come from the already-authenticated session
// (requireAuth ran before this handler); an admin sees every event, a member
// sees only events scoped to targets they own (see canReceive).
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, userID int64, isAdmin bool) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade failed", "error", err)
		return
	}

	client := &Client{
		hub:     h,
		conn:    conn,
		send:    make(chan []byte, 256),
		userID:  userID,
		isAdmin: isAdmin,
	}

	h.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Debug("WebSocket unexpected close", "error", err)
			}
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Every browser message event must contain exactly one JSON document.
			// Joining queued JSON values with newlines into one WebSocket frame made
			// JSON.parse fail whenever events arrived in a burst, silently dropping
			// live task/monitor updates in the dashboard.
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
