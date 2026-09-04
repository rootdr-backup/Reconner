package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/recon-platform/internal/auth"
)

func TestNotificationsAreScopedToTargetOwner(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("notif-bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES
		('notif-admin-target','admin-notif.example',?),('notif-bob-target','bob-notif.example',?)`, adminID, bob.ID)
	_, _ = h.db.Exec(`INSERT INTO notifications(id,target_id,type,title,is_read) VALUES
		('admin-notif','notif-admin-target','finding','admin secret',0),
		('bob-notif','notif-bob-target','finding','bob notice',0),
		('global-notif',NULL,'system','shared notice',0)`)

	req := httptest.NewRequest("GET", "/api/notifications", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, bob.ID))
	rec := httptest.NewRecorder()
	h.handleListNotifications(rec, req)
	var response struct {
		Data struct {
			Notifications []notification `json:"notifications"`
			Unread        int            `json:"unread"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Unread != 2 || len(response.Data.Notifications) != 2 {
		t.Fatalf("member saw wrong notifications: unread=%d items=%+v", response.Data.Unread, response.Data.Notifications)
	}
	for _, n := range response.Data.Notifications {
		if n.ID == "admin-notif" {
			t.Fatal("member received another owner's notification")
		}
	}
}

func TestMemberCannotMarkAnotherOwnersNotificationRead(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, _ := h.auth.CreateUser("mark-bob", "bobpassword", auth.RoleMember)
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES
		('mark-admin-target','admin-mark.example',?),('mark-bob-target','bob-mark.example',?)`, adminID, bob.ID)
	_, _ = h.db.Exec(`INSERT INTO notifications(id,target_id,type,title,is_read) VALUES
		('mark-admin','mark-admin-target','finding','admin',0),('mark-bob','mark-bob-target','finding','bob',0)`)

	body, _ := json.Marshal(map[string]any{"ids": []string{"mark-admin", "mark-bob"}})
	req := httptest.NewRequest("POST", "/api/notifications/read", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, bob.ID))
	rec := httptest.NewRecorder()
	h.handleMarkNotificationsRead(rec, req)

	var adminRead, bobRead int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM notification_reads WHERE notification_id='mark-admin' AND user_id=?`, bob.ID).Scan(&adminRead)
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM notification_reads WHERE notification_id='mark-bob' AND user_id=?`, bob.ID).Scan(&bobRead)
	if adminRead != 0 || bobRead != 1 {
		t.Fatalf("ownership guard failed: admin=%d bob=%d", adminRead, bobRead)
	}
}

func TestNotificationReadStateIsPerUser(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, _ := h.auth.CreateUser("read-bob", "bobpassword", auth.RoleMember)
	_, _ = h.db.Exec(`INSERT INTO notifications(id,target_id,type,title,is_read) VALUES('shared-notif',NULL,'system','shared',0)`)

	body := bytes.NewBufferString(`{"ids":["shared-notif"]}`)
	req := httptest.NewRequest("POST", "/api/notifications/read", body)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, bob.ID))
	h.handleMarkNotificationsRead(httptest.NewRecorder(), req)

	unreadFor := func(uid int64) int {
		listReq := httptest.NewRequest("GET", "/api/notifications", nil)
		listReq = listReq.WithContext(context.WithValue(listReq.Context(), ctxUserIDKey, uid))
		rec := httptest.NewRecorder()
		h.handleListNotifications(rec, listReq)
		var response struct {
			Data struct {
				Unread int `json:"unread"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Data.Unread
	}
	if got := unreadFor(bob.ID); got != 0 {
		t.Fatalf("reader still has %d unread", got)
	}
	if got := unreadFor(adminID); got != 1 {
		t.Fatalf("one user's read state leaked to admin: unread=%d", got)
	}
}
