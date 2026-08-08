package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

func TestControlMessagesUpdateDurableState(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	service := compliance.New(database)
	client := New(database, service, "test")
	now := time.Now().UTC().Truncate(time.Second)
	deviceData, _ := json.Marshal(map[string]any{
		"deviceId": "device-1", "credentialHash": security.Hash("secret"), "plan": "PLUS", "active": true,
		"subscriptionEnds": now.Add(30 * 24 * time.Hour), "periodEnds": now.Add(30 * 24 * time.Hour),
		"quotaBytes": int64(600_000_000_000), "leaseBytes": int64(1_000_000), "leaseExpires": now.Add(time.Hour),
	})
	if err := client.handle(ctx, envelope{Type: "device.upsert", Data: deviceData}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := database.DeviceByID(ctx, "device-1"); err != nil || !found {
		t.Fatalf("device not stored: %v", err)
	}
	if _, err := database.AddUsage(ctx, "device-1", 10, 20, now); err != nil {
		t.Fatal(err)
	}
	events, _ := database.PendingUsage(ctx, 10)
	ackData, _ := json.Marshal(map[string]any{"eventIds": []int64{events[0].ID}})
	if err := client.handle(ctx, envelope{Type: "usage.ack", Data: ackData}); err != nil {
		t.Fatal(err)
	}
	events, _ = database.PendingUsage(ctx, 10)
	if len(events) != 0 {
		t.Fatal("usage ack was not persisted")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SetState(ctx, "controller_public_key", security.Encode(publicKey)); err != nil {
		t.Fatal(err)
	}
	feed := compliance.SignedFeed{Version: "v1", UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
		Rules: json.RawMessage(`{"blockedDomains":["blocked.example"]}`)}
	if err := compliance.Sign(&feed, privateKey); err != nil {
		t.Fatal(err)
	}
	feedData, _ := json.Marshal(feed)
	if err := client.handle(ctx, envelope{Type: "compliance.feed", Data: feedData}); err != nil {
		t.Fatal(err)
	}
	blocked, err := service.Blocked(ctx, "blocked.example:443")
	if err != nil || !blocked {
		t.Fatalf("signed compliance feed not applied: %v", err)
	}
}
