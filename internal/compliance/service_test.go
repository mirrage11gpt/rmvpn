package compliance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

func TestSignedFeedAndMatching(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	feed := SignedFeed{Version: "2026-08-08", UpdatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		Rules: json.RawMessage(`{"blockedDomains":["blocked.example"],"blockedCidrs":["203.0.113.0/24"],"blockedPorts":[25]}`)}
	payload, _ := signingPayload(feed)
	feed.Signature = security.Encode(ed25519.Sign(privateKey, payload))
	service := New(database)
	if err := service.Apply(context.Background(), feed, security.Encode(publicKey)); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"sub.blocked.example:443", "203.0.113.9:443", "mail.example:25"} {
		blocked, err := service.Blocked(context.Background(), address)
		if err != nil || !blocked {
			t.Fatalf("%s should be blocked: %v", address, err)
		}
	}
	blocked, err := service.Blocked(context.Background(), "allowed.example:443")
	if err != nil || blocked {
		t.Fatalf("allowed host was blocked: %v", err)
	}
	feed.Signature = security.Encode(make([]byte, ed25519.SignatureSize))
	if err := service.Apply(context.Background(), feed, security.Encode(publicKey)); err == nil {
		t.Fatal("invalid signature was accepted")
	}
	badFeed := SignedFeed{Version: "bad-cidr", UpdatedAt: now, ExpiresAt: now.Add(time.Hour), Rules: json.RawMessage(`{"blockedCidrs":["not-a-cidr"]}`)}
	if err := Sign(&badFeed, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(context.Background(), badFeed, security.Encode(publicKey)); err == nil {
		t.Fatal("invalid CIDR was accepted")
	}
}

func TestStaleFeedCreatesPersistentAlert(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := New(database)
	service.now = func() time.Time { return time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC) }
	if err := service.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	alerts, err := database.ActiveAlerts(context.Background())
	if err != nil || len(alerts) != 1 || alerts[0].Code != staleAlert {
		t.Fatalf("missing stale alert: %#v %v", alerts, err)
	}
}
