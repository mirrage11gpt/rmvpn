package policy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

func TestPlanPoliciesAndThrottling(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		plan         model.Plan
		wantSpeed    int64
		wantThrottle int64
		wantPriority int
		wantP2P      bool
	}{
		{model.Trial, 30_000_000, 0, 1, false},
		{model.Lite, 50_000_000, 5_000_000, 1, false},
		{model.Plus, 200_000_000, 10_000_000, 2, true},
		{model.Ultra, 0, 20_000_000, 3, true},
	}
	for _, test := range tests {
		t.Run(string(test.plan), func(t *testing.T) {
			database := testStore(t)
			defer database.Close()
			service := New(database, compliance.New(database))
			service.now = func() time.Time { return now }
			planPolicy, _ := test.plan.Policy()
			credential := "credential-" + string(test.plan)
			device := model.Device{ID: "device-" + string(test.plan), CredentialHash: security.Hash(credential),
				Plan: test.plan, Active: true, SubscriptionEnds: now.Add(time.Hour), PeriodEnds: now.Add(30 * 24 * time.Hour),
				QuotaBytes: planPolicy.QuotaBytes, LeaseBytes: planPolicy.QuotaBytes, LeaseExpires: now.Add(time.Hour)}
			if err := database.UpsertDevice(context.Background(), device); err != nil {
				t.Fatal(err)
			}
			decision, err := service.Authenticate(context.Background(), credential)
			if err != nil || !decision.OK {
				t.Fatalf("auth failed: %#v, %v", decision, err)
			}
			if decision.Policy.UpBPS != test.wantSpeed || decision.Policy.Priority != test.wantPriority || decision.Policy.P2PAllowed != test.wantP2P {
				t.Fatalf("unexpected policy: %#v", decision.Policy)
			}
			if _, err := database.AddUsage(context.Background(), device.ID, planPolicy.QuotaBytes, 0, now); err != nil {
				t.Fatal(err)
			}
			decision, err = service.Authenticate(context.Background(), credential)
			if err != nil {
				t.Fatal(err)
			}
			if test.plan == model.Trial {
				if decision.OK || decision.Reason != "trial_quota_exhausted" {
					t.Fatalf("trial should be rejected: %#v", decision)
				}
			} else if !decision.OK || decision.Policy.UpBPS != test.wantThrottle || !decision.Policy.Throttled {
				t.Fatalf("paid plan should be throttled: %#v", decision)
			}
		})
	}
}

func TestExpiredAndRevokedDevicesAreRejected(t *testing.T) {
	database := testStore(t)
	defer database.Close()
	now := time.Now().UTC()
	service := New(database, compliance.New(database))
	service.now = func() time.Time { return now }
	device := model.Device{ID: "expired", CredentialHash: security.Hash("secret"), Plan: model.Lite,
		Active: true, SubscriptionEnds: now.Add(-time.Second), PeriodEnds: now.Add(time.Hour)}
	if err := database.UpsertDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	decision, _ := service.Authenticate(context.Background(), "secret")
	if decision.Reason != "subscription_expired" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestP2PAuthorization(t *testing.T) {
	database := testStore(t)
	defer database.Close()
	now := time.Now().UTC()
	service := New(database, compliance.New(database))
	device := model.Device{ID: "lite", CredentialHash: security.Hash("secret"), Plan: model.Lite,
		Active: true, SubscriptionEnds: now.Add(time.Hour), PeriodEnds: now.Add(time.Hour)}
	if err := database.UpsertDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	ok, reason, err := service.Authorize(context.Background(), "lite", "tracker.example:443", nil)
	if err != nil || ok || reason != "p2p_blocked" {
		t.Fatalf("unexpected authorization: %v %s %v", ok, reason, err)
	}
	ok, _, err = service.Authorize(context.Background(), "lite", "example.com:443", []byte("normal TLS"))
	if err != nil || !ok {
		t.Fatalf("normal traffic was rejected: %v", err)
	}
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	return database
}
