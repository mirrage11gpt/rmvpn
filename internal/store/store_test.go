package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/model"
)

func TestNewBillingPeriodResetsUsage(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC().Truncate(time.Second)
	device := model.Device{ID: "device", CredentialHash: "hash", Plan: model.Plus, Active: true,
		SubscriptionEnds: now.Add(60 * 24 * time.Hour), PeriodEnds: now.Add(30 * 24 * time.Hour), QuotaBytes: 1000}
	if err := database.UpsertDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddUsage(context.Background(), device.ID, 100, 50, now); err != nil {
		t.Fatal(err)
	}
	device.PeriodEnds = now.Add(60 * 24 * time.Hour)
	if err := database.UpsertDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	updated, found, err := database.DeviceByID(context.Background(), device.ID)
	if err != nil || !found || updated.UsedBytes != 0 {
		t.Fatalf("usage was not reset: %#v %v", updated, err)
	}
}
