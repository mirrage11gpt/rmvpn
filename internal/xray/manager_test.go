package xray

import (
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/model"
)

func TestAllowedPolicy(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	manager := &Manager{now: func() time.Time { return now }}
	base := model.Device{ID: "device", Active: true, Plan: model.Trial,
		SubscriptionEnds: now.Add(time.Hour), QuotaBytes: 20_000_000_000,
		LeaseBytes: 10_000, LeaseExpires: now.Add(time.Hour)}
	if !manager.allowed(base) {
		t.Fatal("active leased Trial device should be allowed")
	}
	expired := base
	expired.SubscriptionEnds = now
	if manager.allowed(expired) {
		t.Fatal("expired device should be blocked")
	}
	leaseExpired := base
	leaseExpired.LeaseExpires = now
	if manager.allowed(leaseExpired) {
		t.Fatal("device with expired lease should be blocked")
	}
	trialExhausted := base
	trialExhausted.UsedBytes = trialExhausted.QuotaBytes
	if manager.allowed(trialExhausted) {
		t.Fatal("exhausted Trial should be blocked")
	}
	paidExhausted := trialExhausted
	paidExhausted.Plan = model.Lite
	if !manager.allowed(paidExhausted) {
		t.Fatal("exhausted paid plan should remain available at throttled policy")
	}
}
