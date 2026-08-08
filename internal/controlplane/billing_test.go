package controlplane

import (
	"testing"
	"time"
)

func TestProrateUpgrade(t *testing.T) {
	now := time.Unix(0, 0)
	current := PlanTerms{"LITE", 14900, 150, paidPeriod}
	next := PlanTerms{"PLUS", 29900, 600, paidPeriod}
	cost, quota := ProrateUpgrade(current, next, now, now.Add(15*24*time.Hour))
	if cost != 7500 || quota != 225 {
		t.Fatalf("got %d %d", cost, quota)
	}
}
