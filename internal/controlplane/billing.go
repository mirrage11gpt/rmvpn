package controlplane

import "time"

type PlanTerms struct {
	Code                     string
	PriceKopecks, QuotaBytes int64
	Duration                 time.Duration
}

func ProrateUpgrade(current, next PlanTerms, now, periodEnd time.Time) (cost, quota int64) {
	if !periodEnd.After(now) || current.Duration <= 0 {
		return next.PriceKopecks, next.QuotaBytes
	}
	remaining := periodEnd.Sub(now)
	if remaining > current.Duration {
		remaining = current.Duration
	}
	remainingSeconds := int64(remaining / time.Second)
	periodSeconds := int64(current.Duration / time.Second)
	cost = (next.PriceKopecks - current.PriceKopecks) * remainingSeconds / periodSeconds
	if cost < 0 {
		cost = 0
	}
	quota = (next.QuotaBytes - current.QuotaBytes) * remainingSeconds / periodSeconds
	if quota < 0 {
		quota = 0
	}
	return
}
