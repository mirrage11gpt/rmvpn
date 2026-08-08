package model

import "time"

type Plan string

const (
	Trial Plan = "TRIAL"
	Lite  Plan = "LITE"
	Plus  Plan = "PLUS"
	Ultra Plan = "ULTRA"
)

type PlanPolicy struct {
	UpBPS       int64 `json:"upBps"`
	DownBPS     int64 `json:"downBps"`
	QuotaBytes  int64 `json:"quotaBytes"`
	ThrottleBPS int64 `json:"throttleBps"`
	Priority    int   `json:"priority"`
	P2PAllowed  bool  `json:"p2pAllowed"`
}

func (p Plan) Policy() (PlanPolicy, bool) {
	switch p {
	case Trial:
		return PlanPolicy{30_000_000, 30_000_000, 20_000_000_000, 0, 1, false}, true
	case Lite:
		return PlanPolicy{50_000_000, 50_000_000, 150_000_000_000, 5_000_000, 1, false}, true
	case Plus:
		return PlanPolicy{200_000_000, 200_000_000, 600_000_000_000, 10_000_000, 2, true}, true
	case Ultra:
		return PlanPolicy{0, 0, 2_000_000_000_000, 20_000_000, 3, true}, true
	default:
		return PlanPolicy{}, false
	}
}

type Device struct {
	ID               string
	CredentialHash   string
	Plan             Plan
	Active           bool
	SubscriptionEnds time.Time
	PeriodEnds       time.Time
	QuotaBytes       int64
	UsedBytes        int64
	LeaseBytes       int64
	LeaseExpires     time.Time
	OverrideUpBPS    int64
	OverrideDownBPS  int64
	OverrideP2P      bool
	OverrideExpires  time.Time
}

type SessionPolicy struct {
	UpBPS      int64  `json:"upBps"`
	DownBPS    int64  `json:"downBps"`
	Priority   int    `json:"priority"`
	P2PAllowed bool   `json:"p2pAllowed"`
	DeviceID   string `json:"deviceId"`
	Throttled  bool   `json:"throttled"`
	Compliance bool   `json:"complianceRequired"`
}

type AuthDecision struct {
	OK     bool           `json:"ok"`
	ID     string         `json:"id,omitempty"`
	Policy *SessionPolicy `json:"policy,omitempty"`
	Reason string         `json:"reason,omitempty"`
}

type Alert struct {
	Code      string    `json:"code"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
	Active    bool      `json:"active"`
}
