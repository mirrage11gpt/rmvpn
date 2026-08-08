package policy

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

type Service struct {
	store      *store.Store
	compliance *compliance.Service
	now        func() time.Time
}

func New(s *store.Store, complianceService *compliance.Service) *Service {
	return &Service{store: s, compliance: complianceService, now: time.Now}
}

func (s *Service) Authenticate(ctx context.Context, credential string) (model.AuthDecision, error) {
	if credential == "" {
		return model.AuthDecision{OK: false, Reason: "missing_credential"}, nil
	}
	device, found, err := s.store.DeviceByCredentialHash(ctx, security.Hash(credential))
	if err != nil {
		return model.AuthDecision{}, err
	}
	if !found {
		return model.AuthDecision{OK: false, Reason: "invalid_credential"}, nil
	}
	if !device.Active {
		return model.AuthDecision{OK: false, Reason: "device_revoked"}, nil
	}
	now := s.now().UTC()
	if !device.SubscriptionEnds.After(now) {
		return model.AuthDecision{OK: false, Reason: "subscription_expired"}, nil
	}
	base, ok := device.Plan.Policy()
	if !ok {
		return model.AuthDecision{OK: false, Reason: "unknown_plan"}, nil
	}
	quota := device.QuotaBytes
	if quota <= 0 {
		quota = base.QuotaBytes
	}
	exhausted := device.UsedBytes >= quota
	if device.Plan == model.Trial && exhausted {
		return model.AuthDecision{OK: false, Reason: "trial_quota_exhausted"}, nil
	}
	if !exhausted && device.LeaseBytes > 0 && (!device.LeaseExpires.After(now) || device.UsedBytes >= device.LeaseBytes) {
		return model.AuthDecision{OK: false, Reason: "quota_lease_exhausted"}, nil
	}
	up, down := base.UpBPS, base.DownBPS
	if exhausted {
		up, down = base.ThrottleBPS, base.ThrottleBPS
	}
	return model.AuthDecision{
		OK: true, ID: device.ID,
		Policy: &model.SessionPolicy{UpBPS: up, DownBPS: down, Priority: base.Priority,
			P2PAllowed: base.P2PAllowed, DeviceID: device.ID, Throttled: exhausted, Compliance: true},
	}, nil
}

func (s *Service) Authorize(ctx context.Context, deviceID, address string, initialPayload []byte) (bool, string, error) {
	device, found, err := s.store.DeviceByID(ctx, deviceID)
	if err != nil {
		return false, "backend_error", err
	}
	if !found || !device.Active {
		return false, "device_revoked", nil
	}
	blocked, err := s.compliance.Blocked(ctx, address)
	if err != nil {
		return false, "compliance_error", err
	}
	if blocked {
		return false, "compliance_blocked", nil
	}
	planPolicy, ok := device.Plan.Policy()
	if !ok {
		return false, "unknown_plan", nil
	}
	if !planPolicy.P2PAllowed && isP2P(address, initialPayload) {
		return false, "p2p_blocked", nil
	}
	return true, "", nil
}

func isP2P(address string, payload []byte) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	port, _ := strconv.Atoi(portText)
	if strings.Contains(host, "tracker") || strings.Contains(host, "announce") ||
		(port >= 6881 && port <= 6889) || port == 51413 || port == 6969 {
		return true
	}
	return bytes.HasPrefix(payload, []byte("\x13BitTorrent protocol")) ||
		bytes.Contains(payload, []byte("announce_peer")) || bytes.Contains(payload, []byte("find_node"))
}
