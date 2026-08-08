package compliance

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

const staleAlert = "COMPLIANCE_FEED_STALE"

type SignedFeed struct {
	Version   string          `json:"version"`
	UpdatedAt time.Time       `json:"updatedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Rules     json.RawMessage `json:"rules"`
	Signature string          `json:"signature"`
}

type Service struct {
	store *store.Store
	now   func() time.Time
}

func New(s *store.Store) *Service { return &Service{store: s, now: time.Now} }

func (s *Service) Apply(ctx context.Context, feed SignedFeed, publicKeyEncoded string) error {
	if feed.Version == "" || len(feed.Rules) == 0 || !feed.ExpiresAt.After(feed.UpdatedAt) {
		return errors.New("invalid compliance feed metadata")
	}
	if !feed.ExpiresAt.After(s.now().UTC()) || feed.UpdatedAt.After(s.now().UTC().Add(5*time.Minute)) {
		return errors.New("compliance feed is expired or dated too far in the future")
	}
	if err := validateRules(feed.Rules); err != nil {
		return err
	}
	keyRaw, err := security.Decode(publicKeyEncoded)
	if err != nil || len(keyRaw) != ed25519.PublicKeySize {
		return errors.New("invalid controller public key")
	}
	signature, err := security.Decode(feed.Signature)
	if err != nil {
		return errors.New("invalid feed signature encoding")
	}
	payload, err := signingPayload(feed)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(keyRaw), payload, signature) {
		return errors.New("invalid compliance feed signature")
	}
	if err := s.store.SaveCompliance(ctx, store.ComplianceFeed{
		Version: feed.Version, UpdatedAt: feed.UpdatedAt.UTC(), ExpiresAt: feed.ExpiresAt.UTC(),
		RulesJSON: string(feed.Rules), Signature: feed.Signature,
	}); err != nil {
		return err
	}
	return s.store.ResolveAlert(ctx, staleAlert)
}

func validateRules(raw json.RawMessage) error {
	var rules struct {
		BlockedDomains []string `json:"blockedDomains"`
		BlockedCIDRs   []string `json:"blockedCidrs"`
		BlockedPorts   []int    `json:"blockedPorts"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return fmt.Errorf("invalid compliance rules: %w", err)
	}
	for _, domain := range rules.BlockedDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.ContainsAny(domain, " /:@") {
			return fmt.Errorf("invalid blocked domain %q", domain)
		}
	}
	for _, encoded := range rules.BlockedCIDRs {
		if _, _, err := net.ParseCIDR(encoded); err != nil {
			return fmt.Errorf("invalid compliance CIDR %q", encoded)
		}
	}
	for _, port := range rules.BlockedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid blocked port %d", port)
		}
	}
	return nil
}

func (s *Service) Check(ctx context.Context) error {
	feed, found, err := s.store.Compliance(ctx)
	if err != nil {
		return err
	}
	if found && feed.ExpiresAt.After(s.now().UTC()) {
		return s.store.ResolveAlert(ctx, staleAlert)
	}
	message := "Compliance feed has never been synchronized"
	if found {
		message = fmt.Sprintf("Compliance feed %s expired at %s; the last valid rules remain active", feed.Version, feed.ExpiresAt.Format(time.RFC3339))
	}
	return s.store.SetAlert(ctx, model.Alert{Code: staleAlert, Severity: "critical", Message: message, CreatedAt: s.now().UTC(), Active: true})
}

func (s *Service) CurrentRules(ctx context.Context) (json.RawMessage, string, bool, error) {
	feed, found, err := s.store.Compliance(ctx)
	if err != nil || !found {
		return nil, "", found, err
	}
	return json.RawMessage(feed.RulesJSON), feed.Version, true, nil
}

func (s *Service) Blocked(ctx context.Context, address string) (bool, error) {
	raw, _, found, err := s.CurrentRules(ctx)
	if err != nil || !found {
		return false, err
	}
	var rules struct {
		BlockedDomains []string `json:"blockedDomains"`
		BlockedCIDRs   []string `json:"blockedCidrs"`
		BlockedPorts   []int    `json:"blockedPorts"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		return false, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range rules.BlockedDomains {
		domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
		if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
			return true, nil
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, encoded := range rules.BlockedCIDRs {
			_, network, err := net.ParseCIDR(encoded)
			if err != nil {
				return false, fmt.Errorf("invalid compliance CIDR %q", encoded)
			}
			if network.Contains(ip) {
				return true, nil
			}
		}
	}
	port, _ := strconv.Atoi(portText)
	for _, blockedPort := range rules.BlockedPorts {
		if port == blockedPort {
			return true, nil
		}
	}
	return false, nil
}

func signingPayload(feed SignedFeed) ([]byte, error) {
	return json.Marshal(struct {
		Version   string          `json:"version"`
		UpdatedAt time.Time       `json:"updatedAt"`
		ExpiresAt time.Time       `json:"expiresAt"`
		Rules     json.RawMessage `json:"rules"`
	}{feed.Version, feed.UpdatedAt.UTC(), feed.ExpiresAt.UTC(), feed.Rules})
}

func Sign(feed *SignedFeed, privateKey ed25519.PrivateKey) error {
	payload, err := signingPayload(*feed)
	if err != nil {
		return err
	}
	feed.Signature = security.Encode(ed25519.Sign(privateKey, payload))
	return nil
}
