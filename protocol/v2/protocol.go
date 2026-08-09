package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const Version = 2

type Envelope struct {
	Version   int             `json:"version"`
	MessageID string          `json:"messageId"`
	ReplyTo   string          `json:"replyTo,omitempty"`
	Type      string          `json:"type"`
	SentAt    time.Time       `json:"sentAt"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type Capability string

const (
	CapabilityACK            Capability = "command.ack"
	CapabilityQuotaLease     Capability = "quota.lease.signed"
	CapabilitySessionKick    Capability = "session.kick"
	CapabilityPolicyOverride Capability = "policy.override"
	CapabilityCertRotate     Capability = "certificate.rotate"
	CapabilityAtomicUpdate   Capability = "update.atomic"
	CapabilityTCPFallback    Capability = "fallback.vless-reality"
)

type Hello struct {
	NodeID           string       `json:"nodeId"`
	AgentVersion     string       `json:"agentVersion"`
	Protocols        []int        `json:"protocols"`
	Capabilities     []Capability `json:"capabilities"`
	RealityPublicKey string       `json:"realityPublicKey,omitempty"`
	RealityShortID   string       `json:"realityShortId,omitempty"`
}

type Ack struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
	AppliedAt string `json:"appliedAt,omitempty"`
}

type QuotaLease struct {
	LeaseID   string    `json:"leaseId"`
	DeviceID  string    `json:"deviceId"`
	NodeID    string    `json:"nodeId"`
	Bytes     int64     `json:"bytes"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	KeyID     string    `json:"keyId"`
	Signature string    `json:"signature"`
}

func (l QuotaLease) signingBytes() ([]byte, error) {
	unsigned := struct {
		LeaseID   string    `json:"leaseId"`
		DeviceID  string    `json:"deviceId"`
		NodeID    string    `json:"nodeId"`
		Bytes     int64     `json:"bytes"`
		IssuedAt  time.Time `json:"issuedAt"`
		ExpiresAt time.Time `json:"expiresAt"`
		KeyID     string    `json:"keyId"`
	}{l.LeaseID, l.DeviceID, l.NodeID, l.Bytes, l.IssuedAt.UTC(), l.ExpiresAt.UTC(), l.KeyID}
	return json.Marshal(unsigned)
}

func (l *QuotaLease) Sign(privateKey ed25519.PrivateKey) error {
	payload, err := l.signingBytes()
	if err != nil {
		return err
	}
	l.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func (l QuotaLease) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	if l.LeaseID == "" || l.DeviceID == "" || l.NodeID == "" || l.Bytes < 0 {
		return errors.New("invalid quota lease fields")
	}
	if !l.ExpiresAt.After(now) || l.IssuedAt.After(now.Add(5*time.Minute)) || l.ExpiresAt.Sub(l.IssuedAt) > 24*time.Hour {
		return errors.New("quota lease is outside its validity window")
	}
	signature, err := base64.RawURLEncoding.DecodeString(l.Signature)
	if err != nil {
		return errors.New("invalid quota lease signature encoding")
	}
	payload, err := l.signingBytes()
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("invalid quota lease signature")
	}
	return nil
}

type DeviceUpsert struct {
	DeviceID         string    `json:"deviceId"`
	CredentialHash   string    `json:"credentialHash"`
	Plan             string    `json:"plan"`
	Active           bool      `json:"active"`
	SubscriptionEnds time.Time `json:"subscriptionEnds"`
	PeriodEnds       time.Time `json:"periodEnds"`
	QuotaBytes       int64     `json:"quotaBytes"`
}

type DeviceRef struct {
	DeviceID string `json:"deviceId"`
	Reason   string `json:"reason,omitempty"`
}

type PolicyOverride struct {
	DeviceID  string    `json:"deviceId"`
	UpBPS     int64     `json:"upBps"`
	DownBPS   int64     `json:"downBps"`
	P2P       bool      `json:"p2pAllowed"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type CertificateRotate struct {
	CertificatePEM string    `json:"certificatePem"`
	ControllerCA   string    `json:"controllerCa,omitempty"`
	NotAfter       time.Time `json:"notAfter"`
}

type UsageEvent struct {
	EventID   string    `json:"eventId"`
	DeviceID  string    `json:"deviceId"`
	RXBytes   int64     `json:"rxBytes"`
	TXBytes   int64     `json:"txBytes"`
	StartedAt time.Time `json:"startedAt"`
	EndedAt   time.Time `json:"endedAt"`
}
