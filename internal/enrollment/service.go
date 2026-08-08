package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

const BundlePrefix = "rvpn1_"

type Service struct {
	store   *store.Store
	domain  string
	version string
	now     func() time.Time
}

type Bundle struct {
	Version       int       `json:"version"`
	NodeID        string    `json:"nodeId"`
	Domain        string    `json:"domain"`
	ClaimEndpoint string    `json:"claimEndpoint"`
	NodePublicKey string    `json:"nodePublicKey"`
	ClaimToken    string    `json:"claimToken"`
	ExpiresAt     time.Time `json:"expiresAt"`
	AgentVersion  string    `json:"agentVersion"`
}

type ClaimRequest struct {
	ClaimToken          string `json:"claimToken"`
	ControllerURL       string `json:"controllerUrl"`
	ControllerPublicKey string `json:"controllerPublicKey"`
	NodeCertificatePEM  string `json:"nodeCertificatePem"`
	ControllerCAPEM     string `json:"controllerCaPem"`
}

func New(s *store.Store, domain, version string) *Service {
	return &Service{store: s, domain: domain, version: version, now: time.Now}
}

func (s *Service) Ensure(ctx context.Context) (string, error) {
	if err := s.ensureIdentity(ctx); err != nil {
		return "", err
	}
	e, found, err := s.store.Enrollment(ctx)
	if err != nil {
		return "", err
	}
	if found && e.ClaimedAt != nil {
		return "", nil
	}
	if !found || !e.ExpiresAt.After(s.now()) {
		return s.Reenroll(ctx)
	}
	return s.bundle(ctx, e.Token, e.ExpiresAt)
}

func (s *Service) Current(ctx context.Context) (string, error) {
	e, found, err := s.store.Enrollment(ctx)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errors.New("enrollment has not been initialized")
	}
	if e.ClaimedAt != nil {
		return "", errors.New("node is already claimed")
	}
	if !e.ExpiresAt.After(s.now()) {
		return "", errors.New("enrollment token has expired; run reenroll")
	}
	return s.bundle(ctx, e.Token, e.ExpiresAt)
}

func (s *Service) Reenroll(ctx context.Context) (string, error) {
	if err := s.ensureIdentity(ctx); err != nil {
		return "", err
	}
	token, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	expires := s.now().UTC().Add(24 * time.Hour)
	if err := s.store.ReplaceEnrollment(ctx, token, security.Hash(token), expires); err != nil {
		return "", err
	}
	return s.bundle(ctx, token, expires)
}

func (s *Service) Claim(ctx context.Context, request ClaimRequest) error {
	if strings.TrimSpace(request.ClaimToken) == "" {
		return errors.New("claimToken is required")
	}
	controllerURL, err := url.Parse(request.ControllerURL)
	if err != nil || (controllerURL.Scheme != "wss" && controllerURL.Scheme != "https") || controllerURL.Host == "" {
		return errors.New("controllerUrl must be an absolute wss:// or https:// URL")
	}
	controllerKey, err := security.Decode(request.ControllerPublicKey)
	if err != nil || len(controllerKey) != ed25519.PublicKeySize {
		return errors.New("controllerPublicKey must be a base64url Ed25519 public key")
	}
	nodeCert, err := parseCertificate(request.NodeCertificatePEM)
	if err != nil {
		return fmt.Errorf("invalid node certificate: %w", err)
	}
	controllerCA, err := parseCertificate(request.ControllerCAPEM)
	if err != nil {
		return fmt.Errorf("invalid controller CA: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(controllerCA)
	if _, err := nodeCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: s.now()}); err != nil {
		return fmt.Errorf("node certificate is not valid for the controller CA: %w", err)
	}
	publicEncoded, ok, err := s.store.State(ctx, "node_public_key")
	if err != nil || !ok {
		return errors.New("node identity is missing")
	}
	publicRaw, err := security.Decode(publicEncoded)
	if err != nil {
		return err
	}
	certPublic, ok := nodeCert.PublicKey.(ed25519.PublicKey)
	if !ok || !certPublic.Equal(ed25519.PublicKey(publicRaw)) {
		return errors.New("node certificate does not match this node identity")
	}
	return s.store.Claim(ctx, security.Hash(request.ClaimToken), request.ControllerURL,
		request.ControllerPublicKey, request.NodeCertificatePEM, request.ControllerCAPEM, s.now().UTC())
}

func (s *Service) ensureIdentity(ctx context.Context) error {
	private, hasPrivate, err := s.store.State(ctx, "node_private_key")
	if err != nil {
		return err
	}
	_, hasPublic, err := s.store.State(ctx, "node_public_key")
	if err != nil {
		return err
	}
	_, hasID, err := s.store.State(ctx, "node_id")
	if err != nil {
		return err
	}
	if hasPrivate || hasPublic || hasID {
		if hasPrivate && hasPublic && hasID && private != "" {
			return nil
		}
		return errors.New("node identity is incomplete; restore the database from backup instead of regenerating it")
	}
	publicKey, privateKey, err := security.NewIdentity()
	if err != nil {
		return err
	}
	nodeID, err := security.UUID()
	if err != nil {
		return err
	}
	return s.store.SetStates(ctx, map[string]string{
		"node_id":          nodeID,
		"node_public_key":  security.Encode(publicKey),
		"node_private_key": security.Encode(privateKey),
	})
}

func (s *Service) bundle(ctx context.Context, token string, expires time.Time) (string, error) {
	nodeID, ok, err := s.store.State(ctx, "node_id")
	if err != nil || !ok {
		return "", errors.New("node ID is missing")
	}
	publicKey, ok, err := s.store.State(ctx, "node_public_key")
	if err != nil || !ok {
		return "", errors.New("node public key is missing")
	}
	payload, err := json.Marshal(Bundle{
		Version: 1, NodeID: nodeID, Domain: s.domain,
		ClaimEndpoint: "https://" + s.domain + ":8443/v1/enrollment/claim",
		NodePublicKey: publicKey, ClaimToken: token, ExpiresAt: expires.UTC(), AgentVersion: s.version,
	})
	if err != nil {
		return "", err
	}
	return BundlePrefix + security.Encode(payload), nil
}

func parseCertificate(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM certificate is required")
	}
	return x509.ParseCertificate(block.Bytes)
}
