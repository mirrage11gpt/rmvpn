package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

func TestEnrollmentBundleAndSingleUseClaim(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	service := New(database, "node.example.com", "0.1.0")
	service.now = func() time.Time { return now }
	bundle, err := service.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bundle, BundlePrefix) {
		t.Fatalf("invalid bundle: %s", bundle)
	}
	enrollmentRow, found, err := database.Enrollment(context.Background())
	if err != nil || !found {
		t.Fatal("enrollment row was not created")
	}
	nodePublicEncoded, _, _ := database.State(context.Background(), "node_public_key")
	nodePrivateEncoded, _, _ := database.State(context.Background(), "node_private_key")
	nodePublicRaw, _ := security.Decode(nodePublicEncoded)
	nodePrivateRaw, _ := security.Decode(nodePrivateEncoded)
	caPEM, nodePEM, controllerPublic := certificates(t, now, ed25519.PublicKey(nodePublicRaw), ed25519.PrivateKey(nodePrivateRaw))
	request := ClaimRequest{ClaimToken: enrollmentRow.Token, ControllerURL: "wss://control.example.com/v1/nodes/connect",
		ControllerPublicKey: security.Encode(controllerPublic), NodeCertificatePEM: nodePEM, ControllerCAPEM: caPEM}
	if err := service.Claim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := service.Claim(context.Background(), request); err == nil {
		t.Fatal("replayed claim was accepted")
	}
	if _, err := service.Current(context.Background()); err == nil {
		t.Fatal("claimed token is still visible")
	}
}

func TestExpiredEnrollmentCannotBeShown(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	service := New(database, "node.example.com", "0.1.0")
	service.now = func() time.Time { return now }
	if _, err := service.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(25 * time.Hour) }
	if _, err := service.Current(context.Background()); err == nil {
		t.Fatal("expired token was returned")
	}
}

func certificates(t *testing.T, now time.Time, nodePublic ed25519.PublicKey, nodePrivate ed25519.PrivateKey) (string, string, ed25519.PublicKey) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RiseVPN Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	nodeTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "node"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTemplate, caCert, nodePublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_ = nodePrivate
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nodeDER})), caPublic
}
