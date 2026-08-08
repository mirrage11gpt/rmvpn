package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestQuotaLeaseSignatureAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	lease := QuotaLease{LeaseID: "lease", DeviceID: "device", NodeID: "node", Bytes: 1024, IssuedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "quota-1"}
	if err := lease.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(publicKey, now); err != nil {
		t.Fatal(err)
	}
	lease.Bytes++
	if err := lease.Verify(publicKey, now); err == nil {
		t.Fatal("tampered lease accepted")
	}
}
