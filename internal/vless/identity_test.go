package vless

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestCredentialAndHashProduceSameID(t *testing.T) {
	credential := "device-secret"
	digest := sha256.Sum256([]byte(credential))
	fromHash, err := IDFromCredentialHash(base64.RawURLEncoding.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if fromHash != IDFromCredential(credential) {
		t.Fatalf("IDs differ: %q != %q", fromHash, IDFromCredential(credential))
	}
}

func TestInvalidCredentialHash(t *testing.T) {
	if _, err := IDFromCredentialHash("short"); err == nil {
		t.Fatal("expected invalid hash error")
	}
}
