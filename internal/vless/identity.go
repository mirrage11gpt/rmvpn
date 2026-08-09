package vless

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"
)

var credentialNamespace = uuid.MustParse("38b07a0a-b4a7-50d7-9f39-d40d78a3cb55")

// IDFromCredential derives the VLESS UUID without exposing the Hysteria
// credential to the node. The node receives only the SHA-256 digest and can
// independently derive the same UUID.
func IDFromCredential(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return uuid.NewSHA1(credentialNamespace, digest[:]).String()
}

func IDFromCredentialHash(encoded string) (string, error) {
	digest, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(digest) != sha256.Size {
		return "", errors.New("invalid credential hash")
	}
	return uuid.NewSHA1(credentialNamespace, digest).String(), nil
}
