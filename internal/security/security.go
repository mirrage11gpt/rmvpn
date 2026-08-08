package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

var rawURL = base64.RawURLEncoding

func NewIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func RandomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return rawURL.EncodeToString(value), nil
}

func Hash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return rawURL.EncodeToString(digest[:])
}

func EqualHash(encodedHash, plainValue string) bool {
	expected := Hash(plainValue)
	if len(encodedHash) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(encodedHash), []byte(expected)) == 1
}

func Encode(value []byte) string { return rawURL.EncodeToString(value) }

func Decode(value string) ([]byte, error) { return rawURL.DecodeString(value) }

func UUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
