package controlplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

type Vault struct {
	aead    cipher.AEAD
	hwidKey []byte
}

func NewVault(encryptionKey, hwidKey []byte) (*Vault, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead, hwidKey: append([]byte(nil), hwidKey...)}, nil
}
func (v *Vault) Encrypt(value string, aad []byte) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return v.aead.Seal(nonce, nonce, []byte(value), aad), nil
}
func (v *Vault) Decrypt(value, aad []byte) (string, error) {
	n := v.aead.NonceSize()
	if len(value) < n {
		return "", errors.New("ciphertext too short")
	}
	plain, err := v.aead.Open(nil, value[:n], value[n:], aad)
	return string(plain), err
}
func (v *Vault) HWID(value string) []byte {
	mac := hmac.New(sha256.New, v.hwidKey)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
func Hash(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
func RandomToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
