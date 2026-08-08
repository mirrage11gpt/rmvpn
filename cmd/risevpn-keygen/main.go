package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	for _, name := range []string{"POSTGRES_PASSWORD", "SESSION_SECRET", "ENCRYPTION_KEY", "HWID_HMAC_KEY"} {
		fmt.Printf("%s=%s\n", name, random(32))
	}
	for _, name := range []string{"QUOTA_ED25519_PRIVATE_KEY", "COMPLIANCE_ED25519_PRIVATE_KEY"} {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("%s=%s\n", name, base64.RawURLEncoding.EncodeToString(privateKey))
	}
}

func random(size int) string {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		fmt.Fprintf(os.Stderr, "generate random secret: %v\n", err)
		os.Exit(1)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
