package controlplane

import (
	"encoding/json"
	"testing"
)

func TestFilterTelegramJWKSDropsUnsupportedCurves(t *testing.T) {
	input := []byte(`{"keys":[{"alg":"RS256","kty":"RSA","kid":"oidc-1","n":"test","e":"AQAB"},{"alg":"ES256K","kty":"EC","kid":"oidc-es256k-1","crv":"secp256k1","x":"test","y":"test"}]}`)
	filtered, err := filterTelegramJWKS(input)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Keys []struct {
			Algorithm string `json:"alg"`
			KeyType   string `json:"kty"`
			KeyID     string `json:"kid"`
		} `json:"keys"`
	}
	if err = json.Unmarshal(filtered, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Keys) != 1 || result.Keys[0].Algorithm != "RS256" || result.Keys[0].KeyType != "RSA" || result.Keys[0].KeyID != "oidc-1" {
		t.Fatalf("unexpected filtered keys: %#v", result.Keys)
	}
}

func TestFilterTelegramJWKSRequiresRS256(t *testing.T) {
	_, err := filterTelegramJWKS([]byte(`{"keys":[{"alg":"ES256K","kty":"EC","crv":"secp256k1"}]}`))
	if err == nil {
		t.Fatal("expected missing RS256 key error")
	}
}
