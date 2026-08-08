package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

const telegramJWKSPath = "/.well-known/jwks.json"

// telegramOIDCHTTPClient filters Telegram's multi-algorithm JWKS down to the
// RS256 keys accepted by RiseVPN. go-jose rejects an entire JWKS when it sees
// Telegram's unrelated ES256K/secp256k1 key, which would otherwise prevent an
// RS256 token from being verified. Signature and OIDC claim verification remain
// the responsibility of go-oidc.
func telegramOIDCHTTPClient() *http.Client {
	return &http.Client{Transport: &telegramJWKSTransport{base: http.DefaultTransport}}
}

type telegramJWKSTransport struct {
	base http.RoundTripper
}

func (t *telegramJWKSTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || request.URL.Scheme != "https" || request.URL.Hostname() != "oauth.telegram.org" || request.URL.Path != telegramJWKSPath || response.StatusCode != http.StatusOK {
		return response, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("read Telegram JWKS: %w", err)
	}
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("Telegram JWKS exceeds 1 MiB")
	}
	filtered, err := filterTelegramJWKS(body)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(filtered))
	response.ContentLength = int64(len(filtered))
	response.Header.Set("Content-Length", strconv.Itoa(len(filtered)))
	return response, nil
}

func filterTelegramJWKS(body []byte) ([]byte, error) {
	var keySet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("decode Telegram JWKS: %w", err)
	}
	allowed := make([]json.RawMessage, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		var metadata struct {
			Algorithm string `json:"alg"`
			KeyType   string `json:"kty"`
		}
		if json.Unmarshal(key, &metadata) == nil && metadata.Algorithm == "RS256" && metadata.KeyType == "RSA" {
			allowed = append(allowed, key)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("Telegram JWKS contains no RS256 RSA keys")
	}
	return json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: allowed})
}
