package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProblemUsesUTF8AndDomainIndependentType(t *testing.T) {
	recorder := httptest.NewRecorder()
	problem(recorder, http.StatusUnauthorized, "oidc-token", "Не удалось проверить вход", "")

	if got := recorder.Header().Get("Content-Type"); got != "application/problem+json; charset=utf-8" {
		t.Fatalf("unexpected content type: %q", got)
	}
	var body struct {
		Type  string `json:"type"`
		Title string `json:"title"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Type != "urn:risevpn:problem:oidc-token" {
		t.Fatalf("unexpected problem type: %q", body.Type)
	}
	if body.Title != "Не удалось проверить вход" {
		t.Fatalf("unexpected title: %q", body.Title)
	}
}

func TestHysteriaURIWithSalamander(t *testing.T) {
	raw := hysteriaURI("user:secret", "f1.risevpn.space", "obfs secret")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "hysteria2" || parsed.Host != "f1.risevpn.space:443" {
		t.Fatalf("unexpected endpoint: %s://%s", parsed.Scheme, parsed.Host)
	}
	if parsed.User == nil || parsed.User.Username() != "user:secret" {
		t.Fatalf("unexpected credential: %v", parsed.User)
	}
	query := parsed.Query()
	if query.Get("sni") != "f1.risevpn.space" {
		t.Fatalf("unexpected SNI: %q", query.Get("sni"))
	}
	if query.Get("obfs") != "salamander" || query.Get("obfs-password") != "obfs secret" {
		t.Fatalf("unexpected obfuscation parameters: %v", query)
	}
	if parsed.Fragment != "RiseVPN-Auto" {
		t.Fatalf("unexpected fragment: %q", parsed.Fragment)
	}
}

func TestHysteriaURIWithoutObfuscation(t *testing.T) {
	parsed, err := url.Parse(hysteriaURI("credential", "f1.risevpn.space", ""))
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Has("obfs") || query.Has("obfs-password") {
		t.Fatalf("unexpected obfuscation parameters: %v", query)
	}
}
