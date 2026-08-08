package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
