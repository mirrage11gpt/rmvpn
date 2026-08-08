package usage

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

func TestCollectorPersistsTrafficAndKicksExhaustedTrial(t *testing.T) {
	kicked := false
	database, err := store.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now().UTC()
	device := model.Device{ID: "trial-device", CredentialHash: security.Hash("credential"), Plan: model.Trial,
		Active: true, SubscriptionEnds: now.Add(time.Hour), PeriodEnds: now.Add(time.Hour), QuotaBytes: 20,
		LeaseBytes: 20, LeaseExpires: now.Add(time.Hour)}
	if err := database.UpsertDevice(context.Background(), device); err != nil {
		t.Fatal(err)
	}
	collector := New(database, "http://hysteria.test", "stats-secret")
	collector.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "stats-secret" {
			return testResponse(401, `{}`), nil
		}
		switch request.URL.Path {
		case "/traffic":
			return testResponse(200, `{"trial-device":{"tx":12,"rx":9}}`), nil
		case "/kick":
			kicked = true
			return testResponse(204, ``), nil
		case "/online":
			return testResponse(200, `{"trial-device":1}`), nil
		default:
			return testResponse(404, `{}`), nil
		}
	})}
	collector.now = func() time.Time { return now }
	if err := collector.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	updated, found, err := database.DeviceByID(context.Background(), device.ID)
	if err != nil || !found || updated.UsedBytes != 21 {
		t.Fatalf("traffic was not persisted: %#v %v", updated, err)
	}
	if !kicked {
		t.Fatal("quota-exhausted trial was not kicked")
	}
	events, err := database.PendingUsage(context.Background(), 100)
	if err != nil || len(events) != 1 {
		t.Fatalf("usage batch missing: %#v %v", events, err)
	}
	if err := database.MarkUsageSent(context.Background(), []int64{events[0].ID}, now); err != nil {
		t.Fatal(err)
	}
	events, err = database.PendingUsage(context.Background(), 100)
	if err != nil || len(events) != 0 {
		t.Fatalf("acknowledged event was resent: %#v %v", events, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func testResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
