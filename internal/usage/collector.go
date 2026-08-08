package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

type Counter struct {
	TX int64 `json:"tx"`
	RX int64 `json:"rx"`
}

type Collector struct {
	store   *store.Store
	baseURL string
	secret  string
	client  *http.Client
	now     func() time.Time
}

func New(s *store.Store, baseURL, secret string) *Collector {
	return &Collector{store: s, baseURL: strings.TrimRight(baseURL, "/"), secret: secret,
		client: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
}

func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Collect(ctx); err != nil {
				slog.Error("traffic collection failed", "error", err)
			}
		}
	}
}

func (c *Collector) Collect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/traffic?clear=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.secret)
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("traffic API returned %d: %s", response.StatusCode, body)
	}
	var counters map[string]Counter
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&counters); err != nil {
		return err
	}
	for deviceID, counter := range counters {
		if counter.TX < 0 || counter.RX < 0 {
			continue
		}
		used, err := c.store.AddUsage(ctx, deviceID, counter.TX, counter.RX, c.now().UTC())
		if err != nil {
			return fmt.Errorf("persist usage for %s: %w", deviceID, err)
		}
		device, found, err := c.store.DeviceByID(ctx, deviceID)
		if err != nil || !found {
			continue
		}
		policy, ok := device.Plan.Policy()
		if !ok {
			continue
		}
		quota := device.QuotaBytes
		if quota <= 0 {
			quota = policy.QuotaBytes
		}
		if (device.Plan == model.Trial && used >= quota) || (device.LeaseBytes > 0 && used >= device.LeaseBytes) {
			if err := c.Kick(ctx, deviceID); err != nil {
				slog.Warn("failed to kick quota-exhausted device", "device", deviceID, "error", err)
			}
		}
	}
	return c.collectOnline(ctx)
}

func (c *Collector) collectOnline(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/online", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.secret)
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("online API returned %d", response.StatusCode)
	}
	var online map[string]int
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&online); err != nil {
		return err
	}
	connections := 0
	for _, count := range online {
		if count > 0 {
			connections += count
		}
	}
	if err := c.store.SetState(ctx, "online_devices", fmt.Sprint(len(online))); err != nil {
		return err
	}
	return c.store.SetState(ctx, "online_connections", fmt.Sprint(connections))
}

func (c *Collector) Kick(ctx context.Context, deviceID string) error {
	body, _ := json.Marshal([]string{deviceID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/kick", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.secret)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("kick API returned %d", response.StatusCode)
	}
	return nil
}
