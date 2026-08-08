package control

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

type Client struct {
	store      *store.Store
	compliance *compliance.Service
	version    string
}

type envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

func New(s *store.Store, complianceService *compliance.Service, version string) *Client {
	return &Client{store: s, compliance: complianceService, version: version}
}

func (c *Client) Run(ctx context.Context) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		if err := c.connect(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("control channel disconnected", "error", err, "retry", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	e, found, err := c.store.Enrollment(ctx)
	if err != nil {
		return err
	}
	if !found || e.ClaimedAt == nil {
		return errors.New("node is not claimed")
	}
	controllerURL, ok, err := c.store.State(ctx, "controller_url")
	if err != nil || !ok {
		return errors.New("controller URL is missing")
	}
	if strings.HasPrefix(controllerURL, "https://") {
		controllerURL = "wss://" + strings.TrimPrefix(controllerURL, "https://")
	}
	tlsConfig, err := c.tlsConfig(ctx)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 30 * time.Second}
	connection, _, err := websocket.Dial(ctx, controllerURL, &websocket.DialOptions{HTTPClient: httpClient})
	if err != nil {
		return err
	}
	defer connection.CloseNow()
	connection.SetReadLimit(4 << 20)
	nodeID, _, _ := c.store.State(ctx, "node_id")
	if err := write(ctx, connection, "hello", map[string]any{"version": 1, "nodeId": nodeID, "agentVersion": c.version}); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- c.readLoop(ctx, connection) }()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-ticker.C:
			alerts, _ := c.store.ActiveAlerts(ctx)
			rttStarted := time.Now()
			pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
			pingErr := connection.Ping(pingCtx)
			pingCancel()
			if pingErr != nil {
				return pingErr
			}
			rttMillis := time.Since(rttStarted).Milliseconds()
			onlineDevices := c.stateInt(ctx, "online_devices")
			onlineConnections := c.stateInt(ctx, "online_connections")
			usageEvents, err := c.store.PendingUsage(ctx, 1000)
			if err != nil {
				return err
			}
			if len(usageEvents) > 0 {
				if err := write(ctx, connection, "usage.batch", map[string]any{"events": usageEvents}); err != nil {
					return err
				}
			}
			if err := write(ctx, connection, "heartbeat", map[string]any{
				"at": time.Now().UTC(), "status": "healthy", "alerts": alerts,
				"cpuCount": runtime.NumCPU(), "goroutines": runtime.NumGoroutine(),
				"load1": loadAverage(), "controllerRttMs": rttMillis,
				"onlineDevices": onlineDevices, "onlineConnections": onlineConnections,
			}); err != nil {
				return err
			}
		}
	}
}

func (c *Client) stateInt(ctx context.Context, key string) int64 {
	value, found, err := c.store.State(ctx, key)
	if err != nil || !found {
		return 0
	}
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}

func loadAverage() float64 {
	payload, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(payload))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}

func (c *Client) readLoop(ctx context.Context, connection *websocket.Conn) error {
	for {
		messageType, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageText {
			continue
		}
		var message envelope
		if err := json.Unmarshal(payload, &message); err != nil {
			return err
		}
		if err := c.handle(ctx, message); err != nil {
			slog.Warn("control message rejected", "type", message.Type, "error", err)
			_ = write(ctx, connection, "error", map[string]string{"requestType": message.Type, "message": err.Error()})
		}
	}
}

func (c *Client) handle(ctx context.Context, message envelope) error {
	switch message.Type {
	case "device.upsert", "quota.lease":
		var payload struct {
			DeviceID         string     `json:"deviceId"`
			CredentialHash   string     `json:"credentialHash"`
			Plan             model.Plan `json:"plan"`
			Active           bool       `json:"active"`
			SubscriptionEnds time.Time  `json:"subscriptionEnds"`
			PeriodEnds       time.Time  `json:"periodEnds"`
			QuotaBytes       int64      `json:"quotaBytes"`
			LeaseBytes       int64      `json:"leaseBytes"`
			LeaseExpires     time.Time  `json:"leaseExpires"`
		}
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		if payload.DeviceID == "" || payload.CredentialHash == "" {
			return errors.New("deviceId and credentialHash are required")
		}
		if _, ok := payload.Plan.Policy(); !ok {
			return errors.New("unknown plan")
		}
		return c.store.UpsertDevice(ctx, model.Device{ID: payload.DeviceID, CredentialHash: payload.CredentialHash,
			Plan: payload.Plan, Active: payload.Active, SubscriptionEnds: payload.SubscriptionEnds,
			PeriodEnds: payload.PeriodEnds, QuotaBytes: payload.QuotaBytes,
			LeaseBytes: payload.LeaseBytes, LeaseExpires: payload.LeaseExpires})
	case "device.revoke":
		var payload struct {
			DeviceID string `json:"deviceId"`
		}
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		return c.store.RevokeDevice(ctx, payload.DeviceID)
	case "compliance.feed":
		var feed compliance.SignedFeed
		if err := json.Unmarshal(message.Data, &feed); err != nil {
			return err
		}
		controllerKey, ok, err := c.store.State(ctx, "controller_public_key")
		if err != nil || !ok {
			return errors.New("controller public key is missing")
		}
		return c.compliance.Apply(ctx, feed, controllerKey)
	case "usage.ack":
		var payload struct {
			EventIDs []int64 `json:"eventIds"`
		}
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		if len(payload.EventIDs) > 5000 {
			return errors.New("too many usage event IDs")
		}
		return c.store.MarkUsageSent(ctx, payload.EventIDs, time.Now().UTC())
	case "drain", "update":
		return fmt.Errorf("%s is acknowledged but requires the privileged updater helper", message.Type)
	default:
		return fmt.Errorf("unsupported message type %q", message.Type)
	}
}

func (c *Client) tlsConfig(ctx context.Context) (*tls.Config, error) {
	privateEncoded, ok, err := c.store.State(ctx, "node_private_key")
	if err != nil || !ok {
		return nil, errors.New("node private key is missing")
	}
	privateRaw, err := security.Decode(privateEncoded)
	if err != nil || len(privateRaw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid node private key")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(privateRaw))
	if err != nil {
		return nil, err
	}
	certificatePEM, ok, err := c.store.State(ctx, "node_certificate")
	if err != nil || !ok {
		return nil, errors.New("node certificate is missing")
	}
	pair, err := tls.X509KeyPair([]byte(certificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if err != nil {
		return nil, err
	}
	controllerCA, ok, err := c.store.State(ctx, "controller_ca")
	if err != nil || !ok {
		return nil, errors.New("controller CA is missing")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(controllerCA)) {
		return nil, errors.New("invalid controller CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots}, nil
}

func write(ctx context.Context, connection *websocket.Conn, messageType string, data any) error {
	payload, err := json.Marshal(struct {
		Type string `json:"type"`
		Data any    `json:"data,omitempty"`
	}{messageType, data})
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return connection.Write(writeCtx, websocket.MessageText, payload)
}
