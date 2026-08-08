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
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/store"
	protocol "github.com/mirrage11gpt/rmvpn/protocol/v2"
)

type Client struct {
	store      *store.Store
	compliance *compliance.Service
	version    string
	seenMu     sync.Mutex
	seen       map[string]struct{}
	kicker     interface {
		Kick(context.Context, string) error
	}
}

// envelope remains an alias for protocol-v1 tests and source compatibility.
type envelope = protocol.Envelope

func New(s *store.Store, complianceService *compliance.Service, version string, kickers ...interface {
	Kick(context.Context, string) error
}) *Client {
	c := &Client{store: s, compliance: complianceService, version: version, seen: make(map[string]struct{})}
	if len(kickers) > 0 {
		c.kicker = kickers[0]
	}
	return c
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
	if err := write(ctx, connection, "hello", protocol.Hello{NodeID: nodeID, AgentVersion: c.version, Protocols: []int{1, 2}, Capabilities: []protocol.Capability{protocol.CapabilityACK, protocol.CapabilityQuotaLease, protocol.CapabilitySessionKick, protocol.CapabilityPolicyOverride, protocol.CapabilityCertRotate, protocol.CapabilityAtomicUpdate}}); err != nil {
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
				converted := make([]protocol.UsageEvent, 0, len(usageEvents))
				for _, event := range usageEvents {
					converted = append(converted, protocol.UsageEvent{EventID: strconv.FormatInt(event.ID, 10), DeviceID: event.DeviceID, RXBytes: event.RXBytes, TXBytes: event.TXBytes, StartedAt: event.RecordedAt, EndedAt: event.RecordedAt})
				}
				if err := write(ctx, connection, "usage.batch", map[string]any{"events": converted}); err != nil {
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
		var message protocol.Envelope
		if err := json.Unmarshal(payload, &message); err != nil {
			return err
		}
		if message.MessageID != "" && c.wasSeen(message.MessageID) {
			_ = writeReply(ctx, connection, "ack", message.MessageID, protocol.Ack{OK: true, Code: "duplicate", AppliedAt: time.Now().UTC().Format(time.RFC3339)})
			continue
		}
		if err := c.handle(ctx, message); err != nil {
			slog.Warn("control message rejected", "type", message.Type, "error", err)
			if message.MessageID != "" {
				_ = writeReply(ctx, connection, "nack", message.MessageID, protocol.Ack{OK: false, Code: "apply-failed", Message: err.Error()})
			} else {
				_ = write(ctx, connection, "error", map[string]string{"requestType": message.Type, "message": err.Error()})
			}
			continue
		}
		if message.MessageID != "" {
			c.markSeen(message.MessageID)
			_ = writeReply(ctx, connection, "ack", message.MessageID, protocol.Ack{OK: true, AppliedAt: time.Now().UTC().Format(time.RFC3339)})
		}
	}
}

func (c *Client) handle(ctx context.Context, message protocol.Envelope) error {
	switch message.Type {
	case "device.upsert":
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
		previous, found, _ := c.store.DeviceByID(ctx, payload.DeviceID)
		err := c.store.UpsertDevice(ctx, model.Device{ID: payload.DeviceID, CredentialHash: payload.CredentialHash,
			Plan: payload.Plan, Active: payload.Active, SubscriptionEnds: payload.SubscriptionEnds,
			PeriodEnds: payload.PeriodEnds, QuotaBytes: payload.QuotaBytes,
			LeaseBytes: payload.LeaseBytes, LeaseExpires: payload.LeaseExpires})
		if err == nil && found && previous.CredentialHash != payload.CredentialHash && c.kicker != nil {
			_ = c.kicker.Kick(ctx, payload.DeviceID)
		}
		return err
	case "quota.lease":
		var lease protocol.QuotaLease
		if err := json.Unmarshal(message.Data, &lease); err != nil {
			return err
		}
		keyEncoded, ok, err := c.store.State(ctx, "quota_public_key")
		if err != nil || !ok {
			keyEncoded, ok, err = c.store.State(ctx, "controller_public_key")
		}
		if err != nil || !ok {
			return errors.New("quota verification key is missing")
		}
		keyRaw, err := security.Decode(keyEncoded)
		if err != nil || len(keyRaw) != ed25519.PublicKeySize {
			return errors.New("invalid quota verification key")
		}
		if err := lease.Verify(ed25519.PublicKey(keyRaw), time.Now().UTC()); err != nil {
			return err
		}
		nodeID, _, _ := c.store.State(ctx, "node_id")
		if lease.NodeID != nodeID {
			return errors.New("quota lease belongs to another node")
		}
		device, found, err := c.store.DeviceByID(ctx, lease.DeviceID)
		if err != nil || !found {
			return errors.New("quota lease device is missing")
		}
		device.LeaseBytes = lease.Bytes
		device.LeaseExpires = lease.ExpiresAt
		return c.store.UpsertDevice(ctx, device)
	case "device.revoke":
		var payload struct {
			DeviceID string `json:"deviceId"`
		}
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		if err := c.store.RevokeDevice(ctx, payload.DeviceID); err != nil {
			return err
		}
		if c.kicker != nil {
			return c.kicker.Kick(ctx, payload.DeviceID)
		}
		return nil
	case "session.kick":
		var payload protocol.DeviceRef
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		if payload.DeviceID == "" {
			return errors.New("deviceId is required")
		}
		if c.kicker == nil {
			return errors.New("traffic API kicker is unavailable")
		}
		return c.kicker.Kick(ctx, payload.DeviceID)
	case "policy.override":
		var payload protocol.PolicyOverride
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		if payload.DeviceID == "" || !payload.ExpiresAt.After(time.Now()) {
			return errors.New("invalid policy override")
		}
		return c.store.ApplyPolicyOverride(ctx, payload.DeviceID, payload.UpBPS, payload.DownBPS, payload.P2P, payload.ExpiresAt)
	case "compliance.feed":
		var feed compliance.SignedFeed
		if err := json.Unmarshal(message.Data, &feed); err != nil {
			return err
		}
		controllerKey, ok, err := c.store.State(ctx, "compliance_public_key")
		if err != nil || !ok {
			controllerKey, ok, err = c.store.State(ctx, "controller_public_key")
		}
		if err != nil || !ok {
			return errors.New("controller public key is missing")
		}
		return c.compliance.Apply(ctx, feed, controllerKey)
	case "usage.ack":
		var payload struct {
			EventIDs []json.RawMessage `json:"eventIds"`
		}
		if err := json.Unmarshal(message.Data, &payload); err != nil {
			return err
		}
		if len(payload.EventIDs) > 5000 {
			return errors.New("too many usage event IDs")
		}
		ids := make([]int64, 0, len(payload.EventIDs))
		for _, raw := range payload.EventIDs {
			var text string
			if json.Unmarshal(raw, &text) == nil {
				if id, err := strconv.ParseInt(text, 10, 64); err == nil {
					ids = append(ids, id)
				}
				continue
			}
			var id int64
			if json.Unmarshal(raw, &id) == nil {
				ids = append(ids, id)
			}
		}
		return c.store.MarkUsageSent(ctx, ids, time.Now().UTC())
	case "certificate.rotate":
		var rotation protocol.CertificateRotate
		if err := json.Unmarshal(message.Data, &rotation); err != nil {
			return err
		}
		block, _ := pem.Decode([]byte(rotation.CertificatePEM))
		if block == nil {
			return errors.New("certificate PEM is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		publicEncoded, ok, err := c.store.State(ctx, "node_public_key")
		if err != nil || !ok {
			return errors.New("node public key is missing")
		}
		publicRaw, err := security.Decode(publicEncoded)
		if err != nil {
			return err
		}
		certPublic, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok || !certPublic.Equal(ed25519.PublicKey(publicRaw)) {
			return errors.New("rotated certificate does not match node identity")
		}
		if !certificate.NotAfter.After(time.Now().Add(7 * 24 * time.Hour)) {
			return errors.New("rotated certificate validity is too short")
		}
		states := map[string]string{"node_certificate": rotation.CertificatePEM}
		if rotation.ControllerCA != "" {
			states["controller_ca"] = rotation.ControllerCA
		}
		return c.store.SetStates(ctx, states)
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
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM([]byte(controllerCA)) {
		return nil, errors.New("invalid controller CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots}, nil
}

func write(ctx context.Context, connection *websocket.Conn, messageType string, data any) error {
	rawData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(protocol.Envelope{Version: protocol.Version, MessageID: uuid.NewString(), Type: messageType, SentAt: time.Now().UTC(), Data: rawData})
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return connection.Write(writeCtx, websocket.MessageText, payload)
}

func writeReply(ctx context.Context, connection *websocket.Conn, messageType, replyTo string, data any) error {
	rawData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(protocol.Envelope{Version: protocol.Version, MessageID: uuid.NewString(), ReplyTo: replyTo, Type: messageType, SentAt: time.Now().UTC(), Data: rawData})
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return connection.Write(writeCtx, websocket.MessageText, payload)
}
func (c *Client) wasSeen(id string) bool {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	_, ok := c.seen[id]
	return ok
}
func (c *Client) markSeen(id string) {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if len(c.seen) > 2048 {
		c.seen = make(map[string]struct{})
	}
	c.seen[id] = struct{}{}
}
