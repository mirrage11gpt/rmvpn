package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	protocol "github.com/mirrage11gpt/rmvpn/protocol/v2"
)

type NodeHub struct {
	db     *pgxpool.Pool
	mu     sync.Mutex
	online map[string]*nodeConnection
}
type nodeConnection struct {
	socket  *websocket.Conn
	writeMu sync.Mutex
}

func NewNodeHub(db *pgxpool.Pool) *NodeHub {
	return &NodeHub{db: db, online: map[string]*nodeConnection{}}
}
func (h *NodeHub) Connect(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-RiseVPN-mTLS") != "verified" || r.Header.Get("X-RiseVPN-Client-Serial") == "" {
		http.Error(w, "node mTLS required", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(8 << 20)
	ctx := r.Context()
	_, raw, err := c.Read(ctx)
	if err != nil {
		return
	}
	var helloEnvelope protocol.Envelope
	if json.Unmarshal(raw, &helloEnvelope) != nil || helloEnvelope.Type != "hello" {
		_ = c.Close(websocket.StatusPolicyViolation, "hello required")
		return
	}
	var hello protocol.Hello
	if json.Unmarshal(helloEnvelope.Data, &hello) != nil || hello.NodeID == "" {
		_ = c.Close(websocket.StatusPolicyViolation, "invalid hello")
		return
	}
	if (hello.RealityPublicKey != "" || hello.RealityShortID != "") && !validRealityHello(hello.RealityPublicKey, hello.RealityShortID) {
		_ = c.Close(websocket.StatusPolicyViolation, "invalid Reality capability")
		return
	}
	var certificateSerial string
	if h.db.QueryRow(ctx, `SELECT CASE WHEN certificate_serial=$2 OR next_certificate_serial=$2 THEN $2 ELSE '' END FROM nodes WHERE id=$1`, hello.NodeID, r.Header.Get("X-RiseVPN-Client-Serial")).Scan(&certificateSerial) != nil || certificateSerial == "" {
		_ = c.Close(websocket.StatusPolicyViolation, "unknown node")
		return
	}
	caps, _ := json.Marshal(hello.Capabilities)
	_, _ = h.db.Exec(ctx, `UPDATE nodes SET status='healthy',agent_version=$1,protocol_version=$2,capabilities=$3,reality_public_key=NULLIF($4,''),reality_short_id=NULLIF($5,''),last_heartbeat_at=now() WHERE id=$6`, hello.AgentVersion, helloEnvelope.Version, caps, hello.RealityPublicKey, hello.RealityShortID, hello.NodeID)
	nc := &nodeConnection{socket: c}
	h.mu.Lock()
	if old := h.online[hello.NodeID]; old != nil {
		_ = old.socket.Close(websocket.StatusNormalClosure, "latest connection wins")
	}
	h.online[hello.NodeID] = nc
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if h.online[hello.NodeID] == nc {
			delete(h.online, hello.NodeID)
		}
		h.mu.Unlock()
		_, _ = h.db.Exec(context.Background(), `UPDATE nodes SET status='offline' WHERE id=$1 AND last_heartbeat_at<now()-interval '30 seconds'`, hello.NodeID)
	}()
	delivery := time.NewTicker(2 * time.Second)
	defer delivery.Stop()
	readCh := make(chan error, 1)
	go func() { readCh <- h.readLoop(ctx, hello.NodeID, nc) }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-delivery.C:
			_ = h.deliver(ctx, hello.NodeID, nc)
		case <-readCh:
			return
		}
	}
}

func validRealityHello(publicKey, shortID string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(decoded) != 32 || len(shortID) == 0 || len(shortID) > 16 || len(shortID)%2 != 0 {
		return false
	}
	_, err = hex.DecodeString(shortID)
	return err == nil
}
func (h *NodeHub) readLoop(ctx context.Context, nodeID string, c *nodeConnection) error {
	for {
		_, raw, err := c.socket.Read(ctx)
		if err != nil {
			return err
		}
		var env protocol.Envelope
		if json.Unmarshal(raw, &env) != nil {
			continue
		}
		switch env.Type {
		case "heartbeat":
			var data struct {
				Load1         float64 `json:"load1"`
				ControllerRTT int     `json:"controllerRttMs"`
				Online        int     `json:"onlineDevices"`
				Status        string  `json:"status"`
			}
			if json.Unmarshal(env.Data, &data) == nil {
				status := data.Status
				if status == "" {
					status = "healthy"
				}
				_, _ = h.db.Exec(ctx, `UPDATE nodes SET status=$1,load_ratio=LEAST(1,$2),controller_rtt_ms=$3,last_heartbeat_at=now() WHERE id=$4`, status, data.Load1, data.ControllerRTT, nodeID)
			}
		case "ack", "nack":
			var ack protocol.Ack
			_ = json.Unmarshal(env.Data, &ack)
			status := "acked"
			if env.Type == "nack" || !ack.OK {
				status = "nacked"
			}
			_, _ = h.db.Exec(ctx, `UPDATE node_commands SET status=$1,acked_at=now(),error=$2 WHERE id=$3 AND node_id=$4`, status, ack.Message, env.ReplyTo, nodeID)
			if status == "acked" {
				_, _ = h.db.Exec(ctx, `UPDATE nodes SET compliance_fetched_at=now(),compliance_version=c.payload->>'version' FROM node_commands c WHERE nodes.id=$1 AND c.id=$2 AND c.node_id=nodes.id AND c.type='compliance.feed'`, nodeID, env.ReplyTo)
				_, _ = h.db.Exec(ctx, `UPDATE nodes SET certificate_serial=next_certificate_serial,certificate_not_after=next_certificate_not_after,next_certificate_serial=NULL,next_certificate_not_after=NULL FROM node_commands c WHERE nodes.id=$1 AND c.id=$2 AND c.node_id=nodes.id AND c.type='certificate.rotate'`, nodeID, env.ReplyTo)
				_, _ = h.db.Exec(ctx, `UPDATE node_assignments SET provisioned_at=now(),updated_at=now() FROM node_commands c WHERE node_assignments.node_id=$1 AND c.id=$2 AND c.node_id=node_assignments.node_id AND c.type='device.upsert' AND node_assignments.device_id=(c.payload->>'deviceId')::uuid`, nodeID, env.ReplyTo)
			}
		case "usage.batch":
			_ = h.usage(ctx, nodeID, env, c)
		}
	}
}
func (h *NodeHub) usage(ctx context.Context, nodeID string, env protocol.Envelope, c *nodeConnection) error {
	var body struct {
		Events []protocol.UsageEvent `json:"events"`
	}
	if json.Unmarshal(env.Data, &body) != nil {
		return errors.New("invalid usage")
	}
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ids := make([]string, 0, len(body.Events))
	for _, event := range body.Events {
		tag, err := tx.Exec(ctx, `INSERT INTO usage_events(node_id,event_id,device_id,rx_bytes,tx_bytes,started_at,ended_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, nodeID, event.EventID, event.DeviceID, event.RXBytes, event.TXBytes, event.StartedAt, event.EndedAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			_, err = tx.Exec(ctx, `UPDATE subscriptions SET used_bytes=used_bytes+$1 WHERE user_id=(SELECT user_id FROM devices WHERE id=$2)`, event.RXBytes+event.TXBytes, event.DeviceID)
			if err != nil {
				return err
			}
			_, _ = tx.Exec(ctx, `INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT a.node_id,'session.kick',jsonb_build_object('deviceId',d.id,'reason','quota exhausted'),now()+interval '24 hours' FROM devices d JOIN subscriptions s ON s.user_id=d.user_id JOIN node_assignments a ON a.device_id=d.id WHERE d.id=$1 AND s.used_bytes>=s.quota_bytes AND NOT EXISTS(SELECT 1 FROM node_commands c WHERE c.node_id=a.node_id AND c.type='session.kick' AND c.payload->>'deviceId'=d.id::text AND c.status IN ('pending','sent'))`, event.DeviceID)
		}
		ids = append(ids, event.EventID)
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	return c.write(ctx, "usage.ack", env.MessageID, map[string]any{"eventIds": ids})
}
func (h *NodeHub) deliver(ctx context.Context, nodeID string, c *nodeConnection) error {
	rows, err := h.db.Query(ctx, `SELECT id,type,payload FROM node_commands WHERE node_id=$1 AND status IN ('pending','sent') AND not_before<=now() AND expires_at>now() ORDER BY created_at LIMIT 50`, nodeID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind string
		var payload json.RawMessage
		if rows.Scan(&id, &kind, &payload) != nil {
			continue
		}
		env := protocol.Envelope{Version: protocol.Version, MessageID: id, Type: kind, SentAt: time.Now().UTC(), Data: payload}
		raw, _ := json.Marshal(env)
		c.writeMu.Lock()
		writeCtx, cancel := context.WithTimeout(ctx, commandDeliveryTimeout(kind))
		err = c.socket.Write(writeCtx, websocket.MessageText, raw)
		cancel()
		c.writeMu.Unlock()
		if err != nil {
			return err
		}
		_, _ = h.db.Exec(ctx, `UPDATE node_commands SET status='sent',attempts=attempts+1,not_before=now()+LEAST(interval '5 minutes',interval '2 seconds'*(2^LEAST(attempts,7))) WHERE id=$1`, id)
	}
	_, _ = h.db.Exec(ctx, `UPDATE node_commands SET status='expired' WHERE node_id=$1 AND status IN ('pending','sent') AND expires_at<=now()`, nodeID)
	return nil
}

func commandDeliveryTimeout(kind string) time.Duration {
	if kind == "compliance.feed" {
		return 2 * time.Minute
	}
	return 10 * time.Second
}

func (c *nodeConnection) write(ctx context.Context, kind, reply string, data any) error {
	rawData, _ := json.Marshal(data)
	env := protocol.Envelope{Version: protocol.Version, MessageID: uuid.NewString(), ReplyTo: reply, Type: kind, SentAt: time.Now().UTC(), Data: rawData}
	raw, _ := json.Marshal(env)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.socket.Write(ctx, websocket.MessageText, raw)
}
