package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	protocol "github.com/mirrage11gpt/rmvpn/protocol/v2"
)

func reservableBytes(remaining, activeReservations, requested int64) int64 {
	available := remaining - activeReservations
	if available < 0 {
		return 0
	}
	if requested > available {
		return available
	}
	if requested < 0 {
		return 0
	}
	return requested
}

func (a *App) provisionDevice(ctx context.Context, deviceID, nodeID string) error {
	if len(a.config.QuotaPrivateKey) != ed25519.PrivateKeySize {
		return errors.New("quota signing key is not configured")
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var credentialHash []byte
	var plan, status string
	var subscriptionEnds, periodEnds *time.Time
	var quota, used int64
	err = tx.QueryRow(ctx, `SELECT d.credential_hash,s.plan_code,s.status,s.period_ends_at,s.period_ends_at,s.quota_bytes,s.used_bytes FROM devices d JOIN subscriptions s ON s.user_id=d.user_id WHERE d.id=$1 AND d.revoked_at IS NULL FOR UPDATE`, deviceID).Scan(&credentialHash, &plan, &status, &subscriptionEnds, &periodEnds, &quota, &used)
	if err != nil {
		return err
	}
	if status != "active" && status != "grace" {
		return errors.New("subscription is not active")
	}
	var active int64
	_ = tx.QueryRow(ctx, `SELECT COALESCE(sum(bytes-consumed_bytes),0) FROM quota_leases WHERE device_id=$1 AND expires_at>now()`, deviceID).Scan(&active)
	if active > 0 {
		return nil
	}
	grant := reservableBytes(quota-used, active, 1_000_000_000)
	if grant == 0 {
		return errors.New("no quota remains")
	}
	now := time.Now().UTC()
	lease := protocol.QuotaLease{LeaseID: uuid.NewString(), DeviceID: deviceID, NodeID: nodeID, Bytes: grant, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), KeyID: "quota-v1"}
	if err = lease.Sign(ed25519.PrivateKey(a.config.QuotaPrivateKey)); err != nil {
		return err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(lease.Signature)
	_, err = tx.Exec(ctx, `INSERT INTO quota_leases(id,device_id,node_id,bytes,issued_at,expires_at,signature) VALUES($1,$2,$3,$4,$5,$6,$7)`, lease.LeaseID, deviceID, nodeID, grant, lease.IssuedAt, lease.ExpiresAt, signature)
	if err != nil {
		return err
	}
	upsert, _ := json.Marshal(protocol.DeviceUpsert{DeviceID: deviceID, CredentialHash: base64.RawURLEncoding.EncodeToString(credentialHash), Plan: plan, Active: true, SubscriptionEnds: valueTime(subscriptionEnds), PeriodEnds: valueTime(periodEnds), QuotaBytes: quota})
	leaseJSON, _ := json.Marshal(lease)
	_, err = tx.Exec(ctx, `INSERT INTO node_commands(node_id,type,payload,expires_at) VALUES($1,'device.upsert',$2,now()+interval '24 hours'),($1,'quota.lease',$3,now()+interval '24 hours')`, nodeID, upsert, leaseJSON)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func valueTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}
