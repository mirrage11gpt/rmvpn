package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type Enrollment struct {
	Token     string
	TokenHash string
	ExpiresAt time.Time
	ClaimedAt *time.Time
}

type ComplianceFeed struct {
	Version   string
	UpdatedAt time.Time
	ExpiresAt time.Time
	RulesJSON string
	Signature string
}

type UsageEvent struct {
	ID         int64     `json:"eventId"`
	DeviceID   string    `json:"deviceId"`
	TXBytes    int64     `json:"txBytes"`
	RXBytes    int64     `json:"rxBytes"`
	RecordedAt time.Time `json:"recordedAt"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS enrollment (
			id INTEGER PRIMARY KEY CHECK (id = 1), token TEXT NOT NULL, token_hash TEXT NOT NULL,
			expires_at INTEGER NOT NULL, claimed_at INTEGER)`,
		`CREATE TABLE IF NOT EXISTS devices (
			device_id TEXT PRIMARY KEY, credential_hash TEXT NOT NULL UNIQUE, plan TEXT NOT NULL,
			active INTEGER NOT NULL, subscription_ends INTEGER NOT NULL, period_ends INTEGER NOT NULL,
			quota_bytes INTEGER NOT NULL, used_bytes INTEGER NOT NULL DEFAULT 0,
			lease_bytes INTEGER NOT NULL DEFAULT 0, lease_expires INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS usage_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, tx_bytes INTEGER NOT NULL,
			rx_bytes INTEGER NOT NULL, recorded_at INTEGER NOT NULL, sent_at INTEGER)`,
		`CREATE TABLE IF NOT EXISTS alerts (
			code TEXT PRIMARY KEY, severity TEXT NOT NULL, message TEXT NOT NULL,
			created_at INTEGER NOT NULL, active INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS compliance (
			id INTEGER PRIMARY KEY CHECK (id = 1), version TEXT NOT NULL, updated_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL, rules_json TEXT NOT NULL, signature TEXT NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("database migration: %w", err)
		}
	}
	if exists, err := s.columnExists(ctx, "usage_events", "sent_at"); err != nil {
		return err
	} else if !exists {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE usage_events ADD COLUMN sent_at INTEGER`); err != nil {
			return err
		}
	}
	for column, definition := range map[string]string{"override_up_bps": "INTEGER NOT NULL DEFAULT 0", "override_down_bps": "INTEGER NOT NULL DEFAULT 0", "override_p2p": "INTEGER NOT NULL DEFAULT 0", "override_expires": "INTEGER NOT NULL DEFAULT 0"} {
		exists, err := s.columnExists(ctx, "devices", column)
		if err != nil {
			return err
		}
		if !exists {
			if _, err = s.db.ExecContext(ctx, `ALTER TABLE devices ADD COLUMN `+column+` `+definition); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) columnExists(ctx context.Context, table, column string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notnull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) State(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM state WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func (s *Store) SetState(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO state(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) SetStates(ctx context.Context, values map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO state(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ReplaceEnrollment(ctx context.Context, token, tokenHash string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment(id,token,token_hash,expires_at,claimed_at)
		VALUES(1,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET token=excluded.token,
		token_hash=excluded.token_hash,expires_at=excluded.expires_at,claimed_at=NULL`, token, tokenHash, expires.Unix())
	return err
}

func (s *Store) Enrollment(ctx context.Context) (Enrollment, bool, error) {
	var e Enrollment
	var expires int64
	var claimed sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT token,token_hash,expires_at,claimed_at FROM enrollment WHERE id=1`).
		Scan(&e.Token, &e.TokenHash, &expires, &claimed)
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, false, nil
	}
	if err != nil {
		return Enrollment{}, false, err
	}
	e.ExpiresAt = time.Unix(expires, 0).UTC()
	if claimed.Valid {
		t := time.Unix(claimed.Int64, 0).UTC()
		e.ClaimedAt = &t
	}
	return e, true, nil
}

func (s *Store) Claim(ctx context.Context, tokenHash, controllerURL, controllerPublicKey, nodeCert, controllerCA string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE enrollment SET claimed_at=?
		WHERE id=1 AND token_hash=? AND claimed_at IS NULL AND expires_at>=?`, now.Unix(), tokenHash, now.Unix())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("enrollment token is invalid, expired or already used")
	}
	for key, value := range map[string]string{
		"controller_url": controllerURL, "controller_public_key": controllerPublicKey,
		"node_certificate": nodeCert, "controller_ca": controllerCA,
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO state(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpsertDevice(ctx context.Context, d model.Device) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices(device_id,credential_hash,plan,active,
		subscription_ends,period_ends,quota_bytes,used_bytes,lease_bytes,lease_expires)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
		credential_hash=excluded.credential_hash,plan=excluded.plan,active=excluded.active,
		subscription_ends=excluded.subscription_ends,period_ends=excluded.period_ends,
		quota_bytes=excluded.quota_bytes,
		used_bytes=CASE WHEN devices.period_ends<>excluded.period_ends THEN excluded.used_bytes ELSE devices.used_bytes END,
		lease_bytes=excluded.lease_bytes,lease_expires=excluded.lease_expires`,
		d.ID, d.CredentialHash, string(d.Plan), boolInt(d.Active), d.SubscriptionEnds.Unix(), d.PeriodEnds.Unix(),
		d.QuotaBytes, d.UsedBytes, d.LeaseBytes, d.LeaseExpires.Unix())
	return err
}

func (s *Store) DeviceByCredentialHash(ctx context.Context, hash string) (model.Device, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT device_id,credential_hash,plan,active,subscription_ends,
		period_ends,quota_bytes,used_bytes,lease_bytes,lease_expires,override_up_bps,override_down_bps,override_p2p,override_expires FROM devices WHERE credential_hash=?`, hash)
	return scanDevice(row)
}

func (s *Store) DeviceByID(ctx context.Context, id string) (model.Device, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT device_id,credential_hash,plan,active,subscription_ends,
		period_ends,quota_bytes,used_bytes,lease_bytes,lease_expires,override_up_bps,override_down_bps,override_p2p,override_expires FROM devices WHERE device_id=?`, id)
	return scanDevice(row)
}

type rowScanner interface{ Scan(...any) error }

func scanDevice(row rowScanner) (model.Device, bool, error) {
	var d model.Device
	var plan string
	var active int
	var subscription, period, leaseExpires, overrideExpires int64
	var overrideP2P int
	err := row.Scan(&d.ID, &d.CredentialHash, &plan, &active, &subscription, &period,
		&d.QuotaBytes, &d.UsedBytes, &d.LeaseBytes, &leaseExpires, &d.OverrideUpBPS, &d.OverrideDownBPS, &overrideP2P, &overrideExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, false, nil
	}
	if err != nil {
		return model.Device{}, false, err
	}
	d.Plan, d.Active = model.Plan(plan), active == 1
	d.SubscriptionEnds = time.Unix(subscription, 0).UTC()
	d.PeriodEnds = time.Unix(period, 0).UTC()
	d.LeaseExpires = time.Unix(leaseExpires, 0).UTC()
	d.OverrideP2P = overrideP2P == 1
	d.OverrideExpires = time.Unix(overrideExpires, 0).UTC()
	return d, true, nil
}

func (s *Store) ApplyPolicyOverride(ctx context.Context, id string, up, down int64, p2p bool, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET override_up_bps=?,override_down_bps=?,override_p2p=?,override_expires=? WHERE device_id=?`, up, down, boolInt(p2p), expires.Unix(), id)
	return err
}

func (s *Store) AddUsage(ctx context.Context, deviceID string, txBytes, rxBytes int64, now time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO usage_events(device_id,tx_bytes,rx_bytes,recorded_at) VALUES(?,?,?,?)`,
		deviceID, txBytes, rxBytes, now.Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET used_bytes=used_bytes+? WHERE device_id=?`, txBytes+rxBytes, deviceID); err != nil {
		return 0, err
	}
	var used int64
	if err := tx.QueryRowContext(ctx, `SELECT used_bytes FROM devices WHERE device_id=?`, deviceID).Scan(&used); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return used, nil
}

func (s *Store) PendingUsage(ctx context.Context, limit int) ([]UsageEvent, error) {
	if limit < 1 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,tx_bytes,rx_bytes,recorded_at
		FROM usage_events WHERE sent_at IS NULL ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []UsageEvent
	for rows.Next() {
		var event UsageEvent
		var recorded int64
		if err := rows.Scan(&event.ID, &event.DeviceID, &event.TXBytes, &event.RXBytes, &recorded); err != nil {
			return nil, err
		}
		event.RecordedAt = time.Unix(recorded, 0).UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) MarkUsageSent(ctx context.Context, eventIDs []int64, now time.Time) error {
	if len(eventIDs) == 0 {
		return nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(eventIDs)), ",")
	args := make([]any, 0, len(eventIDs)+1)
	args = append(args, now.Unix())
	for _, id := range eventIDs {
		args = append(args, id)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE usage_events SET sent_at=? WHERE id IN (`+placeholders+`)`, args...)
	return err
}

func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET active=0 WHERE device_id=?`, id)
	return err
}

func (s *Store) SetAlert(ctx context.Context, alert model.Alert) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO alerts(code,severity,message,created_at,active) VALUES(?,?,?,?,?)
		ON CONFLICT(code) DO UPDATE SET severity=excluded.severity,message=excluded.message,
		created_at=excluded.created_at,active=excluded.active`, alert.Code, alert.Severity, alert.Message,
		alert.CreatedAt.Unix(), boolInt(alert.Active))
	return err
}

func (s *Store) ResolveAlert(ctx context.Context, code string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET active=0 WHERE code=?`, code)
	return err
}

func (s *Store) ActiveAlerts(ctx context.Context) ([]model.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT code,severity,message,created_at,active FROM alerts WHERE active=1 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Alert
	for rows.Next() {
		var a model.Alert
		var created int64
		var active int
		if err := rows.Scan(&a.Code, &a.Severity, &a.Message, &created, &active); err != nil {
			return nil, err
		}
		a.CreatedAt, a.Active = time.Unix(created, 0).UTC(), active == 1
		result = append(result, a)
	}
	return result, rows.Err()
}

func (s *Store) SaveCompliance(ctx context.Context, feed ComplianceFeed) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO compliance(id,version,updated_at,expires_at,rules_json,signature)
		VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,
		updated_at=excluded.updated_at,expires_at=excluded.expires_at,rules_json=excluded.rules_json,
		signature=excluded.signature`, feed.Version, feed.UpdatedAt.Unix(), feed.ExpiresAt.Unix(), feed.RulesJSON, feed.Signature)
	return err
}

func (s *Store) Compliance(ctx context.Context) (ComplianceFeed, bool, error) {
	var feed ComplianceFeed
	var updated, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT version,updated_at,expires_at,rules_json,signature FROM compliance WHERE id=1`).
		Scan(&feed.Version, &updated, &expires, &feed.RulesJSON, &feed.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return ComplianceFeed{}, false, nil
	}
	if err != nil {
		return ComplianceFeed{}, false, err
	}
	feed.UpdatedAt, feed.ExpiresAt = time.Unix(updated, 0).UTC(), time.Unix(expires, 0).UTC()
	return feed, true, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
