package controlplane

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	protocol "github.com/mirrage11gpt/rmvpn/protocol/v2"
	"golang.org/x/net/idna"
)

func (a *App) StartWorkers(ctx context.Context) {
	go a.workerLoop(ctx, "lifecycle", time.Minute, a.subscriptionLifecycle)
	go a.workerLoop(ctx, "notifications", 20*time.Second, a.deliverNotifications)
	go a.workerLoop(ctx, "compliance", 15*time.Minute, a.refreshCompliance)
	go a.workerLoop(ctx, "retention", 24*time.Hour, a.enforceRetention)
	go a.workerLoop(ctx, "certificate-rotation", 6*time.Hour, a.rotateCertificates)
}
func (a *App) workerLoop(ctx context.Context, name string, every time.Duration, job func(context.Context) error) {
	if err := job(ctx); err != nil {
		slog.Warn("worker failed", "worker", name, "error", err)
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := job(ctx); err != nil {
				slog.Warn("worker failed", "worker", name, "error", err)
			}
		}
	}
}

func (a *App) subscriptionLifecycle(ctx context.Context) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `WITH due AS (SELECT s.user_id,s.period_ends_at,COALESCE(s.pending_plan_code,s.plan_code) target_plan,p.price_kopecks,p.quota_bytes FROM subscriptions s JOIN plans p ON p.code=COALESCE(s.pending_plan_code,s.plan_code) JOIN wallets w ON w.user_id=s.user_id WHERE s.plan_code<>'TRIAL' AND s.status='active' AND s.period_ends_at<=now() AND w.balance_kopecks>=p.price_kopecks FOR UPDATE OF s,w), debited AS (UPDATE wallets w SET balance_kopecks=w.balance_kopecks-d.price_kopecks,updated_at=now() FROM due d WHERE w.user_id=d.user_id RETURNING w.user_id,w.balance_kopecks,d.price_kopecks,d.target_plan,d.quota_bytes,d.period_ends_at), renewed AS (UPDATE subscriptions s SET plan_code=d.target_plan,pending_plan_code=NULL,status='active',period_started_at=d.period_ends_at,period_ends_at=d.period_ends_at+interval '30 days',grace_ends_at=NULL,quota_bytes=d.quota_bytes,used_bytes=0 FROM debited d WHERE s.user_id=d.user_id RETURNING s.user_id,d.balance_kopecks,d.price_kopecks,d.period_ends_at,d.target_plan) INSERT INTO ledger_entries(user_id,amount_kopecks,balance_after_kopecks,reason,actor_user_id,idempotency_key) SELECT user_id,-price_kopecks,balance_kopecks,'Автопродление '||target_plan,user_id,'renew:'||user_id::text||':'||extract(epoch from period_ends_at)::bigint FROM renewed ON CONFLICT(idempotency_key) DO NOTHING`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE subscriptions SET status='expired' WHERE plan_code='TRIAL' AND status='active' AND period_ends_at<=now();
UPDATE subscriptions SET status='grace',grace_ends_at=now()+interval '24 hours' WHERE plan_code<>'TRIAL' AND status='active' AND period_ends_at<=now();
UPDATE subscriptions SET status='suspended' WHERE status='grace' AND grace_ends_at<=now()`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT a.node_id,'policy.override',jsonb_build_object('deviceId',d.id,'upBps',1000000,'downBps',1000000,'p2pAllowed',false,'expiresAt',s.grace_ends_at),now()+interval '24 hours' FROM devices d JOIN subscriptions s ON s.user_id=d.user_id JOIN node_assignments a ON a.device_id=d.id WHERE s.status='grace' AND s.grace_ends_at>now()+interval '23 hours 58 minutes'`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT a.node_id,'session.kick',jsonb_build_object('deviceId',d.id,'reason','subscription ended'),now()+interval '24 hours' FROM devices d JOIN subscriptions s ON s.user_id=d.user_id JOIN node_assignments a ON a.device_id=d.id WHERE s.status IN ('expired','suspended') AND COALESCE(s.grace_ends_at,s.period_ends_at)>now()-interval '2 minutes' AND NOT EXISTS(SELECT 1 FROM node_commands c WHERE c.node_id=a.node_id AND c.type='session.kick' AND c.payload->>'deviceId'=d.id::text AND c.status IN ('pending','sent'))`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO notifications(user_id,kind,payload,scheduled_at)
SELECT user_id,'trial.'||hours||'h',jsonb_build_object('hours',hours,'periodEndsAt',period_ends_at),period_ends_at-(hours||' hours')::interval FROM subscriptions CROSS JOIN unnest(ARRAY[48,24,12,6,3,1]) hours WHERE plan_code='TRIAL' AND status='active' AND period_ends_at>now() ON CONFLICT DO NOTHING;
INSERT INTO notifications(user_id,kind,payload,scheduled_at) SELECT user_id,'grace.entered','{}',now() FROM subscriptions WHERE status='grace' AND grace_ends_at>now()-interval '2 minutes' ON CONFLICT DO NOTHING;
INSERT INTO notifications(user_id,kind,payload,scheduled_at) SELECT user_id,'grace.'||hours||'h',jsonb_build_object('hours',hours,'graceEndsAt',grace_ends_at),grace_ends_at-(hours||' hours')::interval FROM subscriptions CROSS JOIN unnest(ARRAY[12,1]) hours WHERE status='grace' ON CONFLICT DO NOTHING;
INSERT INTO notifications(user_id,kind,payload,scheduled_at) SELECT user_id,'trial.blocked','{}',period_ends_at FROM subscriptions WHERE plan_code='TRIAL' AND status='expired' AND period_ends_at>now()-interval '2 minutes' ON CONFLICT DO NOTHING;
INSERT INTO notifications(user_id,kind,payload,scheduled_at) SELECT user_id,'grace.blocked','{}',grace_ends_at FROM subscriptions WHERE status='suspended' AND grace_ends_at>now()-interval '2 minutes' ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a *App) deliverNotifications(ctx context.Context) error {
	if a.config.TelegramBotToken == "" {
		return nil
	}
	rows, err := a.db.Query(ctx, `SELECT n.id,u.telegram_subject,n.kind,n.payload FROM notifications n JOIN users u ON u.id=n.user_id WHERE n.sent_at IS NULL AND n.scheduled_at<=now() AND n.attempts<10 ORDER BY n.scheduled_at LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type item struct {
		id, subject, kind string
		payload           []byte
	}
	var items []item
	for rows.Next() {
		var i item
		if rows.Scan(&i.id, &i.subject, &i.kind, &i.payload) == nil {
			items = append(items, i)
		}
	}
	for _, i := range items {
		text := notificationText(i.kind)
		form := url.Values{"chat_id": {i.subject}, "text": {text}}
		request, _ := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+a.config.TelegramBotToken+"/sendMessage", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := http.DefaultClient.Do(request)
		if err == nil && response.StatusCode/100 == 2 {
			_, _ = a.db.Exec(ctx, `UPDATE notifications SET sent_at=now(),attempts=attempts+1 WHERE id=$1`, i.id)
		} else {
			message := "request failed"
			if err != nil {
				message = err.Error()
			}
			_, _ = a.db.Exec(ctx, `UPDATE notifications SET attempts=attempts+1,last_error=$2 WHERE id=$1`, i.id, message)
		}
		if response != nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}
	return nil
}
func notificationText(kind string) string {
	switch {
	case strings.HasPrefix(kind, "trial."):
		if kind == "trial.blocked" {
			return "RiseVPN: Trial завершён, подключение отключено."
		}
		return "RiseVPN: Trial скоро завершится. Проверьте срок в кабинете."
	case kind == "grace.entered":
		return "RiseVPN: подписка перешла в Grace на 24 часа. Скорость ограничена до 1 Мбит/с, P2P отключён."
	case strings.HasPrefix(kind, "grace."):
		if kind == "grace.blocked" {
			return "RiseVPN: Grace завершён, подключение заблокировано."
		}
		return "RiseVPN: Grace скоро завершится, после чего подключение будет заблокировано."
	default:
		return "RiseVPN: изменилось состояние подписки."
	}
}

func (a *App) refreshCompliance(ctx context.Context) error {
	if len(a.config.CompliancePrivateKey) != ed25519.PrivateKeySize {
		_, _ = a.db.Exec(ctx, `INSERT INTO alerts(key,severity,message) VALUES('COMPLIANCE_KEY_MISSING','critical','Compliance signing key is not configured') ON CONFLICT(key) DO UPDATE SET active=true,resolved_at=NULL,message=excluded.message`)
		return nil
	}
	var etag, lastModified string
	var oldCount int
	_ = a.db.QueryRow(ctx, `SELECT COALESCE(etag,''),COALESCE(last_modified,''),jsonb_array_length(domains) FROM compliance_snapshots WHERE valid ORDER BY fetched_at DESC LIMIT 1`).Scan(&etag, &lastModified, &oldCount)
	request, err := http.NewRequestWithContext(ctx, "GET", a.config.ComplianceURL, nil)
	if err != nil {
		return err
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		request.Header.Set("If-Modified-Since", lastModified)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return a.complianceFailure(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode == 304 {
		_, _ = a.db.Exec(ctx, `UPDATE alerts SET active=false,resolved_at=now() WHERE key='COMPLIANCE_STALE'`)
		return nil
	}
	if response.StatusCode != 200 {
		return a.complianceFailure(ctx, fmt.Errorf("feed HTTP %d", response.StatusCode))
	}
	limited := io.LimitReader(response.Body, 32<<20)
	domains, err := parseDomains(limited)
	if err != nil {
		return a.complianceFailure(ctx, err)
	}
	if len(domains) == 0 || (oldCount > 0 && len(domains) < oldCount/2) {
		return a.complianceFailure(ctx, fmt.Errorf("anomalous feed size %d (previous %d)", len(domains), oldCount))
	}
	rawRules, _ := json.Marshal(map[string]any{"blockedDomains": domains, "blockedCidrs": []string{}, "blockedPorts": []int{}})
	now := time.Now().UTC()
	sum := sha256.Sum256(rawRules)
	feed := compliance.SignedFeed{Version: base64.RawURLEncoding.EncodeToString(sum[:12]), UpdatedAt: now, ExpiresAt: now.Add(6 * time.Hour), Rules: rawRules}
	if err = compliance.Sign(&feed, ed25519.PrivateKey(a.config.CompliancePrivateKey)); err != nil {
		return err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(feed.Signature)
	domainJSON, _ := json.Marshal(domains)
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO compliance_snapshots(version,source_url,etag,last_modified,domains,signature,fetched_at,valid) VALUES($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT(version) DO NOTHING`, feed.Version, a.config.ComplianceURL, response.Header.Get("ETag"), response.Header.Get("Last-Modified"), domainJSON, signature, now)
	if err == nil {
		payload, _ := json.Marshal(feed)
		_, err = tx.Exec(ctx, `INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT id,'compliance.feed',$1,now()+interval '24 hours' FROM nodes WHERE status<>'pending'`, payload)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE alerts SET active=false,resolved_at=now() WHERE key IN ('COMPLIANCE_STALE','COMPLIANCE_KEY_MISSING')`)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func parseDomains(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := map[string]struct{}{}
	domains := make([]string, 0, 10000)
	invalid := 0
	total := 0
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		if strings.ContainsAny(line, " /:@\t") || len(line) > 253 {
			invalid++
			continue
		}
		ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(line, "."))
		if err != nil || !strings.Contains(ascii, ".") {
			invalid++
			continue
		}
		if _, ok := seen[ascii]; !ok {
			seen[ascii] = struct{}{}
			domains = append(domains, ascii)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(domains) == 0 || invalid > 1000 || (invalid > 5 && invalid*20 > total) {
		return nil, fmt.Errorf("feed contains too many invalid domains: %d of %d", invalid, total)
	}
	return domains, nil
}
func (a *App) complianceFailure(ctx context.Context, cause error) error {
	_, _ = a.db.Exec(ctx, `INSERT INTO alerts(key,severity,message) VALUES('COMPLIANCE_STALE','critical',$1) ON CONFLICT(key) DO UPDATE SET active=true,resolved_at=NULL,message=excluded.message`, "Compliance refresh failed; last-known-good remains active: "+cause.Error())
	return cause
}

func (a *App) enforceRetention(ctx context.Context) error {
	_, err := a.db.Exec(ctx, `DELETE FROM auth_sessions WHERE created_at<now()-interval '90 days';DELETE FROM usage_events WHERE received_at<now()-interval '13 months';DELETE FROM usage_daily WHERE day<current_date-interval '13 months'`)
	return err
}

func (a *App) rotateCertificates(ctx context.Context) error {
	if a.issuer == nil {
		return nil
	}
	rows, err := a.db.Query(ctx, `SELECT id::text,public_key FROM nodes n WHERE certificate_not_after<now()+interval '7 days' AND status<>'pending' AND NOT EXISTS(SELECT 1 FROM node_commands c WHERE c.node_id=n.id AND c.type='certificate.rotate' AND c.status IN ('pending','sent'))`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type candidate struct {
		id  string
		key []byte
	}
	var nodes []candidate
	for rows.Next() {
		var n candidate
		if rows.Scan(&n.id, &n.key) == nil {
			nodes = append(nodes, n)
		}
	}
	for _, node := range nodes {
		if len(node.key) != ed25519.PublicKeySize {
			continue
		}
		pemValue, certificate, err := a.issuer.Issue(node.id, ed25519.PublicKey(node.key), time.Now().UTC())
		if err != nil {
			return err
		}
		payload, _ := json.Marshal(protocol.CertificateRotate{CertificatePEM: pemValue, ControllerCA: a.issuer.certificatePEM, NotAfter: certificate.NotAfter})
		_, err = a.db.Exec(ctx, `WITH prepared AS (UPDATE nodes SET next_certificate_serial=$1,next_certificate_not_after=$2 WHERE id=$3 RETURNING id) INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT id,'certificate.rotate',$4,now()+interval '24 hours' FROM prepared`, certificate.SerialNumber.String(), certificate.NotAfter, node.id, payload)
		if err != nil {
			return err
		}
	}
	return nil
}
