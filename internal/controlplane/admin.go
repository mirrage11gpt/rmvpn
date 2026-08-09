package controlplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *App) adminOverview(w http.ResponseWriter, r *http.Request) {
	var users, newUsers, active, grace, devices, boundDevices, nodes, alerts int64
	err := a.db.QueryRow(r.Context(), `SELECT
		(SELECT count(*) FROM users),
		(SELECT count(*) FROM users WHERE created_at>=now()-interval '7 days'),
		(SELECT count(*) FROM subscriptions WHERE status IN ('active','grace')),
		(SELECT count(*) FROM subscriptions WHERE status='grace'),
		(SELECT count(*) FROM devices WHERE revoked_at IS NULL),
		(SELECT count(*) FROM devices WHERE revoked_at IS NULL AND hwid_hmac IS NOT NULL),
		(SELECT count(*) FROM nodes WHERE status='healthy'),
		(SELECT count(*) FROM alerts WHERE active)`).Scan(&users, &newUsers, &active, &grace, &devices, &boundDevices, &nodes, &alerts)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить сводку", "")
		return
	}
	jsonResponse(w, 200, map[string]any{"users": users, "newUsers7d": newUsers, "activeSubscriptions": active, "graceSubscriptions": grace, "devices": devices, "boundDevices": boundDevices, "healthyNodes": nodes, "activeAlerts": alerts})
}

func (a *App) adminStatistics(w http.ResponseWriter, r *http.Request) {
	var usage, credits, charges int64
	if err := a.db.QueryRow(r.Context(), `SELECT
		COALESCE((SELECT sum(rx_bytes+tx_bytes) FROM usage_daily WHERE day>=current_date-29),0),
		COALESCE((SELECT sum(amount_kopecks) FROM ledger_entries WHERE amount_kopecks>0 AND created_at>=now()-interval '30 days'),0),
		COALESCE((SELECT -sum(amount_kopecks) FROM ledger_entries WHERE amount_kopecks<0 AND created_at>=now()-interval '30 days'),0)`).Scan(&usage, &credits, &charges); err != nil {
		problem(w, 500, "db", "Не удалось загрузить статистику", "")
		return
	}

	plans := []map[string]any{}
	rows, err := a.db.Query(r.Context(), `SELECT plan_code,count(*),COALESCE(sum(used_bytes),0),COALESCE(sum(quota_bytes),0) FROM subscriptions GROUP BY plan_code ORDER BY CASE plan_code WHEN 'TRIAL' THEN 1 WHEN 'LITE' THEN 2 WHEN 'PLUS' THEN 3 ELSE 4 END`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить статистику", "")
		return
	}
	for rows.Next() {
		var plan string
		var count, used, quota int64
		if rows.Scan(&plan, &count, &used, &quota) == nil {
			plans = append(plans, map[string]any{"plan": plan, "users": count, "usedBytes": used, "quotaBytes": quota})
		}
	}
	rows.Close()

	daily := []map[string]any{}
	rows, err = a.db.Query(r.Context(), `SELECT d.day::date,count(u.id) FROM generate_series(current_date-13,current_date,interval '1 day') AS d(day) LEFT JOIN users u ON u.created_at::date=d.day::date GROUP BY d.day ORDER BY d.day`)
	if err == nil {
		for rows.Next() {
			var day time.Time
			var count int64
			if rows.Scan(&day, &count) == nil {
				daily = append(daily, map[string]any{"day": day.Format("2006-01-02"), "users": count})
			}
		}
		rows.Close()
	}
	jsonResponse(w, 200, map[string]any{"usageBytes30d": usage, "creditsKopecks30d": credits, "chargesKopecks30d": charges, "plans": plans, "registrations": daily})
}

func (a *App) adminUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := a.db.Query(r.Context(), `SELECT u.id,u.display_name,COALESCE(u.username,''),u.status,u.created_at,u.last_login_at,
		w.balance_kopecks,s.plan_code,s.status,s.period_ends_at,s.used_bytes,s.quota_bytes,
		(SELECT count(*) FROM devices d WHERE d.user_id=u.id AND d.revoked_at IS NULL),
		COALESCE((SELECT string_agg(role,',' ORDER BY role) FROM user_roles ur WHERE ur.user_id=u.id),'')
		FROM users u JOIN wallets w ON w.user_id=u.id JOIN subscriptions s ON s.user_id=u.id
		WHERE $1='' OR u.display_name ILIKE '%'||$1||'%' OR COALESCE(u.username,'') ILIKE '%'||$1||'%' OR u.telegram_subject ILIKE '%'||$1||'%'
		ORDER BY u.created_at DESC LIMIT 200`, query)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить пользователей", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, username, status, plan, subscriptionStatus, roles string
		var created time.Time
		var lastLogin, periodEnd *time.Time
		var balance, used, quota, devices int64
		if rows.Scan(&id, &name, &username, &status, &created, &lastLogin, &balance, &plan, &subscriptionStatus, &periodEnd, &used, &quota, &devices, &roles) == nil {
			items = append(items, map[string]any{"id": id, "displayName": name, "username": username, "status": status, "createdAt": created, "lastLoginAt": lastLogin, "balanceKopecks": balance, "plan": plan, "subscriptionStatus": subscriptionStatus, "periodEndsAt": periodEnd, "usedBytes": used, "quotaBytes": quota, "devices": devices, "roles": roles})
		}
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}

func (a *App) updateUserStatus(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	userID := chi.URLParam(r, "userID")
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if decode(r, &body) != nil || (body.Status != "active" && body.Status != "blocked") || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(w, 400, "user-status", "Укажите статус и причину", "")
		return
	}
	if userID == s.UserID && body.Status == "blocked" {
		problem(w, 409, "self-block", "Нельзя заблокировать собственный аккаунт", "")
		return
	}
	var targetRole string
	_ = a.db.QueryRow(r.Context(), `SELECT COALESCE((SELECT role FROM user_roles WHERE user_id=$1 LIMIT 1),'')`, userID).Scan(&targetRole)
	if targetRole != "" && body.Status == "blocked" {
		problem(w, 409, "admin-block", "Сначала снимите административную роль", "")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Статус не изменён", "")
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `UPDATE users SET status=$1 WHERE id=$2`, body.Status, userID)
	if err != nil || tag.RowsAffected() == 0 {
		problem(w, 404, "user", "Пользователь не найден", "")
		return
	}
	if body.Status == "blocked" {
		_, err = tx.Exec(r.Context(), `INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT a.node_id,'device.revoke',jsonb_build_object('deviceId',d.id,'reason','account blocked'),now()+interval '24 hours' FROM devices d JOIN node_assignments a ON a.device_id=d.id WHERE d.user_id=$1 AND d.revoked_at IS NULL`, userID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE node_assignments SET provisioned_at=NULL,updated_at=now() WHERE device_id IN (SELECT id FROM devices WHERE user_id=$1)`, userID)
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'user.status','user',$2,$3,jsonb_build_object('status',$4))`, s.UserID, userID, strings.TrimSpace(body.Reason), body.Status)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "db", "Статус не изменён", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) adjustWallet(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	userID := chi.URLParam(r, "userID")
	var actorRole, targetRole string
	_ = a.db.QueryRow(r.Context(), `SELECT COALESCE((SELECT role FROM user_roles WHERE user_id=$1 LIMIT 1),''),COALESCE((SELECT role FROM user_roles WHERE user_id=$2 LIMIT 1),'')`, s.UserID, userID).Scan(&actorRole, &targetRole)
	if actorRole == "support" && targetRole != "" {
		problem(w, 403, "admin-wallet", "Support не может изменять баланс администратора", "")
		return
	}
	var body struct {
		AmountKopecks int64  `json:"amountKopecks"`
		Reason        string `json:"reason"`
	}
	if decode(r, &body) != nil || body.AmountKopecks == 0 || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(w, 400, "wallet-adjustment", "Укажите ненулевую сумму и причину", "Списание задаётся отрицательной суммой.")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Не удалось изменить баланс", "")
		return
	}
	defer tx.Rollback(r.Context())
	var current int64
	if err = tx.QueryRow(r.Context(), `SELECT balance_kopecks FROM wallets WHERE user_id=$1 FOR UPDATE`, userID).Scan(&current); err != nil {
		problem(w, 404, "user", "Пользователь не найден", "")
		return
	}
	updated := current + body.AmountKopecks
	if updated < 0 {
		problem(w, 409, "negative-balance", "Баланс не может стать отрицательным", "Уменьшите сумму списания.")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	key := "admin-adjustment:" + uuid.NewString()
	_, err = tx.Exec(r.Context(), `UPDATE wallets SET balance_kopecks=$1,updated_at=now() WHERE user_id=$2`, updated, userID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO ledger_entries(user_id,amount_kopecks,balance_after_kopecks,reason,actor_user_id,idempotency_key) VALUES($1,$2,$3,$4,$5,$6)`, userID, body.AmountKopecks, updated, reason, s.UserID, key)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'wallet.adjust','user',$2,$3,jsonb_build_object('amountKopecks',$4::bigint,'balanceAfterKopecks',$5::bigint))`, s.UserID, userID, reason, body.AmountKopecks, updated)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		slog.Error("wallet adjustment failed", "actorUserId", s.UserID, "userId", userID, "amountKopecks", body.AmountKopecks, "error", err)
		problem(w, 500, "ledger", "Баланс не изменён", "")
		return
	}
	jsonResponse(w, 200, map[string]any{"balanceKopecks": updated})
}

func (a *App) admins(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT u.id,u.display_name,COALESCE(u.username,''),ur.role,u.status,COALESCE(t.enabled,false),u.last_login_at FROM user_roles ur JOIN users u ON u.id=ur.user_id LEFT JOIN admin_totp t ON t.user_id=u.id ORDER BY CASE ur.role WHEN 'owner' THEN 1 WHEN 'operator' THEN 2 WHEN 'support' THEN 3 ELSE 4 END,u.display_name`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить команду", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, username, role, status string
		var mfa bool
		var lastLogin *time.Time
		if rows.Scan(&id, &name, &username, &role, &status, &mfa, &lastLogin) == nil {
			items = append(items, map[string]any{"id": id, "displayName": name, "username": username, "role": role, "status": status, "mfaEnabled": mfa, "lastLoginAt": lastLogin})
		}
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}

func (a *App) setAdminRole(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	userID := chi.URLParam(r, "userID")
	var body struct {
		Role   string `json:"role"`
		Reason string `json:"reason"`
	}
	allowed := map[string]bool{"owner": true, "operator": true, "support": true, "auditor": true}
	if decode(r, &body) != nil || !allowed[body.Role] || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(w, 400, "admin-role", "Укажите роль и причину", "")
		return
	}
	var exists bool
	_ = a.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND status='active')`, userID).Scan(&exists)
	if !exists {
		problem(w, 404, "user", "Активный пользователь не найден", "")
		return
	}
	var current string
	_ = a.db.QueryRow(r.Context(), `SELECT COALESCE((SELECT role FROM user_roles WHERE user_id=$1 LIMIT 1),'')`, userID).Scan(&current)
	if current == "owner" && body.Role != "owner" {
		var owners int
		_ = a.db.QueryRow(r.Context(), `SELECT count(*) FROM user_roles WHERE role='owner'`).Scan(&owners)
		if owners <= 1 {
			problem(w, 409, "last-owner", "Нельзя изменить роль последнего владельца", "Сначала назначьте ещё одного Owner.")
			return
		}
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Роль не изменена", "")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `DELETE FROM user_roles WHERE user_id=$1`, userID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO user_roles(user_id,role) VALUES($1,$2)`, userID, body.Role)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'admin.role.set','user',$2,$3,jsonb_build_object('from',$4,'to',$5))`, s.UserID, userID, strings.TrimSpace(body.Reason), current, body.Role)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "db", "Роль не изменена", "")
		return
	}
	jsonResponse(w, 200, map[string]any{"role": body.Role})
}

func (a *App) removeAdminRole(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	userID := chi.URLParam(r, "userID")
	var body struct {
		Reason string `json:"reason"`
	}
	if decode(r, &body) != nil || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(w, 400, "admin-role", "Укажите причину", "")
		return
	}
	var current string
	if err := a.db.QueryRow(r.Context(), `SELECT role FROM user_roles WHERE user_id=$1 LIMIT 1`, userID).Scan(&current); err != nil {
		problem(w, 404, "admin", "Администратор не найден", "")
		return
	}
	if current == "owner" {
		var owners int
		_ = a.db.QueryRow(r.Context(), `SELECT count(*) FROM user_roles WHERE role='owner'`).Scan(&owners)
		if owners <= 1 {
			problem(w, 409, "last-owner", "Нельзя удалить последнего владельца", "")
			return
		}
	}
	if _, err := a.db.Exec(r.Context(), `DELETE FROM user_roles WHERE user_id=$1`, userID); err != nil {
		problem(w, 500, "db", "Права не сняты", "")
		return
	}
	_, _ = a.db.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'admin.role.remove','user',$2,$3,jsonb_build_object('role',$4))`, s.UserID, userID, strings.TrimSpace(body.Reason), current)
	w.WriteHeader(http.StatusNoContent)
}
func (a *App) adminNodes(w http.ResponseWriter, r *http.Request) { a.network(w, r) }
func (a *App) adminAlerts(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT id,key,severity,message,active,created_at,resolved_at FROM alerts ORDER BY active DESC,created_at DESC LIMIT 250`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить уведомления", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, severity, message string
		var active bool
		var created time.Time
		var resolved *time.Time
		_ = rows.Scan(&id, &key, &severity, &message, &active, &created, &resolved)
		items = append(items, map[string]any{"id": id, "key": key, "severity": severity, "message": message, "active": active, "createdAt": created, "resolvedAt": resolved})
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
func (a *App) adminAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT id,actor_user_id,action,subject_type,subject_id,reason,data,created_at FROM audit_events ORDER BY created_at DESC LIMIT 250`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить аудит", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, action, kind, subject string
		var actor, reason *string
		var data []byte
		var created time.Time
		_ = rows.Scan(&id, &actor, &action, &kind, &subject, &reason, &data, &created)
		items = append(items, map[string]any{"id": id, "actorUserId": actor, "action": action, "subjectType": kind, "subjectId": subject, "reason": reason, "data": json.RawMessage(data), "createdAt": created})
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}

func (a *App) adminLedger(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT l.id,l.user_id,u.display_name,COALESCE(u.username,''),l.amount_kopecks,l.balance_after_kopecks,l.reason,l.actor_user_id,l.created_at FROM ledger_entries l JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 250`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить ledger", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, userID, name, username, reason string
		var actor *string
		var amount, balance int64
		var created time.Time
		if rows.Scan(&id, &userID, &name, &username, &amount, &balance, &reason, &actor, &created) == nil {
			items = append(items, map[string]any{"id": id, "userId": userID, "displayName": name, "username": username, "amountKopecks": amount, "balanceAfterKopecks": balance, "reason": reason, "actorUserId": actor, "createdAt": created})
		}
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}

func (a *App) creditWallet(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	userID := chi.URLParam(r, "userID")
	var body struct {
		AmountKopecks  int64  `json:"amountKopecks"`
		Reason         string `json:"reason"`
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if decode(r, &body) != nil || body.AmountKopecks <= 0 || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(w, 400, "invalid-credit", "Укажите положительную сумму и причину", "")
		return
	}
	if body.IdempotencyKey == "" {
		body.IdempotencyKey = uuid.NewString()
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Не удалось изменить баланс", "")
		return
	}
	defer tx.Rollback(r.Context())
	var balance int64
	err = tx.QueryRow(r.Context(), `UPDATE wallets SET balance_kopecks=balance_kopecks+$1,updated_at=now() WHERE user_id=$2 RETURNING balance_kopecks`, body.AmountKopecks, userID).Scan(&balance)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO ledger_entries(user_id,amount_kopecks,balance_after_kopecks,reason,actor_user_id,idempotency_key) VALUES($1,$2,$3,$4,$5,$6)`, userID, body.AmountKopecks, balance, strings.TrimSpace(body.Reason), s.UserID, body.IdempotencyKey)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'wallet.credit','user',$2,$3,jsonb_build_object('amountKopecks',$4::bigint,'balanceAfterKopecks',$5::bigint))`, s.UserID, userID, strings.TrimSpace(body.Reason), body.AmountKopecks, balance)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		slog.Error("wallet credit failed", "actorUserId", s.UserID, "userId", userID, "amountKopecks", body.AmountKopecks, "error", err)
		problem(w, 409, "ledger", "Начисление не выполнено", "Проверьте ключ идемпотентности.")
		return
	}
	jsonResponse(w, 201, map[string]any{"balanceKopecks": balance})
}

func (a *App) enqueueCommand(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	nodeID := chi.URLParam(r, "nodeID")
	var body struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
		Reason  string          `json:"reason"`
	}
	if decode(r, &body) != nil || body.Type == "" || len(body.Payload) == 0 || strings.TrimSpace(body.Reason) == "" {
		problem(w, 400, "command", "Укажите команду, payload и причину", "")
		return
	}
	allowed := map[string]bool{"device.upsert": true, "device.revoke": true, "session.kick": true, "policy.override": true, "certificate.rotate": true, "drain": true, "update": true}
	if !allowed[body.Type] {
		problem(w, 400, "command-type", "Эта команда не поддерживается", "")
		return
	}
	var id string
	err := a.db.QueryRow(r.Context(), `INSERT INTO node_commands(node_id,type,payload,expires_at) VALUES($1,$2,$3,now()+interval '24 hours') RETURNING id`, nodeID, body.Type, body.Payload).Scan(&id)
	if err == nil {
		_, err = a.db.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'node.command','node',$2,$3,jsonb_build_object('commandId',$4,'type',$5))`, s.UserID, nodeID, strings.TrimSpace(body.Reason), id, body.Type)
	}
	if err != nil {
		problem(w, 500, "db", "Не удалось поставить команду в очередь", "")
		return
	}
	jsonResponse(w, 202, map[string]any{"commandId": id, "status": "pending"})
}

func (a *App) queueDeviceCommand(ctx context.Context, deviceID, kind string, payload any) error {
	raw, _ := json.Marshal(payload)
	_, err := a.db.Exec(ctx, `INSERT INTO node_commands(node_id,type,payload,expires_at) SELECT node_id,$2,$3,now()+interval '24 hours' FROM node_assignments WHERE device_id=$1`, deviceID, kind, raw)
	return err
}
