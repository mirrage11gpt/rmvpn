package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (a *App) adminOverview(w http.ResponseWriter, r *http.Request) {
	var users, active, devices, nodes, alerts int64
	_ = a.db.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM subscriptions WHERE status IN ('active','grace')),(SELECT count(*) FROM devices WHERE revoked_at IS NULL),(SELECT count(*) FROM nodes WHERE status='healthy'),(SELECT count(*) FROM alerts WHERE active)`).Scan(&users, &active, &devices, &nodes, &alerts)
	jsonResponse(w, 200, map[string]any{"users": users, "activeSubscriptions": active, "devices": devices, "healthyNodes": nodes, "activeAlerts": alerts})
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
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'wallet.credit','user',$2,$3,jsonb_build_object('amountKopecks',$4,'balanceAfterKopecks',$5))`, s.UserID, userID, strings.TrimSpace(body.Reason), body.AmountKopecks, balance)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
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
