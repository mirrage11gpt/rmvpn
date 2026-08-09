package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type App struct {
	config   Config
	db       *pgxpool.Pool
	redis    *redis.Client
	vault    *Vault
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	assets   fs.FS
	hub      *NodeHub
	issuer   *NodeIssuer
}

type session struct {
	UserID, CSRF, Role string
	AdminMFA           bool
	ExpiresAt          time.Time
}

func NewApp(ctx context.Context, config Config, assets fs.FS) (*App, error) {
	db, err := OpenDatabase(ctx, config.DatabaseURL)
	if err != nil {
		return nil, err
	}
	options, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		db.Close()
		return nil, err
	}
	cache := redis.NewClient(options)
	if err = cache.Ping(ctx).Err(); err != nil {
		db.Close()
		_ = cache.Close()
		return nil, err
	}
	vault, err := NewVault(config.EncryptionKey, config.HWIDKey)
	if err != nil {
		db.Close()
		_ = cache.Close()
		return nil, err
	}
	a := &App{config: config, db: db, redis: cache, vault: vault, assets: assets}
	a.issuer, err = LoadNodeIssuer(config.NodeCACertFile, config.NodeCAKeyFile)
	if err != nil {
		slog.Error("node certificate issuer unavailable", "error", err)
	}
	a.hub = NewNodeHub(db)
	if !config.DevAuth {
		oidcContext := oidc.ClientContext(ctx, telegramOIDCHTTPClient())
		provider, err := oidc.NewProvider(oidcContext, config.TelegramIssuer)
		if err != nil {
			return nil, fmt.Errorf("telegram oidc discovery: %w", err)
		}
		a.verifier = provider.Verifier(&oidc.Config{ClientID: config.TelegramClientID, SupportedSigningAlgs: []string{"RS256"}})
		a.oauth = &oauth2.Config{ClientID: config.TelegramClientID, ClientSecret: config.TelegramSecret, Endpoint: provider.Endpoint(), RedirectURL: strings.TrimRight(config.PublicURL, "/") + "/auth/telegram/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "telegram:bot_access"}}
	}
	if config.DevAuth {
		if err := a.ensureDevOwner(ctx); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *App) Close() { a.db.Close(); _ = a.redis.Close() }

func (a *App) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(a.securityHeaders, a.recoverer, a.requestID)
	r.Get("/healthz", a.health)
	r.Get("/readyz", a.ready)
	r.With(a.rateLimit("oidc-start", 20, time.Minute)).Get("/auth/telegram/start", a.telegramStart)
	r.With(a.rateLimit("oidc-callback", 30, time.Minute)).Get("/auth/telegram/callback", a.telegramCallback)
	r.Post("/auth/logout", a.logout)
	r.With(a.rateLimit("subscription", 120, time.Minute)).Get("/s/{token}", a.subscriptionDocument)
	r.Get("/v2/nodes/connect", a.hub.Connect)
	r.Route("/api/v1", func(api chi.Router) {
		api.Get("/plans", a.plans)
		api.Get("/network", a.network)
		api.Group(func(private chi.Router) {
			private.Use(a.requireSession)
			private.Get("/me", a.me)
			private.Post("/me/accept-terms", a.acceptTerms)
			private.Group(func(accepted chi.Router) {
				accepted.Use(a.requireTerms)
				accepted.Get("/subscription", a.subscription)
				accepted.Get("/devices", a.devices)
				accepted.Post("/devices", a.createDevice)
				accepted.Post("/devices/{id}/subscription", a.deviceSubscription)
				accepted.Post("/devices/{id}/rebind", a.rebindDevice)
				accepted.Post("/subscription/plan", a.changePlan)
			})
			private.Get("/admin/mfa", a.adminMFAStatus)
			private.Post("/admin/mfa/setup", a.adminMFASetup)
			private.With(a.rateLimit("mfa", 10, 5*time.Minute)).Post("/admin/mfa/verify", a.adminMFAVerify)
			private.Route("/admin", func(admin chi.Router) {
				admin.Use(a.requireRole("owner", "operator", "support", "auditor"))
				admin.Get("/overview", a.adminOverview)
				admin.Get("/nodes", a.adminNodes)
				admin.Get("/alerts", a.adminAlerts)
				admin.Get("/audit", a.adminAudit)
				admin.Post("/nodes/enroll", a.requireRole("owner", "operator")(http.HandlerFunc(a.enrollNode)).ServeHTTP)
				admin.Post("/wallets/{userID}/credit", a.requireRole("owner", "support")(http.HandlerFunc(a.creditWallet)).ServeHTTP)
				admin.Post("/nodes/{nodeID}/commands", a.requireRole("owner", "operator")(http.HandlerFunc(a.enqueueCommand)).ServeHTTP)
			})
		})
	})
	r.NotFound(a.frontend)
	return r
}

func (a *App) health(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if a.db.Ping(ctx) != nil || a.redis.Ping(ctx).Err() != nil {
		problem(w, 503, "not-ready", "Сервис ещё не готов", "")
		return
	}
	w.WriteHeader(204)
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' wss:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
func (a *App) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}
func (a *App) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				slog.Error("request panic", "error", v)
				problem(w, 500, "internal", "Внутренняя ошибка", "Повторите попытку позже.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type sessionKey struct{}
type requestIDKey struct{}

func (a *App) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.readSession(r)
		if err != nil {
			problem(w, 401, "unauthorized", "Нужен вход", "Войдите через Telegram.")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && r.Header.Get("X-CSRF-Token") != s.CSRF {
			problem(w, 403, "csrf", "Проверка запроса не пройдена", "Обновите страницу и повторите действие.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
	})
}
func (a *App) requireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, _ := r.Context().Value(sessionKey{}).(session)
			for _, role := range roles {
				if s.Role == role {
					if !s.AdminMFA && !a.config.DevAuth {
						problem(w, 403, "mfa-required", "Требуется второй фактор", "Подтвердите вход одноразовым кодом TOTP.")
						return
					}
					next.ServeHTTP(w, r)
					return
				}
			}
			problem(w, 403, "forbidden", "Недостаточно прав", "")
		})
	}
}
func (a *App) readSession(r *http.Request) (session, error) {
	cookie, err := r.Cookie("rvpn_session")
	if err != nil {
		return session{}, err
	}
	raw, err := a.redis.Get(r.Context(), a.sessionRedisKey(cookie.Value)).Bytes()
	if err == nil {
		var s session
		if json.Unmarshal(raw, &s) == nil && time.Now().Before(s.ExpiresAt) {
			return s, nil
		}
		_ = a.redis.Del(r.Context(), a.sessionRedisKey(cookie.Value)).Err()
	} else if err != redis.Nil {
		return session{}, err
	}

	// Redis is an acceleration layer. A valid, non-revoked PostgreSQL session
	// remains the source of truth and can rebuild the cache after a Redis restart
	// or eviction. MFA verification is intentionally not restored: an admin must
	// confirm TOTP again after cache loss.
	csrfCookie, err := r.Cookie("rvpn_csrf")
	if err != nil || csrfCookie.Value == "" {
		return session{}, errors.New("session cache missing and CSRF cookie unavailable")
	}
	var s session
	err = a.db.QueryRow(r.Context(), `
		SELECT auth.user_id::text, auth.expires_at,
		       COALESCE((SELECT role FROM user_roles WHERE user_id=auth.user_id
		                 ORDER BY CASE role WHEN 'owner' THEN 1 WHEN 'operator' THEN 2 WHEN 'support' THEN 3 ELSE 4 END LIMIT 1),'')
		FROM auth_sessions auth
		JOIN users u ON u.id=auth.user_id
		WHERE auth.token_hash=$1 AND auth.revoked_at IS NULL AND auth.expires_at>now() AND u.status='active'`, Hash(cookie.Value)).Scan(&s.UserID, &s.ExpiresAt, &s.Role)
	if err != nil {
		return session{}, errors.New("session is expired, revoked or unknown")
	}
	s.CSRF = csrfCookie.Value
	raw, err = json.Marshal(s)
	if err != nil {
		return session{}, err
	}
	if err = a.redis.Set(r.Context(), a.sessionRedisKey(cookie.Value), raw, time.Until(s.ExpiresAt)).Err(); err != nil {
		return session{}, err
	}
	return s, nil
}
func (a *App) issueSession(r *http.Request, w http.ResponseWriter, userID, role string, adminMFA bool) error {
	token, err := RandomToken(32)
	if err != nil {
		return err
	}
	csrf, _ := RandomToken(24)
	s := session{UserID: userID, Role: role, CSRF: csrf, AdminMFA: adminMFA, ExpiresAt: time.Now().UTC().Add(sessionTTL)}
	raw, _ := json.Marshal(s)
	if err = a.redis.Set(r.Context(), a.sessionRedisKey(token), raw, sessionTTL).Err(); err != nil {
		return err
	}
	if _, err = a.db.Exec(r.Context(), `INSERT INTO auth_sessions(user_id,token_hash,ip,user_agent,expires_at) VALUES($1,$2,NULLIF($3,'')::inet,$4,$5)`, userID, Hash(token), clientIP(r), r.UserAgent(), s.ExpiresAt); err != nil {
		_ = a.redis.Del(r.Context(), a.sessionRedisKey(token)).Err()
		return err
	}
	secure := strings.HasPrefix(a.config.PublicURL, "https://")
	http.SetCookie(w, &http.Cookie{Name: "rvpn_session", Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds()), Expires: s.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: "rvpn_csrf", Value: csrf, Path: "/", Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()), Expires: s.ExpiresAt})
	return nil
}

func (a *App) telegramStart(w http.ResponseWriter, r *http.Request) {
	if a.config.DevAuth {
		var id, role string
		err := a.db.QueryRow(r.Context(), `SELECT u.id,COALESCE((SELECT role FROM user_roles WHERE user_id=u.id ORDER BY role LIMIT 1),'') FROM users u WHERE telegram_subject=$1`, a.config.DevTelegramSubject).Scan(&id, &role)
		if err != nil || a.issueSession(r, w, id, role, true) != nil {
			problem(w, 500, "dev-auth", "Не удалось выполнить вход", "")
			return
		}
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}
	state, _ := RandomToken(24)
	nonce, _ := RandomToken(24)
	verifier, _ := RandomToken(32)
	challenge := sha256.Sum256([]byte(verifier))
	payload, _ := json.Marshal(map[string]string{"nonce": nonce, "verifier": verifier})
	a.redis.Set(r.Context(), "oidc:"+state, payload, 10*time.Minute)
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256")), http.StatusFound)
}
func (a *App) telegramCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	raw, err := a.redis.GetDel(r.Context(), "oidc:"+state).Bytes()
	if err != nil {
		problem(w, 400, "oidc-state", "Ссылка входа истекла", "Начните вход заново.")
		return
	}
	var pending map[string]string
	_ = json.Unmarshal(raw, &pending)
	token, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", pending["verifier"]))
	if err != nil {
		slog.WarnContext(r.Context(), "telegram authorization code exchange failed", "requestId", currentRequestID(r), "error", err)
		problem(w, 401, "oidc-code", "Telegram не подтвердил вход", "")
		return
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.WarnContext(r.Context(), "telegram token response has no id_token", "requestId", currentRequestID(r))
		problem(w, 401, "oidc-token", "Telegram не вернул идентификатор", "")
		return
	}
	verified, err := a.verifier.Verify(r.Context(), idToken)
	if err != nil {
		slog.WarnContext(r.Context(), "telegram id_token verification failed", "requestId", currentRequestID(r), "error", err)
		problem(w, 401, "oidc-token", "Не удалось проверить вход", "")
		return
	}
	var claims struct {
		Subject  string `json:"sub"`
		Name     string `json:"name"`
		Username string `json:"preferred_username"`
		Picture  string `json:"picture"`
		Nonce    string `json:"nonce"`
	}
	if err = verified.Claims(&claims); err != nil {
		slog.WarnContext(r.Context(), "telegram id_token claims are invalid", "requestId", currentRequestID(r), "error", err)
		problem(w, 401, "oidc-nonce", "Проверка входа не пройдена", "")
		return
	}
	if claims.Nonce != pending["nonce"] {
		slog.WarnContext(r.Context(), "telegram id_token nonce mismatch", "requestId", currentRequestID(r))
		problem(w, 401, "oidc-nonce", "Проверка входа не пройдена", "")
		return
	}
	var userID string
	err = a.db.QueryRow(r.Context(), `INSERT INTO users(telegram_subject,display_name,username,avatar_url,last_login_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(telegram_subject) DO UPDATE SET display_name=excluded.display_name,username=excluded.username,avatar_url=excluded.avatar_url,last_login_at=now() RETURNING id`, claims.Subject, claims.Name, claims.Username, claims.Picture).Scan(&userID)
	if err == nil {
		_, _ = a.db.Exec(r.Context(), `INSERT INTO wallets(user_id) VALUES($1) ON CONFLICT DO NOTHING`, userID)
		_, _ = a.db.Exec(r.Context(), `INSERT INTO subscriptions(user_id,plan_code,status) VALUES($1,'TRIAL','pending_trial') ON CONFLICT(user_id) DO NOTHING`, userID)
	}
	var role string
	if err == nil {
		_ = a.db.QueryRow(r.Context(), `SELECT COALESCE((SELECT role FROM user_roles WHERE user_id=$1 ORDER BY CASE role WHEN 'owner' THEN 1 WHEN 'operator' THEN 2 WHEN 'support' THEN 3 ELSE 4 END LIMIT 1),'')`, userID).Scan(&role)
	}
	if err != nil || a.issueSession(r, w, userID, role, false) != nil {
		problem(w, 500, "login", "Не удалось создать аккаунт", "")
		return
	}
	http.Redirect(w, r, "/app", 302)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("rvpn_session"); err == nil {
		a.redis.Del(r.Context(), a.sessionRedisKey(cookie.Value))
		_, _ = a.db.Exec(r.Context(), `UPDATE auth_sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, Hash(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "rvpn_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	w.WriteHeader(204)
}

func (a *App) ensureDevOwner(ctx context.Context) error {
	var id string
	err := a.db.QueryRow(ctx, `INSERT INTO users(telegram_subject,display_name,last_login_at) VALUES($1,'Владелец RiseVPN',now()) ON CONFLICT(telegram_subject) DO UPDATE SET last_login_at=now() RETURNING id`, a.config.DevTelegramSubject).Scan(&id)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(ctx, `INSERT INTO user_roles(user_id,role) VALUES($1,'owner') ON CONFLICT DO NOTHING; INSERT INTO wallets(user_id,balance_kopecks) VALUES($1,0) ON CONFLICT DO NOTHING; INSERT INTO subscriptions(user_id,plan_code,status) VALUES($1,'TRIAL','pending_trial') ON CONFLICT(user_id) DO NOTHING`, id)
	return err
}

func (a *App) plans(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT code,name,price_kopecks,period_seconds,device_limit,quota_bytes,speed_bps,throttle_bps,p2p_allowed FROM plans ORDER BY price_kopecks`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить тарифы", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var code, name string
		var price, period, quota, speed, throttle int64
		var devices int
		var p2p bool
		_ = rows.Scan(&code, &name, &price, &period, &devices, &quota, &speed, &throttle, &p2p)
		items = append(items, map[string]any{"code": code, "name": name, "priceKopecks": price, "periodSeconds": period, "deviceLimit": devices, "quotaBytes": quota, "speedBps": speed, "throttleBps": throttle, "p2pAllowed": p2p, "automaticLocation": true})
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
func currentSession(r *http.Request) session { return r.Context().Value(sessionKey{}).(session) }
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	var name, username, status string
	var balance int64
	var termsAccepted bool
	err := a.db.QueryRow(r.Context(), `SELECT u.display_name,COALESCE(u.username,''),u.status,w.balance_kopecks,u.terms_accepted_at IS NOT NULL FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.id=$1`, s.UserID).Scan(&name, &username, &status, &balance, &termsAccepted)
	if err != nil {
		problem(w, 404, "user", "Пользователь не найден", "")
		return
	}
	jsonResponse(w, 200, map[string]any{"id": s.UserID, "displayName": name, "username": username, "status": status, "balanceKopecks": balance, "role": s.Role, "csrfToken": s.CSRF, "termsAccepted": termsAccepted})
}

const currentTermsVersion = "2026-08-09"

func (a *App) acceptTerms(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	if _, err := a.db.Exec(r.Context(), `UPDATE users SET terms_accepted_at=COALESCE(terms_accepted_at,now()),terms_version=$1 WHERE id=$2`, currentTermsVersion, s.UserID); err != nil {
		problem(w, 500, "terms", "Не удалось сохранить согласие", "Попробуйте ещё раз.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) requireTerms(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var accepted bool
		if err := a.db.QueryRow(r.Context(), `SELECT terms_accepted_at IS NOT NULL FROM users WHERE id=$1`, currentSession(r).UserID).Scan(&accepted); err != nil || !accepted {
			problem(w, http.StatusPreconditionRequired, "terms-required", "Примите соглашение", "После этого откроются устройства и подписка.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) subscription(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	var item map[string]any
	row := a.db.QueryRow(r.Context(), `SELECT s.plan_code,s.status,s.period_started_at,s.period_ends_at,s.grace_ends_at,s.quota_bytes,s.used_bytes,p.speed_bps,p.throttle_bps,p.p2p_allowed FROM subscriptions s JOIN plans p ON p.code=s.plan_code WHERE s.user_id=$1`, s.UserID)
	var code, status string
	var start, end, grace *time.Time
	var quota, used, speed, throttle int64
	var p2p bool
	if err := row.Scan(&code, &status, &start, &end, &grace, &quota, &used, &speed, &throttle, &p2p); err != nil {
		problem(w, 404, "subscription", "Подписка не найдена", "")
		return
	}
	item = map[string]any{"plan": code, "status": status, "periodStartedAt": start, "periodEndsAt": end, "graceEndsAt": grace, "quotaBytes": quota, "usedBytes": used, "speedBps": speed, "throttleBps": throttle, "p2pAllowed": p2p, "automaticLocation": true}
	jsonResponse(w, 200, item)
}
func (a *App) devices(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	rows, err := a.db.Query(r.Context(), `SELECT id,slot,name,last_bound_at,last_seen_at,revoked_at,hwid_hmac IS NOT NULL FROM devices WHERE user_id=$1 ORDER BY slot`, s.UserID)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить устройства", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name string
		var slot int
		var bound, seen, revoked *time.Time
		var hasHWID bool
		_ = rows.Scan(&id, &slot, &name, &bound, &seen, &revoked, &hasHWID)
		items = append(items, map[string]any{"id": id, "slot": slot, "name": name, "lastBoundAt": bound, "lastSeenAt": seen, "revokedAt": revoked, "bound": hasHWID})
	}
	jsonResponse(w, 200, map[string]any{"items": items})
}
func (a *App) createDevice(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	var body struct {
		Name string `json:"name"`
	}
	if decode(r, &body) != nil || strings.TrimSpace(body.Name) == "" {
		problem(w, 400, "invalid", "Укажите название устройства", "")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Не удалось создать устройство", "")
		return
	}
	defer tx.Rollback(r.Context())
	var limit, count int
	err = tx.QueryRow(r.Context(), `SELECT p.device_limit,(SELECT count(*) FROM devices d WHERE d.user_id=s.user_id AND d.revoked_at IS NULL) FROM subscriptions s JOIN plans p ON p.code=s.plan_code WHERE s.user_id=$1 FOR UPDATE`, s.UserID).Scan(&limit, &count)
	if err != nil || count >= limit {
		problem(w, 409, "device-limit", "Все слоты устройств заняты", "Удалите устройство или смените тариф.")
		return
	}
	credential, _ := RandomToken(32)
	token, _ := RandomToken(32)
	id := uuid.NewString()
	ciphertext, _ := a.vault.Encrypt(credential, []byte(id))
	tokenCiphertext, _ := a.vault.Encrypt(token, []byte("subscription:"+id))
	var slot int
	err = tx.QueryRow(r.Context(), `INSERT INTO devices(id,user_id,slot,name,credential_ciphertext,credential_hash,subscription_token_hash,subscription_token_ciphertext) SELECT $1,$2,COALESCE(max(slot),0)+1,$3,$4,$5,$6,$7 FROM devices WHERE user_id=$2 RETURNING slot`, id, s.UserID, strings.TrimSpace(body.Name), ciphertext, Hash(credential), Hash(token), tokenCiphertext).Scan(&slot)
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "db", "Не удалось создать устройство", "")
		return
	}
	jsonResponse(w, 201, map[string]any{"id": id, "slot": slot, "name": body.Name, "subscriptionUrl": strings.TrimRight(a.config.PublicURL, "/") + "/s/" + token})
}

func (a *App) deviceSubscription(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	id := chi.URLParam(r, "id")
	var encrypted []byte
	if err := a.db.QueryRow(r.Context(), `SELECT subscription_token_ciphertext FROM devices WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, s.UserID).Scan(&encrypted); err != nil {
		problem(w, 404, "device", "Устройство не найдено", "")
		return
	}
	var token string
	var err error
	if len(encrypted) > 0 {
		token, err = a.vault.Decrypt(encrypted, []byte("subscription:"+id))
	} else {
		token, err = RandomToken(32)
		if err == nil {
			encrypted, err = a.vault.Encrypt(token, []byte("subscription:"+id))
		}
		if err == nil {
			_, err = a.db.Exec(r.Context(), `UPDATE devices SET subscription_token_hash=$1,subscription_token_ciphertext=$2 WHERE id=$3 AND user_id=$4`, Hash(token), encrypted, id, s.UserID)
		}
	}
	if err != nil {
		problem(w, 500, "subscription-token", "Не удалось получить ссылку", "Попробуйте ещё раз.")
		return
	}
	jsonResponse(w, 200, map[string]string{"subscriptionUrl": strings.TrimRight(a.config.PublicURL, "/") + "/s/" + token})
}
func (a *App) rebindDevice(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	id := chi.URLParam(r, "id")
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Не удалось перепривязать устройство", "")
		return
	}
	defer tx.Rollback(r.Context())
	var last *time.Time
	err = tx.QueryRow(r.Context(), `SELECT last_bound_at FROM devices WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL FOR UPDATE`, id, s.UserID).Scan(&last)
	if err != nil {
		problem(w, 404, "device", "Устройство не найдено", "")
		return
	}
	if last != nil && last.Add(24*time.Hour).After(time.Now()) {
		problem(w, 429, "rebind-limit", "Перепривязка пока недоступна", "Повторите через 24 часа после предыдущей привязки.")
		return
	}
	credential, _ := RandomToken(32)
	ciphertext, _ := a.vault.Encrypt(credential, []byte(id))
	_, err = tx.Exec(r.Context(), `UPDATE devices SET credential_ciphertext=$1,credential_hash=$2,hwid_hmac=NULL,last_bound_at=NULL WHERE id=$3`, ciphertext, Hash(credential), id)
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM quota_leases WHERE device_id=$1`, id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE node_assignments SET provisioned_at=NULL,updated_at=now() WHERE device_id=$1`, id)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "db", "Не удалось перепривязать устройство", "")
		return
	}
	_ = a.queueDeviceCommand(r.Context(), id, "device.revoke", map[string]any{"deviceId": id, "reason": "credential rotation"})
	w.WriteHeader(204)
}
func (a *App) changePlan(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	var body struct {
		Plan string `json:"plan"`
	}
	if decode(r, &body) != nil || body.Plan == "" || body.Plan == "TRIAL" {
		problem(w, 400, "plan", "Выберите платный тариф", "")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "db", "Не удалось сменить тариф", "")
		return
	}
	defer tx.Rollback(r.Context())
	var currentCode, status string
	var started, ends *time.Time
	var currentQuota, used, balance int64
	err = tx.QueryRow(r.Context(), `SELECT s.plan_code,s.status,s.period_started_at,s.period_ends_at,s.quota_bytes,s.used_bytes,w.balance_kopecks FROM subscriptions s JOIN wallets w ON w.user_id=s.user_id WHERE s.user_id=$1 FOR UPDATE`, s.UserID).Scan(&currentCode, &status, &started, &ends, &currentQuota, &used, &balance)
	if err != nil {
		problem(w, 404, "subscription", "Подписка не найдена", "")
		return
	}
	var current, next PlanTerms
	current.Code = currentCode
	next.Code = body.Plan
	var currentSeconds, nextSeconds int64
	err = tx.QueryRow(r.Context(), `SELECT price_kopecks,quota_bytes,period_seconds FROM plans WHERE code=$1`, currentCode).Scan(&current.PriceKopecks, &current.QuotaBytes, &currentSeconds)
	if err == nil {
		err = tx.QueryRow(r.Context(), `SELECT price_kopecks,quota_bytes,period_seconds FROM plans WHERE code=$1`, body.Plan).Scan(&next.PriceKopecks, &next.QuotaBytes, &nextSeconds)
	}
	current.Duration = time.Duration(currentSeconds) * time.Second
	next.Duration = time.Duration(nextSeconds) * time.Second
	if err != nil {
		problem(w, 400, "plan", "Тариф не найден", "")
		return
	}
	if next.PriceKopecks <= current.PriceKopecks && status == "active" {
		_, err = tx.Exec(r.Context(), `UPDATE subscriptions SET pending_plan_code=$1 WHERE user_id=$2`, body.Plan, s.UserID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'subscription.downgrade','subscription',$2,'user request',jsonb_build_object('from',$3,'to',$4))`, s.UserID, s.UserID, currentCode, body.Plan)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
		if err != nil {
			problem(w, 500, "db", "Не удалось запланировать тариф", "")
			return
		}
		jsonResponse(w, 202, map[string]any{"plan": currentCode, "pendingPlan": body.Plan, "appliesAt": ends})
		return
	}
	now := time.Now().UTC()
	cost := next.PriceKopecks
	quota := next.QuotaBytes
	periodStart := now
	periodEnd := now.Add(paidPeriod)
	if status == "active" && ends != nil && currentCode != "TRIAL" {
		cost, quota = ProrateUpgrade(current, next, now, *ends)
		quota = currentQuota + quota
		periodStart = now
		if started != nil {
			periodStart = *started
		}
		periodEnd = *ends
	}
	if balance < cost {
		problem(w, 409, "balance", "Недостаточно средств", "Пополните баланс через поддержку.")
		return
	}
	newBalance := balance - cost
	key := "plan:" + uuid.NewString()
	_, err = tx.Exec(r.Context(), `UPDATE wallets SET balance_kopecks=$1,updated_at=now() WHERE user_id=$2;UPDATE subscriptions SET plan_code=$3,pending_plan_code=NULL,status='active',period_started_at=$4,period_ends_at=$5,grace_ends_at=NULL,quota_bytes=$6 WHERE user_id=$2`, newBalance, s.UserID, body.Plan, periodStart, periodEnd, quota)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO ledger_entries(user_id,amount_kopecks,balance_after_kopecks,reason,actor_user_id,idempotency_key) VALUES($1,$2,$3,$4,$1,$5)`, s.UserID, -cost, newBalance, "Смена тарифа "+currentCode+" → "+body.Plan, key)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(actor_user_id,action,subject_type,subject_id,reason,data) VALUES($1,'subscription.upgrade','subscription',$1,'user request',jsonb_build_object('from',$2,'to',$3,'costKopecks',$4,'quotaBytes',$5))`, s.UserID, currentCode, body.Plan, cost, quota)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		problem(w, 500, "billing", "Смена тарифа не выполнена", "")
		return
	}
	jsonResponse(w, 200, map[string]any{"plan": body.Plan, "chargedKopecks": cost, "balanceKopecks": newBalance, "quotaBytes": quota, "periodEndsAt": periodEnd})
}

func (a *App) network(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `SELECT id,domain,status,capacity_mbps,load_ratio,controller_rtt_ms,last_heartbeat_at FROM nodes ORDER BY domain`)
	if err != nil {
		problem(w, 500, "db", "Не удалось загрузить сеть", "")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, domain, status string
		var capacity int
		var load float64
		var rtt *int
		var heartbeat *time.Time
		_ = rows.Scan(&id, &domain, &status, &capacity, &load, &rtt, &heartbeat)
		items = append(items, map[string]any{"id": id, "domain": domain, "status": status, "capacityMbps": capacity, "loadRatio": load, "controllerRttMs": rtt, "lastHeartbeatAt": heartbeat})
	}
	jsonResponse(w, 200, map[string]any{"items": items, "automaticSelection": true})
}

func (a *App) subscriptionDocument(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	hwid := strings.TrimSpace(r.Header.Get("X-HWID"))
	if hwid == "" {
		problem(w, 428, "hwid-required", "Нужно привязать устройство", "Откройте ссылку в v2RayTun, чтобы приложение передало X-HWID.")
		return
	}
	var deviceID, subject, domain, nodeID string
	var assignedDomain, assignedNodeID *string
	var cipher, storedHWID []byte
	var plan, status string
	var periodEnd *time.Time
	var termsAccepted bool
	err := a.db.QueryRow(r.Context(), `SELECT d.id,u.telegram_subject,d.credential_ciphertext,d.hwid_hmac,s.plan_code,s.status,s.period_ends_at,n.id::text,n.domain,u.terms_accepted_at IS NOT NULL FROM devices d JOIN users u ON u.id=d.user_id JOIN subscriptions s ON s.user_id=d.user_id LEFT JOIN node_assignments a ON a.device_id=d.id LEFT JOIN nodes n ON n.id=a.node_id WHERE d.subscription_token_hash=$1 AND d.revoked_at IS NULL`, Hash(token)).Scan(&deviceID, &subject, &cipher, &storedHWID, &plan, &status, &periodEnd, &assignedNodeID, &assignedDomain, &termsAccepted)
	if err != nil {
		problem(w, 404, "subscription-token", "Ссылка подписки недействительна", "")
		return
	}
	if !termsAccepted {
		problem(w, http.StatusPreconditionRequired, "terms-required", "Сначала примите соглашение", "Откройте кабинет RiseVPN.")
		return
	}
	fingerprint := a.vault.HWID(hwid)
	if len(storedHWID) == 0 {
		tx, _ := a.db.Begin(r.Context())
		defer tx.Rollback(r.Context())
		if plan == "TRIAL" && status == "pending_trial" {
			var reused bool
			_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM trial_fingerprints WHERE telegram_subject=$1 OR hwid_hmac=$2)`, subject, fingerprint).Scan(&reused)
			if reused {
				problem(w, 409, "trial-used", "Trial уже использован", "Выберите платный тариф.")
				return
			}
			now := time.Now().UTC()
			trialEnd := now.Add(trialDuration)
			_, err = tx.Exec(r.Context(), `UPDATE subscriptions SET status='active',period_started_at=$1,period_ends_at=$2,quota_bytes=20000000000 WHERE user_id=(SELECT user_id FROM devices WHERE id=$3) AND status='pending_trial'`, now, trialEnd, deviceID)
			if err == nil {
				_, err = tx.Exec(r.Context(), `INSERT INTO trial_fingerprints(telegram_subject,hwid_hmac) VALUES($1,$2)`, subject, fingerprint)
			}
			if err == nil {
				periodEnd = ptrTime(trialEnd)
				status = "active"
			}
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE devices SET hwid_hmac=$1,last_bound_at=now(),last_seen_at=now() WHERE id=$2`, fingerprint, deviceID)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
		if err != nil {
			problem(w, 500, "bind", "Не удалось привязать устройство", "")
			return
		}
	} else if !bytesEqual(storedHWID, fingerprint) {
		problem(w, 409, "hwid-mismatch", "Подписка привязана к другому устройству", "Запустите перепривязку в кабинете.")
		return
	}
	if status != "active" && status != "grace" {
		problem(w, 403, "subscription-inactive", "Подписка не активна", "")
		return
	}
	if assignedDomain != nil && assignedNodeID != nil {
		domain = *assignedDomain
		nodeID = *assignedNodeID
	}
	if domain == "" {
		err = a.db.QueryRow(r.Context(), `SELECT id,domain FROM nodes WHERE status='healthy' AND compliance_fetched_at>now()-interval '6 hours' ORDER BY load_ratio ASC,controller_rtt_ms ASC NULLS LAST LIMIT 1`).Scan(&nodeID, &domain)
		if err != nil {
			problem(w, 503, "no-route", "Сейчас нет доступного маршрута", "Попробуйте обновить подписку позже.")
			return
		}
		_, _ = a.db.Exec(r.Context(), `INSERT INTO node_assignments(device_id,node_id,score,provisioned_at) VALUES($1,$2,1,now()) ON CONFLICT(device_id) DO UPDATE SET node_id=excluded.node_id,score=excluded.score,updated_at=now()`, deviceID, nodeID)
	}
	if err = a.provisionDevice(r.Context(), deviceID, nodeID); err != nil {
		problem(w, 503, "provisioning", "Маршрут ещё не готов", "Обновите подписку через несколько секунд.")
		return
	}
	credential, err := a.vault.Decrypt(cipher, []byte(deviceID))
	if err != nil {
		problem(w, 500, "credential", "Не удалось открыть конфигурацию", "")
		return
	}
	uri := hysteriaURI(credential, domain, a.config.HysteriaObfsPassword)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("profile-title", "RiseVPN · Auto")
	w.Header().Set("profile-update-interval", "1")
	w.Header().Set("update-always", "true")
	if periodEnd != nil {
		w.Header().Set("subscription-userinfo", "upload=0; download=0; total=0; expire="+strconv.FormatInt(periodEnd.Unix(), 10))
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(uri + "\n"))
}

func ptrTime(t time.Time) *time.Time { return &t }
func hysteriaURI(credential, domain, obfsPassword string) string {
	query := url.Values{"sni": []string{domain}}
	if obfsPassword != "" {
		query.Set("obfs", "salamander")
		query.Set("obfs-password", obfsPassword)
	}
	return "hysteria2://" + url.QueryEscape(credential) + "@" + domain + ":443/?" + query.Encode() + "#RiseVPN-Auto"
}
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (a *App) frontend(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		problem(w, 404, "not-found", "Маршрут API не найден", "")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || !strings.Contains(path, ".") {
		path = "index.html"
	}
	data, err := fs.ReadFile(a.assets, path)
	if err != nil {
		data, err = fs.ReadFile(a.assets, "index.html")
	}
	if err != nil {
		http.Error(w, "frontend is not built", 503)
		return
	}
	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	}
	if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "text/javascript")
	}
	_, _ = w.Write(data)
}
func decode(r *http.Request, d any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(d)
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, kind, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:risevpn:problem:" + kind, "title": title, "status": status, "detail": detail})
}

func currentRequestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}
