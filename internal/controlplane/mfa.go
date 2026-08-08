package controlplane

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // TOTP compatibility requires HMAC-SHA-1 (RFC 6238).
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *App) adminMFAStatus(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	if s.Role == "" {
		problem(w, http.StatusForbidden, "forbidden", "Недостаточно прав", "")
		return
	}
	var enabled bool
	_ = a.db.QueryRow(r.Context(), `SELECT enabled FROM admin_totp WHERE user_id=$1`, s.UserID).Scan(&enabled)
	jsonResponse(w, http.StatusOK, map[string]any{"enabled": enabled, "verified": s.AdminMFA || a.config.DevAuth})
}

func (a *App) adminMFASetup(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	if s.Role == "" {
		problem(w, http.StatusForbidden, "forbidden", "Недостаточно прав", "")
		return
	}
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		problem(w, 500, "mfa-random", "Не удалось создать второй фактор", "")
		return
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	ciphertext, err := a.vault.Encrypt(secret, []byte("admin-totp:"+s.UserID))
	if err != nil {
		problem(w, 500, "mfa-encrypt", "Не удалось защитить второй фактор", "")
		return
	}
	tag, err := a.db.Exec(r.Context(), `INSERT INTO admin_totp(user_id,secret_ciphertext) VALUES($1,$2) ON CONFLICT DO NOTHING`, s.UserID, ciphertext)
	if err != nil {
		problem(w, 500, "mfa-store", "Не удалось сохранить второй фактор", "")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 409, "mfa-exists", "Второй фактор уже настроен", "Введите код из приложения-аутентификатора.")
		return
	}
	label := url.QueryEscape("RiseVPN:" + s.UserID)
	issuer := url.QueryEscape("RiseVPN")
	jsonResponse(w, http.StatusCreated, map[string]any{"secret": secret, "otpauthUri": fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, issuer)})
}

func (a *App) adminMFAVerify(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	if s.Role == "" {
		problem(w, http.StatusForbidden, "forbidden", "Недостаточно прав", "")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
		problem(w, 400, "mfa-code", "Неверный код", "Введите шесть цифр.")
		return
	}
	var encrypted []byte
	if err := a.db.QueryRow(r.Context(), `SELECT secret_ciphertext FROM admin_totp WHERE user_id=$1`, s.UserID).Scan(&encrypted); err != nil {
		problem(w, 409, "mfa-setup", "Сначала настройте второй фактор", "")
		return
	}
	secret, err := a.vault.Decrypt(encrypted, []byte("admin-totp:"+s.UserID))
	if err != nil || !validTOTP(secret, strings.TrimSpace(body.Code), time.Now().UTC()) {
		problem(w, 401, "mfa-code", "Код не подошёл", "Проверьте время на устройстве и попробуйте снова.")
		return
	}
	if _, err = a.db.Exec(r.Context(), `UPDATE admin_totp SET enabled=true,verified_at=now() WHERE user_id=$1`, s.UserID); err != nil {
		problem(w, 500, "mfa-store", "Не удалось подтвердить второй фактор", "")
		return
	}
	s.AdminMFA = true
	if err = a.updateCurrentSession(r, s); err != nil {
		problem(w, 500, "mfa-session", "Не удалось обновить сессию", "Войдите заново.")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"verified": true})
}

func (a *App) updateCurrentSession(r *http.Request, s session) error {
	cookie, err := r.Cookie("rvpn_session")
	if err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return a.redis.Set(r.Context(), a.sessionRedisKey(cookie.Value), raw, time.Until(s.ExpiresAt)).Err()
}

func validTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	for delta := int64(-1); delta <= 1; delta++ {
		counter := uint64(now.Unix()/30 + delta)
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], counter)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(input[:])
		digest := mac.Sum(nil)
		offset := digest[len(digest)-1] & 0x0f
		value := (binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff) % 1000000
		if hmac.Equal([]byte(code), []byte(fmt.Sprintf("%06d", value))) {
			return true
		}
	}
	return false
}
