package controlplane

import (
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddress        string
	PublicURL            string
	ControlURL           string
	DatabaseURL          string
	RedisURL             string
	TelegramIssuer       string
	TelegramClientID     string
	TelegramSecret       string
	TelegramBotToken     string
	SessionSecret        []byte
	EncryptionKey        []byte
	HWIDKey              []byte
	QuotaPrivateKey      []byte
	CompliancePrivateKey []byte
	ComplianceURL        string
	HysteriaObfsPassword string
	NodeCACertFile       string
	NodeCAKeyFile        string
	DevAuth              bool
	DevTelegramSubject   string
}

func LoadConfig() (Config, error) {
	c := Config{
		ListenAddress: env("RISEVPN_LISTEN", ":8080"),
		PublicURL:     env("RISEVPN_PUBLIC_URL", "http://localhost:8080"),
		ControlURL:    env("RISEVPN_CONTROL_URL", "wss://control.localhost/v2/nodes/connect"),
		DatabaseURL:   os.Getenv("DATABASE_URL"), RedisURL: os.Getenv("REDIS_URL"),
		TelegramIssuer:   env("TELEGRAM_OIDC_ISSUER", "https://oauth.telegram.org"),
		TelegramClientID: os.Getenv("TELEGRAM_CLIENT_ID"), TelegramSecret: os.Getenv("TELEGRAM_CLIENT_SECRET"),
		TelegramBotToken:     os.Getenv("TELEGRAM_BOT_TOKEN"),
		ComplianceURL:        env("COMPLIANCE_URL", "https://antifilter.download/list/domains.lst"),
		HysteriaObfsPassword: strings.TrimSpace(os.Getenv("HYSTERIA_OBFS_PASSWORD")),
		NodeCACertFile:       env("NODE_CA_CERT_FILE", "/run/secrets/node_ca.pem"),
		NodeCAKeyFile:        env("NODE_CA_KEY_FILE", "/run/secrets/node_ca.key"),
		DevAuth:              envBool("RISEVPN_DEV_AUTH"), DevTelegramSubject: env("RISEVPN_DEV_TELEGRAM_SUBJECT", "dev-owner"),
	}
	var err error
	if c.SessionSecret, err = secret("SESSION_SECRET", 32, c.DevAuth); err != nil {
		return c, err
	}
	if c.EncryptionKey, err = secret("ENCRYPTION_KEY", 32, c.DevAuth); err != nil {
		return c, err
	}
	if c.HWIDKey, err = secret("HWID_HMAC_KEY", 32, c.DevAuth); err != nil {
		return c, err
	}
	c.QuotaPrivateKey, _ = decodeOptional("QUOTA_ED25519_PRIVATE_KEY")
	c.CompliancePrivateKey, _ = decodeOptional("COMPLIANCE_ED25519_PRIVATE_KEY")
	if c.DatabaseURL == "" || c.RedisURL == "" {
		return c, errors.New("DATABASE_URL and REDIS_URL are required")
	}
	if !c.DevAuth && (c.TelegramClientID == "" || c.TelegramSecret == "") {
		return c, errors.New("Telegram OIDC credentials are required")
	}
	return c, nil
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
func envBool(key string) bool { v, _ := strconv.ParseBool(os.Getenv(key)); return v }
func decodeOptional(key string) ([]byte, error) {
	if os.Getenv(key) == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(os.Getenv(key))
}
func secret(key string, size int, development bool) ([]byte, error) {
	decoded, err := decodeOptional(key)
	if len(decoded) == size {
		return decoded, nil
	}
	if development {
		return []byte(strings.Repeat(key+"-", size))[:size], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New(key + " must be base64url and exactly " + strconv.Itoa(size) + " bytes")
}

const (
	sessionTTL    = 30 * 24 * time.Hour
	trialDuration = 3 * 24 * time.Hour
	paidPeriod    = 30 * 24 * time.Hour
	graceDuration = 24 * time.Hour
)
