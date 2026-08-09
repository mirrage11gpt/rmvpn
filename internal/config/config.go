package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Domain             string
	MasqueradeURL      string
	DatabasePath       string
	InternalListen     string
	EnrollmentListen   string
	TLSCertFile        string
	TLSKeyFile         string
	TrafficStatsURL    string
	TrafficStatsSecret string
	XrayAPIAddress     string
	RealityPrivateKey  string
	RealityPublicKey   string
	RealityShortID     string
	AgentVersion       string
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	values := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("invalid config line: %q", line)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := s.Err(); err != nil {
		return Config{}, err
	}
	cfg := Config{
		Domain:             values["domain"],
		MasqueradeURL:      values["masquerade_url"],
		DatabasePath:       fallback(values["database_path"], "/var/lib/risevpn/node.db"),
		InternalListen:     fallback(values["internal_listen"], "127.0.0.1:9080"),
		EnrollmentListen:   fallback(values["enrollment_listen"], ":8443"),
		TLSCertFile:        fallback(values["tls_cert_file"], "/etc/letsencrypt/live/"+values["domain"]+"/fullchain.pem"),
		TLSKeyFile:         fallback(values["tls_key_file"], "/etc/letsencrypt/live/"+values["domain"]+"/privkey.pem"),
		TrafficStatsURL:    fallback(values["traffic_stats_url"], "http://127.0.0.1:9999"),
		TrafficStatsSecret: values["traffic_stats_secret"],
		XrayAPIAddress:     fallback(values["xray_api_address"], "127.0.0.1:10085"),
		RealityPrivateKey:  values["reality_private_key"],
		RealityPublicKey:   values["reality_public_key"],
		RealityShortID:     values["reality_short_id"],
		AgentVersion:       fallback(values["agent_version"], "dev"),
	}
	if cfg.Domain == "" || cfg.MasqueradeURL == "" || cfg.TrafficStatsSecret == "" {
		return Config{}, errors.New("domain, masquerade_url and traffic_stats_secret are required")
	}
	return cfg, nil
}

func fallback(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func ParsePort(address string) (int, error) {
	index := strings.LastIndex(address, ":")
	if index < 0 {
		return 0, fmt.Errorf("address has no port: %s", address)
	}
	return strconv.Atoi(address[index+1:])
}
