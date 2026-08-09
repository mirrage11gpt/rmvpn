package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/config"
	"github.com/mirrage11gpt/rmvpn/internal/control"
	"github.com/mirrage11gpt/rmvpn/internal/enrollment"
	"github.com/mirrage11gpt/rmvpn/internal/model"
	"github.com/mirrage11gpt/rmvpn/internal/policy"
	"github.com/mirrage11gpt/rmvpn/internal/security"
	"github.com/mirrage11gpt/rmvpn/internal/server"
	"github.com/mirrage11gpt/rmvpn/internal/store"
	"github.com/mirrage11gpt/rmvpn/internal/usage"
	"github.com/mirrage11gpt/rmvpn/internal/xray"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "risevpn-node:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "status":
		return status(args[1:])
	case "doctor":
		return doctor(args[1:])
	case "enrollment":
		return enrollmentCommand(args[1:])
	case "device":
		return deviceCommand(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "reality-keypair":
		return realityKeypair(args[1:])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: risevpn-node <serve|status|doctor|enrollment|device|version|reality-keypair> [options]")
}

func commonFlags(name string, args []string) (*flag.FlagSet, *string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := flags.String("config", "/etc/risevpn/node.conf", "path to node configuration")
	if err := flags.Parse(args); err != nil {
		return nil, nil, err
	}
	return flags, configPath, nil
}

func openConfigured(path string) (config.Config, *store.Store, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, nil, err
	}
	database, err := store.Open(cfg.DatabasePath)
	return cfg, database, err
}

func serve(args []string) error {
	_, configPath, err := commonFlags("serve", args)
	if err != nil {
		return err
	}
	cfg, database, err := openConfigured(*configPath)
	if err != nil {
		return err
	}
	defer database.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	enrollmentService := enrollment.New(database, cfg.Domain, effectiveVersion(cfg))
	bundle, err := enrollmentService.Ensure(ctx)
	if err != nil {
		return err
	}
	if bundle != "" {
		slog.Info("node is ready for enrollment; use `risevpn-node enrollment show`")
	}
	complianceService := compliance.New(database)
	policyService := policy.New(database, complianceService)
	_ = complianceService.Check(ctx)
	servers := server.New(database, policyService, enrollmentService, complianceService)
	if err := servers.StartInternal(cfg.InternalListen); err != nil {
		return fmt.Errorf("internal API: %w", err)
	}

	e, found, err := database.Enrollment(ctx)
	if err != nil {
		return err
	}
	if found && e.ClaimedAt == nil {
		if err := servers.StartEnrollment(cfg.EnrollmentListen, cfg.TLSCertFile, cfg.TLSKeyFile, nil); err != nil {
			return fmt.Errorf("enrollment API: %w", err)
		}
	}
	collector := usage.New(database, cfg.TrafficStatsURL, cfg.TrafficStatsSecret)
	var xrayManager *xray.Manager
	if cfg.RealityPublicKey != "" && cfg.RealityShortID != "" {
		if err := database.SetStates(ctx, map[string]string{"reality_public_key": cfg.RealityPublicKey, "reality_short_id": cfg.RealityShortID}); err != nil {
			return err
		}
		xrayManager = xray.New(database, cfg.XrayAPIAddress)
		go xrayManager.Run(ctx)
	}
	go collector.Run(ctx)
	if xrayManager != nil {
		go control.New(database, complianceService, effectiveVersion(cfg), collector, xrayManager).Run(ctx)
	} else {
		go control.New(database, complianceService, effectiveVersion(cfg), collector).Run(ctx)
	}
	go complianceLoop(ctx, complianceService)
	slog.Info("RiseVPN node agent started", "version", effectiveVersion(cfg), "internal", cfg.InternalListen)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return servers.Shutdown(shutdown)
}

func realityKeypair(args []string) error {
	flags := flag.NewFlagSet("reality-keypair", flag.ContinueOnError)
	privatePath := flags.String("private-file", "", "private key output path")
	publicPath := flags.String("public-file", "", "public key output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" {
		return errors.New("private-file and public-file are required")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateEncoded := base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	publicEncoded := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	if err := os.WriteFile(*privatePath, []byte(privateEncoded+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(*publicPath, []byte(publicEncoded+"\n"), 0o600)
}

func status(args []string) error {
	_, configPath, err := commonFlags("status", args)
	if err != nil {
		return err
	}
	_, database, err := openConfigured(*configPath)
	if err != nil {
		return err
	}
	defer database.Close()
	ctx := context.Background()
	nodeID, _, _ := database.State(ctx, "node_id")
	e, found, err := database.Enrollment(ctx)
	if err != nil {
		return err
	}
	alerts, err := database.ActiveAlerts(ctx)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"nodeId": nodeID, "claimed": found && e.ClaimedAt != nil, "alerts": alerts})
}

func doctor(args []string) error {
	_, configPath, err := commonFlags("doctor", args)
	if err != nil {
		return err
	}
	cfg, database, err := openConfigured(*configPath)
	if err != nil {
		return err
	}
	defer database.Close()
	checks := map[string]string{"config": "ok", "database": "ok"}
	if _, err := os.Stat(cfg.TLSCertFile); err != nil {
		checks["tlsCertificate"] = err.Error()
	} else {
		checks["tlsCertificate"] = "ok"
	}
	if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
		checks["tlsKey"] = err.Error()
	} else {
		checks["tlsKey"] = "ok"
	}
	if addresses, err := net.LookupHost(cfg.Domain); err != nil || len(addresses) == 0 {
		checks["dns"] = fmt.Sprint(err)
	} else {
		checks["dns"] = strings.Join(addresses, ",")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.TrafficStatsURL, "/")+"/online", nil)
	request.Header.Set("Authorization", cfg.TrafficStatsSecret)
	if response, err := client.Do(request); err != nil {
		checks["hysteriaStats"] = err.Error()
	} else {
		response.Body.Close()
		checks["hysteriaStats"] = fmt.Sprintf("HTTP %d", response.StatusCode)
	}
	return printJSON(checks)
}

func enrollmentCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: risevpn-node enrollment <show|reenroll> --config PATH")
	}
	action := args[0]
	_, configPath, err := commonFlags("enrollment "+action, args[1:])
	if err != nil {
		return err
	}
	cfg, database, err := openConfigured(*configPath)
	if err != nil {
		return err
	}
	defer database.Close()
	service := enrollment.New(database, cfg.Domain, effectiveVersion(cfg))
	var bundle string
	if action == "show" {
		bundle, err = service.Current(context.Background())
	} else if action == "reenroll" {
		bundle, err = service.Reenroll(context.Background())
	} else {
		return errors.New("unknown enrollment action")
	}
	if err != nil {
		return err
	}
	fmt.Println(bundle)
	if action == "reenroll" {
		fmt.Fprintln(os.Stderr, "restart risevpn-node to reopen the temporary enrollment endpoint")
	}
	return nil
}

func deviceCommand(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return errors.New("usage: risevpn-node device issue --plan PLAN [--days N] --config PATH")
	}
	flags := flag.NewFlagSet("device issue", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/risevpn/node.conf", "configuration path")
	planName := flags.String("plan", "TRIAL", "TRIAL, LITE, PLUS or ULTRA")
	days := flags.Int("days", 30, "subscription duration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	cfg, database, err := openConfigured(*configPath)
	if err != nil {
		return err
	}
	defer database.Close()
	plan := model.Plan(strings.ToUpper(*planName))
	planPolicy, ok := plan.Policy()
	if !ok {
		return errors.New("unknown plan")
	}
	credential, err := security.RandomToken(32)
	if err != nil {
		return err
	}
	deviceID, err := security.UUID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if plan == model.Trial {
		*days = 3
	}
	device := model.Device{ID: deviceID, CredentialHash: security.Hash(credential), Plan: plan, Active: true,
		SubscriptionEnds: now.Add(time.Duration(*days) * 24 * time.Hour), PeriodEnds: now.Add(30 * 24 * time.Hour),
		QuotaBytes: planPolicy.QuotaBytes, LeaseBytes: planPolicy.QuotaBytes, LeaseExpires: now.Add(30 * 24 * time.Hour)}
	if err := database.UpsertDevice(context.Background(), device); err != nil {
		return err
	}
	_ = cfg
	return printJSON(map[string]any{"deviceId": deviceID, "credential": credential, "plan": plan})
}

func complianceLoop(ctx context.Context, service *compliance.Service) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := service.Check(ctx); err != nil {
				slog.Error("compliance check failed", "error", err)
			}
		}
	}
}

func effectiveVersion(cfg config.Config) string {
	if version != "dev" {
		return version
	}
	return cfg.AgentVersion
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func init() {
	_ = filepath.Separator
}
