package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/controlplane"
	"github.com/mirrage11gpt/rmvpn/webembed"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	config, err := controlplane.LoadConfig()
	if err != nil {
		slog.Error("configuration rejected", "error", err)
		os.Exit(1)
	}
	assets, err := fs.Sub(webembed.Dist, "dist")
	if err != nil {
		slog.Error("frontend assets unavailable", "error", err)
		os.Exit(1)
	}
	app, err := controlplane.NewApp(ctx, config, assets)
	if err != nil {
		slog.Error("control startup failed", "error", err)
		os.Exit(1)
	}
	defer app.Close()
	app.StartWorkers(ctx)
	server := &http.Server{Addr: config.ListenAddress, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second}
	go func() {
		slog.Info("RiseVPN Control listening", "address", config.ListenAddress, "version", version)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
