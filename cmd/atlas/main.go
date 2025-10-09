package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"atlas/internal/cache"
	"atlas/internal/config"
	"atlas/internal/outbound"
	"atlas/internal/routing"
	"atlas/internal/server"

	"github.com/xxxsen/common/logger"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON configuration file")
	flag.Parse()

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "config path is required (use --config)")
		os.Exit(1)
	}

	logkit := logger.Init("", "info", 0, 0, 0, true)
	defer logkit.Sync() //nolint:errcheck
	rootLogger := logutil.GetLogger(context.Background())

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		rootLogger.Fatal("load config failed", zap.Error(err))
	}

	outboundManager, err := outbound.NewManager(cfg.Outbounds)
	if err != nil {
		rootLogger.Fatal("initialise outbounds failed", zap.Error(err))
	}

	rules, err := routing.BuildRules(cfg.Routes)
	if err != nil {
		rootLogger.Fatal("initialise routing rules failed", zap.Error(err))
	}

	var responseCache *cache.Cache
	if cfg.Cache.Size > 0 {
		responseCache = cache.New(cfg.Cache.Size, cfg.Cache.Lazy)
	}

	forwarder := server.New(cfg, outboundManager, rules, responseCache)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rootLogger.Info("dns forwarder listening", zap.String("addr", cfg.Bind))
	if err := forwarder.Start(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, syscall.EINTR) {
		rootLogger.Fatal("server error", zap.Error(err))
	}
	rootLogger.Info("shutdown complete")
}
