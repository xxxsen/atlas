package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"atlas/internal/cache"
	"atlas/internal/config"
	"atlas/internal/outbound"
	"atlas/internal/provider"
	"atlas/internal/routing"
	"atlas/internal/server"

	"github.com/xxxsen/common/logger"
	"go.uber.org/zap"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON configuration file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		// logger not initialised yet, fallback to stderr
		log.Fatalf("init config failed, err:%v", err)
	}
	logkit := logger.Init(cfg.Log.File, cfg.Log.Level, int(cfg.Log.FileCount),
		int(cfg.Log.FileSize), int(cfg.Log.KeepDays), cfg.Log.Console)
	defer logkit.Sync() //nolint:errcheck

	domainProviders, err := provider.LoadProviders(cfg.DataProviders)
	if err != nil {
		logkit.Fatal("load data providers failed", zap.Error(err))
	}
	outboundManager := outbound.NewManager()
	for _, ob := range cfg.Outbounds {
		resolvers, err := outbound.MakeOutbounds(ob.ServerList)
		if err != nil {
			logkit.Fatal("initialise resolvers failed", zap.Error(err))
		}
		if err := outboundManager.AddOutbound(ob.Tag, resolvers, ob.Parallel); err != nil {
			logkit.Fatal("initialise outbounds failed", zap.Error(err))
		}
	}

	rules, err := routing.BuildRules(cfg.Routes, domainProviders)
	if err != nil {
		logkit.Fatal("initialise routing rules failed", zap.Error(err))
	}

	var responseCache *cache.Cache
	if cfg.Cache.Size > 0 {
		responseCache = cache.New(cfg.Cache.Size, cfg.Cache.Lazy)
	}

	serverOpts := []server.Option{
		server.WithBind(cfg.Bind),
		server.WithOutboundManager(outboundManager),
		server.WithRoutes(rules),
	}
	if responseCache != nil {
		serverOpts = append(serverOpts, server.WithCache(responseCache))
	}

	forwarder, err := server.New(serverOpts...)
	if err != nil {
		logkit.Fatal("initialise server failed", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logkit.Info("dns forwarder listening", zap.String("addr", cfg.Bind))
	if err := forwarder.Start(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, syscall.EINTR) {
		logkit.Fatal("server error", zap.Error(err))
	}
	logkit.Info("shutdown complete")
}
