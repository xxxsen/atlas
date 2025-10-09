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
	"atlas/internal/routing"
	"atlas/internal/server"
)

func main() {
	cfgPath := flag.String("config", "", "path to JSON configuration file")
	flag.Parse()

	if *cfgPath == "" {
		log.Fatal("config path is required (use --config)")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	outboundManager, err := outbound.NewManager(cfg.Outbounds)
	if err != nil {
		log.Fatalf("initialise outbounds: %v", err)
	}

	rules, err := routing.BuildRules(cfg.Routes)
	if err != nil {
		log.Fatalf("initialise routing rules: %v", err)
	}

	var responseCache *cache.Cache
	if cfg.Cache.Size > 0 {
		responseCache = cache.New(cfg.Cache.Size, cfg.Cache.Lazy)
	}

	logger := log.New(os.Stdout, "[atlas] ", log.LstdFlags)
	forwarder := server.New(cfg, outboundManager, rules, responseCache, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("dns forwarder listening on %s", cfg.Bind)
	if err := forwarder.Start(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, syscall.EINTR) {
		logger.Fatalf("server error: %v", err)
	}
	logger.Println("shutdown complete")
}
