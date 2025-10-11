package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xxxsen/atlas/internal/action"
	_ "github.com/xxxsen/atlas/internal/action/register"
	"github.com/xxxsen/atlas/internal/config"
	"github.com/xxxsen/atlas/internal/matcher"
	_ "github.com/xxxsen/atlas/internal/matcher/register"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/rule"
	"github.com/xxxsen/atlas/internal/server"
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

	resolver.ConfigureCache(resolver.CacheOptions{
		Size:    cfg.Cache.Size,
		Lazy:    cfg.Cache.Lazy,
		Persist: cfg.Cache.Persist,
		File:    cfg.Cache.File,
	})

	ms, err := buildMatcherMap(cfg.Resource.Matcher)
	if err != nil {
		logkit.Fatal("build matcher map failed", zap.Error(err))
	}
	as, err := buildActionMap(cfg.Resource.Action)
	if err != nil {
		logkit.Fatal("build action map failed", zap.Error(err))
	}
	engine, err := buildRuleEngine(cfg.Rules, ms, as)
	if err != nil {
		logkit.Fatal("build rule engine failed", zap.Error(err))
	}

	serverOpts := []server.Option{
		server.WithBind(cfg.Bind),
		server.WithRuleEngine(engine),
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

func buildActionMap(ats []config.ActionConfig) (map[string]action.IDNSAction, error) {
	m := make(map[string]action.IDNSAction, len(ats))
	for _, at := range ats {
		inst, err := action.MakeAction(at.Type, at.Name, at.Data)
		if err != nil {
			return nil, fmt.Errorf("make action failed, name:%s, type:%s, err:%w", at.Name, at.Type, err)
		}
		m[at.Name] = inst
	}
	return m, nil
}

func buildMatcherMap(ms []config.MatcherConfig) (map[string]matcher.IDNSMatcher, error) {
	rs := make(map[string]matcher.IDNSMatcher, len(ms))
	for _, m := range ms {
		inst, err := matcher.MakeMatcher(m.Type, m.Name, m.Data)
		if err != nil {
			return nil, err
		}
		rs[m.Name] = inst
	}
	if _, ok := rs["any"]; !ok {
		anyMatcher, err := matcher.MakeMatcher("any", "any", nil)
		if err != nil {
			return nil, fmt.Errorf("create default any matcher: %w", err)
		}
		rs["any"] = anyMatcher
	}
	return rs, nil
}

func buildRuleEngine(rules []config.Rule, mat map[string]matcher.IDNSMatcher, atm map[string]action.IDNSAction) (rule.IDNSRuleEngine, error) {
	rs := make([]rule.IDNSRule, 0, len(rules))
	for idx, r := range rules {
		remark := r.Remark
		if len(remark) == 0 {
			remark = fmt.Sprintf("rule:%d", idx)
		}
		expr := strings.TrimSpace(r.Match)
		if expr == "" {
			expr = "any"
		}
		m, err := matcher.BuildExpressionMatcher(expr, mat)
		if err != nil {
			return nil, fmt.Errorf("compile matcher expression failed, expr:%s, err:%w", expr, err)
		}
		a, ok := atm[r.Action]
		if !ok {
			return nil, fmt.Errorf("action not found, name:%s", r.Action)
		}
		inst := rule.NewRule(remark, m, a)
		rs = append(rs, inst)
	}
	return rule.NewEngine(rs...), nil
}
