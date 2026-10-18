package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/xxxsen/atlas/internal/action"
	_ "github.com/xxxsen/atlas/internal/action/register"
	"github.com/xxxsen/atlas/internal/bootstrap"
	"github.com/xxxsen/atlas/internal/config"
	"github.com/xxxsen/atlas/internal/hosts"
	"github.com/xxxsen/atlas/internal/ipset"
	"github.com/xxxsen/atlas/internal/matcher"
	_ "github.com/xxxsen/atlas/internal/matcher/register"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/rule"
	"github.com/xxxsen/atlas/internal/server"
	"github.com/xxxsen/common/logger"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := newRootCommand(time.Now).Execute(); err != nil {
		log.Printf("atlas stopped with error: %v", err)
		os.Exit(1)
	}
}

func newRootCommand(now func() time.Time) *cobra.Command {
	var configPath string
	var showVersion bool
	cmd := &cobra.Command{
		Use:           "atlas",
		Short:         "DNS forwarder with verified bootstrap resolution",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if showVersion {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "atlas %s (commit %s, built %s)\n", version, commit, buildDate)
				return err
			}
			return run(configPath)
		},
	}
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.Flags().StringVar(&configPath, "config", "", "path to YAML configuration file")
	cmd.Flags().BoolVar(&showVersion, "version", false, "print version information and exit")
	cmd.AddCommand(newBootstrapCommand(now))
	return cmd
}

func run(configPath string) (returnErr error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("initialize config: %w", err)
	}
	logkit := logger.Init(cfg.Log.File, cfg.Log.Level, int(cfg.Log.FileCount),
		int(cfg.Log.FileSize), int(cfg.Log.KeepDays), cfg.Log.Console)
	defer func() {
		if err := logkit.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTTY) && returnErr == nil {
			returnErr = fmt.Errorf("flush logger: %w", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ipSets, err := ipset.Load(cfg.Resource.IPSet)
	if err != nil {
		return fmt.Errorf("initialize IP sets: %w", err)
	}
	for _, set := range cfg.Resource.IPSet {
		format := strings.ToLower(strings.TrimSpace(set.Format))
		if format == "" {
			format = "cidr"
		}
		logkit.Info("loaded IP set", zap.String("name", set.Name), zap.String("format", format), zap.Strings("files", set.Files), zap.Strings("countries", set.Countries), zap.Int("cidr_count", ipSets.Count(set.Name)))
	}

	var cacheManager *resolver.CacheManager
	cacheOptions, err := makeCacheOptions(cfg)
	if err != nil {
		return err
	}
	if cfg.Cache.Size > 0 {
		ordinaryCacheOptions := cacheOptions
		ordinaryCacheOptions.QueryTimeout = time.Duration(cfg.Server.RequestTimeout) * time.Second
		cacheManager, err = resolver.NewCacheManager(ctx, ordinaryCacheOptions)
		if err != nil {
			return fmt.Errorf("initialize cache: %w", err)
		}
		if warning := cacheManager.LastPersistenceError(); warning != nil {
			logkit.Warn("discarded unusable DNS cache persistence data", zap.Error(warning))
		}
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cacheManager.Close(closeCtx); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close cache: %w", err))
			}
		}()
	}

	ms, err := buildMatcherMap(cfg.Resource.Matcher)
	if err != nil {
		return fmt.Errorf("build matcher map: %w", err)
	}
	as, err := buildActionMap(cfg.Resource.Action, action.Dependencies{
		Cache: cacheManager, IPSets: ipSets,
		QueryTimeout: time.Duration(cfg.Server.RequestTimeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("build action map: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeActions(as))
	}()
	hosts, err := buildHostStore(cfg.Resource.Host)
	if err != nil {
		return fmt.Errorf("build host store: %w", err)
	}
	var bootstrapManager *bootstrap.Manager
	if cfg.Bootstrap != nil {
		bootstrapManager, err = bootstrap.New(ctx, *cfg.Bootstrap, bootstrap.Options{Cache: cacheOptions, Hosts: hosts})
		if err != nil {
			return fmt.Errorf("initialize bootstrap: %w", err)
		}
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			returnErr = errors.Join(returnErr, bootstrapManager.Close(closeCtx))
		}()
	}
	engine, err := buildRuleEngine(cfg.Rule, ms, as)
	if err != nil {
		return fmt.Errorf("build rule engine: %w", err)
	}

	serverOpts := []server.Option{
		server.WithBind(cfg.Bind),
		server.WithHostResolver(hosts),
		server.WithRuleEngine(engine),
		server.WithUDPSize(cfg.Server.UDPSize),
		server.WithMaxResponseUDPSize(cfg.Server.MaxResponseUDPSize),
		server.WithMaxInflight(cfg.Server.MaxInflight),
		server.WithRequestTimeout(time.Duration(cfg.Server.RequestTimeout) * time.Second),
		server.WithClientRateLimit(cfg.Server.RateLimitQPS, cfg.Server.RateLimitBurst, cfg.Server.RateLimitClients),
		server.WithAllowedCIDRs(cfg.Server.AllowedCIDRs),
	}
	if bootstrapManager != nil {
		serverOpts = append(serverOpts, server.WithBootstrapResolver(bootstrapManager))
	}

	forwarder, err := server.New(serverOpts...)
	if err != nil {
		return fmt.Errorf("initialize server: %w", err)
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error { return forwarder.Start(groupCtx) })
	if cfg.Pprof.Enable {
		group.Go(func() error {
			return runPprofServer(groupCtx, cfg.Pprof.Bind, logkit, func() any {
				snapshot := struct {
					DNS   server.Stats         `json:"dns"`
					Cache *resolver.CacheStats `json:"cache,omitempty"`
				}{DNS: forwarder.Stats()}
				if cacheManager != nil {
					stats := cacheManager.Stats()
					snapshot.Cache = &stats
				}
				return snapshot
			})
		})
	}
	logkit.Info("starting DNS forwarder server", zap.String("addr", cfg.Bind))
	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, syscall.EINTR) {
		return fmt.Errorf("server runtime: %w", err)
	}
	logkit.Info("shutdown complete")
	return nil
}

func makeCacheOptions(cfg *config.Config) (resolver.CacheOptions, error) {
	fingerprint, err := cfg.Fingerprint()
	if err != nil {
		return resolver.CacheOptions{}, err
	}
	return resolver.CacheOptions{
		Size: cfg.Cache.Size, MaxBytes: cfg.Cache.MaxBytes, MaxEntryBytes: cfg.Cache.MaxEntryBytes,
		Lazy: cfg.Cache.Lazy, MaxStale: time.Duration(cfg.Cache.MaxStale) * time.Second,
		Persist: cfg.Cache.Persist, File: cfg.Cache.File, Interval: time.Duration(cfg.Cache.Interval) * time.Second,
		RefreshConcurrency: cfg.Cache.RefreshConcurrency, NegativeTTLMax: time.Duration(cfg.Cache.NegativeTTLMax) * time.Second,
		Fingerprint: fingerprint,
	}, nil
}

func buildActionMap(ats []config.ActionConfig, dependencies ...action.Dependencies) (map[string]action.IDNSAction, error) {
	m := make(map[string]action.IDNSAction, len(ats))
	for _, at := range ats {
		if _, exists := m[at.Name]; exists {
			return nil, errors.Join(fmt.Errorf("duplicate action name %q", at.Name), closeActions(m))
		}
		inst, err := action.MakeAction(at.Type, at.Name, at.Data, dependencies...)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("make action failed, name:%s, type:%s, err:%w", at.Name, at.Type, err), closeActions(m))
		}
		m[at.Name] = inst
	}
	if err := action.ResolveReferences(m); err != nil {
		return nil, errors.Join(err, closeActions(m))
	}
	return m, nil
}

func closeActions(actions map[string]action.IDNSAction) error {
	var errs []error
	for name, item := range actions {
		closer, ok := item.(action.Closer)
		if !ok {
			continue
		}
		if err := closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close action %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func buildMatcherMap(ms []config.MatcherConfig) (map[string]matcher.IDNSMatcher, error) {
	rs := make(map[string]matcher.IDNSMatcher, len(ms))
	for _, m := range ms {
		if _, exists := rs[m.Name]; exists {
			return nil, fmt.Errorf("duplicate matcher name %q", m.Name)
		}
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

func buildHostStore(cfg config.HostConfig) (hosts.IHostResolver, error) {
	if len(cfg.Records) == 0 && len(cfg.Files) == 0 {
		return nil, nil
	}
	recs, err := hosts.LoadRecordsFromFiles(cfg.Files)
	if err != nil {
		return nil, err
	}
	return hosts.New(append(recs, cfg.Records)...)
}
