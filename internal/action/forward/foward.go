package forward

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/ipset"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/strictdecode"
	"go.uber.org/zap"
)

type forwardAction struct {
	name         string
	r            resolver.IDNSResolver
	strategy     *validatedResolver
	queryTimeout time.Duration
}

func (f *forwardAction) Name() string {
	return f.name
}

func (f *forwardAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		return nil, fmt.Errorf("forward action context is nil")
	}
	ctx = querylog.WithQuery(ctx, req)
	ctx, cancel := resolver.WithQueryBudget(ctx, f.queryTimeout)
	defer cancel()
	start := time.Now()
	logger := querylog.Logger(ctx).With(zap.String("action", f.name), zap.String("target_resolver", querylog.SafeText(f.r.Name())))
	logger.Debug("forward action start")
	resp, err := f.r.Query(ctx, req)
	if err != nil {
		logger.Debug("forward action query failed", querylog.Error(err), querylog.Elapsed(start))
		return nil, err
	}
	ans := 0
	if resp != nil {
		ans = len(resp.Answer)
	}
	if checked := logger.Check(zap.DebugLevel, "forward action query success"); checked != nil {
		checked.Write(append(querylog.Fields(ctx), zap.Int("answer_count", ans), zap.Strings("ips", querylog.IPs(resp)), querylog.Elapsed(start))...)
	}
	return resp, nil
}

func (h *forwardAction) Type() string {
	return "forward"
}

func createForwardAction(name string, args interface{}, dependencies ...action.Dependencies) (action.IDNSAction, error) {
	c := &config{}
	if err := strictdecode.Decode(args, c); err != nil {
		return nil, err
	}
	var deps action.Dependencies
	if len(dependencies) > 0 {
		deps = dependencies[0]
	}
	if (c.Validate != nil) != (c.Fallback != nil) {
		return nil, fmt.Errorf("forward action %q validate and fallback must be configured together", name)
	}
	var validator *ipset.Validator
	if c.Validate != nil {
		*c.Fallback = strings.TrimSpace(*c.Fallback)
		if *c.Fallback == "" {
			return nil, fmt.Errorf("forward action %q fallback is empty", name)
		}
		var err error
		validator, err = deps.IPSets.Compile(*c.Validate)
		if err != nil {
			return nil, fmt.Errorf("forward action %q: %w", name, err)
		}
	}
	if len(c.ServerList) == 0 {
		return nil, fmt.Errorf("forward action %q requires at least one server", name)
	}
	seenServers := make(map[string]struct{}, len(c.ServerList))
	for index, server := range c.ServerList {
		server = strings.TrimSpace(server)
		if server == "" {
			return nil, fmt.Errorf("forward action %q server_list[%d] is empty", name, index)
		}
		if _, exists := seenServers[server]; exists {
			return nil, fmt.Errorf("forward action %q contains duplicate server %q", name, server)
		}
		seenServers[server] = struct{}{}
		c.ServerList[index] = server
	}
	if c.Parallel < 1 || c.Parallel > len(c.ServerList) {
		return nil, fmt.Errorf("forward action %q parallel must be between 1 and %d", name, len(c.ServerList))
	}
	res, err := resolver.MakeResolvers(c.ServerList)
	if err != nil {
		return nil, err
	}
	r, err := resolver.NewGroupResolver(name, res, c.Parallel)
	if err != nil {
		return nil, errors.Join(err, resolver.CloseResolvers(res))
	}
	var strategy *validatedResolver
	if validator != nil {
		strategy = &validatedResolver{name: name, primary: r, validator: validator, fallbackName: *c.Fallback}
		r = strategy
	}
	if deps.Cache != nil {
		wrapped, wrapErr := deps.Cache.Wrap(name, r)
		if wrapErr != nil {
			if closer, ok := r.(resolver.ResolverCloser); ok {
				return nil, errors.Join(wrapErr, closer.Close())
			}
			return nil, wrapErr
		}
		r = wrapped
	}
	return &forwardAction{name: name, r: r, strategy: strategy, queryTimeout: deps.QueryTimeout}, nil
}

func (f *forwardAction) References() []string {
	if f.strategy == nil {
		return nil
	}
	return []string{f.strategy.fallbackName}
}

func (f *forwardAction) BindReferences(actions map[string]action.IDNSAction) error {
	if f.strategy == nil {
		return nil
	}
	target := actions[f.strategy.fallbackName]
	if target == nil || target.Type() != "forward" {
		return fmt.Errorf("fallback %q must reference a forward action", f.strategy.fallbackName)
	}
	f.strategy.fallback = target
	return nil
}

func (f *forwardAction) Close() error {
	if closer, ok := f.r.(resolver.ResolverCloser); ok {
		return closer.Close()
	}
	return nil
}

func init() {
	action.Register("forward", func(name string, args interface{}, dependencies action.Dependencies) (action.IDNSAction, error) {
		return createForwardAction(name, args, dependencies)
	})
}
