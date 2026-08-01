package forward

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/strictdecode"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type forwardAction struct {
	name string
	r    resolver.IDNSResolver
}

func (f *forwardAction) Name() string {
	return f.name
}

func (f *forwardAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	logger := logutil.GetLogger(ctx).With(zap.String("action", f.name), zap.String("target_resolver", f.r.Name()))
	logger.Debug("forward action start")
	resp, err := f.r.Query(ctx, req)
	if err != nil {
		logger.Debug("forward action query failed", zap.Error(err))
		return nil, err
	}
	ans := 0
	if resp != nil {
		ans = len(resp.Answer)
	}
	logger.Debug("forward action query success", zap.Int("answer_count", ans))
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
	if len(dependencies) > 0 && dependencies[0].Cache != nil {
		wrapped, wrapErr := dependencies[0].Cache.Wrap(name, r)
		if wrapErr != nil {
			if closer, ok := r.(resolver.ResolverCloser); ok {
				return nil, errors.Join(wrapErr, closer.Close())
			}
			return nil, wrapErr
		}
		r = wrapped
	}
	return &forwardAction{name: name, r: r}, nil
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
