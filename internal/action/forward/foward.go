package forward

import (
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/common/logutil"
	"github.com/xxxsen/common/utils"
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
		logger.Error("forward action query failed", zap.Error(err))
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

func createForwardAction(name string, args interface{}) (action.IDNSAction, error) {
	c := &config{}
	if err := utils.ConvStructJson(args, c); err != nil {
		return nil, err
	}
	res, err := resolver.MakeResolvers(c.ServerList)
	if err != nil {
		return nil, err
	}
	r := resolver.NewGroupResolver(res, c.Parallel)
	r = resolver.TryEnableResolverCache(r)
	return &forwardAction{name: name, r: r}, nil
}

func init() {
	action.Register("forward", createForwardAction)
}
