package rule

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"go.uber.org/zap"
)

type IDNSRuleEngine interface {
	Execute(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type defaultEngine struct {
	rules []IDNSRule
}

func (d *defaultEngine) Execute(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	for _, r := range d.rules {
		ok, err := r.Match(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("exec rule failed, name:%s, err:%w", r.Name(), err)
		}
		if !ok {
			continue
		}
		querylog.Logger(ctx).Debug("match rule", zap.String("rule_remark", r.Name()))
		res, err := r.Perform(ctx, req)
		if err != nil {
			querylog.Logger(ctx).Debug("perform rule failed", querylog.Error(err))
			return nil, err
		}
		querylog.Logger(ctx).Debug("perform rule succ", querylog.Fields(ctx)...)
		return res, nil
	}
	return nil, fmt.Errorf("no rule match, may be you need a default rule?")
}

func NewEngine(rules ...IDNSRule) IDNSRuleEngine {
	return &defaultEngine{rules: rules}
}
