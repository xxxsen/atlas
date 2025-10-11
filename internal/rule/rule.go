package rule

import (
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/matcher"
)

type IDNSRule interface {
	Name() string
	Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	Match(ctx context.Context, req *dns.Msg) (bool, error)
}

type defaultRule struct {
	name string
	act  action.IDNSAction
	mat  matcher.IDNSMatcher
}

func (d defaultRule) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return d.act.Perform(ctx, req)
}

func (d defaultRule) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	return d.mat.Match(ctx, req)
}

func (d defaultRule) Name() string {
	return d.name
}

func NewRule(name string, mat matcher.IDNSMatcher, act action.IDNSAction) IDNSRule {
	return defaultRule{name: name, mat: mat, act: act}
}
