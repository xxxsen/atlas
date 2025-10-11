package forward

import (
	"atlas/internal/action"
	"atlas/internal/resolver"
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/utils"
)

type forwardAction struct {
	name string
	r    resolver.IDNSResolver
}

func (f *forwardAction) Name() string {
	return f.name
}

func (f *forwardAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f.r.Query(ctx, req)
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

	return &forwardAction{name: name, r: r}, nil
}

func init() {
	action.Register("forward", createForwardAction)
}
