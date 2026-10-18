package rcode

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/atlas/internal/strictdecode"
)

type rcodeAction struct {
	name  string
	rcode int
}

func (a *rcodeAction) Name() string {
	return a.name
}

func (a *rcodeAction) Type() string {
	return "rcode"
}

func (a *rcodeAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = a.rcode
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil
	querylog.SetResult(ctx, querylog.Result{Source: "rcode", Action: a.name})

	return resp, nil
}

func newRCodeAction(name string, code int) action.IDNSAction {
	return &rcodeAction{
		name:  name,
		rcode: code,
	}
}

const maxRcode = 0x0F

func createRcodeAction(name string, args interface{}) (action.IDNSAction, error) {
	cfg := &config{}
	if err := strictdecode.Decode(args, cfg); err != nil {
		return nil, err
	}
	code := cfg.Code
	if code < 0 || code > maxRcode {
		return nil, fmt.Errorf("rcode action invalid code:%d", code)
	}
	return newRCodeAction(name, code), nil

}

func init() {
	action.Register("rcode", func(name string, args interface{}, _ action.Dependencies) (action.IDNSAction, error) {
		return createRcodeAction(name, args)
	})
}
