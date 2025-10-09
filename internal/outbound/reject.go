package outbound

import (
	"context"

	"github.com/miekg/dns"
)

type rejectResolver struct{}

func (r *rejectResolver) String() string { return "reject" }

func (r *rejectResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Authoritative = true
	reply.RecursionAvailable = true
	reply.Rcode = dns.RcodeSuccess
	return reply, nil
}
