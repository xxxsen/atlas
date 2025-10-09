package outbound

import (
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type rejectResolver struct{}

func (r *rejectResolver) String() string { return "reject" }

func (r *rejectResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	logutil.GetLogger(ctx).Debug("reject resolver answering request", zap.String("question", questionName(req)))
	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Authoritative = true
	reply.RecursionAvailable = true
	reply.Rcode = dns.RcodeSuccess
	return reply, nil
}
