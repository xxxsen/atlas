package forward

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/resolver/model"
)

type stubResolver struct {
	err error
}

func (s *stubResolver) Name() string { return "stub-resolver" }

func (s *stubResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if s.err != nil {
		return nil, s.err
	}
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  req.Question[0].Qclass,
			Ttl:    60,
		},
		A: net.IPv4(1, 1, 1, 1),
	})
	return msg, nil
}

func TestForwardActionPerformSuccess(t *testing.T) {
	resolver.ConfigureCache(resolver.CacheOptions{})
	resolver.Register("mockforward", func(schema, host string, params *model.Params) (resolver.IDNSResolver, error) {
		return &stubResolver{}, nil
	})

	act, err := createForwardAction("test", map[string]interface{}{
		"server_list": []string{"mockforward://ok"},
		"parallel":    1,
	})
	if err != nil {
		t.Fatalf("createForwardAction error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp, err := act.Perform(context.Background(), req)
	if err != nil {
		t.Fatalf("Perform error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected answer count 1, got %d", len(resp.Answer))
	}
}

func TestForwardActionPerformError(t *testing.T) {
	resolver.ConfigureCache(resolver.CacheOptions{})
	resolver.Register("mockforwarderr", func(schema, host string, params *model.Params) (resolver.IDNSResolver, error) {
		return &stubResolver{err: errors.New("upstream failure")}, nil
	})

	act, err := createForwardAction("fail", map[string]interface{}{
		"server_list": []string{"mockforwarderr://fail"},
		"parallel":    1,
	})
	if err != nil {
		t.Fatalf("createForwardAction error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := act.Perform(context.Background(), req); err == nil {
		t.Fatalf("expected perform error")
	}
}
