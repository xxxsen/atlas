package forward

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/resolver/model"
)

type stubResolver struct {
	err error
}

var (
	registerSuccessResolver sync.Once
	registerFailureResolver sync.Once
)

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
	registerSuccessResolver.Do(func() {
		resolver.Register("mockforward", func(schema, host string, params *model.Params) (resolver.IDNSResolver, error) {
			return &stubResolver{}, nil
		})
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
	registerFailureResolver.Do(func() {
		resolver.Register("mockforwarderr", func(schema, host string, params *model.Params) (resolver.IDNSResolver, error) {
			return &stubResolver{err: errors.New("upstream failure")}, nil
		})
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

func TestForwardActionStrictConfiguration(t *testing.T) {
	if _, err := createForwardAction("empty", map[string]any{"server_list": []string{}, "parallel": 1}); err == nil {
		t.Fatal("empty upstream list should fail")
	}
	if _, err := createForwardAction("parallel", map[string]any{"server_list": []string{"udp://127.0.0.1:53"}, "parallel": 2}); err == nil {
		t.Fatal("parallel larger than upstream list should fail")
	}
	if _, err := createForwardAction("strict", map[string]any{"server_list": []string{"udp://127.0.0.1:53"}, "paralell": 1}); err == nil {
		t.Fatal("unknown forward config key should fail")
	}
	if _, err := createForwardAction("duplicate", map[string]any{"server_list": []string{"udp://127.0.0.1:53", "udp://127.0.0.1:53"}, "parallel": 1}); err == nil {
		t.Fatal("duplicate upstream URL should fail")
	}
}
