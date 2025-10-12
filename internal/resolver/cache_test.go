package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type mockResolver struct {
	count int
	msg   *dns.Msg
	err   error
}

func (m *mockResolver) Name() string {
	return "mock"
}

func (m *mockResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	m.count++
	if m.err != nil {
		return nil, m.err
	}
	return m.msg.Copy(), nil
}

func newResponse(ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.Id = 1
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: net.IPv4(1, 1, 1, 1),
	})
	return msg
}

func newRequest() *dns.Msg {
	req := new(dns.Msg)
	req.Id = 1234
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{
			Name:   "example.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}
	return req
}

func TestCacheResolverBasic(t *testing.T) {
	ConfigureCache(CacheOptions{Size: 10})
	defer ConfigureCache(CacheOptions{})

	base := &mockResolver{msg: newResponse(30)}
	wrapped := TryEnableResolverCache(base)

	req := newRequest()

	if _, err := wrapped.Query(context.Background(), req); err != nil {
		t.Fatalf("first query error: %v", err)
	}
	if base.count != 1 {
		t.Fatalf("expected base resolver called once, got %d", base.count)
	}

	if _, err := wrapped.Query(context.Background(), req); err != nil {
		t.Fatalf("second query error: %v", err)
	}
	if base.count != 1 {
		t.Fatalf("expected cached response, base count=%d", base.count)
	}
}

func TestCacheResolverLazyRefresh(t *testing.T) {
	ConfigureCache(CacheOptions{Size: 10, Lazy: true})
	defer ConfigureCache(CacheOptions{})

	base := &mockResolver{msg: newResponse(1)}
	wrapped := TryEnableResolverCache(base)

	req := newRequest()
	if _, err := wrapped.Query(context.Background(), req); err != nil {
		t.Fatalf("first query error: %v", err)
	}
	if base.count != 1 {
		t.Fatalf("expected base call once, got %d", base.count)
	}

	time.Sleep(1500 * time.Millisecond)

	if _, err := wrapped.Query(context.Background(), req); err != nil {
		t.Fatalf("second query error: %v", err)
	}
	if base.count != 1 {
		t.Fatalf("lazy cache should return stale immediately, count=%d", base.count)
	}

	// give refresh goroutine time to run
	time.Sleep(600 * time.Millisecond)
	if base.count < 2 {
		t.Fatalf("expected refresh to trigger, base count=%d", base.count)
	}
}
