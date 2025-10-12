package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
)

type stubDNSResolver struct {
	err error
}

func (s *stubDNSResolver) Name() string { return "stub" }
func (s *stubDNSResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if s.err != nil {
		return nil, s.err
	}
	msg := new(dns.Msg)
	msg.SetReply(req)
	return msg, nil
}

func TestRegisterAndMakeResolver(t *testing.T) {
	Register("stub", func(schema string, host string, params *model.Params) (IDNSResolver, error) {
		return &stubDNSResolver{}, nil
	})

	r, err := MakeResolver("stub://resolver")
	if err != nil {
		t.Fatalf("MakeResolver error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := r.Query(context.Background(), req); err != nil {
		t.Fatalf("Query error: %v", err)
	}
}

func TestGroupResolver(t *testing.T) {
	success := &stubDNSResolver{}
	fail := &stubDNSResolver{err: errors.New("failure")}

	group := NewGroupResolver([]IDNSResolver{fail, success}, 2)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := group.Query(context.Background(), req); err != nil {
		t.Fatalf("group.Query error: %v", err)
	}

	groupFail := NewGroupResolver([]IDNSResolver{fail}, 1)
	if _, err := groupFail.Query(context.Background(), req); err == nil {
		t.Fatalf("expected group resolver failure")
	}
}
