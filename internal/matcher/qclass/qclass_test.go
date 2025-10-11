package matcher

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestQClassMatcher(t *testing.T) {
	m, err := newQClassMatcher("test", []uint16{dns.ClassINET})
	if err != nil {
		t.Fatalf("newQClassMatcher error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Question[0].Qclass = dns.ClassINET
	match, err := m.Match(context.Background(), req)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if !match {
		t.Fatalf("expected match for ClassINET")
	}

	req.Question[0].Qclass = dns.ClassCHAOS
	match, err = m.Match(context.Background(), req)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if match {
		t.Fatalf("expected no match for ClassCHAOS")
	}
}
