package matcher

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestQTypeMatcher(t *testing.T) {
	m, err := newQTypeMatcher("test", []uint16{dns.TypeA, dns.TypeAAAA})
	if err != nil {
		t.Fatalf("newQTypeMatcher error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	match, err := m.Match(context.Background(), req)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if !match {
		t.Fatalf("expected match for TypeA")
	}

	req.Question[0].Qtype = dns.TypeMX
	match, err = m.Match(context.Background(), req)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if match {
		t.Fatalf("expected no match for TypeMX")
	}
}
