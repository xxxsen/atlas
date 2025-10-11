package rcode

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestRcodeActionPerform(t *testing.T) {
	act, err := createRcodeAction("block", &config{Code: dns.RcodeRefused})
	if err != nil {
		t.Fatalf("createRcodeAction error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp, err := act.Perform(context.Background(), req)
	if err != nil {
		t.Fatalf("Perform error: %v", err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("expected rcode %d, got %d", dns.RcodeRefused, resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected empty answer section")
	}
}

func TestRcodeActionInvalidCode(t *testing.T) {
	if _, err := createRcodeAction("invalid", &config{Code: -1}); err == nil {
		t.Fatalf("expected error for invalid code")
	}
}
