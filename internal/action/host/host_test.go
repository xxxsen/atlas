package host

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestHostActionPerform(t *testing.T) {
	act, err := createHostAction("host", &config{
		Records: map[string]string{
			"example.com": "1.1.1.1, 2001:4860:4860::8888",
		},
	})
	if err != nil {
		t.Fatalf("createHostAction error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	resp, err := act.Perform(context.Background(), req)
	if err != nil {
		t.Fatalf("Perform error: %v", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(resp.Answer))
	}
	if resp.Answer[0].Header().Ttl != defaultHostRecordTTL {
		t.Fatalf("unexpected ttl: %d", resp.Answer[0].Header().Ttl)
	}
}

func TestHostActionNoMatch(t *testing.T) {
	act, err := createHostAction("host", &config{
		Records: map[string]string{
			"example.com": "1.1.1.1",
		},
	})
	if err != nil {
		t.Fatalf("createHostAction error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("nomatch.com.", dns.TypeA)
	if _, err := act.Perform(context.Background(), req); err == nil {
		t.Fatalf("expected error when no record matched")
	}
}
