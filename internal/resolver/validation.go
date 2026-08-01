package resolver

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func ValidateResponse(req, resp *dns.Msg) error {
	if req == nil {
		return fmt.Errorf("DNS request is nil")
	}
	if resp == nil {
		return fmt.Errorf("DNS response is nil")
	}
	if !resp.Response {
		return fmt.Errorf("DNS message is not a response")
	}
	if resp.Id != req.Id {
		return fmt.Errorf("DNS response ID mismatch: got %d, want %d", resp.Id, req.Id)
	}
	if resp.Opcode != req.Opcode {
		return fmt.Errorf("DNS response opcode mismatch: got %d, want %d", resp.Opcode, req.Opcode)
	}
	if len(resp.Question) != len(req.Question) {
		return fmt.Errorf("DNS response question count mismatch: got %d, want %d", len(resp.Question), len(req.Question))
	}
	for i := range req.Question {
		want := req.Question[i]
		got := resp.Question[i]
		if !strings.EqualFold(dns.Fqdn(got.Name), dns.Fqdn(want.Name)) || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
			return fmt.Errorf("DNS response question %d does not match request", i)
		}
	}
	return nil
}
