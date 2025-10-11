package matcher

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestDomainMatcherDefaultSuffix(t *testing.T) {
	m, err := newDomainMatcher("test", []string{
		"example.com",       // implicit suffix
		"suffix:sub.domain", // explicit suffix
		"full:exact.match",  // full match
		"keyword:needle",    // keyword
	})
	if err != nil {
		t.Fatalf("newDomainMatcher error: %v", err)
	}

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{"implicit suffix", "api.example.com.", true},
		{"explicit suffix", "deep.sub.domain.", true},
		{"full match positive", "exact.match.", true},
		{"keyword positive", "with-needle-inside.com.", true},
		{"negative case", "otherdomain.com.", false},
	}

	for _, tc := range tests {
		req := new(dns.Msg)
		req.SetQuestion(tc.domain, dns.TypeA)
		ok, err := m.Match(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if ok != tc.expected {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.expected, ok)
		}
	}
}
