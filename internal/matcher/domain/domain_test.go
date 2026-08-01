package matcher

import (
	"context"
	"strings"
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

func TestDomainMatcherRegexpIsCaseInsensitiveAndInputIsValidated(t *testing.T) {
	item, err := newDomainMatcher("regexp", []string{"regexp:^API\\.Example\\.COM$"})
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("api.example.com.", dns.TypeA)
	matched, err := item.Match(context.Background(), request)
	if err != nil || !matched {
		t.Fatalf("case-insensitive regexp did not match: matched=%v err=%v", matched, err)
	}
	if _, err := item.Match(context.Background(), new(dns.Msg)); err == nil {
		t.Fatal("empty question should be rejected")
	}
	if _, err := newDomainMatcher("empty", nil); err == nil {
		t.Fatal("empty domain matcher should fail")
	}
	if _, err := newDomainMatcher("invalid", []string{"suffix:bad..name"}); err == nil {
		t.Fatal("invalid domain rule should fail")
	}
}

func TestDomainMatcherStrictConfigAndDeduplication(t *testing.T) {
	if _, err := createDomainMatcher("strict", map[string]any{"domians": []string{"example.com"}}); err == nil {
		t.Fatal("unknown domain config key should fail")
	}
	item, err := newDomainMatcher("dedupe", []string{"regexp:foo", "regexp:foo", "suffix:example.com", "suffix:example.com"})
	if err != nil {
		t.Fatal(err)
	}
	matcher := item.(*domainMatcher)
	if len(matcher.reg) != 1 {
		t.Fatalf("duplicate regex rules were retained: %d", len(matcher.reg))
	}
}

func BenchmarkDomainMatcherBuild(b *testing.B) {
	rules := make([]string, 10_000)
	for index := range rules {
		rules[index] = "suffix:host-" + strings.Repeat("x", index%20) + ".example." + string(rune('a'+index%26))
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := newDomainMatcher("benchmark", rules); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDomainMatcherMatch(b *testing.B) {
	item, err := newDomainMatcher("benchmark", []string{"suffix:example.com", "keyword:tracking", "regexp:^api-[0-9]+\\.service\\.test$"})
	if err != nil {
		b.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("deep.api.example.com.", dns.TypeA)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := item.Match(ctx, request); err != nil {
			b.Fatal(err)
		}
	}
}
