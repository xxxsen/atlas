package matcher

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

type fakeMatcher struct {
	name   string
	result bool
}

func (f fakeMatcher) Name() string {
	return f.name
}

func (f fakeMatcher) Type() string {
	return "fake"
}

func (f fakeMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	return f.result, nil
}

func TestBuildExpressionMatcherBasic(t *testing.T) {
	registry := map[string]IDNSMatcher{
		"one": fakeMatcher{name: "one", result: true},
		"two": fakeMatcher{name: "two", result: false},
	}

	expr, err := BuildExpressionMatcher("one && !two", registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := expr.Match(context.Background(), &dns.Msg{})
	if err != nil {
		t.Fatalf("match failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected true got false")
	}
}

func TestBuildExpressionMatcherPrecedence(t *testing.T) {
	registry := map[string]IDNSMatcher{
		"one":   fakeMatcher{name: "one", result: false},
		"two":   fakeMatcher{name: "two", result: true},
		"three": fakeMatcher{name: "three", result: true},
	}

	expr, err := BuildExpressionMatcher("one || two && three", registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := expr.Match(context.Background(), &dns.Msg{})
	if err != nil {
		t.Fatalf("match failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected true got false")
	}
}

func TestBuildExpressionMatcherParenthesesOverride(t *testing.T) {
	registry := map[string]IDNSMatcher{
		"one":   fakeMatcher{name: "one", result: false},
		"two":   fakeMatcher{name: "two", result: true},
		"three": fakeMatcher{name: "three", result: false},
	}

	expr, err := BuildExpressionMatcher("(one || two) && three", registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := expr.Match(context.Background(), &dns.Msg{})
	if err != nil {
		t.Fatalf("match failed: %v", err)
	}
	if ok {
		t.Fatalf("expected false got true")
	}
}

func TestBuildExpressionMatcherKeywords(t *testing.T) {
	registry := map[string]IDNSMatcher{
		"alpha": fakeMatcher{name: "alpha", result: true},
		"beta":  fakeMatcher{name: "beta", result: false},
	}

	expr, err := BuildExpressionMatcher("alpha and not beta", registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, err := expr.Match(context.Background(), &dns.Msg{})
	if err != nil {
		t.Fatalf("match failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected true got false")
	}
}

func TestBuildExpressionMatcherDoubleNot(t *testing.T) {
	registry := map[string]IDNSMatcher{
		"alpha": fakeMatcher{name: "alpha", result: true},
	}
	expr, err := BuildExpressionMatcher("!!alpha", registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ok, err := expr.Match(context.Background(), &dns.Msg{})
	if err != nil {
		t.Fatalf("match failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected true got false")
	}
}

func TestBuildExpressionMatcherUnknownIdentifier(t *testing.T) {
	registry := map[string]IDNSMatcher{}
	if _, err := BuildExpressionMatcher("missing", registry); err == nil {
		t.Fatalf("expected error for missing matcher")
	}
}

func TestBuildExpressionMatcherInvalidSyntax(t *testing.T) {
	registry := map[string]IDNSMatcher{
		"alpha": fakeMatcher{name: "alpha", result: true},
	}
	if _, err := BuildExpressionMatcher("(alpha", registry); err == nil {
		t.Fatalf("expected error for invalid syntax")
	}
}
