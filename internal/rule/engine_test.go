package rule

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/matcher"
)

type stubMatcher struct {
	shouldMatch bool
	err         error
	calls       int
}

func (s *stubMatcher) Name() string { return "stub-matcher" }
func (s *stubMatcher) Type() string { return "stub" }
func (s *stubMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	s.calls++
	return s.shouldMatch, s.err
}

type stubAction struct {
	resp  *dns.Msg
	err   error
	calls int
}

func (s *stubAction) Name() string { return "stub-action" }
func (s *stubAction) Type() string { return "stub" }
func (s *stubAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func TestEngineExecuteFirstMatch(t *testing.T) {
	falseMatcher := &stubMatcher{shouldMatch: false}
	trueMatcher := &stubMatcher{shouldMatch: true}
	resp := new(dns.Msg)
	action := &stubAction{resp: resp}

	rules := []IDNSRule{
		NewRule("false", falseMatcher, action),
		NewRule("true", trueMatcher, action),
	}
	engine := NewEngine(rules...)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	got, err := engine.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if got != resp {
		t.Fatalf("expected response object")
	}
	if falseMatcher.calls != 1 {
		t.Fatalf("first matcher should be evaluated once")
	}
	if trueMatcher.calls != 1 {
		t.Fatalf("second matcher should be evaluated once")
	}
	if action.calls != 1 {
		t.Fatalf("action should be called once")
	}
}

func TestEngineExecuteActionError(t *testing.T) {
	m := &stubMatcher{shouldMatch: true}
	a := &stubAction{err: errors.New("action failed")}
	engine := NewEngine(NewRule("fail", m, a))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := engine.Execute(context.Background(), req); err == nil {
		t.Fatalf("expected execute error")
	}
}

func TestEngineNoMatch(t *testing.T) {
	m := &stubMatcher{shouldMatch: false}
	a := &stubAction{resp: new(dns.Msg)}
	engine := NewEngine(NewRule("nomatch", m, a))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := engine.Execute(context.Background(), req); err == nil {
		t.Fatalf("expected error when no rule matches")
	}
}

var _ matcher.IDNSMatcher = (*stubMatcher)(nil)
var _ action.IDNSAction = (*stubAction)(nil)
