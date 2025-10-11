package matcher

import (
	"context"

	"github.com/miekg/dns"
)

type anyMatcher struct {
	name string
}

func (a *anyMatcher) Name() string {
	if a == nil || a.name == "" {
		return "any"
	}
	return a.name
}

func (a *anyMatcher) Type() string {
	return "any"
}

func (a *anyMatcher) Match(context.Context, *dns.Msg) (bool, error) {
	return true, nil
}

func newAnyMatcher(name string) IDNSMatcher {
	return &anyMatcher{name: name}
}

func createAnyMatcher(name string, args interface{}) (IDNSMatcher, error) {
	return newAnyMatcher(name), nil
}

func init() {
	Register("any", createAnyMatcher)
}
