package matcher

import (
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/strictdecode"
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
	if err := strictdecode.Decode(args, &struct{}{}); err != nil {
		return nil, err
	}
	return newAnyMatcher(name), nil
}

func init() {
	Register("any", createAnyMatcher)
}
