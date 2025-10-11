package matcher

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

type IDNSMatcher interface {
	Name() string
	Type() string
	Match(ctx context.Context, req *dns.Msg) (bool, error)
}

type Factory func(name string, args interface{}) (IDNSMatcher, error)

var m = make(map[string]Factory)

func Register(typ string, fac Factory) {
	m[typ] = fac
}

func MakeMatcher(typ string, name string, args interface{}) (IDNSMatcher, error) {
	cr, ok := m[typ]
	if !ok {
		return nil, fmt.Errorf("matcher type:%s not found", typ)
	}
	return cr(name, args)
}
