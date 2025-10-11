package action

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

type IDNSAction interface {
	Name() string
	Type() string
	Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type Factory func(name string, args interface{}) (IDNSAction, error)

var m = make(map[string]Factory)

func Register(typ string, fac Factory) {
	m[typ] = fac
}

func MakeAction(typ string, name string, args interface{}) (IDNSAction, error) {
	cr, ok := m[typ]
	if !ok {
		return nil, fmt.Errorf("action type:%s not found", typ)
	}
	return cr(name, args)
}
