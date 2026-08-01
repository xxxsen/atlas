package matcher

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type IDNSMatcher interface {
	Name() string
	Type() string
	Match(ctx context.Context, req *dns.Msg) (bool, error)
}

type Factory func(name string, args interface{}) (IDNSMatcher, error)

var (
	m  = make(map[string]Factory)
	mu sync.RWMutex
)

func Register(typ string, fac Factory) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "" || fac == nil {
		panic("matcher registration requires a non-empty type and factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := m[typ]; exists {
		panic(fmt.Sprintf("matcher type %q already registered", typ))
	}
	m[typ] = fac
}

func MakeMatcher(typ string, name string, args interface{}) (IDNSMatcher, error) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	mu.RLock()
	cr, ok := m[typ]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("matcher type:%s not found", typ)
	}
	return cr(name, args)
}
