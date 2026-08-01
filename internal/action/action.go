package action

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver"
)

type IDNSAction interface {
	Name() string
	Type() string
	Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type Dependencies struct {
	Cache *resolver.CacheManager
}

type Factory func(name string, args interface{}, dependencies Dependencies) (IDNSAction, error)

var (
	m  = make(map[string]Factory)
	mu sync.RWMutex
)

func Register(typ string, fac Factory) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "" || fac == nil {
		panic("action registration requires a non-empty type and factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := m[typ]; exists {
		panic(fmt.Sprintf("action type %q already registered", typ))
	}
	m[typ] = fac
}

func MakeAction(typ string, name string, args interface{}, dependencies ...Dependencies) (IDNSAction, error) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	mu.RLock()
	cr, ok := m[typ]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("action type:%s not found", typ)
	}
	var deps Dependencies
	if len(dependencies) > 0 {
		deps = dependencies[0]
	}
	return cr(name, args, deps)
}

type Closer interface {
	Close() error
}
