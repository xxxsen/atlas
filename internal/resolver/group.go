package resolver

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync/atomic"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

type groupResolver struct {
	res        []IDNSResolver
	concurrent int
}

func (p *groupResolver) String() string {
	return "group"
}

func (p *groupResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(p.concurrent)
	var result atomic.Value
	pos := rand.Int()
	for i := 0; i < p.concurrent; i++ {
		res := p.res[(i+pos)%len(p.res)]
		eg.Go(func() error {
			defer cancel()
			rs, err := res.Query(ctx, req)
			if err != nil {
				return err
			}
			result.Store(rs)
			return nil
		})
	}
	err := eg.Wait()
	v, ok := result.Load().(*dns.Msg)
	if ok {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no err return and no dns record found?")
}

func NewGroupResolver(res []IDNSResolver, concurrent int) IDNSResolver {
	return &groupResolver{res: res, concurrent: concurrent}
}
