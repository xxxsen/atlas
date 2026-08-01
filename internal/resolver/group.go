package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type groupResolver struct {
	name       string
	res        []IDNSResolver
	concurrent int
	next       atomic.Uint64
	closeOnce  sync.Once
	closeErr   error
	closed     atomic.Bool
}

func (p *groupResolver) Name() string {
	return p.name
}

type groupResult struct {
	msg      *dns.Msg
	err      error
	resolver string
}

func (p *groupResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		return nil, fmt.Errorf("group resolver context is nil")
	}
	if p.closed.Load() {
		return nil, fmt.Errorf("group resolver is closed")
	}
	if req == nil || len(req.Question) != 1 {
		return nil, fmt.Errorf("group resolver requires exactly one DNS question")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// dns.Msg is mutable: Pack updates EDNS OPT state. Copy every request before
	// any worker starts so concurrent transports never share mutable records.
	attempts := make([]struct {
		resolver IDNSResolver
		request  *dns.Msg
	}, len(p.res))
	start := int((p.next.Add(1) - 1) % uint64(len(p.res)))
	for i := range p.res {
		idx := (start + i) % len(p.res)
		attempts[i].resolver = p.res[idx]
		attempts[i].request = req.Copy()
	}

	logger := logutil.GetLogger(ctx).With(zap.String("resolver", p.name), zap.Int("parallel", p.concurrent))
	resultCh := make(chan groupResult, len(attempts))
	var workers sync.WaitGroup
	launch := func(attempt int) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			resolver := attempts[attempt].resolver
			msg, err := resolver.Query(ctx, attempts[attempt].request)
			if err == nil {
				err = ValidateResponse(attempts[attempt].request, msg)
			}
			if err == nil && retryableRcode(msg.Rcode) {
				err = fmt.Errorf("upstream returned retryable rcode %s", dns.RcodeToString[msg.Rcode])
			}
			if err == nil && msg.Truncated {
				err = fmt.Errorf("upstream returned a truncated response")
			}
			resultCh <- groupResult{msg: msg, err: err, resolver: resolver.Name()}
		}()
	}

	initial := p.concurrent
	if initial > len(attempts) {
		initial = len(attempts)
	}
	for i := 0; i < initial; i++ {
		launch(i)
	}
	next := initial
	inflight := initial
	errs := make([]error, 0, len(attempts))

	for inflight > 0 {
		select {
		case <-ctx.Done():
			cancel()
			workers.Wait()
			return nil, ctx.Err()
		case result := <-resultCh:
			inflight--
			if result.err == nil {
				if err := ctx.Err(); err != nil {
					cancel()
					workers.Wait()
					return nil, err
				}
				cancel()
				workers.Wait()
				logger.Debug("group resolver query succeeded", zap.String("winner", result.resolver))
				return result.msg, nil
			}
			if !errors.Is(result.err, context.Canceled) {
				logger.Debug("group resolver attempt failed", zap.String("child_resolver", result.resolver), zap.Error(result.err))
				errs = append(errs, fmt.Errorf("%s: %w", result.resolver, result.err))
			}
			if next < len(attempts) {
				launch(next)
				next++
				inflight++
			}
		}
	}
	workers.Wait()
	if len(errs) == 0 {
		return nil, fmt.Errorf("group resolver %s produced no response", p.name)
	}
	return nil, fmt.Errorf("group resolver %s exhausted all upstreams: %w", p.name, errors.Join(errs...))
}

func retryableRcode(rcode int) bool {
	switch rcode {
	case dns.RcodeFormatError, dns.RcodeServerFailure, dns.RcodeNotImplemented, dns.RcodeRefused:
		return true
	default:
		return false
	}
}

func (p *groupResolver) Close() error {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		var errs []error
		for _, child := range p.res {
			if closer, ok := child.(ResolverCloser); ok {
				if err := closer.Close(); err != nil {
					errs = append(errs, fmt.Errorf("close %s: %w", child.Name(), err))
				}
			}
		}
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}

func NewGroupResolver(name string, res []IDNSResolver, concurrent int) (IDNSResolver, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("group resolver name is required")
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("group resolver %q requires at least one child resolver", name)
	}
	if concurrent < 1 || concurrent > len(res) {
		return nil, fmt.Errorf("group resolver %q concurrency must be between 1 and %d", name, len(res))
	}
	children := append([]IDNSResolver(nil), res...)
	for i, child := range children {
		if child == nil {
			return nil, fmt.Errorf("group resolver %q child %d is nil", name, i)
		}
	}
	return &groupResolver{name: buildGroupName(name, children, concurrent), res: children, concurrent: concurrent}, nil
}

func buildGroupName(name string, res []IDNSResolver, cc int) string {
	return fmt.Sprintf("group:{%s:%d:%d}", name, len(res), cc)
}
