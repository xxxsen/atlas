package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/schema"
	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
)

type Factory func(schema string, host string, params *model.Params) (IDNSResolver, error)

var (
	m  = make(map[string]Factory)
	mu sync.RWMutex
)

func MakeResolvers(links []string) ([]IDNSResolver, error) {
	rs := make([]IDNSResolver, 0, len(links))
	for _, item := range links {
		r, err := MakeResolver(item)
		if err != nil {
			return nil, errors.Join(err, CloseResolvers(rs))
		}
		rs = append(rs, r)
	}
	return rs, nil
}

// CloseResolvers releases every closeable resolver and joins all failures.
func CloseResolvers(resolvers []IDNSResolver) error {
	var errs []error
	for _, item := range resolvers {
		if closer, ok := item.(ResolverCloser); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close resolver %s: %w", item.Name(), err))
			}
		}
	}
	return errors.Join(errs...)
}

func MakeResolver(link string) (IDNSResolver, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, fmt.Errorf("resolver URL is empty")
	}
	uri, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("parse resolver URL %q: %w", link, err)
	}
	scheme := strings.ToLower(uri.Scheme)
	if scheme == "" || uri.Host == "" {
		return nil, fmt.Errorf("resolver URL must include scheme and host: %q", link)
	}
	if uri.User != nil {
		return nil, fmt.Errorf("resolver URL userinfo is not supported: %q", link)
	}
	if uri.Fragment != "" || uri.Opaque != "" {
		return nil, fmt.Errorf("resolver URL fragment and opaque data are not supported: %q", link)
	}
	uri.Scheme = scheme
	mu.RLock()
	cr, ok := m[scheme]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no resolver type found, type:%s", scheme)
	}
	localQuery, endpointQuery, endpointParams, err := splitResolverQuery(uri.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("parse resolver URL query: %w", err)
	}
	for _, key := range []string{"timeout", "pool", "max_conns", "max_inflight"} {
		if values, exists := localQuery[key]; exists {
			if len(values) != 1 {
				return nil, fmt.Errorf("resolver URL parameter %q must appear exactly once", key)
			}
		}
	}
	if scheme != "https" && endpointParams != 0 {
		return nil, fmt.Errorf("resolver type %s does not support endpoint query parameters", scheme)
	}
	uri.RawQuery = endpointQuery
	urlinfo := &model.Params{
		URL: uri,
	}
	if err := decodeParams(&urlinfo.CustomParams, localQuery); err != nil {
		return nil, fmt.Errorf("decode resolver URL parameters: %w", err)
	}
	if urlinfo.CustomParams.Timeout < 0 || urlinfo.CustomParams.Timeout > 300_000 {
		return nil, fmt.Errorf("resolver timeout must be between 0 and 300000 milliseconds")
	}
	if urlinfo.CustomParams.PoolSize < 0 || urlinfo.CustomParams.PoolSize > 256 {
		return nil, fmt.Errorf("resolver pool must be between 0 and 256")
	}
	if urlinfo.CustomParams.MaxConns < 0 || urlinfo.CustomParams.MaxConns > 4096 {
		return nil, fmt.Errorf("resolver max_conns must be between 0 and 4096")
	}
	if urlinfo.CustomParams.MaxInflight < 0 || urlinfo.CustomParams.MaxInflight > 100_000 {
		return nil, fmt.Errorf("resolver max_inflight must be between 0 and 100000")
	}
	switch scheme {
	case "udp":
		if urlinfo.CustomParams.PoolSize != 0 || urlinfo.CustomParams.MaxConns != 0 {
			return nil, fmt.Errorf("UDP resolver supports only the timeout parameter")
		}
	case "tcp", "dot":
		if urlinfo.CustomParams.MaxConns != 0 {
			return nil, fmt.Errorf("%s resolver does not support max_conns; use pool", scheme)
		}
	case "https":
		if urlinfo.CustomParams.PoolSize != 0 {
			return nil, fmt.Errorf("HTTPS resolver does not support pool; use max_conns")
		}
	}
	item, err := cr(scheme, uri.Host, urlinfo)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, fmt.Errorf("resolver factory %s returned nil", scheme)
	}
	// Limit admission before consulting the circuit breaker. Queries queued on
	// the limiter therefore observe a newly opened circuit instead of forming a
	// large backlog of already-authorized upstream attempts.
	return newLimitedResolver(newCircuitBreakerResolver(item), resolverInflightLimit(scheme, urlinfo.CustomParams)), nil
}

var resolverLocalQueryKeys = map[string]struct{}{
	"timeout":      {},
	"pool":         {},
	"max_conns":    {},
	"max_inflight": {},
}

// splitResolverQuery decodes Atlas-local transport parameters while retaining
// every endpoint parameter's original escaping and order. This matters for
// DoH endpoints whose routing token is signed over the raw query string.
func splitResolverQuery(raw string) (url.Values, string, int, error) {
	local := make(url.Values)
	if raw == "" {
		return local, "", 0, nil
	}
	endpoint := make([]string, 0)
	for _, segment := range strings.Split(raw, "&") {
		if segment == "" {
			return nil, "", 0, fmt.Errorf("empty query parameter")
		}
		rawKey, rawValue, _ := strings.Cut(segment, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil || key == "" {
			return nil, "", 0, fmt.Errorf("invalid query parameter name %q", rawKey)
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, "", 0, fmt.Errorf("invalid value for query parameter %q", key)
		}
		if _, isLocal := resolverLocalQueryKeys[key]; isLocal {
			local[key] = append(local[key], value)
			continue
		}
		endpoint = append(endpoint, segment)
	}
	return local, strings.Join(endpoint, "&"), len(endpoint), nil
}

func resolverInflightLimit(scheme string, params model.BasicParam) int {
	if params.MaxInflight > 0 {
		return params.MaxInflight
	}
	switch scheme {
	case "tcp", "dot":
		return poolSize(params.PoolSize)
	case "https":
		if params.MaxConns > 0 {
			return params.MaxConns
		}
		return defaultDoHMaxConnections
	case "udp":
		return 256
	default:
		return 64
	}
}

func decodeParams(out interface{}, in map[string][]string) error {
	d := schema.NewDecoder()
	if err := d.Decode(out, in); err != nil {
		return err
	}
	return nil
}

func Register(schema string, fac Factory) {
	schema = strings.ToLower(strings.TrimSpace(schema))
	if schema == "" || fac == nil {
		panic("resolver registration requires a non-empty scheme and factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := m[schema]; exists {
		panic(fmt.Sprintf("resolver scheme %q already registered", schema))
	}
	m[schema] = fac
}

// IDNSResolver represents a downstream resolver.
type IDNSResolver interface {
	Name() string
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type ResolverCloser interface {
	Close() error
}

type limitedResolver struct {
	next      IDNSResolver
	slots     chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func newLimitedResolver(next IDNSResolver, limit int) IDNSResolver {
	return &limitedResolver{next: next, slots: make(chan struct{}, limit), done: make(chan struct{})}
}

func (r *limitedResolver) Name() string { return r.next.Name() }

func (r *limitedResolver) Query(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		return nil, fmt.Errorf("resolver query context is nil")
	}
	if r.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.done:
		return nil, net.ErrClosed
	}
	if r.closed.Load() {
		return nil, net.ErrClosed
	}
	return r.next.Query(ctx, request)
}

func (r *limitedResolver) Close() error {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		close(r.done)
		if closer, ok := r.next.(ResolverCloser); ok {
			r.closeErr = closer.Close()
		}
	})
	return r.closeErr
}

func (r *limitedResolver) resolverHealth() upstreamHealth {
	if r.closed.Load() {
		return upstreamHealth{}
	}
	if reporter, ok := r.next.(healthReportingResolver); ok {
		return reporter.resolverHealth()
	}
	return upstreamHealth{Available: !r.closed.Load()}
}

var _ ResolverCloser = (*limitedResolver)(nil)
var _ healthReportingResolver = (*limitedResolver)(nil)
