package resolver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/atlas/internal/resolver/model"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

const defaultClassicPoolSize = 16

func init() {
	Register("tcp", basicResolverFactory)
	Register("udp", basicResolverFactory)
	Register("dot", basicResolverFactory)
}

func basicResolverFactory(scheme string, host string, params *model.Params) (IDNSResolver, error) {
	if params == nil || params.URL == nil {
		return nil, fmt.Errorf("resolver parameters are required")
	}
	if params.URL.Path != "" && params.URL.Path != "/" {
		return nil, fmt.Errorf("%s resolver does not support URL path %q", scheme, params.URL.Path)
	}
	timeout := time.Duration(params.CustomParams.Timeout) * time.Millisecond
	switch scheme {
	case "udp", "tcp":
		addr, err := ensurePort(host, "53")
		if err != nil {
			return nil, err
		}
		client := &dns.Client{Net: scheme, Timeout: timeout}
		resolver := &classicResolver{addr: addr, scheme: scheme, client: client}
		if scheme == "udp" {
			resolver.fallback = &dns.Client{Net: "tcp", Timeout: timeout}
			return resolver, nil
		}
		resolver.pool = newDNSConnectionPool(client, addr, poolSize(params.CustomParams.PoolSize))
		return resolver, nil
	case "dot":
		addr, err := ensurePort(host, "853")
		if err != nil {
			return nil, err
		}
		hostname, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		client := &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeout,
			TLSConfig: &tls.Config{
				ServerName: hostname,
				MinVersion: tls.VersionTLS12,
			},
		}
		resolver := &classicResolver{addr: addr, scheme: scheme, client: client}
		resolver.pool = newDNSConnectionPool(client, addr, poolSize(params.CustomParams.PoolSize))
		return resolver, nil
	default:
		return nil, fmt.Errorf("unsupported DNS type:%s", scheme)
	}
}

func poolSize(configured int) int {
	if configured > 0 {
		return configured
	}
	return defaultClassicPoolSize
}

type classicResolver struct {
	addr     string
	scheme   string
	client   *dns.Client
	fallback *dns.Client
	pool     *dnsConnectionPool
}

func (r *classicResolver) Name() string {
	return fmt.Sprintf("%s/%s", r.client.Net, r.addr)
}

func (r *classicResolver) Query(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
	if req == nil {
		return nil, fmt.Errorf("classic resolver received a nil request")
	}
	ctx, span := querylog.StartUpstream(ctx, req, r.Name(), r.scheme)
	defer func() { querylog.Finish(ctx, span, err) }()
	logger := querylog.Logger(ctx).With(zap.String("resolver", querylog.SafeText(r.Name())), zap.String("server_addr", r.addr))
	if r.pool != nil {
		resp, err = r.pool.Exchange(ctx, req)
	} else {
		resp, _, err = r.client.ExchangeContext(ctx, req, r.addr)
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("no response from %s", r.addr)
	}
	if r.scheme == "udp" && resp.Truncated {
		logger.Debug("UDP response truncated; retrying over TCP")
		resp, _, err = r.fallback.ExchangeContext(ctx, req.Copy(), r.addr)
		if err != nil {
			return nil, fmt.Errorf("TCP fallback after truncated UDP response: %w", err)
		}
		if resp == nil || resp.Truncated {
			return nil, fmt.Errorf("TCP fallback from %s returned no complete response", r.addr)
		}
	}
	if err := ValidateResponse(req, resp); err != nil {
		return nil, fmt.Errorf("validate classic DNS response: %w", err)
	}
	if resp.Truncated {
		return nil, fmt.Errorf("%s resolver returned a truncated response", r.scheme)
	}
	span.SetAttributes(attribute.Int("dns.response_code", resp.Rcode))
	logger.Debug("classic resolver query succeeded", zap.Int("answer_count", len(resp.Answer)))
	return resp, nil
}

func (r *classicResolver) Close() error {
	if r.pool != nil {
		return r.pool.Close()
	}
	return nil
}

type dnsConnectionPool struct {
	client   *dns.Client
	addr     string
	idle     chan *dns.Conn
	slots    chan struct{}
	done     chan struct{}
	closed   atomic.Bool
	once     sync.Once
	closeErr error
}

func newDNSConnectionPool(client *dns.Client, addr string, size int) *dnsConnectionPool {
	return &dnsConnectionPool{
		client: client,
		addr:   addr,
		idle:   make(chan *dns.Conn, size),
		slots:  make(chan struct{}, size),
		done:   make(chan struct{}),
	}
}

func (p *dnsConnectionPool) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := p.acquire(ctx)
		if err != nil {
			return nil, err
		}
		resp, _, err := p.client.ExchangeWithConnContext(ctx, req, conn)
		if err == nil {
			err = ValidateResponse(req, resp)
		}
		p.release(conn, err == nil)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("pooled DNS exchange failed after reconnect: %w", lastErr)
}

func (p *dnsConnectionPool) acquire(ctx context.Context) (*dns.Conn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case conn := <-p.idle:
		if conn != nil {
			if p.closed.Load() {
				_ = conn.Close()
				<-p.slots
				return nil, net.ErrClosed
			}
			return conn, nil
		}
	default:
	}
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case p.slots <- struct{}{}:
		if p.closed.Load() {
			<-p.slots
			return nil, net.ErrClosed
		}
		conn, err := p.client.DialContext(ctx, p.addr)
		if err != nil {
			<-p.slots
			return nil, err
		}
		if p.closed.Load() {
			_ = conn.Close()
			<-p.slots
			return nil, net.ErrClosed
		}
		return conn, nil
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, net.ErrClosed
	case conn := <-p.idle:
		if conn == nil {
			return nil, net.ErrClosed
		}
		if p.closed.Load() {
			_ = conn.Close()
			<-p.slots
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (p *dnsConnectionPool) release(conn *dns.Conn, healthy bool) {
	if conn == nil {
		return
	}
	if !healthy || p.closed.Load() {
		_ = conn.Close()
		<-p.slots
		return
	}
	select {
	case p.idle <- conn:
	default:
		_ = conn.Close()
		<-p.slots
	}
}

func (p *dnsConnectionPool) Close() error {
	p.once.Do(func() {
		p.closed.Store(true)
		close(p.done)
		var errs []error
		for {
			select {
			case conn := <-p.idle:
				if conn != nil {
					errs = append(errs, conn.Close())
					<-p.slots
				}
			default:
				p.closeErr = errors.Join(errs...)
				return
			}
		}
	})
	return p.closeErr
}

func ensurePort(host string, defaultPort string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("resolver host is empty")
	}
	if hostname, port, err := net.SplitHostPort(host); err == nil {
		if err := validateResolverHostPort(hostname, port); err != nil {
			return "", err
		}
		return net.JoinHostPort(hostname, port), nil
	}
	cleanHost := host
	if strings.HasPrefix(cleanHost, "[") && strings.HasSuffix(cleanHost, "]") {
		cleanHost = strings.TrimPrefix(cleanHost, "[")
		cleanHost = strings.TrimSuffix(cleanHost, "]")
	}
	if strings.Contains(cleanHost, ":") && net.ParseIP(cleanHost) == nil {
		return "", fmt.Errorf("invalid resolver host %q", host)
	}
	if defaultPort == "" {
		return "", fmt.Errorf("resolver port is required for host %q", host)
	}
	if err := validateResolverHostPort(cleanHost, defaultPort); err != nil {
		return "", err
	}
	return net.JoinHostPort(cleanHost, defaultPort), nil
}

func validateResolverHostPort(host, port string) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("resolver hostname is empty")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("resolver port %q must be between 1 and 65535", port)
	}
	return nil
}

var _ ResolverCloser = (*classicResolver)(nil)
