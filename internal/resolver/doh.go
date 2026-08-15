package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

const (
	defaultDoHMaxConnections            = 16
	defaultDoHRequestTimeout            = 4 * time.Second
	defaultDoHDialTimeout               = 2 * time.Second
	defaultDoHTLSHandshakeTimeout       = 3 * time.Second
	defaultDoHResponseHeaderTimeout     = 3 * time.Second
	defaultDoHIdleConnectionTimeout     = 90 * time.Second
	defaultDoHTCPKeepAlive              = 30 * time.Second
	defaultDoHHTTP2SendPingTimeout      = 10 * time.Second
	defaultDoHHTTP2PingTimeout          = 3 * time.Second
	defaultDoHHTTP2WriteByteTimeout     = 5 * time.Second
	defaultDoHTransportFailureThreshold = 1
	defaultDoHMaxResponseHeaderBytes    = 64 << 10
)

func init() {
	Register("https", dohResolverFactory)
}

func dohResolverFactory(scheme string, host string, params *model.Params) (IDNSResolver, error) {
	if params == nil || params.URL == nil {
		return nil, fmt.Errorf("DoH resolver parameters are required")
	}
	endpointURL := *params.URL
	endpointURL.Scheme = scheme
	endpointURL.Host = host
	if endpointURL.EscapedPath() == "" {
		endpointURL.Path = "/"
	}
	maxConnections := params.CustomParams.MaxConns
	if maxConnections == 0 {
		maxConnections = defaultDoHMaxConnections
	}
	return newDoHResolver(endpointURL.String(), time.Duration(params.CustomParams.Timeout)*time.Millisecond, maxConnections)
}

func newDoHResolver(endpoint string, timeout time.Duration, maxConnections ...int) (IDNSResolver, error) {
	return newDoHResolverWithTLSConfig(endpoint, timeout, nil, maxConnections...)
}

func newDoHResolverWithTLSConfig(endpoint string, timeout time.Duration, tlsConfig *tls.Config, maxConnections ...int) (IDNSResolver, error) {
	connections := defaultDoHMaxConnections
	if len(maxConnections) > 0 && maxConnections[0] > 0 {
		connections = maxConnections[0]
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse DoH endpoint: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("DoH endpoint must be an https URL with a host")
	}
	if timeout <= 0 {
		timeout = defaultDoHRequestTimeout
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:         u.Hostname(),
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(connections),
		}
	} else {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = u.Hostname()
		}
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	r := &dohResolver{
		endpoint:       endpoint,
		timeout:        timeout,
		maxConnections: connections,
		tlsConfig:      tlsConfig,
	}
	state := r.newTransportState(1)
	r.generation.Store(1)
	r.state.Store(state)
	return r, nil
}

type dohTransportState struct {
	generation uint64
	client     *http.Client
	transport  *http.Transport
	failures   atomic.Int64
	inflight   atomic.Int64
	retired    atomic.Bool
}

type dohResolver struct {
	endpoint       string
	timeout        time.Duration
	maxConnections int
	tlsConfig      *tls.Config

	state      atomic.Pointer[dohTransportState]
	generation atomic.Uint64
	resetMu    sync.Mutex
	closed     atomic.Bool
	closeOnce  sync.Once
}

func (r *dohResolver) Name() string {
	return "doh:" + r.endpoint
}

func (r *dohResolver) newTransportState(generation uint64) *dohTransportState {
	dialer := &net.Dialer{Timeout: defaultDoHDialTimeout, KeepAlive: defaultDoHTCPKeepAlive}
	transport := &http.Transport{
		DialContext:            dialer.DialContext,
		MaxConnsPerHost:        r.maxConnections,
		MaxIdleConns:           r.maxConnections,
		MaxIdleConnsPerHost:    r.maxConnections,
		IdleConnTimeout:        defaultDoHIdleConnectionTimeout,
		TLSHandshakeTimeout:    defaultDoHTLSHandshakeTimeout,
		ResponseHeaderTimeout:  defaultDoHResponseHeaderTimeout,
		MaxResponseHeaderBytes: defaultDoHMaxResponseHeaderBytes,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        r.tlsConfig.Clone(),
		HTTP2: &http.HTTP2Config{
			SendPingTimeout:  defaultDoHHTTP2SendPingTimeout,
			PingTimeout:      defaultDoHHTTP2PingTimeout,
			WriteByteTimeout: defaultDoHHTTP2WriteByteTimeout,
		},
	}
	client := &http.Client{Timeout: r.timeout, Transport: transport}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &dohTransportState{generation: generation, client: client, transport: transport}
}

func (r *dohResolver) acquireState() (*dohTransportState, error) {
	for {
		if r.closed.Load() {
			return nil, net.ErrClosed
		}
		state := r.state.Load()
		if state == nil {
			return nil, net.ErrClosed
		}
		state.inflight.Add(1)
		if !r.closed.Load() && r.state.Load() == state && !state.retired.Load() {
			return state, nil
		}
		r.releaseState(state)
	}
}

func (r *dohResolver) releaseState(state *dohTransportState) {
	if state.inflight.Add(-1) == 0 && state.retired.Load() {
		state.transport.CloseIdleConnections()
	}
}

func (r *dohResolver) recordTransportSuccess(state *dohTransportState) {
	if r.state.Load() == state && !state.retired.Load() {
		state.failures.Store(0)
	}
}

func (r *dohResolver) recordTransportFailure(ctx context.Context, state *dohTransportState, queryErr error) {
	if queryErr == nil || (ctx != nil && ctx.Err() != nil) || errors.Is(queryErr, net.ErrClosed) {
		return
	}
	if state.failures.Add(1) < defaultDoHTransportFailureThreshold {
		return
	}

	r.resetMu.Lock()
	defer r.resetMu.Unlock()
	if r.closed.Load() || r.state.Load() != state || state.retired.Load() {
		return
	}
	nextGeneration := r.generation.Add(1)
	next := r.newTransportState(nextGeneration)
	state.retired.Store(true)
	r.state.Store(next)
	state.transport.CloseIdleConnections()
	logutil.GetLogger(ctx).Warn(
		"replaced failed DoH transport generation",
		zap.String("resolver", r.Name()),
		zap.Uint64("old_generation", state.generation),
		zap.Uint64("new_generation", nextGeneration),
		zap.Error(queryErr),
	)
}

func (r *dohResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		return nil, fmt.Errorf("DoH resolver context is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("DoH resolver received a nil request")
	}
	logger := logutil.GetLogger(ctx).With(zap.String("resolver", r.Name()))
	payload, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	state, err := r.acquireState()
	if err != nil {
		return nil, err
	}
	defer r.releaseState(state)
	resp, err := state.client.Do(httpReq)
	if err != nil {
		r.recordTransportFailure(ctx, state, err)
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()
	r.recordTransportSuccess(state)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("DoH %s returned %d: %s", r.endpoint, resp.StatusCode, string(body))
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, fmt.Errorf("DoH %s returned invalid Content-Type %q", r.endpoint, resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > dns.MaxMsgSize {
		return nil, fmt.Errorf("DoH response is too large: %d bytes", resp.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		r.recordTransportFailure(ctx, state, err)
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	r.recordTransportSuccess(state)
	if len(body) > dns.MaxMsgSize {
		return nil, fmt.Errorf("DoH response exceeds %d bytes", dns.MaxMsgSize)
	}
	message := new(dns.Msg)
	if err := message.Unpack(body); err != nil {
		return nil, fmt.Errorf("decode DoH response: %w", err)
	}
	if err := ValidateResponse(req, message); err != nil {
		return nil, fmt.Errorf("validate DoH response: %w", err)
	}
	logger.Debug("DoH resolver query succeeded", zap.Uint64("transport_generation", state.generation), zap.Int("answer_count", len(message.Answer)))
	return message, nil
}

func (r *dohResolver) Close() error {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		r.resetMu.Lock()
		state := r.state.Swap(nil)
		if state != nil {
			state.retired.Store(true)
			state.transport.CloseIdleConnections()
		}
		r.resetMu.Unlock()
	})
	return nil
}

var _ ResolverCloser = (*dohResolver)(nil)
