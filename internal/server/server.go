package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/common/logutil"
	"github.com/xxxsen/common/trace"
	"go.uber.org/zap"
)

type IDNSServer interface {
	Start(ctx context.Context) error
	Stats() Stats
}

type Stats struct {
	Requests       uint64 `json:"requests"`
	Handled        uint64 `json:"handled"`
	Overloaded     uint64 `json:"overloaded"`
	RateLimited    uint64 `json:"rate_limited"`
	AccessDenied   uint64 `json:"access_denied"`
	PipelineErrors uint64 `json:"pipeline_errors"`
	Panics         uint64 `json:"panics"`
	InFlight       int    `json:"in_flight"`
}

type dnsServer struct {
	c              *options
	udpServer      *dns.Server
	tcpServer      *dns.Server
	tid            atomic.Uint64
	started        atomic.Bool
	inflight       chan struct{}
	limiter        *clientRateLimiter
	allowedClients []netip.Prefix
	requests       atomic.Uint64
	handled        atomic.Uint64
	overloads      atomic.Uint64
	rateLimited    atomic.Uint64
	accessDenied   atomic.Uint64
	pipelineErrors atomic.Uint64
	panics         atomic.Uint64
}

func New(opts ...Option) (IDNSServer, error) {
	cfg := &options{
		bind:               "127.0.0.1:5353",
		udpSize:            4096,
		maxResponseUDPSize: 1232,
		maxInflight:        1024,
		requestTimeout:     10 * time.Second,
		rateLimitClients:   4096,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.re == nil {
		return nil, fmt.Errorf("no rule engine found")
	}
	if strings.TrimSpace(cfg.bind) == "" {
		return nil, fmt.Errorf("DNS bind address is empty")
	}
	if err := validateBind(cfg.bind); err != nil {
		return nil, err
	}
	if cfg.udpSize < dns.MinMsgSize || cfg.udpSize > 64*1024 {
		return nil, fmt.Errorf("UDP read size must be between 512 and 65536")
	}
	if cfg.maxResponseUDPSize < dns.MinMsgSize || cfg.maxResponseUDPSize > cfg.udpSize {
		return nil, fmt.Errorf("maximum UDP response size must be between 512 and UDP read size")
	}
	if cfg.maxInflight < 1 {
		return nil, fmt.Errorf("maximum in-flight requests must be positive")
	}
	if cfg.requestTimeout <= 0 {
		return nil, fmt.Errorf("request timeout must be positive")
	}
	if math.IsNaN(cfg.rateLimitQPS) || math.IsInf(cfg.rateLimitQPS, 0) || cfg.rateLimitQPS < 0 || cfg.rateLimitQPS > 1_000_000_000 {
		return nil, fmt.Errorf("client rate limit QPS must be finite and between 0 and 1000000000")
	}
	if cfg.rateLimitQPS > 0 && cfg.rateLimitBurst < 1 {
		return nil, fmt.Errorf("client rate limit burst must be positive when rate limiting is enabled")
	}
	if cfg.rateLimitClients < 1 {
		return nil, fmt.Errorf("client rate limit capacity must be positive")
	}
	limiter, err := newClientRateLimiter(cfg.rateLimitQPS, cfg.rateLimitBurst, cfg.rateLimitClients)
	if err != nil {
		return nil, fmt.Errorf("create client rate limiter: %w", err)
	}
	allowedClients, err := parseAllowedCIDRs(cfg.allowedCIDRs)
	if err != nil {
		return nil, err
	}
	return &dnsServer{c: cfg, inflight: make(chan struct{}, cfg.maxInflight), limiter: limiter, allowedClients: allowedClients}, nil
}

func (s *dnsServer) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("DNS server context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.started.CompareAndSwap(false, true) {
		return fmt.Errorf("DNS server is already started")
	}
	defer s.started.Store(false)
	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	s.udpServer = &dns.Server{
		Addr:              s.c.bind,
		Net:               "udp",
		UDPSize:           s.c.udpSize,
		Handler:           dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) { s.handleDNS(ctx, w, req) }),
		NotifyStartedFunc: func() { close(udpReady) },
	}
	s.tcpServer = &dns.Server{
		Addr:              s.c.bind,
		Net:               "tcp",
		Handler:           dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) { s.handleDNS(ctx, w, req) }),
		NotifyStartedFunc: func() { close(tcpReady) },
	}
	errCh := make(chan error, 2)
	go func() { errCh <- s.udpServer.ListenAndServe() }()
	go func() { errCh <- s.tcpServer.ListenAndServe() }()

	udpWait := (<-chan struct{})(udpReady)
	tcpWait := (<-chan struct{})(tcpReady)
	for udpWait != nil || tcpWait != nil {
		select {
		case <-ctx.Done():
			return s.shutdown(ctx, ctx.Err())
		case err := <-errCh:
			if err == nil {
				err = fmt.Errorf("DNS listener stopped unexpectedly during startup")
			}
			return s.shutdown(ctx, err)
		case <-udpWait:
			udpWait = nil
		case <-tcpWait:
			tcpWait = nil
		}
	}
	if s.c.ready != nil {
		s.c.ready()
	}

	select {
	case <-ctx.Done():
		return s.shutdown(ctx, ctx.Err())
	case err := <-errCh:
		if err == nil {
			err = fmt.Errorf("DNS listener stopped unexpectedly")
		}
		return s.shutdown(ctx, err)
	}
}

func (s *dnsServer) shutdown(parent context.Context, cause error) error {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	var errs []error
	if s.udpServer != nil {
		errs = append(errs, s.udpServer.ShutdownContext(shutdownCtx))
	}
	if s.tcpServer != nil {
		errs = append(errs, s.tcpServer.ShutdownContext(shutdownCtx))
	}
	joined := errors.Join(errs...)
	if cause != nil {
		if joined != nil {
			return errors.Join(cause, joined)
		}
		return cause
	}
	return joined
}

func (s *dnsServer) handleDNS(parent context.Context, w dns.ResponseWriter, req *dns.Msg) {
	s.requests.Add(1)
	wrote := false
	defer func() {
		if recovered := recover(); recovered != nil {
			s.panics.Add(1)
			logger := logutil.GetLogger(parent)
			logger.Error("panic while handling DNS request", zap.Any("panic", recovered), zap.Stack("stack"))
			if !wrote && req != nil {
				_ = writeRcode(w, req, dns.RcodeServerFailure)
			}
		}
	}()
	client := clientAddress(w.RemoteAddr())
	if !s.clientAllowed(client) {
		s.accessDenied.Add(1)
		_ = writeRcode(w, req, dns.RcodeRefused)
		return
	}
	if !s.limiter.Allow(client, time.Now()) {
		s.rateLimited.Add(1)
		_ = writeRcode(w, req, dns.RcodeRefused)
		return
	}
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.overloads.Add(1)
		_ = writeRcode(w, req, dns.RcodeServerFailure)
		return
	}
	tid := s.tid.Add(1)
	ctx, cancel := context.WithTimeout(parent, s.c.requestTimeout)
	defer cancel()
	ctx = trace.WithTraceId(ctx, strconv.FormatUint(tid, 10))
	logger := logutil.GetLogger(ctx)
	if req == nil {
		logger.Error("received nil DNS request")
		return
	}
	if req.Response {
		wrote = writeRcode(w, req, dns.RcodeFormatError) == nil
		return
	}
	if req.Opcode != dns.OpcodeQuery {
		wrote = writeRcode(w, req, dns.RcodeNotImplemented) == nil
		return
	}
	if len(req.Question) != 1 {
		wrote = writeRcode(w, req, dns.RcodeFormatError) == nil
		return
	}
	ctx = matcher.WithRequestMeta(ctx, req)
	logger = logger.With(zap.String("domain", req.Question[0].Name), zap.Uint16("qtype", req.Question[0].Qtype))
	start := time.Now()
	resp, err := s.processRequest(ctx, req)
	if err == nil && resp == nil {
		err = fmt.Errorf("request pipeline returned a nil response")
	}
	if err == nil {
		err = resolver.ValidateResponse(req, resp)
	}
	if err != nil {
		s.pipelineErrors.Add(1)
		logger.Error("process DNS request failed", zap.Error(err))
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}
	if isUDPWriter(w) {
		resp.Truncate(s.responseUDPSize(req))
	}
	writeStart := time.Now()
	if err := w.WriteMsg(resp); err != nil {
		logger.Error("write DNS response failed", zap.Error(err))
		return
	}
	wrote = true
	s.handled.Add(1)
	if checked := logger.Check(zap.DebugLevel, "handled DNS request"); checked != nil {
		checked.Write(
			zap.Duration("proc_cost", writeStart.Sub(start)),
			zap.Duration("write_cost", time.Since(writeStart)),
			zap.String("ips", summariseIPs(resp)),
			zap.Int("rcode", resp.Rcode),
		)
	}
}

func (s *dnsServer) Stats() Stats {
	return Stats{
		Requests:       s.requests.Load(),
		Handled:        s.handled.Load(),
		Overloaded:     s.overloads.Load(),
		RateLimited:    s.rateLimited.Load(),
		AccessDenied:   s.accessDenied.Load(),
		PipelineErrors: s.pipelineErrors.Load(),
		Panics:         s.panics.Load(),
		InFlight:       len(s.inflight),
	}
}

func parseAllowedCIDRs(rawPrefixes []string) ([]netip.Prefix, error) {
	if len(rawPrefixes) > 256 {
		return nil, fmt.Errorf("allowed client CIDRs cannot contain more than 256 entries")
	}
	prefixes := make([]netip.Prefix, 0, len(rawPrefixes))
	for _, raw := range rawPrefixes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid allowed client CIDR %q: %w", raw, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, fmt.Errorf("IPv4-mapped allowed client CIDR %q must use a prefix of /96 or longer", raw)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (s *dnsServer) clientAllowed(client string) bool {
	if len(s.allowedClients) == 0 {
		return true
	}
	address, err := netip.ParseAddr(client)
	if err != nil {
		return false
	}
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	address = address.Unmap()
	for _, prefix := range s.allowedClients {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func validateBind(address string) error {
	_, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || port == "" {
		return fmt.Errorf("DNS bind must be a host:port address: %q", address)
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("DNS bind port must be between 1 and 65535: %q", address)
	}
	return nil
}

func writeRcode(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	if w == nil || req == nil {
		return fmt.Errorf("cannot write DNS error response without writer and request")
	}
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	return w.WriteMsg(resp)
}

func clientAddress(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
}

func isUDPWriter(w dns.ResponseWriter) bool {
	return w != nil && w.LocalAddr() != nil && strings.HasPrefix(w.LocalAddr().Network(), "udp")
}

func (s *dnsServer) responseUDPSize(req *dns.Msg) int {
	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
		size = int(opt.UDPSize())
	}
	if size > s.c.maxResponseUDPSize {
		size = s.c.maxResponseUDPSize
	}
	return size
}

func summariseIPs(msg *dns.Msg) string {
	addrs := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.A:
			addrs = append(addrs, record.A.String())
		case *dns.AAAA:
			addrs = append(addrs, record.AAAA.String())
		}
	}
	if len(addrs) > 3 {
		addrs = append(addrs[:3], "...")
	}
	return strings.Join(addrs, ",")
}

func (s *dnsServer) processRequest(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if response, ok := s.tryHosts(ctx, req); ok {
		return response, nil
	}
	return s.c.re.Execute(ctx, req)
}

func (s *dnsServer) tryHosts(ctx context.Context, req *dns.Msg) (*dns.Msg, bool) {
	if s.c.hosts == nil {
		return nil, false
	}
	response := new(dns.Msg)
	response.SetReply(req)
	response.Authoritative = true
	if answers, ok := s.c.hosts.Resolve(req.Question[0]); ok {
		response.Answer = append(response.Answer, answers...)
	}
	if len(response.Answer) == 0 {
		return nil, false
	}
	logutil.GetLogger(ctx).Debug("DNS request matched hosts")
	return response, true
}
