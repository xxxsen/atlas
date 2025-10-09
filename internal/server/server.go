package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"

	"atlas/internal/cache"
	"atlas/internal/outbound"
	"atlas/internal/routing"
)

// IDNSServer exposes the DNS server behaviour.
type IDNSServer interface {
	Start(ctx context.Context) error
}

type dnsServer struct {
	bind         string
	udpServer    *dns.Server
	tcpServer    *dns.Server
	outbounds    outbound.IOutboundManager
	routes       []routing.IRouteRule
	cache        cache.IDNSCache
	cacheEnabled bool
	timeout      time.Duration
}

// New creates a DNS forwarder server using the supplied configuration.
func New(opts ...Option) (IDNSServer, error) {
	cfg := options{
		bind:    ":5353",
		timeout: 6 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.manager == nil {
		return nil, fmt.Errorf("outbound manager is required")
	}
	if len(cfg.routes) == 0 {
		return nil, fmt.Errorf("routing rules are required")
	}

	s := &dnsServer{
		bind:         cfg.bind,
		outbounds:    cfg.manager,
		routes:       cfg.routes,
		cache:        cfg.cache,
		cacheEnabled: cfg.cache != nil,
		timeout:      cfg.timeout,
	}
	return s, nil
}

// Start begins listening on both UDP and TCP.
func (s *dnsServer) Start(ctx context.Context) error {
	if s.outbounds == nil {
		return fmt.Errorf("outbound manager not initialised")
	}
	s.udpServer = &dns.Server{
		Addr: s.bind,
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			s.handleDNS(ctx, w, req)
		}),
	}
	s.tcpServer = &dns.Server{
		Addr: s.bind,
		Net:  "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			s.handleDNS(ctx, w, req)
		}),
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- s.udpServer.ListenAndServe()
	}()
	go func() {
		errCh <- s.tcpServer.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		s.shutdown()
		return ctx.Err()
	case err := <-errCh:
		s.shutdown()
		return err
	}
}

func (s *dnsServer) shutdown() {
	_ = s.udpServer.Shutdown()
	_ = s.tcpServer.Shutdown()
}

func (s *dnsServer) handleDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	log := logutil.GetLogger(ctx)
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic recovered while handling dns request", zap.Any("panic", r))
		}
	}()

	resp := s.processRequest(ctx, req)
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}
	if len(resp.Question) == 0 {
		resp.Question = req.Question
	}
	resp.Id = req.Id
	resp.RecursionAvailable = true
	resp.Compress = true

	if err := w.WriteMsg(resp); err != nil {
		log.Error("write response failed", zap.Error(err))
	}
	log.Debug("response sent to client", zap.String("question", questionName(resp)))
}

func (s *dnsServer) processRequest(ctx context.Context, req *dns.Msg) *dns.Msg {
	if req == nil {
		return nil
	}
	if req.Opcode != dns.OpcodeQuery || len(req.Question) == 0 {
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeNotImplemented)
		return msg
	}
	question := req.Question[0]
	key := cacheKey(question)
	log := logutil.GetLogger(ctx)
	log.Debug("processing dns question", zap.String("question", questionName(req)))

	for _, rule := range s.routes {
		decision, ok := rule.Match(question)
		if !ok || decision == nil {
			continue
		}
		if len(decision.Records) > 0 {
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, cloneRecords(decision.Records)...)
			log.Info("served response from static records", zap.String("question", questionName(req)), zap.Int("answer_count", len(reply.Answer)))
			return reply
		}
		if decision.OutboundTag == "" {
			continue
		}
		group, ok := s.outbounds.Get(decision.OutboundTag)
		if !ok {
			log.Warn("no outbound found for tag", zap.String("tag", decision.OutboundTag))
			continue
		}
		log.Debug("route matched outbound", zap.String("tag", decision.OutboundTag), zap.String("question", questionName(req)))

		// Cache lookup
		if s.cacheEnabled && decision.Cacheable {
			if res, found := s.cache.Get(key); found && res.Msg != nil {
				reply := res.Msg.Copy()
				reply.Question = req.Question
				log.Debug("cache hit for question", zap.String("question", questionName(req)), zap.Bool("stale", res.Expired))
				if res.ShouldRefresh {
					log.Debug("scheduling cache refresh", zap.String("question", questionName(req)))
					go s.refresh(ctx, key, req, group)
				}
				return reply
			}
			log.Debug("cache miss for question", zap.String("question", questionName(req)))
		}

		ctxTimeout, cancel := context.WithTimeout(ctx, s.timeout)
		resp, err := group.Query(ctxTimeout, cloneRequest(req))
		cancel()
		if err != nil {
			logutil.GetLogger(ctx).Error("query outbound failed", zap.String("tag", decision.OutboundTag), zap.Error(err))
			continue
		}
		resp.Question = req.Question
		if s.cacheEnabled && decision.Cacheable {
			s.cache.Set(key, resp)
			log.Debug("cached outbound response", zap.String("question", questionName(req)))
		}
		log.Info("forwarded response from outbound", zap.String("tag", decision.OutboundTag), zap.String("question", questionName(req)))
		return resp
	}

	log.Warn("no routing rule matched question", zap.String("question", questionName(req)))
	return nil
}

func (s *dnsServer) refresh(ctx context.Context, key string, req *dns.Msg, group outbound.IDnsOutbound) {
	if s.cache == nil {
		return
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := group.Query(ctxTimeout, cloneRequest(req))
	if err != nil {
		logutil.GetLogger(ctx).Warn("lazy refresh failed", zap.String("key", key), zap.Error(err))
		s.cache.MarkRefreshComplete(key)
		return
	}
	resp.Question = req.Question
	s.cache.Set(key, resp)
	logutil.GetLogger(ctx).Debug("cache refreshed", zap.String("question", questionName(req)))
}

func cloneRecords(records []dns.RR) []dns.RR {
	if len(records) == 0 {
		return nil
	}
	cloned := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if rr == nil {
			continue
		}
		cloned = append(cloned, dns.Copy(rr))
	}
	return cloned
}

func cloneRequest(req *dns.Msg) *dns.Msg {
	if req == nil {
		return nil
	}
	return req.Copy()
}

func cacheKey(question dns.Question) string {
	name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	return fmt.Sprintf("%s:%d:%d", name, question.Qtype, question.Qclass)
}

func questionName(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return ""
	}
	return strings.TrimSuffix(msg.Question[0].Name, ".")
}
