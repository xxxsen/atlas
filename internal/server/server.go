package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"

	"atlas/internal/cache"
	"atlas/internal/config"
	"atlas/internal/outbound"
	"atlas/internal/routing"
)

// Server handles inbound DNS requests.
type Server struct {
	addr         string
	udpServer    *dns.Server
	tcpServer    *dns.Server
	outbounds    *outbound.Manager
	routes       []routing.IRouteRule
	cache        *cache.Cache
	cacheEnabled bool
	timeout      time.Duration
	logger       *log.Logger
}

// New creates a DNS forwarder server using the supplied configuration.
func New(cfg *config.Config, outbounds *outbound.Manager, routes []routing.IRouteRule, responseCache *cache.Cache, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		addr:         cfg.Bind,
		outbounds:    outbounds,
		routes:       routes,
		cache:        responseCache,
		cacheEnabled: responseCache != nil,
		timeout:      6 * time.Second,
		logger:       logger,
	}
	s.udpServer = &dns.Server{
		Addr:    cfg.Bind,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNS),
	}
	s.tcpServer = &dns.Server{
		Addr:    cfg.Bind,
		Net:     "tcp",
		Handler: dns.HandlerFunc(s.handleDNS),
	}
	return s
}

// Start begins listening on both UDP and TCP.
func (s *Server) Start(ctx context.Context) error {
	if s.outbounds == nil {
		return fmt.Errorf("outbound manager not initialised")
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

func (s *Server) shutdown() {
	_ = s.udpServer.Shutdown()
	_ = s.tcpServer.Shutdown()
}

func (s *Server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("panic recovered while handling dns request: %v", r)
		}
	}()

	resp := s.processRequest(req)
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}
	if resp.Question == nil || len(resp.Question) == 0 {
		resp.Question = req.Question
	}
	resp.Id = req.Id
	resp.RecursionAvailable = true
	resp.Compress = true

	if err := w.WriteMsg(resp); err != nil {
		s.logger.Printf("write response failed: %v", err)
	}
}

func (s *Server) processRequest(req *dns.Msg) *dns.Msg {
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

	for _, rule := range s.routes {
		decision, ok := rule.Match(question)
		if !ok || decision == nil {
			continue
		}
		if len(decision.Records) > 0 {
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, cloneRecords(decision.Records)...)
			return reply
		}
		if decision.OutboundTag == "" {
			continue
		}
		group, ok := s.outbounds.Get(decision.OutboundTag)
		if !ok {
			s.logger.Printf("no outbound found for tag %q", decision.OutboundTag)
			continue
		}

		// Cache lookup
		if s.cacheEnabled && decision.Cacheable {
			if res, found := s.cache.Get(key); found && res.Msg != nil {
				reply := res.Msg.Copy()
				reply.Question = req.Question
				if res.ShouldRefresh {
					go s.refresh(key, req, group)
				}
				return reply
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		resp, err := group.Query(ctx, cloneRequest(req))
		cancel()
		if err != nil {
			s.logger.Printf("query outbound %q failed: %v", decision.OutboundTag, err)
			continue
		}
		resp.Question = req.Question
		if s.cacheEnabled && decision.Cacheable {
			s.cache.Set(key, resp)
		}
		return resp
	}

	return nil
}

func (s *Server) refresh(key string, req *dns.Msg, group outbound.IDnsOutbound) {
	if s.cache == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	resp, err := group.Query(ctx, cloneRequest(req))
	if err != nil {
		s.logger.Printf("lazy refresh failed for %s: %v", key, err)
		s.cache.MarkRefreshComplete(key)
		return
	}
	resp.Question = req.Question
	s.cache.Set(key, resp)
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
