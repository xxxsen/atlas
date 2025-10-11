package server

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"github.com/xxxsen/common/trace"
	"go.uber.org/zap"
)

// IDNSServer exposes the DNS server behaviour.
type IDNSServer interface {
	Start(ctx context.Context) error
}

type dnsServer struct {
	c         *options
	udpServer *dns.Server
	tcpServer *dns.Server
	tid       uint64
}

// New creates a DNS forwarder server using the supplied configuration.
func New(opts ...Option) (IDNSServer, error) {
	cfg := &options{
		bind: ":5353",
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.re == nil {
		return nil, fmt.Errorf("no rule engine found")
	}

	s := &dnsServer{
		c: cfg,
	}
	return s, nil
}

// Start begins listening on both UDP and TCP.
func (s *dnsServer) Start(ctx context.Context) error {
	s.udpServer = &dns.Server{
		Addr: s.c.bind,
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			s.handleDNS(ctx, w, req)
		}),
	}
	s.tcpServer = &dns.Server{
		Addr: s.c.bind,
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
	tid := atomic.AddUint64(&s.tid, 1)
	ctx = trace.WithTraceId(ctx, strconv.FormatUint(tid, 10))
	logger := logutil.GetLogger(ctx)
	resp, err := s.processRequest(ctx, req)
	if err != nil {
		logger.Error("process dns request failed", zap.Error(err))
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		logger.Error("write response failed", zap.Error(err))
		return
	}
	logger.Debug("response sent to client succ")
}

func (s *dnsServer) processRequest(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if req.Opcode != dns.OpcodeQuery || len(req.Question) == 0 {
		return nil, fmt.Errorf("invalid dns request, may be not implment yet")
	}
	question := req.Question[0]
	logger := logutil.GetLogger(ctx)
	logger.Debug("recv dns request", zap.String("domain", question.Name), zap.Uint16("qtype", question.Qtype))

	rsp, err := s.c.re.Execute(ctx, req)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}
