package server

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type engineFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f engineFunc) Execute(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	return f(ctx, request)
}

func reserveBind(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

type runningServer struct {
	server IDNSServer
	bind   string
	cancel context.CancelFunc
	done   chan error
}

func startTestServer(t *testing.T, engine engineFunc, options ...Option) *runningServer {
	t.Helper()
	bind := reserveBind(t)
	ready := make(chan struct{})
	base := []Option{WithBind(bind), WithRuleEngine(engine), WithReady(func() { close(ready) })}
	base = append(base, options...)
	item, err := New(base...)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- item.Start(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("DNS server failed to start: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("DNS server did not become ready")
	}
	running := &runningServer{server: item, bind: bind, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("DNS server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("DNS server did not shut down")
		}
	})
	return running
}

func exchange(t *testing.T, network, address string, request *dns.Msg) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: network, Timeout: time.Second, UDPSize: 4096}
	response, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func exchangeUDPWire(t *testing.T, address string, request *dns.Msg) (*dns.Msg, int) {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wire, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(wire); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	length, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	if err := response.Unpack(buffer[:length]); err != nil {
		t.Fatal(err)
	}
	return response, length
}

func largeAnswerEngine(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
	response := new(dns.Msg)
	response.SetReply(request)
	for index := 0; index < 50; index++ {
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, byte(index+1)),
		})
	}
	return response, nil
}

func TestServerTruncatesUDPByClientCapacityAndKeepsTCPComplete(t *testing.T) {
	running := startTestServer(t, largeAnswerEngine)

	request := new(dns.Msg)
	request.SetQuestion("large.test.", dns.TypeA)
	udp, udpLength := exchangeUDPWire(t, running.bind, request)
	if !udp.Truncated || udpLength > dns.MinMsgSize {
		t.Fatalf("plain UDP response must be truncated to 512 bytes, TC=%v wire_len=%d", udp.Truncated, udpLength)
	}

	tcp := exchange(t, "tcp", running.bind, request)
	if tcp.Truncated || len(tcp.Answer) != 50 {
		t.Fatalf("TCP response must remain complete, TC=%v answers=%d", tcp.Truncated, len(tcp.Answer))
	}

	ednsRequest := request.Copy()
	ednsRequest.SetEdns0(1232, false)
	edns, ednsLength := exchangeUDPWire(t, running.bind, ednsRequest)
	if edns.Truncated || len(edns.Answer) != 50 || ednsLength > 1232 {
		t.Fatalf("EDNS 1232 response should fit, TC=%v answers=%d wire_len=%d", edns.Truncated, len(edns.Answer), ednsLength)
	}
}

func TestServerRejectsInvalidProtocolMessages(t *testing.T) {
	engine := engineFunc(func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(request)
		return response, nil
	})
	running := startTestServer(t, engine)

	notify := new(dns.Msg)
	notify.SetQuestion("notify.test.", dns.TypeSOA)
	notify.Opcode = dns.OpcodeNotify
	if got := exchange(t, "udp", running.bind, notify).Rcode; got != dns.RcodeNotImplemented {
		t.Fatalf("NOTIFY rcode=%d, want NOTIMP", got)
	}

	badQuestion := new(dns.Msg)
	badQuestion.Id = dns.Id()
	badQuestion.RecursionDesired = true
	if got := exchange(t, "udp", running.bind, badQuestion).Rcode; got != dns.RcodeFormatError {
		t.Fatalf("empty-question rcode=%d, want FORMERR", got)
	}

}

func TestServerOverloadFailsFast(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	engine := engineFunc(func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
		if strings.EqualFold(request.Question[0].Name, "hold.test.") {
			once.Do(func() { close(entered) })
			<-release
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return response, nil
	})
	running := startTestServer(t, engine, WithMaxInflight(1))

	firstDone := make(chan error, 1)
	go func() {
		request := new(dns.Msg)
		request.SetQuestion("hold.test.", dns.TypeA)
		client := &dns.Client{Net: "udp", Timeout: time.Second}
		_, _, err := client.Exchange(request, running.bind)
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request did not enter engine")
	}
	second := new(dns.Msg)
	second.SetQuestion("second.test.", dns.TypeA)
	if got := exchange(t, "udp", running.bind, second).Rcode; got != dns.RcodeServerFailure {
		t.Fatalf("overload rcode=%d, want SERVFAIL", got)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if running.server.Stats().Overloaded != 1 {
		t.Fatalf("expected overload metric, got %+v", running.server.Stats())
	}
}

func TestServerPerClientRateLimit(t *testing.T) {
	engine := engineFunc(func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(request)
		return response, nil
	})
	running := startTestServer(t, engine, WithClientRateLimit(0.01, 1, 16))
	request := new(dns.Msg)
	request.SetQuestion("rate.test.", dns.TypeA)
	if got := exchange(t, "udp", running.bind, request).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("first request rcode=%d", got)
	}
	request.Id = dns.Id()
	if got := exchange(t, "udp", running.bind, request).Rcode; got != dns.RcodeRefused {
		t.Fatalf("second request rcode=%d, want REFUSED", got)
	}
	if running.server.Stats().RateLimited != 1 {
		t.Fatalf("expected rate-limit metric, got %+v", running.server.Stats())
	}
}

func TestServerClientACL(t *testing.T) {
	engine := engineFunc(func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
		response := new(dns.Msg)
		response.SetReply(request)
		return response, nil
	})
	t.Run("allowed", func(t *testing.T) {
		running := startTestServer(t, engine, WithAllowedCIDRs([]string{"127.0.0.0/8"}))
		request := new(dns.Msg)
		request.SetQuestion("acl.test.", dns.TypeA)
		if got := exchange(t, "udp", running.bind, request).Rcode; got != dns.RcodeSuccess {
			t.Fatalf("allowed client rcode=%d", got)
		}
	})
	t.Run("denied", func(t *testing.T) {
		running := startTestServer(t, engine, WithAllowedCIDRs([]string{"192.0.2.0/24"}))
		request := new(dns.Msg)
		request.SetQuestion("acl.test.", dns.TypeA)
		if got := exchange(t, "udp", running.bind, request).Rcode; got != dns.RcodeRefused {
			t.Fatalf("denied client rcode=%d, want REFUSED", got)
		}
		if running.server.Stats().AccessDenied != 1 {
			t.Fatalf("expected ACL metric, got %+v", running.server.Stats())
		}
	})
}

func TestServerRequestTimeoutAndPanicRecovery(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		engine := engineFunc(func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		running := startTestServer(t, engine, WithRequestTimeout(20*time.Millisecond))
		request := new(dns.Msg)
		request.SetQuestion("timeout.test.", dns.TypeA)
		if got := exchange(t, "udp", running.bind, request).Rcode; got != dns.RcodeServerFailure {
			t.Fatalf("timeout rcode=%d, want SERVFAIL", got)
		}
		if running.server.Stats().PipelineErrors != 1 {
			t.Fatalf("expected pipeline error metric")
		}
	})

	t.Run("panic", func(t *testing.T) {
		engine := engineFunc(func(context.Context, *dns.Msg) (*dns.Msg, error) {
			panic("test panic")
		})
		running := startTestServer(t, engine)
		request := new(dns.Msg)
		request.SetQuestion("panic.test.", dns.TypeA)
		if got := exchange(t, "udp", running.bind, request).Rcode; got != dns.RcodeServerFailure {
			t.Fatalf("panic rcode=%d, want SERVFAIL", got)
		}
		if running.server.Stats().Panics != 1 {
			t.Fatalf("expected panic metric")
		}
	})
}

func TestServerConstructorValidation(t *testing.T) {
	engine := engineFunc(func(context.Context, *dns.Msg) (*dns.Msg, error) { return nil, nil })
	tests := []Option{
		WithBind("missing-port"),
		WithBind("127.0.0.1:70000"),
		WithUDPSize(1),
		WithMaxInflight(0),
		WithRequestTimeout(-time.Second),
		WithClientRateLimit(math.NaN(), 1, 1),
		WithClientRateLimit(1, 0, 1),
		WithClientRateLimit(1, 1, 0),
		WithAllowedCIDRs([]string{"not-a-prefix"}),
		WithAllowedCIDRs([]string{"::ffff:0:0/80"}),
	}
	for index, option := range tests {
		base := []Option{WithRuleEngine(engine)}
		if index != 0 && index != 1 {
			base = append(base, WithBind("127.0.0.1:5353"))
		}
		base = append(base, option)
		if _, err := New(base...); err == nil {
			t.Errorf("validation case %d unexpectedly succeeded", index)
		}
	}
	if _, err := New(WithBind("127.0.0.1:5353")); err == nil {
		t.Fatal("missing rule engine must fail")
	}
}
