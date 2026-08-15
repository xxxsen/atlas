package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type countingListener struct {
	net.Listener
	accepts atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return connection, err
}

type dnsPair struct {
	address  string
	udp      *dns.Server
	tcp      *dns.Server
	listener *countingListener
}

func startDNSPair(t *testing.T, handler dns.Handler) *dnsPair {
	t.Helper()
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: baseListener}
	packet, err := net.ListenPacket("udp", baseListener.Addr().String())
	if err != nil {
		_ = baseListener.Close()
		t.Fatal(err)
	}
	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	pair := &dnsPair{
		address:  baseListener.Addr().String(),
		listener: listener,
		udp: &dns.Server{
			PacketConn:        packet,
			Handler:           handler,
			NotifyStartedFunc: func() { close(udpReady) },
		},
		tcp: &dns.Server{
			Listener:          listener,
			Handler:           handler,
			NotifyStartedFunc: func() { close(tcpReady) },
		},
	}
	errors := make(chan error, 2)
	go func() { errors <- pair.udp.ActivateAndServe() }()
	go func() { errors <- pair.tcp.ActivateAndServe() }()
	select {
	case <-udpReady:
	case err := <-errors:
		t.Fatalf("start UDP test server: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("UDP test server did not start")
	}
	select {
	case <-tcpReady:
	case err := <-errors:
		t.Fatalf("start TCP test server: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("TCP test server did not start")
	}
	t.Cleanup(func() {
		_ = pair.udp.Shutdown()
		_ = pair.tcp.Shutdown()
	})
	return pair
}

func TestClassicUDPTruncationFallsBackToTCP(t *testing.T) {
	var udpCalls atomic.Int64
	var tcpCalls atomic.Int64
	pair := startDNSPair(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if strings.HasPrefix(writer.LocalAddr().Network(), "udp") {
			udpCalls.Add(1)
			response.Truncated = true
		} else {
			tcpCalls.Add(1)
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.IPv4(192, 0, 2, 42),
			})
		}
		_ = writer.WriteMsg(response)
	}))

	item, err := MakeResolver("udp://" + pair.address + "?timeout=1000")
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("fallback.test.", dns.TypeA)
	response, err := item.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || response.Truncated {
		t.Fatalf("expected complete TCP fallback response, got %+v", response)
	}
	if udpCalls.Load() != 1 || tcpCalls.Load() != 1 {
		t.Fatalf("expected one UDP and one TCP query, got %d/%d", udpCalls.Load(), tcpCalls.Load())
	}
}

func TestClassicTCPPoolReusesConnection(t *testing.T) {
	pair := startDNSPair(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	}))
	item, err := MakeResolver("tcp://" + pair.address + "?timeout=1000&pool=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = item.(ResolverCloser).Close() })
	for i := 0; i < 2; i++ {
		request := new(dns.Msg)
		request.SetQuestion("pool.test.", dns.TypeA)
		if _, err := item.Query(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if pair.listener.accepts.Load() != 1 {
		t.Fatalf("expected one reused TCP connection, got %d accepts", pair.listener.accepts.Load())
	}
}

func TestClassicRejectsMismatchedResponse(t *testing.T) {
	pair := startDNSPair(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Id++
		_ = writer.WriteMsg(response)
	}))
	item, err := MakeResolver("udp://" + pair.address + "?timeout=50")
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("mismatch.test.", dns.TypeA)
	if _, err := item.Query(context.Background(), request); err == nil {
		t.Fatalf("expected response validation error, got %v", err)
	}
}

func TestTCPPoolDropsProtocolMismatchedConnection(t *testing.T) {
	pair := startDNSPair(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Id++
		_ = writer.WriteMsg(response)
	}))
	item, err := MakeResolver("tcp://" + pair.address + "?timeout=200&pool=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = item.(ResolverCloser).Close() })
	request := new(dns.Msg)
	request.SetQuestion("mismatch-pool.test.", dns.TypeA)
	if _, err := item.Query(context.Background(), request); err == nil {
		t.Fatal("expected pooled response validation error")
	}
	if pair.listener.accepts.Load() < 2 {
		t.Fatalf("protocol-mismatched connection was reused; accepts=%d", pair.listener.accepts.Load())
	}
}

func TestDNSConnectionPoolCloseUnblocksWaiter(t *testing.T) {
	pair := startDNSPair(t, dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = writer.WriteMsg(response)
	}))
	pool := newDNSConnectionPool(&dns.Client{Net: "tcp", Timeout: time.Second}, pair.address, 1)
	first, err := pool.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	waiter := make(chan error, 1)
	go func() {
		_, err := pool.acquire(context.Background())
		waiter <- err
	}()
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiter:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("pool waiter returned %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pool waiter was not released by Close")
	}
	pool.release(first, true)
}

func TestResolverURLValidationAndDoHQueryPreservation(t *testing.T) {
	item, err := MakeResolver("https://resolver.example/dns-query?token=%2fexact+value&route=b&timeout=1500&max_conns=7&max_inflight=5")
	if err != nil {
		t.Fatal(err)
	}
	limited := item.(*limitedResolver)
	circuit := limited.next.(*circuitBreakerResolver)
	doh := circuit.next.(*dohResolver)
	endpoint, err := url.Parse(doh.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.RawQuery != "token=%2fexact+value&route=b" || endpoint.Query().Get("token") != "/exact value" || endpoint.Query().Has("timeout") || endpoint.Query().Has("max_conns") || endpoint.Query().Has("max_inflight") {
		t.Fatalf("unexpected DoH endpoint query: %s", endpoint.RawQuery)
	}
	transport := doh.state.Load().transport
	if transport.MaxConnsPerHost != 7 || transport.MaxIdleConnsPerHost != 7 || !transport.ForceAttemptHTTP2 {
		t.Fatalf("unexpected DoH transport bounds: %+v", transport)
	}
	if transport.HTTP2 == nil || transport.HTTP2.SendPingTimeout != defaultDoHHTTP2SendPingTimeout || transport.HTTP2.PingTimeout != defaultDoHHTTP2PingTimeout {
		t.Fatalf("unexpected DoH HTTP/2 health-check defaults: %+v", transport.HTTP2)
	}
	if cap(limited.slots) != 5 {
		t.Fatalf("unexpected upstream in-flight limit: %d", cap(limited.slots))
	}
	_ = doh.Close()

	defaultItem, err := MakeResolver("https://resolver.example/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	defaultLimited := defaultItem.(*limitedResolver)
	defaultCircuit := defaultLimited.next.(*circuitBreakerResolver)
	defaultDoH := defaultCircuit.next.(*dohResolver)
	if cap(defaultLimited.slots) != defaultDoHMaxConnections || defaultDoH.timeout != defaultDoHRequestTimeout || defaultDoH.maxConnections != defaultDoHMaxConnections {
		t.Fatalf("unexpected default DoH budgets: slots=%d timeout=%s connections=%d", cap(defaultLimited.slots), defaultDoH.timeout, defaultDoH.maxConnections)
	}
	_ = defaultItem.(ResolverCloser).Close()

	for _, link := range []string{
		"",
		"udp://:53",
		"udp://127.0.0.1:70000",
		"udp://127.0.0.1:53/path",
		"udp://127.0.0.1:53?pool=2",
		"tcp://127.0.0.1:53?max_conns=2",
		"https://resolver.example/dns-query?pool=2",
		"https://user:pass@resolver.example/dns-query",
		"udp://127.0.0.1:53?timeout=-1",
		"udp://127.0.0.1:53?timeout=1&timeout=2",
		"https://resolver.example/dns-query?bad=%zz",
		"https://resolver.example/dns-query?token=ok&&route=bad",
	} {
		t.Run(link, func(t *testing.T) {
			if resolver, err := MakeResolver(link); err == nil {
				if closer, ok := resolver.(ResolverCloser); ok {
					_ = closer.Close()
				}
				t.Fatalf("expected resolver URL %q to fail", link)
			}
		})
	}
}

func TestDoHQuerySuccess(t *testing.T) {
	var sawToken atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("token") == "secret" {
			sawToken.Store(true)
		}
		if request.Header.Get("Content-Type") != "application/dns-message" || request.Header.Get("Accept") != "application/dns-message" {
			http.Error(writer, "bad DNS media headers", http.StatusBadRequest)
			return
		}
		wire, _ := io.ReadAll(request.Body)
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 80),
		})
		payload, _ := response.Pack()
		writer.Header().Set("Content-Type", "application/dns-message; charset=binary")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	item := testDoHResolver(t, server, "?token=secret")
	request := new(dns.Msg)
	request.SetQuestion("doh.test.", dns.TypeA)
	response, err := item.Query(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !sawToken.Load() || len(response.Answer) != 1 {
		t.Fatalf("DoH request did not preserve endpoint query or answer")
	}
}

func TestDoHUsesHTTP2AndReusesConnection(t *testing.T) {
	var protocol atomic.Int64
	var connections atomic.Int64
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		protocol.Store(int64(request.ProtoMajor))
		wire, _ := io.ReadAll(request.Body)
		query := new(dns.Msg)
		_ = query.Unpack(wire)
		response := new(dns.Msg)
		response.SetReply(query)
		payload, _ := response.Pack()
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(payload)
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig
	item, err := newDoHResolverWithTLSConfig(server.URL, time.Second, tlsConfig, 4)
	if err != nil {
		t.Fatal(err)
	}
	doh := item.(*dohResolver)
	t.Cleanup(func() { _ = doh.Close() })
	for index := 0; index < 2; index++ {
		request := new(dns.Msg)
		request.SetQuestion("http2.test.", dns.TypeA)
		if _, err := doh.Query(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if protocol.Load() != 2 {
		t.Fatalf("DoH used HTTP/%d instead of HTTP/2", protocol.Load())
	}
	if connections.Load() != 1 {
		t.Fatalf("DoH did not reuse its HTTP/2 connection: %d connections", connections.Load())
	}
}

func TestDoHRejectsInvalidResponses(t *testing.T) {
	tests := map[string]func(http.ResponseWriter, *http.Request){
		"status": func(writer http.ResponseWriter, _ *http.Request) {
			http.Error(writer, "upstream unavailable", http.StatusServiceUnavailable)
		},
		"content type": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte("not dns"))
		},
		"declared oversize": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/dns-message")
			writer.Header().Set("Content-Length", strconv.Itoa(dns.MaxMsgSize+1))
			writer.WriteHeader(http.StatusOK)
		},
		"streamed oversize": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/dns-message")
			writer.Header().Set("Trailer", "X-End")
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = writer.Write(bytes.Repeat([]byte{'x'}, dns.MaxMsgSize+1))
		},
		"wrong id":       dnsMutationHandler(func(_ *dns.Msg, response *dns.Msg) { response.Id++ }),
		"not response":   dnsMutationHandler(func(_ *dns.Msg, response *dns.Msg) { response.Response = false }),
		"wrong question": dnsMutationHandler(func(_ *dns.Msg, response *dns.Msg) { response.Question[0].Name = "other.test." }),
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(handler))
			defer server.Close()
			item := testDoHResolver(t, server, "")
			request := new(dns.Msg)
			request.SetQuestion("doh-invalid.test.", dns.TypeA)
			if _, err := item.Query(context.Background(), request); err == nil {
				t.Fatal("expected invalid DoH response to fail")
			}
		})
	}
}

func dnsMutationHandler(mutate func(*dns.Msg, *dns.Msg)) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		wire, _ := io.ReadAll(request.Body)
		query := new(dns.Msg)
		_ = query.Unpack(wire)
		response := new(dns.Msg)
		response.SetReply(query)
		mutate(query, response)
		payload, _ := response.Pack()
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(payload)
	}
}

func testDoHResolver(t *testing.T, server *httptest.Server, suffix string) *dohResolver {
	t.Helper()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig
	item, err := newDoHResolverWithTLSConfig(server.URL+suffix, time.Second, tlsConfig, 4)
	if err != nil {
		t.Fatal(err)
	}
	doh := item.(*dohResolver)
	t.Cleanup(func() { _ = doh.Close() })
	return doh
}

func TestEnsurePort(t *testing.T) {
	for input, expected := range map[string]string{
		"resolver.example": "resolver.example:53",
		"127.0.0.1":        "127.0.0.1:53",
		"[::1]":            "[::1]:53",
		"[::1]:5353":       "[::1]:5353",
	} {
		t.Run(fmt.Sprintf("%s_to_%s", input, expected), func(t *testing.T) {
			actual, err := ensurePort(input, "53")
			if err != nil || actual != expected {
				t.Fatalf("ensurePort(%q)=%q,%v; want %q", input, actual, err, expected)
			}
		})
	}
}
