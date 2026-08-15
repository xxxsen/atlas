package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type recoverableResolver struct {
	name    string
	healthy atomic.Bool
	calls   atomic.Int64
}

func (r *recoverableResolver) Name() string { return r.name }

func (r *recoverableResolver) Query(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	if !r.healthy.Load() {
		return nil, errors.New("upstream unavailable")
	}
	response := new(dns.Msg)
	response.SetReply(request)
	return response, nil
}

func TestCircuitBreakerProbesAndRecovers(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)}
	upstream := &recoverableResolver{name: "recoverable"}
	breaker := newCircuitBreakerResolverWithConfig(upstream, circuitBreakerConfig{
		FailureThreshold: 2,
		InitialBackoff:   20 * time.Millisecond,
		MaximumBackoff:   80 * time.Millisecond,
		JitterPercent:    0,
		Now:              clock.Now,
	})
	request := new(dns.Msg)
	request.SetQuestion("recovery.test.", dns.TypeA)

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := breaker.Query(context.Background(), request.Copy()); err == nil {
			t.Fatal("unhealthy upstream unexpectedly succeeded")
		}
	}
	if health := breaker.resolverHealth(); health.Available || health.Probing {
		t.Fatalf("circuit did not open after consecutive failures: %+v", health)
	}
	if _, err := breaker.Query(context.Background(), request.Copy()); !errors.Is(err, ErrUpstreamCircuitOpen) {
		t.Fatalf("open circuit returned %v, want ErrUpstreamCircuitOpen", err)
	}
	if calls := upstream.calls.Load(); calls != 2 {
		t.Fatalf("open circuit reached upstream; calls=%d", calls)
	}

	clock.Advance(20 * time.Millisecond)
	upstream.healthy.Store(true)
	if _, err := breaker.Query(context.Background(), request.Copy()); err != nil {
		t.Fatalf("half-open recovery probe failed: %v", err)
	}
	if health := breaker.resolverHealth(); !health.Available || health.Probing {
		t.Fatalf("successful probe did not close circuit: %+v", health)
	}
	if _, err := breaker.Query(context.Background(), request.Copy()); err != nil {
		t.Fatalf("recovered circuit rejected normal query: %v", err)
	}
	if calls := upstream.calls.Load(); calls != 4 {
		t.Fatalf("unexpected upstream call count after recovery: %d", calls)
	}
}

type canceledResolver struct {
	calls atomic.Int64
}

func (*canceledResolver) Name() string { return "canceled" }

func (r *canceledResolver) Query(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	return nil, ctx.Err()
}

func TestCircuitBreakerIgnoresCallerCancellation(t *testing.T) {
	upstream := &canceledResolver{}
	breaker := newCircuitBreakerResolverWithConfig(upstream, circuitBreakerConfig{
		FailureThreshold: 1,
		InitialBackoff:   time.Hour,
		MaximumBackoff:   time.Hour,
		Now:              time.Now,
	})
	request := new(dns.Msg)
	request.SetQuestion("canceled.test.", dns.TypeA)
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := breaker.Query(ctx, request.Copy()); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled query returned %v", err)
		}
	}
	if health := breaker.resolverHealth(); !health.Available || health.Probing {
		t.Fatalf("caller cancellations changed circuit health: %+v", health)
	}
}

func TestCircuitBreakerCanceledHalfOpenProbeCanRetry(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)}
	upstream := &recoverableResolver{name: "half-open"}
	breaker := newCircuitBreakerResolverWithConfig(upstream, circuitBreakerConfig{
		FailureThreshold: 1,
		InitialBackoff:   20 * time.Millisecond,
		MaximumBackoff:   80 * time.Millisecond,
		JitterPercent:    0,
		Now:              clock.Now,
	})
	request := new(dns.Msg)
	request.SetQuestion("half-open-cancel.test.", dns.TypeA)
	if _, err := breaker.Query(context.Background(), request.Copy()); err == nil {
		t.Fatal("expected initial query to open circuit")
	}
	clock.Advance(20 * time.Millisecond)
	breaker.next = &canceledResolver{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := breaker.Query(ctx, request.Copy()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled half-open probe returned %v", err)
	}
	if health := breaker.resolverHealth(); health.Available || health.Probing {
		t.Fatalf("canceled probe left circuit in an invalid state: %+v", health)
	}

	clock.Advance(20 * time.Millisecond)
	upstream.healthy.Store(true)
	breaker.next = upstream
	if _, err := breaker.Query(context.Background(), request.Copy()); err != nil {
		t.Fatalf("circuit could not probe again after cancellation: %v", err)
	}
}

func TestGroupResolverSkipsCoolingCircuit(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)}
	unhealthy := &recoverableResolver{name: "unhealthy"}
	breaker := newCircuitBreakerResolverWithConfig(unhealthy, circuitBreakerConfig{
		FailureThreshold: 1,
		InitialBackoff:   time.Hour,
		MaximumBackoff:   time.Hour,
		JitterPercent:    0,
		Now:              clock.Now,
	})
	healthy := &recoverableResolver{name: "healthy"}
	healthy.healthy.Store(true)
	request := new(dns.Msg)
	request.SetQuestion("group-recovery.test.", dns.TypeA)
	if _, err := breaker.Query(context.Background(), request.Copy()); err == nil {
		t.Fatal("expected initial unhealthy query to open circuit")
	}
	group, err := NewGroupResolver("health-aware", []IDNSResolver{breaker, healthy}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := group.Query(context.Background(), request); err != nil {
		t.Fatalf("group did not use healthy child: %v", err)
	}
	if calls := unhealthy.calls.Load(); calls != 1 {
		t.Fatalf("group retried cooling upstream; calls=%d", calls)
	}
}

func TestGroupResolverLimitsAllOpenRecoveryProbe(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)}
	first := &recoverableResolver{name: "first"}
	second := &recoverableResolver{name: "second"}
	config := circuitBreakerConfig{
		FailureThreshold: 1,
		InitialBackoff:   time.Hour,
		MaximumBackoff:   time.Hour,
		JitterPercent:    0,
		Now:              clock.Now,
	}
	firstCircuit := newCircuitBreakerResolverWithConfig(first, config)
	secondCircuit := newCircuitBreakerResolverWithConfig(second, config)
	request := new(dns.Msg)
	request.SetQuestion("all-open.test.", dns.TypeA)
	for _, child := range []*circuitBreakerResolver{firstCircuit, secondCircuit} {
		if _, err := child.Query(context.Background(), request.Copy()); err == nil {
			t.Fatal("expected initial query to open circuit")
		}
	}
	group, err := NewGroupResolver("all-open", []IDNSResolver{firstCircuit, secondCircuit}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := group.Query(context.Background(), request.Copy()); !errors.Is(err, ErrNoAvailableUpstream) {
		t.Fatalf("cooling group returned %v, want ErrNoAvailableUpstream", err)
	}
	if first.calls.Load()+second.calls.Load() != 2 {
		t.Fatal("cooling group reached an upstream before retry time")
	}

	clock.Advance(time.Hour)
	first.healthy.Store(true)
	second.healthy.Store(true)
	if _, err := group.Query(context.Background(), request.Copy()); err != nil {
		t.Fatalf("group recovery probe failed: %v", err)
	}
	if calls := first.calls.Load() + second.calls.Load(); calls != 3 {
		t.Fatalf("all-open recovery fanned out to multiple probes; calls=%d", calls)
	}
}

type connectionGenerationKey struct{}

func TestDoHReplacesPoisonedHTTP2TransportAndRecovers(t *testing.T) {
	var currentResolver atomic.Pointer[dohResolver]
	var connections atomic.Int64
	var poisonFirstGeneration atomic.Bool
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		generation, _ := request.Context().Value(connectionGenerationKey{}).(uint64)
		if poisonFirstGeneration.Load() && generation == 1 {
			<-request.Context().Done()
			return
		}
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		payload, _ := response.Pack()
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(payload)
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		connections.Add(1)
		generation := uint64(0)
		if resolver := currentResolver.Load(); resolver != nil {
			generation = resolver.generation.Load()
		}
		return context.WithValue(ctx, connectionGenerationKey{}, generation)
	}
	server.StartTLS()
	defer server.Close()

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig
	item, err := newDoHResolverWithTLSConfig(server.URL, 150*time.Millisecond, tlsConfig, 1)
	if err != nil {
		t.Fatal(err)
	}
	resolver := item.(*dohResolver)
	currentResolver.Store(resolver)
	defer resolver.Close()
	request := new(dns.Msg)
	request.SetQuestion("transport-recovery.test.", dns.TypeA)

	if _, err := resolver.Query(context.Background(), request.Copy()); err != nil {
		t.Fatalf("initial DoH query failed: %v", err)
	}
	poisonFirstGeneration.Store(true)
	for attempt := 0; attempt < defaultDoHTransportFailureThreshold; attempt++ {
		if _, err := resolver.Query(context.Background(), request.Copy()); err == nil {
			t.Fatal("poisoned HTTP/2 transport unexpectedly succeeded")
		}
	}
	if generation := resolver.generation.Load(); generation != 2 {
		t.Fatalf("failed transport was not replaced; generation=%d", generation)
	}
	if _, err := resolver.Query(context.Background(), request.Copy()); err != nil {
		t.Fatalf("new transport generation did not recover: %v", err)
	}
	if count := connections.Load(); count < 2 {
		t.Fatalf("transport replacement did not establish a new connection: %d", count)
	}
	if state := resolver.state.Load(); state == nil || state.generation != 2 || state.failures.Load() != 0 {
		t.Fatalf("unexpected recovered transport state: %s", fmt.Sprint(state))
	}
}

func TestDoHConcurrentFailuresReplaceGenerationOnce(t *testing.T) {
	item, err := newDoHResolver("https://resolver.example/dns-query", time.Second, 4)
	if err != nil {
		t.Fatal(err)
	}
	resolver := item.(*dohResolver)
	t.Cleanup(func() { _ = resolver.Close() })
	failedState := resolver.state.Load()
	const workers = 32
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(workers)
	done.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			resolver.recordTransportFailure(context.Background(), failedState, errors.New("injected transport failure"))
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	current := resolver.state.Load()
	if generation := resolver.generation.Load(); generation != 2 {
		t.Fatalf("concurrent failures created more than one generation: %d", generation)
	}
	if current == nil || current == failedState || current.generation != 2 || !failedState.retired.Load() {
		t.Fatalf("unexpected generation swap: old=%p current=%p", failedState, current)
	}
}
