package forward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	_ "github.com/xxxsen/atlas/internal/action/rcode"
	"github.com/xxxsen/atlas/internal/ipset"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/resolver/model"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type policyUpstream struct {
	name   string
	calls  atomic.Int64
	closes atomic.Int64
	query  func(context.Context, *dns.Msg) (*dns.Msg, error)
}

func (r *policyUpstream) Name() string {
	if r.name != "" {
		return r.name
	}
	return "policy-test"
}
func (r *policyUpstream) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	return r.query(ctx, req)
}
func (r *policyUpstream) Close() error { r.closes.Add(1); return nil }

var policyEndpoints sync.Map
var policyEndpointID atomic.Uint64
var registerPolicyUpstream sync.Once

func policyURL(t *testing.T, r *policyUpstream) string {
	t.Helper()
	registerPolicyUpstream.Do(func() {
		resolver.Register("policytest", func(_ string, host string, _ *model.Params) (resolver.IDNSResolver, error) {
			value, ok := policyEndpoints.Load(host)
			if !ok {
				return nil, fmt.Errorf("unknown test endpoint %s", host)
			}
			return value.(*policyUpstream), nil
		})
	})
	id := fmt.Sprint(policyEndpointID.Add(1))
	policyEndpoints.Store(id, r)
	t.Cleanup(func() { policyEndpoints.Delete(id) })
	return "policytest://" + id
}

func makePolicyAction(t *testing.T, name string, upstreams []*policyUpstream, policy map[string]any, deps action.Dependencies) action.IDNSAction {
	t.Helper()
	urls := make([]string, len(upstreams))
	for i, upstream := range upstreams {
		urls[i] = policyURL(t, upstream)
	}
	data := map[string]any{"server_list": urls, "parallel": 1}
	for key, value := range policy {
		data[key] = value
	}
	item, err := createForwardAction(name, data, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := item.(action.Closer).Close(); err != nil {
			t.Error(err)
		}
	})
	return item
}

func policyRequest() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)
	return req
}

func replyWithIP(ip string) func(context.Context, *dns.Msg) (*dns.Msg, error) {
	return func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
		return msg, nil
	}
}

func privatePolicy(target string) map[string]any {
	return map[string]any{"validate": map[string]any{"networks": []string{"private"}}, "fallback": target}
}

func newPolicyCache(t *testing.T, mutate ...func(*resolver.CacheOptions)) *resolver.CacheManager {
	t.Helper()
	options := resolver.CacheOptions{
		Size: 64, MaxBytes: 1024 * 1024, MaxEntryBytes: 65535,
		RefreshConcurrency: 2, QueryTimeout: time.Second, Lazy: true, MaxStale: time.Minute,
	}
	for _, change := range mutate {
		change(&options)
	}
	cache, err := resolver.NewCacheManager(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cache.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return cache
}

func TestValidationChecksAllAnswerAddressesAndHints(t *testing.T) {
	var registry *ipset.Registry
	v, err := registry.Compile(ipset.ValidationConfig{Networks: []string{"private", "loopback"}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		rrs  []string
		bad  bool
	}{
		{"union per address", []string{"test. 60 IN A 10.0.0.1", "test. 60 IN AAAA ::1"}, false},
		{"mixed A records", []string{"test. 60 IN A 10.0.0.1", "test. 60 IN A 1.1.1.1"}, true},
		{"mixed families", []string{"test. 60 IN A 10.0.0.1", "test. 60 IN AAAA 2001:db8::1"}, true},
		{"mapped AAAA", []string{"test. 60 IN AAAA ::ffff:10.0.0.1"}, false},
		{"CNAME chain", []string{"test. 60 IN CNAME target.", "target. 60 IN A 1.1.1.1"}, true},
		{"CNAME only", []string{"test. 60 IN CNAME target."}, false},
		{"TXT", []string{`test. 60 IN TXT "1.1.1.1"`}, false},
		{"HTTPS allowed hints", []string{`test. 60 IN HTTPS 1 . ipv4hint=10.0.0.1,127.0.0.1 ipv6hint=fc00::1`}, false},
		{"HTTPS mixed hints", []string{`test. 60 IN HTTPS 1 . ipv4hint=10.0.0.1,1.1.1.1`}, true},
		{"SVCB IPv6 hints", []string{`test. 60 IN SVCB 1 . ipv6hint=fc00::1,2001:db8::1`}, true},
		{"SVCB IPv4 hints", []string{`test. 60 IN SVCB 1 . ipv4hint=1.1.1.1`}, true},
		{"HTTPS IPv6 hints", []string{`test. 60 IN HTTPS 1 . ipv6hint=2001:db8::1`}, true},
		{"no hints", []string{`test. 60 IN HTTPS 1 . alpn=h2`}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			for _, raw := range tt.rrs {
				rr, err := dns.NewRR(raw)
				if err != nil {
					t.Fatal(err)
				}
				msg.Answer = append(msg.Answer, rr)
			}
			if address, bad := rejectedAddress(msg, v); bad != tt.bad {
				t.Fatalf("rejected=%v address=%s, want %v", bad, address, tt.bad)
			}
		})
	}
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{&dns.A{A: net.ParseIP("1.1.1.1")}}
	msg.Extra = []dns.RR{&dns.AAAA{AAAA: net.ParseIP("2001:db8::1")}}
	if _, bad := rejectedAddress(msg, v); bad {
		t.Fatal("validated Authority/Additional instead of Answer only")
	}
}

func TestFirstRejectedWinnerFallsBackAndCachesFinalResponse(t *testing.T) {
	cache := newPolicyCache(t)
	deps := action.Dependencies{Cache: cache}
	bad := &policyUpstream{query: replyWithIP("1.1.1.1")}
	laterDomestic := &policyUpstream{query: replyWithIP("10.0.0.1")}
	foreign := &policyUpstream{query: replyWithIP("2.2.2.2")}
	cn := makePolicyAction(t, "cn", []*policyUpstream{bad, laterDomestic}, privatePolicy("remote"), deps)
	remote := makePolicyAction(t, "remote", []*policyUpstream{foreign}, nil, deps)
	if err := action.ResolveReferences(map[string]action.IDNSAction{"cn": cn, "remote": remote}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []action.IDNSAction{cn, cn, remote} {
		msg, err := item.Perform(context.Background(), policyRequest())
		if err != nil || msg.Answer[0].(*dns.A).A.String() != "2.2.2.2" || len(msg.Answer) != 1 {
			t.Fatalf("wrong final response: %v, %v", msg, err)
		}
	}
	if bad.calls.Load() != 1 || laterDomestic.calls.Load() != 0 || foreign.calls.Load() != 1 {
		t.Fatalf("queries: rejected=%d other-domestic=%d fallback=%d", bad.calls.Load(), laterDomestic.calls.Load(), foreign.calls.Load())
	}
	if cache.Stats().Entries != 2 {
		t.Fatalf("expected original and target cache entries: %+v", cache.Stats())
	}
}

func TestRejectedParallelWinnerCancelsOtherDomesticQuery(t *testing.T) {
	cancelled := make(chan struct{})
	started := make(chan struct{})
	slow := &policyUpstream{query: func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}}
	bad := &policyUpstream{query: func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		select {
		case <-started:
			return replyWithIP("1.1.1.1")(ctx, req)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	cn := makePolicyAction(t, "cn", []*policyUpstream{bad, slow}, map[string]any{
		"parallel": 2, "validate": map[string]any{"networks": []string{"private"}}, "fallback": "remote",
	}, action.Dependencies{})
	foreign := &policyUpstream{query: replyWithIP("2.2.2.2")}
	remote := makePolicyAction(t, "remote", []*policyUpstream{foreign}, nil, action.Dependencies{})
	if err := action.ResolveReferences(map[string]action.IDNSAction{"cn": cn, "remote": remote}); err != nil {
		t.Fatal(err)
	}
	if _, err := cn.Perform(context.Background(), policyRequest()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("fallback started before cancelling and joining the other domestic query")
	}
	if bad.calls.Load() != 1 || slow.calls.Load() != 1 || foreign.calls.Load() != 1 {
		t.Fatalf("unexpected attempts: %d %d %d", bad.calls.Load(), slow.calls.Load(), foreign.calls.Load())
	}
}

func TestValidationDoesNotFallbackOnOrdinaryFailureOrEmptyAnswers(t *testing.T) {
	for _, outcome := range []string{"transport error", "SERVFAIL", "NXDOMAIN", "NODATA", "CNAME"} {
		t.Run(outcome, func(t *testing.T) {
			primary := &policyUpstream{query: func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
				if outcome == "transport error" {
					return nil, errors.New("transport failed")
				}
				msg := new(dns.Msg)
				msg.SetReply(req)
				switch outcome {
				case "SERVFAIL":
					msg.Rcode = dns.RcodeServerFailure
				case "NXDOMAIN":
					msg.Rcode = dns.RcodeNameError
				case "CNAME":
					msg.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target."}}
				}
				return msg, nil
			}}
			foreign := &policyUpstream{query: replyWithIP("2.2.2.2")}
			cn := makePolicyAction(t, "cn", []*policyUpstream{primary}, privatePolicy("remote"), action.Dependencies{})
			remote := makePolicyAction(t, "remote", []*policyUpstream{foreign}, nil, action.Dependencies{})
			if err := action.ResolveReferences(map[string]action.IDNSAction{"cn": cn, "remote": remote}); err != nil {
				t.Fatal(err)
			}
			_, err := cn.Perform(context.Background(), policyRequest())
			wantError := outcome == "transport error" || outcome == "SERVFAIL"
			if (err != nil) != wantError || foreign.calls.Load() != 0 {
				t.Fatalf("unexpected fallback: err=%v calls=%d", err, foreign.calls.Load())
			}
		})
	}
}

func TestFallbackGraphOrderSharingAndLifecycle(t *testing.T) {
	upstream := &policyUpstream{query: replyWithIP("2.2.2.2")}
	remote := makePolicyAction(t, "remote", []*policyUpstream{upstream}, nil, action.Dependencies{})
	m := map[string]action.IDNSAction{"remote": remote}
	for _, name := range []string{"a", "b"} {
		m[name] = makePolicyAction(t, name, []*policyUpstream{{query: replyWithIP("1.1.1.1")}}, privatePolicy("remote"), action.Dependencies{})
	}
	if err := action.ResolveReferences(m); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if _, err := m[name].Perform(context.Background(), policyRequest()); err != nil {
			t.Fatal(err)
		}
		if err := m[name].(action.Closer).Close(); err != nil {
			t.Fatal(err)
		}
	}
	if upstream.calls.Load() != 2 || upstream.closes.Load() != 0 {
		t.Fatalf("fallback was not shared independently: calls=%d closes=%d", upstream.calls.Load(), upstream.closes.Load())
	}
	if err := remote.(action.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	if upstream.closes.Load() != 1 {
		t.Fatalf("shared target closed %d times", upstream.closes.Load())
	}
}

func TestFallbackGraphRejectsInvalidReferences(t *testing.T) {
	for _, kind := range []string{"missing", "self", "cycle", "non-forward"} {
		t.Run(kind, func(t *testing.T) {
			target := "b"
			if kind == "self" {
				target = "a"
			}
			a := makePolicyAction(t, "a", []*policyUpstream{{query: replyWithIP("1.1.1.1")}}, privatePolicy(target), action.Dependencies{})
			m := map[string]action.IDNSAction{"a": a}
			if kind == "cycle" {
				m["b"] = makePolicyAction(t, "b", []*policyUpstream{{query: replyWithIP("1.1.1.1")}}, privatePolicy("a"), action.Dependencies{})
			} else if kind == "non-forward" {
				var err error
				m["b"], err = action.MakeAction("rcode", "b", map[string]any{"code": 0})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := action.ResolveReferences(m); err == nil {
				t.Fatalf("accepted %s fallback graph", kind)
			}
		})
	}
}

func TestValidationConfigPairingAndEmptySets(t *testing.T) {
	r, err := ipset.Load([]ipset.Config{{Name: "empty"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []map[string]any{
		{"fallback": "remote"}, {"validate": map[string]any{"networks": []string{"private"}}},
		{"fallback": "remote", "validate": map[string]any{}},
		{"fallback": "remote", "validate": map[string]any{"ip_sets": []string{}}},
		{"fallback": "", "validate": map[string]any{"networks": []string{"private"}}},
		{"fallback": "remote", "validate": map[string]any{"ip_sets": []string{"missing"}}},
		{"fallback": "remote", "validate": map[string]any{"networks": []string{"reserved"}}},
		{"fallback": "remote", "validate": map[string]any{"network": []string{"private"}}},
	} {
		policy["server_list"] = []string{"udp://127.0.0.1:53"}
		policy["parallel"] = 1
		if item, err := createForwardAction("bad", policy, action.Dependencies{IPSets: r}); err == nil {
			item.(action.Closer).Close()
			t.Errorf("accepted invalid config: %+v", policy)
		}
	}
	item := makePolicyAction(t, "empty", []*policyUpstream{{query: replyWithIP("1.1.1.1")}}, map[string]any{
		"validate": map[string]any{"ip_sets": []string{"empty"}}, "fallback": "remote",
	}, action.Dependencies{IPSets: r})
	if _, err := item.Perform(context.Background(), policyRequest()); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("empty set should compile and reject addresses: %v", err)
	}
}

func TestMultiLevelFallbackSharesDeadlineWithAndWithoutCache(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprint("cache=", cached), func(t *testing.T) {
			deps := action.Dependencies{QueryTimeout: 400 * time.Millisecond}
			if cached {
				deps.Cache = newPolicyCache(t)
			}
			deadlines := make(chan time.Time, 3)
			delayed := func(final bool) *policyUpstream {
				return &policyUpstream{query: func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
					deadline, _ := ctx.Deadline()
					deadlines <- deadline
					if final {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					timer := time.NewTimer(30 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-timer.C:
						return replyWithIP("1.1.1.1")(ctx, req)
					}
				}}
			}
			first := makePolicyAction(t, "a", []*policyUpstream{delayed(false)}, privatePolicy("b"), deps)
			second := makePolicyAction(t, "b", []*policyUpstream{delayed(false)}, privatePolicy("c"), deps)
			third := makePolicyAction(t, "c", []*policyUpstream{delayed(true)}, nil, deps)
			if err := action.ResolveReferences(map[string]action.IDNSAction{"c": third, "b": second, "a": first}); err != nil {
				t.Fatal(err)
			}
			if _, err := first.Perform(context.Background(), policyRequest()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected shared deadline failure, got %v", err)
			}
			var original time.Time
			for i := 0; i < 3; i++ {
				select {
				case deadline := <-deadlines:
					if i == 0 {
						original = deadline
					} else if !deadline.Equal(original) {
						t.Fatalf("fallback reset budget: %s != %s", deadline, original)
					}
				case <-time.After(time.Second):
					t.Fatal("fallback did not reach every hop")
				}
			}
			if deps.Cache != nil && deps.Cache.Stats().Entries != 0 {
				t.Fatal("failed fallback was cached")
			}
		})
	}
}

func TestLazyRefreshValidatesAndFallsBackAfterCallerLeaves(t *testing.T) {
	cache := newPolicyCache(t)
	deps := action.Dependencies{Cache: cache, QueryTimeout: time.Second}
	var polluted atomic.Bool
	primary := &policyUpstream{query: func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		if polluted.Load() {
			return replyWithIP("1.1.1.1")(ctx, req)
		}
		msg, _ := replyWithIP("10.0.0.1")(ctx, req)
		msg.Answer[0].Header().Ttl = 1
		return msg, nil
	}}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	foreign := &policyUpstream{query: func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return replyWithIP("2.2.2.2")(ctx, req)
		}
	}}
	cn := makePolicyAction(t, "cn", []*policyUpstream{primary}, privatePolicy("remote"), deps)
	remote := makePolicyAction(t, "remote", []*policyUpstream{foreign}, nil, deps)
	if err := action.ResolveReferences(map[string]action.IDNSAction{"cn": cn, "remote": remote}); err != nil {
		t.Fatal(err)
	}
	if _, err := cn.Perform(context.Background(), policyRequest()); err != nil {
		t.Fatal(err)
	}
	polluted.Store(true)
	time.Sleep(1100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	msg, err := cn.Perform(ctx, policyRequest())
	cancel()
	if err != nil || msg.Answer[0].(*dns.A).A.String() != "10.0.0.1" || msg.Answer[0].Header().Ttl != 0 {
		t.Fatalf("expected immediate stale response with TTL 0: %v, %v", msg, err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not invoke fallback")
	}
	msg, err = cn.Perform(context.Background(), policyRequest())
	if err != nil || msg.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("rejected response replaced stale cache: %v, %v", msg, err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		msg, err = cn.Perform(context.Background(), policyRequest())
		if err != nil {
			t.Fatal(err)
		}
		if msg.Answer[0].(*dns.A).A.String() == "2.2.2.2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fallback did not replace original action cache after caller cancellation")
		}
		time.Sleep(time.Millisecond)
	}
	if foreign.calls.Load() != 1 {
		t.Fatalf("duplicate fallback refresh: %d", foreign.calls.Load())
	}
}

func TestFailedLazyFallbackKeepsOldDataOnlyUntilMaxStale(t *testing.T) {
	cache := newPolicyCache(t, func(options *resolver.CacheOptions) { options.MaxStale = 300 * time.Millisecond })
	deps := action.Dependencies{Cache: cache}
	var polluted atomic.Bool
	primary := &policyUpstream{query: func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		if polluted.Load() {
			return replyWithIP("1.1.1.1")(ctx, req)
		}
		msg, _ := replyWithIP("10.0.0.1")(ctx, req)
		msg.Answer[0].Header().Ttl = 1
		return msg, nil
	}}
	failed := make(chan struct{}, 4)
	foreign := &policyUpstream{query: func(context.Context, *dns.Msg) (*dns.Msg, error) {
		failed <- struct{}{}
		return nil, errors.New("overseas unavailable")
	}}
	cn := makePolicyAction(t, "cn", []*policyUpstream{primary}, privatePolicy("remote"), deps)
	remote := makePolicyAction(t, "remote", []*policyUpstream{foreign}, nil, deps)
	if err := action.ResolveReferences(map[string]action.IDNSAction{"cn": cn, "remote": remote}); err != nil {
		t.Fatal(err)
	}
	if _, err := cn.Perform(context.Background(), policyRequest()); err != nil {
		t.Fatal(err)
	}
	polluted.Store(true)
	time.Sleep(1050 * time.Millisecond)
	msg, err := cn.Perform(context.Background(), policyRequest())
	if err != nil || msg.Answer[0].(*dns.A).A.String() != "10.0.0.1" || msg.Answer[0].Header().Ttl != 0 {
		t.Fatalf("expected stale response: %v, %v", msg, err)
	}
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach failing fallback")
	}
	time.Sleep(350 * time.Millisecond)
	if msg, err = cn.Perform(context.Background(), policyRequest()); err == nil || msg != nil {
		t.Fatalf("failed refresh extended old cache beyond max_stale: %v, %v", msg, err)
	}
}

func TestFallbackLogsCostsSourceAndSeparatesCachedProvenance(t *testing.T) {
	cache := newPolicyCache(t)
	deps := action.Dependencies{Cache: cache}
	cn := makePolicyAction(t, "cn", []*policyUpstream{{name: "domestic-upstream", query: replyWithIP("1.1.1.1")}}, privatePolicy("remote"), deps)
	remote := makePolicyAction(t, "remote", []*policyUpstream{{name: "foreign-upstream", query: replyWithIP("2.2.2.2")}}, nil, deps)
	if err := action.ResolveReferences(map[string]action.IDNSAction{"cn": cn, "remote": remote}); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zapcore.DebugLevel)
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	var firstWork trace.SpanContext
	for _, id := range []string{"first-client", "second-client"} {
		req := policyRequest()
		ctx := querylog.WithQuery(querylog.WithLogger(querylog.WithTracerProvider(context.Background(), provider), zap.New(core)), req)
		ctx, span := querylog.Start(ctx, "dns.query")
		if _, err := cn.Perform(ctx, req); err != nil {
			t.Fatal(err)
		}
		querylog.Finish(ctx, span, nil)
		snapshot := querylog.Read(ctx)
		if id == "first-client" {
			firstWork = snapshot.Work
		}
		if snapshot.Result.Resolver != "foreign-upstream" || snapshot.Result.Action != "remote" || !snapshot.Result.ViaFallback {
			t.Fatalf("lost original response provenance: %+v", snapshot)
		}
		if snapshot.FallbackExecuted != (id == "first-client") {
			t.Fatalf("cache hit was reported as executing fallback: %+v", snapshot)
		}
	}
	trigger := logs.FilterMessage("forward response failed address validation").All()
	finished := logs.FilterMessage("forward fallback succeeded").All()
	if len(trigger) != 1 || len(finished) != 1 {
		t.Fatalf("unexpected fallback events: %d %d", len(trigger), len(finished))
	}
	if fields := trigger[0].ContextMap(); fields["primary_resolver"] != "domestic-upstream" || fields["rejected_ip"] != "1.1.1.1" || fields["trace_id"] != firstWork.TraceID().String() || fields["span_id"] == nil || fields["parent_traceid"] != nil {
		t.Fatalf("missing fallback trigger context: %+v", fields)
	}
	fields := finished[0].ContextMap()
	if finished[0].Level != zapcore.InfoLevel || fields["result_resolver"] != "foreign-upstream" || fields["elapsed_ms"] == nil || fields["primary_elapsed_ms"] == nil || fields["fallback_elapsed_ms"] == nil {
		t.Fatalf("missing fallback timing/source: %+v", fields)
	}
	if err := cache.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	fallbacks, rejectedEvents := 0, 0
	for _, span := range recorder.Ended() {
		if span.Name() == "forward.fallback" {
			fallbacks++
			if span.Parent().SpanID() != firstWork.SpanID() || span.SpanContext().TraceID() != firstWork.TraceID() || span.SpanContext().SpanID().String() != fields["span_id"] {
				t.Fatal("fallback span has the wrong parent or log context")
			}
		}
		for _, event := range span.Events() {
			if event.Name == "forward.validation.failed" {
				rejectedEvents++
			}
		}
	}
	if fallbacks != 1 || rejectedEvents != 1 || len(recorder.Started()) != len(recorder.Ended()) {
		t.Fatalf("fallback/cache trace mismatch or unfinished spans: fallbacks=%d rejected=%d started=%d ended=%d", fallbacks, rejectedEvents, len(recorder.Started()), len(recorder.Ended()))
	}
}
