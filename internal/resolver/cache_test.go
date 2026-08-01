package resolver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type mockResolver struct {
	count    atomic.Int64
	msg      *dns.Msg
	err      error
	delay    time.Duration
	dynamic  bool
	started  chan struct{}
	startOne sync.Once
}

func (m *mockResolver) Name() string { return "mock" }

func (m *mockResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	call := m.count.Add(1)
	if m.started != nil {
		m.startOne.Do(func() { close(m.started) })
	}
	if m.delay > 0 {
		timer := time.NewTimer(m.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	msg := m.msg.Copy()
	msg.Id = req.Id
	msg.Response = true
	msg.Question = append([]dns.Question(nil), req.Question...)
	if m.dynamic && len(msg.Answer) > 0 {
		if record, ok := msg.Answer[0].(*dns.A); ok {
			record.A = net.IPv4(192, 0, 2, byte(call%200+1))
		}
	}
	return msg, nil
}

func newResponse(ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.IPv4(1, 1, 1, 1),
	})
	return msg
}

func newNXDomainResponse(ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeNameError
	msg.Ns = append(msg.Ns, &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  1,
		Refresh: 60,
		Retry:   60,
		Expire:  300,
		Minttl:  ttl,
	})
	return msg
}

func newRequest() *dns.Msg {
	req := new(dns.Msg)
	req.Id = 1234
	req.RecursionDesired = true
	req.SetQuestion("example.com.", dns.TypeA)
	return req
}

func newTestCache(t *testing.T, mutate func(*CacheOptions)) *CacheManager {
	t.Helper()
	options := CacheOptions{
		Size:               64,
		MaxBytes:           1024 * 1024,
		MaxEntryBytes:      dns.MaxMsgSize,
		RefreshConcurrency: 2,
		QueryTimeout:       time.Second,
	}
	if mutate != nil {
		mutate(&options)
	}
	manager, err := NewCacheManager(context.Background(), options)
	if err != nil {
		t.Fatalf("NewCacheManager error: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := manager.Close(ctx); err != nil {
			t.Errorf("close cache: %v", err)
		}
	})
	return manager
}

func TestCacheOptionsRejectInertSettings(t *testing.T) {
	base := CacheOptions{
		Size:               64,
		MaxBytes:           1024 * 1024,
		MaxEntryBytes:      dns.MaxMsgSize,
		RefreshConcurrency: 2,
		QueryTimeout:       time.Second,
	}
	tests := map[string]func(*CacheOptions){
		"stale without lazy":           func(options *CacheOptions) { options.MaxStale = time.Minute },
		"file without persistence":     func(options *CacheOptions) { options.File = "cache.jsonl" },
		"interval without persistence": func(options *CacheOptions) { options.Interval = time.Minute },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if _, err := NewCacheManager(context.Background(), options); err == nil {
				t.Fatal("expected invalid cache options to be rejected")
			}
		})
	}
}

func TestCacheResolverBasic(t *testing.T) {
	manager := newTestCache(t, nil)
	base := &mockResolver{msg: newResponse(30)}
	wrapper, err := manager.Wrap("basic", base)
	if err != nil {
		t.Fatalf("Wrap error: %v", err)
	}
	req := newRequest()
	first, err := wrapper.Query(context.Background(), req)
	if err != nil {
		t.Fatalf("first query error: %v", err)
	}
	secondReq := req.Copy()
	secondReq.Id++
	second, err := wrapper.Query(context.Background(), secondReq)
	if err != nil {
		t.Fatalf("second query error: %v", err)
	}
	if base.count.Load() != 1 {
		t.Fatalf("expected one upstream call, got %d", base.count.Load())
	}
	if first.Id != req.Id || second.Id != secondReq.Id {
		t.Fatalf("cache did not restore per-request IDs")
	}
	stats := manager.Stats()
	if stats.Misses != 1 || stats.Hits != 1 || stats.Entries != 1 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

func TestCacheResolverSingleflight(t *testing.T) {
	manager := newTestCache(t, nil)
	base := &mockResolver{msg: newResponse(30), delay: 30 * time.Millisecond}
	wrapper, err := manager.Wrap("singleflight", base)
	if err != nil {
		t.Fatalf("Wrap error: %v", err)
	}
	const clients = 1000
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req := newRequest()
			req.Id = uint16(id + 1)
			resp, err := wrapper.Query(context.Background(), req)
			if err == nil && resp.Id != req.Id {
				err = errors.New("response ID was not restored")
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent query failed: %v", err)
		}
	}
	if base.count.Load() != 1 {
		t.Fatalf("expected one shared upstream query, got %d", base.count.Load())
	}
}

func TestCacheKeySeparatesDNSFlagsAndBypassesEDNSOptions(t *testing.T) {
	manager := newTestCache(t, nil)
	base := &mockResolver{msg: newResponse(30)}
	wrapper, err := manager.Wrap("flags", base)
	if err != nil {
		t.Fatalf("Wrap error: %v", err)
	}
	plain := newRequest()
	if _, err := wrapper.Query(context.Background(), plain); err != nil {
		t.Fatal(err)
	}
	dnssec := newRequest()
	dnssec.SetEdns0(1232, true)
	if _, err := wrapper.Query(context.Background(), dnssec); err != nil {
		t.Fatal(err)
	}
	if base.count.Load() != 2 {
		t.Fatalf("DO/EDNS request should use a separate key, calls=%d", base.count.Load())
	}
	checkingDisabled := newRequest()
	checkingDisabled.CheckingDisabled = true
	if _, err := wrapper.Query(context.Background(), checkingDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Query(context.Background(), checkingDisabled); err != nil {
		t.Fatal(err)
	}
	nonRecursive := newRequest()
	nonRecursive.RecursionDesired = false
	if _, err := wrapper.Query(context.Background(), nonRecursive); err != nil {
		t.Fatal(err)
	}
	if base.count.Load() != 4 {
		t.Fatalf("CD and RD semantics should use distinct keys, calls=%d", base.count.Load())
	}
	withCookie := newRequest()
	withCookie.SetEdns0(1232, false)
	withCookie.IsEdns0().Option = append(withCookie.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"})
	if _, err := wrapper.Query(context.Background(), withCookie); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Query(context.Background(), withCookie); err != nil {
		t.Fatal(err)
	}
	if base.count.Load() != 6 {
		t.Fatalf("EDNS COOKIE requests must bypass cache, calls=%d", base.count.Load())
	}
}

func TestCacheBypassesTruncatedServfailAndResponseOptions(t *testing.T) {
	manager := newTestCache(t, nil)
	tests := map[string]*dns.Msg{
		"truncated": func() *dns.Msg {
			msg := newResponse(30)
			msg.Truncated = true
			return msg
		}(),
		"servfail": func() *dns.Msg {
			msg := newResponse(30)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}(),
		"response option": func() *dns.Msg {
			msg := newResponse(30)
			msg.SetEdns0(1232, false)
			msg.IsEdns0().Option = append(msg.IsEdns0().Option, &dns.EDNS0_LOCAL{Code: 65001, Data: []byte("client-specific")})
			return msg
		}(),
	}
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			base := &mockResolver{msg: message}
			wrapper, err := manager.Wrap("bypass-"+name, base)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
					t.Fatal(err)
				}
			}
			if base.count.Load() != 2 {
				t.Fatalf("uncacheable response was cached")
			}
		})
	}
}

func TestCacheNamespacesAreIsolated(t *testing.T) {
	manager := newTestCache(t, nil)
	firstBase := &mockResolver{msg: newResponse(30)}
	secondMsg := newResponse(30)
	secondMsg.Answer[0].(*dns.A).A = net.IPv4(2, 2, 2, 2)
	secondBase := &mockResolver{msg: secondMsg}
	first, _ := manager.Wrap("first", firstBase)
	second, _ := manager.Wrap("second", secondBase)
	if _, err := first.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	resp, err := second.Query(context.Background(), newRequest())
	if err != nil {
		t.Fatal(err)
	}
	if secondBase.count.Load() != 1 || !resp.Answer[0].(*dns.A).A.Equal(net.IPv4(2, 2, 2, 2)) {
		t.Fatalf("cache leaked a response across namespaces")
	}
}

func TestCacheNegativeResponse(t *testing.T) {
	manager := newTestCache(t, nil)
	base := &mockResolver{msg: newNXDomainResponse(30)}
	wrapper, _ := manager.Wrap("negative", base)
	for i := 0; i < 2; i++ {
		resp, err := wrapper.Query(context.Background(), newRequest())
		if err != nil {
			t.Fatal(err)
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("unexpected rcode %d", resp.Rcode)
		}
	}
	if base.count.Load() != 1 {
		t.Fatalf("expected negative response cache hit, calls=%d", base.count.Load())
	}
}

func TestCacheCapsNegativeTTL(t *testing.T) {
	manager := newTestCache(t, func(options *CacheOptions) {
		options.NegativeTTLMax = 10 * time.Second
	})
	base := &mockResolver{msg: newNXDomainResponse(3600)}
	wrapper, _ := manager.Wrap("negative-cap", base)
	if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	cached, err := wrapper.Query(context.Background(), newRequest())
	if err != nil {
		t.Fatal(err)
	}
	soa := cached.Ns[0].(*dns.SOA)
	if soa.Hdr.Ttl > 10 || soa.Minttl > 10 {
		t.Fatalf("negative TTL was not capped: ttl=%d minimum=%d", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestCacheNegativeSOATTLUsesRFC2308Minimum(t *testing.T) {
	manager := newTestCache(t, nil)
	message := newNXDomainResponse(30)
	message.Ns[0].(*dns.SOA).Hdr.Ttl = 300
	base := &mockResolver{msg: message}
	wrapper, _ := manager.Wrap("negative-minimum", base)
	if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	cached, err := wrapper.Query(context.Background(), newRequest())
	if err != nil {
		t.Fatal(err)
	}
	soa := cached.Ns[0].(*dns.SOA)
	if soa.Hdr.Ttl > 30 || soa.Minttl > 30 {
		t.Fatalf("cached SOA TTL did not use RFC 2308 minimum: ttl=%d minimum=%d", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestCacheBypassesQueriesWithNonQuestionSections(t *testing.T) {
	manager := newTestCache(t, nil)
	base := &mockResolver{msg: newResponse(30)}
	wrapper, _ := manager.Wrap("query-sections", base)
	request := newRequest()
	request.Answer = append(request.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.IPv4(192, 0, 2, 1),
	})
	for range 2 {
		if _, err := wrapper.Query(context.Background(), request.Copy()); err != nil {
			t.Fatal(err)
		}
	}
	if base.count.Load() != 2 {
		t.Fatalf("query with answer section must bypass cache, calls=%d", base.count.Load())
	}
}

func TestAdjustMessageTTLPerRecord(t *testing.T) {
	msg := newResponse(300)
	msg.Ns = append(msg.Ns, &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.com."})
	adjustMessageTTL(msg, 10, false)
	if got := msg.Answer[0].Header().Ttl; got != 290 {
		t.Fatalf("answer TTL=%d, want 290", got)
	}
	if got := msg.Ns[0].Header().Ttl; got != 50 {
		t.Fatalf("authority TTL=%d, want 50", got)
	}
	adjustMessageTTL(msg, 0, true)
	if msg.Answer[0].Header().Ttl != 0 || msg.Ns[0].Header().Ttl != 0 {
		t.Fatal("stale response TTLs must be zero")
	}
}

func TestCacheEntryByteLimit(t *testing.T) {
	manager := newTestCache(t, func(options *CacheOptions) {
		options.MaxEntryBytes = 100
	})
	msg := newResponse(30)
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30},
		Txt: []string{"this response is deliberately too large for the configured entry budget"},
	})
	base := &mockResolver{msg: msg}
	wrapper, _ := manager.Wrap("large", base)
	if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	if base.count.Load() != 2 || manager.Stats().Entries != 0 {
		t.Fatalf("oversized entry should not be cached")
	}
}

func TestCachePersistsOnCloseAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.jsonl")
	options := CacheOptions{
		Size:               16,
		MaxBytes:           1024 * 1024,
		MaxEntryBytes:      dns.MaxMsgSize,
		Persist:            true,
		File:               path,
		Interval:           time.Hour,
		RefreshConcurrency: 1,
		QueryTimeout:       time.Second,
		Fingerprint:        "test-fingerprint",
	}
	first, err := NewCacheManager(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	base := &mockResolver{msg: newResponse(30)}
	wrapper, _ := first.Wrap("persist", base)
	if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	second, err := NewCacheManager(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = second.Close(ctx)
	})
	failing := &mockResolver{msg: newResponse(30), err: errors.New("upstream should not be called")}
	reloaded, _ := second.Wrap("persist", failing)
	if _, err := reloaded.Query(context.Background(), newRequest()); err != nil {
		t.Fatalf("persisted cache miss: %v", err)
	}
	if failing.count.Load() != 0 {
		t.Fatalf("persisted cache did not satisfy the query")
	}
}

func persistentOptions(path string) CacheOptions {
	return CacheOptions{
		Size:               16,
		MaxBytes:           1024 * 1024,
		MaxEntryBytes:      dns.MaxMsgSize,
		Persist:            true,
		File:               path,
		Interval:           20 * time.Millisecond,
		RefreshConcurrency: 1,
		QueryTimeout:       time.Second,
		Fingerprint:        "persistence-test",
	}
}

func TestCacheDiscardsAndReplacesCorruptPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.jsonl")
	if err := os.WriteFile(path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewCacheManager(context.Background(), persistentOptions(path))
	if err != nil {
		t.Fatalf("corrupt cache must not prevent startup: %v", err)
	}
	if manager.LastPersistenceError() == nil || manager.Stats().PersistenceErrors != 1 || manager.Stats().Entries != 0 {
		t.Fatalf("expected a recorded, safely discarded checkpoint error: %+v", manager.Stats())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := manager.Close(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()

	reloaded, err := NewCacheManager(context.Background(), persistentOptions(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reloaded.Close(context.Background()) }()
	if warning := reloaded.LastPersistenceError(); warning != nil {
		t.Fatalf("corrupt checkpoint was not replaced: %v", warning)
	}
}

type gateResolver struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gateResolver) Name() string { return "gate" }
func (r *gateResolver) Query(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	response := newResponse(30)
	response.Id = request.Id
	response.Question = append([]dns.Question(nil), request.Question...)
	return response, nil
}

func TestCacheCloseCanResumeAfterCallerTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.jsonl")
	options := persistentOptions(path)
	options.Interval = time.Hour
	manager, err := NewCacheManager(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	warm, _ := manager.Wrap("warm", &mockResolver{msg: newResponse(30)})
	if _, err := warm.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}

	gate := &gateResolver{started: make(chan struct{}), release: make(chan struct{})}
	blocking, _ := manager.Wrap("blocking", gate)
	queryDone := make(chan error, 1)
	go func() {
		request := newRequest()
		request.Question[0].Name = "blocking.test."
		_, err := blocking.Query(context.Background(), request)
		queryDone <- err
	}()
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("blocking cache task did not start")
	}
	shortCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	if err := manager.Close(shortCtx); !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatalf("first Close should respect its caller timeout, got %v", err)
	}
	cancel()
	close(gate.release)
	if err := <-queryDone; err != nil {
		t.Fatal(err)
	}
	longCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := manager.Close(longCtx); err != nil {
		t.Fatalf("second Close should observe completed shutdown: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("final checkpoint was not written: %v", err)
	}
}

func TestCachePersistenceFailureRetries(t *testing.T) {
	dir := t.TempDir()
	blockedParent := filepath.Join(dir, "parent")
	if err := os.WriteFile(blockedParent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blockedParent, "cache.jsonl")
	manager, err := NewCacheManager(context.Background(), persistentOptions(path))
	if err != nil {
		t.Fatal(err)
	}
	base := &mockResolver{msg: newResponse(30)}
	wrapper, _ := manager.Wrap("retry", base)
	if _, err := wrapper.Query(context.Background(), newRequest()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return manager.Stats().PersistenceErrors > 0 }, "initial persistence failure")
	if err := os.Remove(blockedParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blockedParent, 0o700); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, "persistence retry success")
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type boundedRefreshResolver struct {
	warmCalls int64
	calls     atomic.Int64
	active    atomic.Int64
	maximum   atomic.Int64
	release   chan struct{}
}

func (r *boundedRefreshResolver) Name() string { return "bounded-refresh" }
func (r *boundedRefreshResolver) Query(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	call := r.calls.Add(1)
	if call > r.warmCalls {
		active := r.active.Add(1)
		for {
			maximum := r.maximum.Load()
			if active <= maximum || r.maximum.CompareAndSwap(maximum, active) {
				break
			}
		}
		defer r.active.Add(-1)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.release:
		}
	}
	response := newResponse(30)
	response.Id = request.Id
	response.Question = append([]dns.Question(nil), request.Question...)
	response.Answer[0].Header().Name = request.Question[0].Name
	return response, nil
}

func TestCacheBoundsConcurrentStaleRefreshes(t *testing.T) {
	const entries = 8
	manager := newTestCache(t, func(options *CacheOptions) {
		options.Lazy = true
		options.MaxStale = time.Minute
		options.RefreshConcurrency = 2
	})
	base := &boundedRefreshResolver{warmCalls: entries, release: make(chan struct{})}
	wrapper, _ := manager.Wrap("refresh", base)
	requests := make([]*dns.Msg, 0, entries)
	for index := 0; index < entries; index++ {
		request := newRequest()
		request.Question[0].Name = dns.Fqdn("stale-" + string(rune('a'+index)) + ".test")
		requests = append(requests, request)
		if _, err := wrapper.Query(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	for _, shard := range manager.shards {
		shard.mu.Lock()
		for _, entry := range shard.cache.Values() {
			entry.expire = now.Add(-time.Second)
			entry.staleUntil = now.Add(time.Minute)
		}
		shard.mu.Unlock()
	}
	for _, request := range requests {
		if _, err := wrapper.Query(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, time.Second, func() bool { return base.active.Load() == 2 }, "two bounded refresh workers")
	if maximum := base.maximum.Load(); maximum > 2 {
		t.Fatalf("refresh concurrency exceeded limit: %d", maximum)
	}
	close(base.release)
	waitFor(t, time.Second, func() bool { return base.active.Load() == 0 }, "refresh workers to finish")
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
