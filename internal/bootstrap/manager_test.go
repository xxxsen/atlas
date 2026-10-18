package bootstrap_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/bootstrap"
	"github.com/xxxsen/atlas/internal/hosts"
	"github.com/xxxsen/atlas/internal/resolver"
)

type queryFunc struct {
	name  string
	query func(context.Context, *dns.Msg) (*dns.Msg, error)
}

func (f queryFunc) Name() string { return f.name }
func (f queryFunc) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f.query(ctx, req)
}

type fixture struct {
	t       *testing.T
	private ed25519.PrivateKey
	config  bootstrap.Config
	options bootstrap.Options
	clock   atomic.Int64
}

func newFixture(t *testing.T, names string) *fixture {
	t.Helper()
	public, private := keyPair(t)
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "bootstrap.pub")
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, publicPath, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	domainPath := filepath.Join(dir, "domains.txt")
	if names == "" {
		names = "disk.sendev.cc\n"
	}
	writeFile(t, domainPath, names)
	f := &fixture{t: t, private: private, config: bootstrap.Config{Files: []string{domainPath}, PublicKeys: []string{publicPath}}, options: bootstrap.Options{Cache: resolver.CacheOptions{Size: 10}}}
	f.clock.Store(1_800_000_000_000)
	f.options.Now = f.now
	return f
}
func writeFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) now() time.Time          { return time.UnixMilli(f.clock.Load()) }
func (f *fixture) advance(d time.Duration) { f.clock.Add(d.Milliseconds()) }
func (f *fixture) wire(domain, address string, version int64, lifetime time.Duration) string {
	f.t.Helper()
	value, err := bootstrap.Sign(f.private, bootstrap.Record{Domain: domain, IssuedAt: version, ExpiresAt: f.now().Add(lifetime).UnixMilli(), A: []string{address}})
	if err != nil {
		f.t.Fatal(err)
	}
	return value
}
func (f *fixture) manager(upstreams ...resolver.IDNSResolver) *bootstrap.Manager {
	f.t.Helper()
	f.config.ServerList = make([]string, len(upstreams))
	for i := range upstreams {
		f.config.ServerList[i] = fmt.Sprintf("udp://192.0.2.%d:53", i+1)
	}
	f.options.Upstreams = upstreams
	m, err := bootstrap.New(context.Background(), f.config, f.options)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			f.t.Errorf("close bootstrap: %v", err)
		}
	})
	return m
}
func txtReply(req *dns.Msg, ttl uint32, values ...string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	for _, wire := range values {
		var parts []string
		for len(wire) > 255 {
			parts = append(parts, wire[:255])
			wire = wire[255:]
		}
		parts = append(parts, wire)
		msg.Answer = append(msg.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: parts})
	}
	return msg
}
func answer(wire string, ttl uint32) queryFunc {
	return queryFunc{"test", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) { return txtReply(req, ttl, wire), nil }}
}
func lookup(m *bootstrap.Manager, domain string, qtype uint16) (*dns.Msg, bool, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(domain), qtype)
	return m.Resolve(context.Background(), req)
}
func requireAddress(t *testing.T, msg *dns.Msg, handled bool, err error, address string, ttl uint32) {
	t.Helper()
	if err != nil || !handled || msg == nil {
		t.Fatalf("resolution failed: handled=%v msg=%v err=%v", handled, msg, err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("want one address, got %v", msg.Answer)
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != address || a.Hdr.Ttl != ttl {
		t.Fatalf("unexpected answer: %v, want %s TTL=%d", msg.Answer, address, ttl)
	}
}

func TestManagerWaitsForAllAndChoosesHighestVerifiedVersion(t *testing.T) {
	f := newFixture(t, "")
	version := f.now().UnixMilli() - 1000
	low := f.wire("disk.sendev.cc", "1.2.3.4", version, time.Hour)
	high := f.wire("disk.sendev.cc", "2.3.4.5", version+1, time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	m := f.manager(answer(low, 60), queryFunc{"slow", func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		close(entered)
		select {
		case <-release:
			return txtReply(req, 60, high), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	type result struct {
		msg     *dns.Msg
		handled bool
		err     error
	}
	done := make(chan result, 1)
	go func() { msg, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA); done <- result{msg, handled, err} }()
	<-entered
	select {
	case got := <-done:
		t.Fatalf("returned before collecting slow upstream: %+v", got)
	case <-time.After(25 * time.Millisecond):
	}
	release <- struct{}{}
	got := <-done
	requireAddress(t, got.msg, got.handled, got.err, "2.3.4.5", 60)
}

func TestManagerIgnoresInvalidCandidatesAndDoesNotCombineRRs(t *testing.T) {
	f := newFixture(t, "")
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), time.Hour)
	m := f.manager(queryFunc{"candidates", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		if req.Question[0].Name != "_atlas.disk.sendev.cc." || req.Question[0].Qtype != dns.TypeTXT {
			t.Errorf("unexpected internal question: %+v", req.Question)
		}
		return txtReply(req, 60, "unrelated TXT", wire[:len(wire)/2], wire[len(wire)/2:], wire), nil
	}})
	msg, handled, err := lookup(m, "DISK.sendev.cc.", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 60)
	g := newFixture(t, "")
	split := g.wire("disk.sendev.cc", "2.3.4.5", g.now().UnixMilli(), time.Hour)
	bad := g.manager(queryFunc{"split", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		return txtReply(req, 60, split[:len(split)/2], split[len(split)/2:]), nil
	}})
	if _, handled, err := lookup(bad, "disk.sendev.cc", dns.TypeA); !handled || err == nil {
		t.Fatal("separate TXT RRs were accepted as one record")
	}
}

func TestManagerSharesFamiliesAndHandlesOnlyExactNames(t *testing.T) {
	f := newFixture(t, "disk.sendev.cc:proof.sendev.cc\n")
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), time.Hour)
	var calls atomic.Int64
	m := f.manager(queryFunc{"one", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		if req.Question[0].Name != "proof.sendev.cc." {
			t.Errorf("TXT mapping lost: %v", req.Question)
		}
		return txtReply(req, 60, wire), nil
	}})
	for _, qtype := range []uint16{dns.TypeTXT, dns.TypeCNAME, dns.TypeHTTPS, dns.TypeSVCB} {
		msg, handled, err := lookup(m, "disk.sendev.cc", qtype)
		if err != nil || !handled || len(msg.Answer) != 0 {
			t.Fatalf("unsupported type leaked: msg=%v handled=%v err=%v", msg, handled, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsupported queries performed DNS discovery")
	}
	msg, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 60)
	msg, handled, err = lookup(m, "disk.sendev.cc", dns.TypeAAAA)
	if err != nil || !handled || len(msg.Answer) != 0 || msg.Rcode != dns.RcodeSuccess {
		t.Fatal("missing signed AAAA must be NODATA")
	}
	msg, handled, err = lookup(m, "disk.sendev.cc", dns.TypeANY)
	requireAddress(t, msg, handled, err, "1.2.3.4", 60)
	if calls.Load() != 1 {
		t.Fatalf("A and AAAA must share authenticated cache, calls=%d", calls.Load())
	}
	for _, name := range []string{"sub.disk.sendev.cc", "sendev.cc", "_atlas.disk.sendev.cc"} {
		if _, handled, err := lookup(m, name, dns.TypeA); err != nil || handled {
			t.Fatalf("incorrectly claimed %s", name)
		}
	}
}

func TestManagerKeepsVersionsWithoutCachedAnswers(t *testing.T) {
	for _, size := range []int64{0, 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := newFixture(t, "disk.sendev.cc\nlocal.sendev.cc\n")
			f.options.Cache.Size = size
			version := f.now().UnixMilli() - 1000
			var stage atomic.Int64
			m := f.manager(queryFunc{"versions", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
				domain := strings.TrimSuffix(strings.TrimPrefix(req.Question[0].Name, "_atlas."), ".")
				v := version + 10
				if stage.Load() > 0 {
					v = version
				}
				return txtReply(req, 1, f.wire(domain, "1.2.3.4", v, time.Hour)), nil
			}})
			if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
				t.Fatal(err)
			}
			if _, _, err := lookup(m, "local.sendev.cc", dns.TypeA); err != nil {
				t.Fatal(err)
			}
			stage.Store(1)
			if _, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA); !handled || err == nil || !strings.Contains(err.Error(), "rollback") {
				t.Fatalf("replay after eviction accepted: %v", err)
			}
		})
	}
}

func TestManagerRejectsConflictingHighestVersion(t *testing.T) {
	f := newFixture(t, "")
	version := f.now().UnixMilli()
	one := f.wire("disk.sendev.cc", "1.2.3.4", version, time.Hour)
	two := f.wire("disk.sendev.cc", "2.3.4.5", version, time.Hour)
	m := f.manager(answer(one, 60), answer(two, 60))
	if _, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA); !handled || err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("same-version conflict not rejected: %v", err)
	}
}

func TestManagerLazyCacheNeverOutlivesSignature(t *testing.T) {
	f := newFixture(t, "")
	f.options.Cache.Lazy = true
	f.options.Cache.MaxStale = time.Hour
	f.config.TTLMax = 2
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), 5*time.Second)
	var calls atomic.Int64
	refreshed := make(chan struct{}, 10)
	m := f.manager(queryFunc{"invalid-refresh", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		if calls.Add(1) == 1 {
			return txtReply(req, 600, wire), nil
		}
		refreshed <- struct{}{}
		return nil, errors.New("upstream unavailable")
	}})
	msg, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 2)
	f.advance(3 * time.Second)
	msg, handled, err = lookup(m, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 0)
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("stale hit did not refresh")
	}
	msg, handled, err = lookup(m, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 0)
	f.advance(2 * time.Second)
	if _, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA); !handled || err == nil {
		t.Fatal("served an expired signature from optimistic cache")
	}
}

func TestManagerNewUncacheableVersionRemovesOldCache(t *testing.T) {
	f := newFixture(t, "")
	f.options.Cache.Lazy, f.options.Cache.MaxStale = true, time.Hour
	version := f.now().UnixMilli()
	old := f.wire("disk.sendev.cc", "1.2.3.4", version, time.Hour)
	newer := f.wire("disk.sendev.cc", "2.3.4.5", version+1, time.Hour)
	var calls atomic.Int64
	m := f.manager(queryFunc{"uncacheable", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		switch calls.Add(1) {
		case 1:
			return txtReply(req, 1, old), nil
		case 2:
			return txtReply(req, 0, newer), nil
		default:
			return nil, errors.New("offline")
		}
	}})
	if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	f.advance(2 * time.Second)
	if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, _, err := lookup(m, "disk.sendev.cc", dns.TypeA)
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old cached answer survived new TTL-zero version")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestManagerHonorsDeadlineAndParallelLimit(t *testing.T) {
	f := newFixture(t, "")
	f.config.Parallel = 2
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), time.Hour)
	var active, maximum atomic.Int64
	upstreams := make([]resolver.IDNSResolver, 5)
	for i := range upstreams {
		upstreams[i] = queryFunc{fmt.Sprint(i), func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for previous := maximum.Load(); current > previous && !maximum.CompareAndSwap(previous, current); previous = maximum.Load() {
			}
			select {
			case <-time.After(5 * time.Millisecond):
				return txtReply(req, 60, wire), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}}
	}
	m := f.manager(upstreams...)
	msg, handled, err := lookup(m, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 60)
	if maximum.Load() > 2 {
		t.Fatalf("parallel bound exceeded: %d", maximum.Load())
	}
	g := newFixture(t, "")
	g.config.RequestTimeout = 1
	valid := g.wire("disk.sendev.cc", "1.2.3.4", g.now().UnixMilli(), time.Hour)
	limited := g.manager(queryFunc{"timeout", func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) { <-ctx.Done(); return nil, ctx.Err() }})
	req := new(dns.Msg)
	req.SetQuestion("disk.sendev.cc.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, handled, err = limited.Resolve(ctx, req)
	if !handled || err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("caller deadline ignored: %v", err)
	}
	// With the caller still waiting, the unified timeout may return a valid
	// result collected from one upstream even though another never responds.
	g.options.Cache.Size = 0
	limited2 := g.manager(answer(valid, 60), queryFunc{"timeout", func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) { <-ctx.Done(); return nil, ctx.Err() }})
	msg, handled, err = lookup(limited2, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 60)
}

func TestManagerSingleflightForConcurrentFamilies(t *testing.T) {
	f := newFixture(t, "")
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), time.Hour)
	var calls atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	m := f.manager(queryFunc{"shared", func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		once.Do(func() { close(entered) })
		select {
		case <-release:
			return txtReply(req, 60, wire), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			qtype := uint16(dns.TypeA)
			if i%2 != 0 {
				qtype = dns.TypeAAAA
			}
			if _, handled, err := lookup(m, "disk.sendev.cc", qtype); err != nil || !handled {
				t.Errorf("concurrent lookup failed: %v", err)
			}
		}(i)
	}
	<-entered
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expected shared discovery and cache, got %d queries", calls.Load())
	}
}

func TestManagerRejectsHostsOverlap(t *testing.T) {
	f := newFixture(t, "")
	store, err := hosts.New(map[string]string{"disk.sendev.cc": "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	f.options.Hosts = store
	f.config.ServerList = []string{"udp://127.0.0.1:53"}
	if _, err := bootstrap.New(context.Background(), f.config, f.options); err == nil || !strings.Contains(err.Error(), "conflicts with hosts") {
		t.Fatalf("hosts collision was not rejected: %v", err)
	}
}
