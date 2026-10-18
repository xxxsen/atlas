package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/config"
	"github.com/xxxsen/atlas/internal/ipset"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/atlas/internal/server"
)

func fallbackUpstream(t *testing.T, answer func(*dns.Msg) *dns.Msg) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	upstream := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if err := w.WriteMsg(answer(req)); err != nil {
			t.Errorf("test upstream write: %v", err)
		}
	})}
	done := make(chan error, 1)
	go func() { done <- upstream.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("start upstream: %v", err)
	}
	t.Cleanup(func() {
		if err := upstream.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return "udp://" + conn.LocalAddr().String() + "?timeout=500"
}

func fallbackAnswer(req *dns.Msg, ip string, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	if ip != "" {
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(ip)}}
	}
	return msg
}

func writeFallbackFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServerGeoIPValidationFallbackAndHostsWithRealUpstreams(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int64
	primary := fallbackUpstream(t, func(req *dns.Msg) *dns.Msg {
		primaryCalls.Add(1)
		switch req.Question[0].Name {
		case "allowed.test.":
			return fallbackAnswer(req, "111.235.160.1", 60)
		case "mixed.test.":
			msg := fallbackAnswer(req, "111.235.160.1", 60)
			msg.Answer = append(msg.Answer, fallbackAnswer(req, "81.2.69.142", 60).Answer...)
			return msg
		case "unknown.test.":
			return fallbackAnswer(req, "198.51.100.9", 60)
		case "nxdomain.test.":
			msg := fallbackAnswer(req, "", 0)
			msg.Rcode = dns.RcodeNameError
			return msg
		case "nodata.test.":
			return fallbackAnswer(req, "", 0)
		case "primary-failure.test.":
			msg := fallbackAnswer(req, "", 0)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		default:
			return fallbackAnswer(req, "81.2.69.142", 60)
		}
	})
	remote := fallbackUpstream(t, func(req *dns.Msg) *dns.Msg {
		fallbackCalls.Add(1)
		if req.Question[0].Name == "fallback-failure.test." {
			msg := fallbackAnswer(req, "", 0)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}
		return fallbackAnswer(req, "203.0.113.9", 60)
	})
	sets, err := ipset.Load([]ipset.Config{{
		Name: "cn", Format: "maxmind_mmdb", Countries: []string{"CN"},
		Files: []string{filepath.Join("..", "..", "internal", "ipset", "testdata", "GeoLite2-Country-Test.mmdb")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// The reference appears before its target in configuration.
	actions, err := buildActionMap([]config.ActionConfig{
		{Name: "cn", Type: "forward", Data: map[string]any{"server_list": []string{primary}, "parallel": 1, "validate": map[string]any{"ip_sets": []string{"cn"}}, "fallback": "remote"}},
		{Name: "remote", Type: "forward", Data: map[string]any{"server_list": []string{remote}, "parallel": 1}},
	}, action.Dependencies{IPSets: sets, QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeActions(actions); err != nil {
			t.Error(err)
		}
	})
	matchers, err := buildMatcherMap(nil)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := buildRuleEngine([]config.Rule{{Match: "any", Action: "cn"}}, matchers, actions)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := buildHostStore(config.HostConfig{Records: map[string]string{"host.test": "1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bind := listener.Addr().String()
	listener.Close()
	ready := make(chan struct{})
	forwarder, err := server.New(server.WithBind(bind), server.WithRuleEngine(engine), server.WithHostResolver(hosts), server.WithRequestTimeout(time.Second), server.WithReady(func() { close(ready) }))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("server did not start")
	}
	for _, network := range []string{"udp", "tcp"} {
		for _, test := range []struct {
			name     string
			rcode    int
			ip       string
			primary  int64
			fallback int64
		}{
			{"allowed.test.", dns.RcodeSuccess, "111.235.160.1", 1, 0},
			{"polluted.test.", dns.RcodeSuccess, "203.0.113.9", 1, 1},
			{"mixed.test.", dns.RcodeSuccess, "203.0.113.9", 1, 1},
			{"unknown.test.", dns.RcodeSuccess, "203.0.113.9", 1, 1},
			{"fallback-failure.test.", dns.RcodeServerFailure, "", 1, 1},
			{"primary-failure.test.", dns.RcodeServerFailure, "", 1, 0},
			{"nxdomain.test.", dns.RcodeNameError, "", 1, 0},
			{"nodata.test.", dns.RcodeSuccess, "", 1, 0},
			{"host.test.", dns.RcodeSuccess, "1.1.1.1", 0, 0},
		} {
			t.Run(network+"/"+test.name, func(t *testing.T) {
				p, f := primaryCalls.Load(), fallbackCalls.Load()
				req := new(dns.Msg)
				req.SetQuestion(test.name, dns.TypeA)
				client := &dns.Client{Net: network, Timeout: 2 * time.Second}
				msg, _, err := client.Exchange(req, bind)
				if err != nil {
					t.Fatal(err)
				}
				if msg.Rcode != test.rcode {
					t.Fatalf("rcode=%d, want %d", msg.Rcode, test.rcode)
				}
				if test.ip != "" && (len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != test.ip) {
					t.Fatalf("incorrect response: %v", msg)
				}
				if primaryCalls.Load()-p != test.primary || fallbackCalls.Load()-f != test.fallback {
					t.Fatalf("unexpected upstream calls: primary=%d fallback=%d", primaryCalls.Load()-p, fallbackCalls.Load()-f)
				}
			})
		}
	}
}

func TestValidationPolicyChangesRetainPersistedFreshAndStaleAnswers(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "fresh"
		if stale {
			name = "stale"
		}
		t.Run(name, func(t *testing.T) {
			var primaryCalls, fallbackCalls atomic.Int64
			ttl := uint32(60)
			if stale {
				ttl = 1
			}
			primary := fallbackUpstream(t, func(req *dns.Msg) *dns.Msg {
				primaryCalls.Add(1)
				return fallbackAnswer(req, "1.1.1.1", ttl)
			})
			remote := fallbackUpstream(t, func(req *dns.Msg) *dns.Msg {
				fallbackCalls.Add(1)
				msg := fallbackAnswer(req, "", 0)
				msg.Rcode = dns.RcodeServerFailure
				return msg
			})
			dir := t.TempDir()
			cfg := &config.Config{
				Resource: config.Resource{Action: []config.ActionConfig{
					{Name: "cn", Type: "forward", Data: map[string]any{"server_list": []string{primary}, "parallel": 1}},
					{Name: "remote", Type: "forward", Data: map[string]any{"server_list": []string{remote}, "parallel": 1}},
				}},
				Rule: []config.Rule{{Match: "any", Action: "cn"}},
				Cache: config.CacheConfig{
					Size: 64, MaxBytes: 1024 * 1024, MaxEntryBytes: 65535,
					Persist: true, File: filepath.Join(dir, "cache.jsonl"), Interval: 3600,
					Lazy: true, MaxStale: 5, RefreshConcurrency: 2, NegativeTTLMax: 3600,
				},
			}
			options, err := makeCacheOptions(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cache, err := resolver.NewCacheManager(context.Background(), options)
			if err != nil {
				t.Fatal(err)
			}
			oldActions, err := buildActionMap(cfg.Resource.Action, action.Dependencies{Cache: cache})
			if err != nil {
				t.Fatal(err)
			}
			req := new(dns.Msg)
			req.SetQuestion("cached.test.", dns.TypeA)
			if _, err := oldActions["cn"].Perform(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if err := cache.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := closeActions(oldActions); err != nil {
				t.Fatal(err)
			}
			if stale {
				time.Sleep(1100 * time.Millisecond)
			}
			ipFile := filepath.Join(dir, "cn.txt")
			writeFallbackFile(t, ipFile, "192.0.2.0/24\n")
			cfg.Resource.IPSet = []ipset.Config{{Name: "cn", Files: []string{ipFile}}}
			data := cfg.Resource.Action[0].Data.(map[string]any)
			data["validate"] = map[string]any{"ip_sets": []string{"cn"}}
			data["fallback"] = "remote"
			// Changing the rule file before restart also preserves the cache.
			writeFallbackFile(t, ipFile, "203.0.113.0/24\n")
			sets, err := ipset.Load(cfg.Resource.IPSet)
			if err != nil {
				t.Fatal(err)
			}
			newOptions, err := makeCacheOptions(cfg)
			if err != nil || options.Fingerprint != newOptions.Fingerprint {
				t.Fatalf("validation change altered fingerprint: %v", err)
			}
			reloaded, err := resolver.NewCacheManager(context.Background(), newOptions)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { reloaded.Close(context.Background()) })
			newActions, err := buildActionMap(cfg.Resource.Action, action.Dependencies{Cache: reloaded, IPSets: sets})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeActions(newActions) })
			if warning := reloaded.LastPersistenceError(); warning != nil {
				t.Fatal(warning)
			}
			msg, err := newActions["cn"].Perform(context.Background(), req)
			if err != nil || len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
				t.Fatalf("persisted answer was discarded: %v, %v", msg, err)
			}
			if stale {
				if msg.Answer[0].Header().Ttl != 0 || reloaded.Stats().StaleHits != 1 {
					t.Fatalf("stale persistence semantics changed: %v %+v", msg, reloaded.Stats())
				}
			} else if primaryCalls.Load() != 1 || fallbackCalls.Load() != 0 {
				t.Fatal("fresh persisted answer was revalidated")
			}
		})
	}
}
