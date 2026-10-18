package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/common/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestCachePersistsProvenanceAndLoadsLegacyEntries(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "provenance", true: "legacy"}[legacy], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.jsonl")
			manager := newTestCache(t, func(cfg *CacheOptions) {
				cfg.Persist, cfg.File, cfg.Interval = true, path, time.Hour
				cfg.Fingerprint = "logging-provenance"
			})
			base := budgetQuery(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
				querylog.StartFallback(ctx)
				querylog.SetResult(ctx, querylog.Result{Source: "upstream", Resolver: "doh:https://dns.example/query?key=secret", Action: "remote", ViaFallback: true})
				msg := newResponse(60)
				msg.Id, msg.Question = req.Id, req.Question
				return msg, nil
			})
			if _, err := manager.Query(context.Background(), "local", base, newRequest()); err != nil {
				t.Fatal(err)
			}
			if err := manager.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "secret") {
				t.Fatal("persisted sensitive resolver URL parameters")
			}
			if legacy {
				var old strings.Builder
				scanner := bufio.NewScanner(strings.NewReader(string(data)))
				for scanner.Scan() {
					var record map[string]json.RawMessage
					if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
						t.Fatal(err)
					}
					delete(record, "result")
					line, err := json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
					old.Write(line)
					old.WriteByte('\n')
				}
				if err := scanner.Err(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(old.String()), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reloaded, err := NewCacheManager(context.Background(), manager.cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := reloaded.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			if err := reloaded.LastPersistenceError(); err != nil {
				t.Fatal(err)
			}
			req := newRequest()
			ctx := querylog.WithQuery(context.Background(), req)
			unexpected := budgetQuery(func(context.Context, *dns.Msg) (*dns.Msg, error) { return nil, errors.New("unexpected query") })
			if _, err := reloaded.Query(ctx, "local", unexpected, req); err != nil {
				t.Fatal(err)
			}
			snapshot := querylog.Read(ctx)
			if snapshot.CacheStatus != "fresh" || snapshot.FallbackExecuted {
				t.Fatalf("cache hit confused with new work: %+v", snapshot)
			}
			if legacy {
				if snapshot.Result.Source != "cache" || snapshot.Result.Resolver != "unknown" {
					t.Fatalf("invented legacy upstream provenance: %+v", snapshot)
				}
			} else if snapshot.Result.Resolver != "doh:https://dns.example/query" || snapshot.Result.Action != "remote" || !snapshot.Result.ViaFallback {
				t.Fatalf("lost persisted provenance: %+v", snapshot)
			}
		})
	}
}

func TestFailedBackgroundRefreshRetainsParentAndFailureContext(t *testing.T) {
	manager := newTestCache(t, func(cfg *CacheOptions) { cfg.Lazy, cfg.MaxStale = true, time.Minute })
	req := newRequest()
	key, _ := buildCacheKey("local", req)
	msg := newResponse(60)
	msg.Question = req.Question
	manager.store(key, msg, querylog.Result{Source: "upstream", Resolver: "old-upstream", Action: "local"})
	shard := manager.shard(key)
	shard.mu.Lock()
	entry, _ := shard.cache.Get(key)
	entry.expire = time.Now().Add(-time.Second)
	shard.mu.Unlock()
	core, logs := observer.New(zapcore.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = querylog.WithQuery(querylog.WithLogger(trace.WithTraceId(ctx, "stale-client"), zap.New(core)), req)
	fail := budgetQuery(func(context.Context, *dns.Msg) (*dns.Msg, error) { return nil, errors.New("fallback unavailable") })
	response, err := manager.Query(ctx, "local", fail, req)
	cancel()
	if err != nil || response.Answer[0].Header().Ttl != 0 {
		t.Fatalf("stale return changed: %v %v", response, err)
	}
	waitFor(t, time.Second, func() bool { return logs.FilterMessage("DNS cache refresh failed").Len() == 1 }, "refresh failure log")
	fields := logs.FilterMessage("DNS cache refresh failed").All()[0].ContextMap()
	if fields["parent_traceid"] != "stale-client" || fields["background"] != true || fields["namespace"] != "local" || fields["domain"] != "example.com." || fields["elapsed_ms"] == nil || fields["error"] != "fallback unavailable" {
		t.Fatalf("lost background failure context: %+v", fields)
	}
}

func TestCacheRechecksCompletedFlightBeforeStartingUpstream(t *testing.T) {
	manager := newTestCache(t, nil)
	req := newRequest()
	ctx := querylog.WithQuery(context.Background(), req)
	key, _ := buildCacheKey("local", req)
	if _, _, found, _ := manager.get(key); found {
		t.Fatal("expected initial cache miss")
	}
	querylog.SetCache(ctx, "local", "miss")
	// Simulate the previous flight finishing after this client's first lookup
	// but before it acquires the shared-flight lock.
	msg := newResponse(60)
	msg.Question = req.Question
	msg.Id = req.Id + 1
	origin := querylog.Result{Source: "upstream", Resolver: "remote-upstream", Action: "remote", ViaFallback: true}
	if !manager.store(key, msg, origin) {
		t.Fatal("could not seed completed response")
	}
	base := &mockResolver{msg: newResponse(60)}
	response, err := manager.queryFlight(ctx, key, base, req)
	if err != nil {
		t.Fatal(err)
	}
	if base.count.Load() != 0 || response.Id != req.Id {
		t.Fatalf("completed flight was queried again or response ID lost: calls=%d response=%v", base.count.Load(), response)
	}
	info := querylog.Read(ctx)
	if info.Result != origin || info.CacheStatus != "fresh" || info.FallbackExecuted || info.WorkID != "" {
		t.Fatalf("rechecked cache hit lost provenance or invented work: %+v", info)
	}
	if stats := manager.Stats(); stats.Hits != 1 || stats.Misses != 0 {
		t.Fatalf("rechecked cache hit counted as upstream work: %+v", stats)
	}
}
