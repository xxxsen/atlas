package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
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

func TestFailedBackgroundRefreshRetainsTraceLinkAndFailureContext(t *testing.T) {
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
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	ctx, cancel := context.WithCancel(context.Background())
	ctx = querylog.WithQuery(querylog.WithLogger(querylog.WithTracerProvider(ctx, provider), zap.New(core)), req)
	ctx, clientSpan := querylog.Start(ctx, "dns.query")
	defer querylog.Finish(ctx, clientSpan, nil)
	fail := budgetQuery(func(context.Context, *dns.Msg) (*dns.Msg, error) { return nil, errors.New("fallback unavailable") })
	response, err := manager.Query(ctx, "local", fail, req)
	cancel()
	if err != nil || response.Answer[0].Header().Ttl != 0 {
		t.Fatalf("stale return changed: %v %v", response, err)
	}
	waitFor(t, time.Second, func() bool { return logs.FilterMessage("DNS cache refresh failed").Len() == 1 }, "refresh failure log")
	fields := logs.FilterMessage("DNS cache refresh failed").All()[0].ContextMap()
	if fields["parent_traceid"] != nil || fields["trace_id"] == querylog.ID(ctx) || fields["span_id"] == nil || fields["background"] != true || fields["namespace"] != "local" || fields["domain"] != "example.com." || fields["elapsed_ms"] == nil || fields["error"] != "fallback unavailable" {
		t.Fatalf("lost background failure context: %+v", fields)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, span := range recorder.Ended() {
		if span.Name() == "cache.refresh" {
			if span.Parent().IsValid() || len(span.Links()) != 1 || span.Links()[0].SpanContext.TraceID() != clientSpan.SpanContext().TraceID() || span.Status().Code != codes.Error || span.SpanContext().TraceID().String() != fields["trace_id"] {
				t.Fatalf("incorrect refresh trace or failure: %+v", span)
			}
			return
		}
	}
	t.Fatal("refresh span did not end")
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
	if info.Result != origin || info.CacheStatus != "fresh" || info.FallbackExecuted || info.Work.IsValid() {
		t.Fatalf("rechecked cache hit lost provenance or invented work: %+v", info)
	}
	if stats := manager.Stats(); stats.Hits != 1 || stats.Misses != 0 {
		t.Fatalf("rechecked cache hit counted as upstream work: %+v", stats)
	}
}

func TestSharedCacheWorkLinksAllWaitersAndSurvivesInitiatorCancellation(t *testing.T) {
	manager := newTestCache(t, nil)
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	core, logs := observer.New(zapcore.DebugLevel)
	baseCtx := querylog.WithLogger(querylog.WithTracerProvider(context.Background(), provider), zap.New(core))
	req := newRequest()
	firstCtx, cancel := context.WithCancel(querylog.WithQuery(baseCtx, req))
	firstCtx, first := querylog.Start(firstCtx, "dns.query")
	defer querylog.Finish(firstCtx, first, nil)
	defer cancel()
	secondCtx := querylog.WithQuery(baseCtx, req)
	secondCtx, second := querylog.Start(secondCtx, "dns.query")
	defer querylog.Finish(secondCtx, second, nil)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int64
	upstream := budgetQuery(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		querylog.SetResult(ctx, querylog.Result{Source: "upstream", Resolver: "shared-upstream", Action: "local"})
		msg := newResponse(60)
		msg.Id, msg.Question = req.Id, req.Question
		return msg, nil
	})
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := manager.Query(firstCtx, "local", upstream, req.Copy()); firstDone <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("shared work did not start")
	}
	go func() { _, err := manager.Query(secondCtx, "local", upstream, req.Copy()); secondDone <- err }()
	waitFor(t, time.Second, func() bool { return logs.FilterMessage("DNS cache query waiting").Len() == 2 }, "both shared waiters")
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter did not cancel: %v", err)
	}
	once.Do(func() { close(release) })
	if err := <-secondDone; err != nil {
		t.Fatalf("initiator canceled another client's work: %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	querylog.Finish(firstCtx, first, nil)
	querylog.Finish(secondCtx, second, nil)
	var work trace.SpanContext
	waiters := 0
	for _, span := range recorder.Ended() {
		if span.Name() == "cache.upstream" {
			work = span.SpanContext()
			if span.Parent().IsValid() || len(span.Links()) != 1 || span.Links()[0].SpanContext.TraceID() != first.SpanContext().TraceID() {
				t.Fatal("shared work is not an independent trace linked to its initiator")
			}
		}
	}
	if !work.IsValid() || calls.Load() != 1 || querylog.Read(firstCtx).Work.TraceID() != work.TraceID() || !querylog.Read(secondCtx).Work.Equal(work) {
		t.Fatal("callers did not share one upstream task")
	}
	for _, span := range recorder.Ended() {
		if span.Name() == "cache.wait" {
			waiters++
			if len(span.Links()) != 1 || !span.Links()[0].SpanContext.Equal(work) || !span.Parent().IsValid() || span.SpanContext().TraceID() == work.TraceID() {
				t.Fatal("waiter span lacks the shared task link or has the wrong parent")
			}
		}
	}
	if waiters != 2 || len(recorder.Started()) != len(recorder.Ended()) {
		t.Fatalf("missing waiters or leaked spans: waiters=%d started=%d ended=%d", waiters, len(recorder.Started()), len(recorder.Ended()))
	}
}
