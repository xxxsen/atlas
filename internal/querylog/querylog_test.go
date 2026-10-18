package querylog

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestDetachedWorkKeepsDiagnosticsAndHasIndependentState(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeAAAA)
	caller, cancel := context.WithCancel(context.Background())
	caller = WithQuery(WithLogger(caller, zap.New(core)), req)
	caller, clientSpan := Start(caller, "dns.query")
	defer Finish(caller, clientSpan, nil)
	SetResult(caller, Result{Source: "cache", Action: "local"})
	work, workSpan := Fork(context.Background(), caller, "cache.refresh", true)
	defer Finish(work, workSpan, nil)
	cancel()
	if work.Err() != nil || ID(work) == "" || ID(work) == ID(caller) {
		t.Fatal("detached work inherited client cancellation or lost its ID")
	}
	SetResult(work, Result{Source: "upstream", Resolver: "remote", Action: "foreign"})
	Logger(work).Info("refresh test")
	entry := logs.All()[0].ContextMap()
	if entry["trace_id"] != ID(work) || entry["span_id"] != workSpan.SpanContext().SpanID().String() || entry["parent_traceid"] != nil || entry["domain"] != "example.test." || entry["background"] != true {
		t.Fatalf("lost detached query context: %+v", entry)
	}
	if Read(caller).Result.Source != "cache" {
		t.Fatal("background work modified the response already returned to its client")
	}
}

func TestResultProvenanceIsSeparateFromFallbackExecutedNow(t *testing.T) {
	ctx := WithQuery(context.Background(), nil)
	Apply(ctx, Result{Source: "upstream", Resolver: "remote", Action: "foreign", ViaFallback: true}, false)
	if s := Read(ctx); !s.Result.ViaFallback || s.FallbackExecuted {
		t.Fatalf("cached provenance was confused with a new fallback: %+v", s)
	}
	StartFallback(ctx)
	SetResult(ctx, Result{Source: "upstream", Resolver: "another", Action: "another"})
	if s := Read(ctx); !s.FallbackExecuted || s.Result.Resolver != "another" {
		t.Fatalf("fallback execution was lost: %+v", s)
	}
}

func TestSensitiveURLPartsAreRemovedAndErrorsBounded(t *testing.T) {
	for _, input := range []string{
		"doh:https://user:password@dns.example/dns-query?token=secret#fragment",
		"request to HTTPS://user:password@dns.example/dns-query?token=secret failed",
	} {
		value := SafeText(input)
		for _, sensitive := range []string{"password", "secret", "token", "fragment"} {
			if strings.Contains(value, sensitive) {
				t.Fatalf("sensitive URL part %s survived: %s", sensitive, value)
			}
		}
		if !strings.Contains(value, "dns.example/dns-query") {
			t.Fatalf("lost useful endpoint identity: %s", value)
		}
	}
	if value := SafeText(strings.Repeat("x", 20_000)); len(value) > 1027 {
		t.Fatalf("unbounded upstream error: %d", len(value))
	}
}
