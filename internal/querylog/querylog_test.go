package querylog

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestDetachedWorkKeepsDiagnosticsAndHasIndependentState(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeAAAA)
	caller, cancel := context.WithCancel(context.Background())
	caller = WithQuery(WithLogger(trace.WithTraceId(caller, "client-1"), zap.New(core)), req)
	SetResult(caller, Result{Source: "cache", Action: "local"})
	work := Fork(context.Background(), caller, "refresh-1", true)
	cancel()
	if work.Err() != nil || ID(work) != "refresh-1" {
		t.Fatal("detached work inherited client cancellation or lost its ID")
	}
	SetResult(work, Result{Source: "upstream", Resolver: "remote", Action: "foreign"})
	Logger(work).Info("refresh test")
	entry := logs.All()[0].ContextMap()
	if entry["traceid"] != "refresh-1" || entry["parent_traceid"] != "client-1" || entry["domain"] != "example.test." || entry["background"] != true {
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
