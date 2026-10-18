package server

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/common/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestSlowQuerySummaryIsVisibleWithoutDebugLogging(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	req := new(dns.Msg)
	req.SetQuestion("slow.test.", dns.TypeA)
	ctx := querylog.WithQuery(querylog.WithLogger(trace.WithTraceId(context.Background(), "slow-client"), zap.New(core)), req)
	querylog.SetResult(ctx, querylog.Result{Source: "upstream", Resolver: "foreign", Action: "remote", ViaFallback: true})
	querylog.Apply(ctx, querylog.Read(ctx).Result, true)
	querylog.SetCache(ctx, "local", "miss")
	querylog.SetWork(ctx, "shared-work")
	msg := new(dns.Msg)
	msg.SetReply(req)
	logHandledRequest(ctx, msg, 5*time.Millisecond, time.Millisecond)
	if logs.Len() != 0 {
		t.Fatal("normal queries should not produce info-level summaries")
	}
	logHandledRequest(ctx, msg, 1500*time.Millisecond, time.Millisecond)
	entries := logs.FilterMessage("slow DNS request").All()
	if len(entries) != 1 || entries[0].Level != zapcore.WarnLevel {
		t.Fatalf("missing slow query warning: %+v", entries)
	}
	fields := entries[0].ContextMap()
	if fields["traceid"] != "slow-client" || fields["result_resolver"] != "foreign" || fields["fallback_executed"] != true || fields["cache_status"] != "miss" || fields["upstream_traceid"] != "shared-work" || fields["proc_ms"] != float64(1500) {
		t.Fatalf("insufficient slow query diagnostics: %+v", fields)
	}
}
