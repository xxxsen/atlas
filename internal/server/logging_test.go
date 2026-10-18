package server

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestSlowQuerySummaryIsVisibleWithoutDebugLogging(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	req := new(dns.Msg)
	req.SetQuestion("slow.test.", dns.TypeA)
	ctx := querylog.WithQuery(querylog.WithLogger(context.Background(), zap.New(core)), req)
	ctx, span := querylog.Start(ctx, "dns.query")
	defer querylog.Finish(ctx, span, nil)
	querylog.SetResult(ctx, querylog.Result{Source: "upstream", Resolver: "foreign", Action: "remote", ViaFallback: true})
	querylog.Apply(ctx, querylog.Read(ctx).Result, true)
	querylog.SetCache(ctx, "local", "miss")
	workCtx, workSpan := querylog.Fork(context.Background(), ctx, "cache.upstream", false)
	defer querylog.Finish(workCtx, workSpan, nil)
	querylog.SetWork(ctx, workSpan.SpanContext())
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
	if fields["trace_id"] != querylog.ID(ctx) || fields["span_id"] != span.SpanContext().SpanID().String() || fields["result_resolver"] != "foreign" || fields["fallback_executed"] != true || fields["cache_status"] != "miss" || fields["work_trace_id"] != querylog.ID(workCtx) || fields["work_span_id"] != workSpan.SpanContext().SpanID().String() || fields["proc_ms"] != float64(1500) {
		t.Fatalf("insufficient slow query diagnostics: %+v", fields)
	}
}
