package bootstrap_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/bootstrap"
	"github.com/xxxsen/atlas/internal/querylog"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestTXTRejectionIsLoggedEvenWhenAnUpstreamAlsoReturnsValidData(t *testing.T) {
	for _, reason := range []string{"signature verification failed", "signature expired", "domain mismatch", "untrusted key"} {
		t.Run(reason, func(t *testing.T) {
			f := newFixture(t, "")
			version := f.now().UnixMilli() - 5000
			valid := f.wire("disk.sendev.cc", "1.2.3.4", version+1, time.Hour)
			bad := f.wire("disk.sendev.cc", "2.3.4.5", version, time.Hour)
			switch reason {
			case "signature verification failed":
				parts := strings.Split(bad, ".")
				signature, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				bad = strings.Join(parts, ".")
			case "signature expired":
				bad = f.wire("disk.sendev.cc", "2.3.4.5", version, -time.Second)
			case "domain mismatch":
				bad = f.wire("another.test", "2.3.4.5", version, time.Hour)
			case "untrusted key":
				_, otherKey := keyPair(t)
				var err error
				bad, err = bootstrap.Sign(otherKey, bootstrap.Record{Domain: "disk.sendev.cc", IssuedAt: version, ExpiresAt: f.now().Add(time.Hour).UnixMilli(), A: []string{"2.3.4.5"}})
				if err != nil {
					t.Fatal(err)
				}
			}
			m := f.manager(queryFunc{"mixed-upstream", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
				return txtReply(req, 60, bad, valid), nil
			}}, answer(f.wire("disk.sendev.cc", "1.2.3.4", version, time.Hour), 60))
			core, logs := observer.New(zapcore.DebugLevel)
			recorder := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
			ctx := querylog.WithLogger(querylog.WithTracerProvider(context.Background(), provider), zap.New(core))
			ctx, clientSpan := querylog.Start(ctx, "dns.query")
			defer querylog.Finish(ctx, clientSpan, nil)
			req := new(dns.Msg)
			req.SetQuestion("disk.sendev.cc.", dns.TypeA)
			_, handled, err := m.Resolve(ctx, req)
			if err != nil || !handled {
				t.Fatalf("valid candidate should succeed: %v", err)
			}
			if err := m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			rejected := logs.FilterMessage("bootstrap TXT candidate rejected").All()
			if len(rejected) != 1 {
				t.Fatalf("missing rejected candidate log: %+v", rejected)
			}
			fields := rejected[0].ContextMap()
			if rejected[0].Level != zapcore.WarnLevel || !strings.Contains(fmt.Sprint(fields["error"]), reason) || fields["resolver"] != "mixed-upstream" || fields["txt_domain"] != "_atlas.disk.sendev.cc" || fields["trace_id"] == nil || fields["span_id"] == nil || fields["parent_traceid"] != nil || fields["candidate_key_id"] == nil {
				t.Fatalf("insufficient TXT rejection context: %+v", fields)
			}
			accepted := logs.FilterMessage("accepted signed bootstrap addresses").All()
			if len(accepted) != 1 || accepted[0].ContextMap()["result_resolver"] != "mixed-upstream" {
				t.Fatalf("missing selected source: %+v", accepted)
			}
			linked, rejectedEvent := false, false
			for _, span := range recorder.Ended() {
				if span.Name() == "bootstrap.query" {
					linked = !span.Parent().IsValid() && len(span.Links()) == 1 && span.Links()[0].SpanContext.TraceID() == clientSpan.SpanContext().TraceID()
				}
				for _, event := range span.Events() {
					if event.Name == "bootstrap.candidate.rejected" {
						rejectedEvent = span.SpanContext().TraceID().String() == fields["trace_id"] && span.SpanContext().SpanID().String() == fields["span_id"]
					}
				}
			}
			if !linked || !rejectedEvent {
				t.Fatal("missing bootstrap Span Link or candidate rejection event")
			}
			for _, entry := range logs.All() {
				text := fmt.Sprint(entry.ContextMap())
				if strings.Contains(text, bad) || strings.Contains(text, valid) {
					t.Fatal("logged a signed TXT payload")
				}
			}
		})
	}
}
