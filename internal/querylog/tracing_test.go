package querylog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func recordingContext(t *testing.T) (context.Context, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return WithTracerProvider(context.Background(), provider), recorder
}

func TestSpanParentsAndDetachedLinksAreRecordedBySDK(t *testing.T) {
	base, recorder := recordingContext(t)
	caller, cancel := context.WithCancel(base)
	caller, root := Start(caller, "dns.query")
	forward, child := Start(caller, "forward")
	work, job := Fork(context.Background(), forward, "cache.upstream", false)
	wait, waiter := Start(forward, "cache.wait", trace.WithLinks(trace.Link{SpanContext: job.SpanContext()}))
	cancel()
	if work.Err() != nil {
		t.Fatal("shared work inherited caller cancellation")
	}
	Finish(wait, waiter, context.Canceled)
	Finish(work, job, nil)
	Finish(forward, child, nil)
	Finish(caller, root, nil)
	spans := make(map[string]sdktrace.ReadOnlySpan)
	for _, span := range recorder.Ended() {
		spans[span.Name()] = span
	}
	if len(spans) != 4 || len(recorder.Started()) != len(recorder.Ended()) {
		t.Fatalf("unfinished or missing spans: %+v", spans)
	}
	if spans["forward"].Parent().SpanID() != root.SpanContext().SpanID() || child.SpanContext().TraceID() != root.SpanContext().TraceID() {
		t.Fatal("SDK did not preserve normal parent/child relationships")
	}
	jobSpan := spans["cache.upstream"]
	if jobSpan.Parent().IsValid() || jobSpan.SpanContext().TraceID() == root.SpanContext().TraceID() || len(jobSpan.Links()) != 1 || !jobSpan.Links()[0].SpanContext.Equal(child.SpanContext()) {
		t.Fatal("shared work is not a separate trace linked to its initiator")
	}
	waitSpan := spans["cache.wait"]
	if waitSpan.Parent().SpanID() != child.SpanContext().SpanID() || len(waitSpan.Links()) != 1 || !waitSpan.Links()[0].SpanContext.Equal(job.SpanContext()) {
		t.Fatal("waiter is not linked to shared work")
	}
}

func TestFinishSanitizesExportedErrorsAndResolverAttributes(t *testing.T) {
	ctx, recorder := recordingContext(t)
	ctx = WithQuery(ctx, nil)
	ctx, span := Start(ctx, "dns.upstream")
	SetResult(ctx, Result{Source: "upstream", Resolver: "https://user:password@dns.example/dns-query?token=secret#fragment"})
	Finish(ctx, span, errors.New("request https://user:password@dns.example/dns-query?token=secret#fragment failed"))
	recorded := recorder.Ended()[0]
	if recorded.Status().Code != codes.Error || len(recorded.Events()) != 1 {
		t.Fatal("missing error status or exception event")
	}
	values := recorded.Status().Description
	for _, attr := range recorded.Attributes() {
		values += attr.Value.Emit()
	}
	for _, event := range recorded.Events() {
		for _, attr := range event.Attributes {
			values += attr.Value.Emit()
		}
	}
	for _, secret := range []string{"password", "secret", "fragment", "token="} {
		if strings.Contains(values, secret) {
			t.Fatalf("exported sensitive data: %s", values)
		}
	}
}

func TestNoExportStillProvidesTraceAndSpanIDs(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	ctx, provider, err := ConfigureTracing(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	ctx, root := Start(ctx, "dns.query")
	childCtx, child := Start(ctx, "forward")
	if !root.SpanContext().IsValid() || !child.SpanContext().IsValid() || ID(ctx) != ID(childCtx) || root.SpanContext().SpanID() == child.SpanContext().SpanID() || root.IsRecording() || child.IsRecording() {
		t.Fatal("non-exporting SDK did not keep independent, non-recording correlation IDs")
	}
	Finish(childCtx, child, nil)
	Finish(ctx, root, nil)
}

func TestOTLPHTTPExportsParentsLinksAndServiceResource(t *testing.T) {
	requests := make(chan *collectortrace.ExportTraceServiceRequest, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/traces" || req.Header.Get("Content-Type") != "application/x-protobuf" {
			http.Error(w, "invalid OTLP request", http.StatusBadRequest)
			return
		}
		data, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		var message collectortrace.ExportTraceServiceRequest
		if err != nil || proto.Unmarshal(data, &message) != nil {
			http.Error(w, "invalid protobuf", http.StatusBadRequest)
			return
		}
		requests <- &message
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")
	t.Setenv("OTEL_SERVICE_NAME", "atlas-otlp-test")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	ctx, provider, err := ConfigureTracing(context.Background(), "test-version")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	ctx, root := Start(ctx, "dns.query")
	childCtx, child := Start(ctx, "forward")
	work, job := Fork(context.Background(), childCtx, "cache.upstream", false)
	Finish(work, job, nil)
	Finish(childCtx, child, nil)
	Finish(ctx, root, nil)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := provider.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	var message *collectortrace.ExportTraceServiceRequest
	select {
	case message = <-requests:
	case <-shutdownCtx.Done():
		t.Fatal("OTLP exporter did not send traces")
	}
	count, parentFound, linkFound, serviceFound := 0, false, false, false
	rootID, childID := root.SpanContext().SpanID(), child.SpanContext().SpanID()
	for _, resource := range message.ResourceSpans {
		for _, attr := range resource.Resource.Attributes {
			if attr.Key == "service.name" && attr.Value.GetStringValue() == "atlas-otlp-test" {
				serviceFound = true
			}
		}
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				count++
				if span.Name == "forward" {
					parentFound = string(span.ParentSpanId) == string(rootID[:])
				}
				if span.Name == "cache.upstream" {
					linkFound = len(span.ParentSpanId) == 0 && len(span.Links) == 1 && string(span.Links[0].SpanId) == string(childID[:])
				}
			}
		}
	}
	if count != 3 || !parentFound || !linkFound || !serviceFound {
		t.Fatalf("incomplete OTLP export: count=%d parent=%v link=%v service=%v", count, parentFound, linkFound, serviceFound)
	}
}

func TestInvalidExporterConfigurationIsRejected(t *testing.T) {
	for _, exporter := range []string{"unknown", "otlp"} {
		t.Run(exporter, func(t *testing.T) {
			t.Setenv("OTEL_TRACES_EXPORTER", exporter)
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc")
			if _, provider, err := ConfigureTracing(context.Background(), "test"); err == nil {
				_ = provider.Shutdown(context.Background())
				t.Fatal("expected unsupported exporter/protocol to fail startup")
			}
		})
	}
}
