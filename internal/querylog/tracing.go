package querylog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type providerKey struct{}

// Keep valid correlation IDs even when these modules are used without the CLI.
// A non-recording SDK has no exporter or worker and retains no completed spans.
var localProvider = sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()))

func WithTracerProvider(ctx context.Context, provider trace.TracerProvider) context.Context {
	return context.WithValue(ctx, providerKey{}, provider)
}

func tracerProvider(ctx context.Context) trace.TracerProvider {
	if provider, ok := ctx.Value(providerKey{}).(trace.TracerProvider); ok {
		return provider
	}
	return localProvider
}

// ConfigureTracing uses standard OTel environment settings. Export is opt-in;
// none still generates valid IDs for every request without recording spans.
func ConfigureTracing(ctx context.Context, version string) (context.Context, *sdktrace.TracerProvider, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", "atlas"), attribute.String("service.version", version)),
		resource.WithFromEnv())
	if err != nil {
		return nil, nil, fmt.Errorf("initialize tracing resource: %w", err)
	}
	options := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}
	var exporter sdktrace.SpanExporter
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER"))) {
	case "", "none":
		options = append(options, sdktrace.WithSampler(sdktrace.NeverSample()))
	case "console":
		exporter, err = stdouttrace.New()
	case "otlp":
		protocol := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
		if protocol == "" {
			protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		}
		if protocol != "" && protocol != "http/protobuf" {
			return nil, nil, fmt.Errorf("Atlas OTLP export supports http/protobuf")
		}
		exporter, err = otlptracehttp.New(ctx)
	default:
		return nil, nil, fmt.Errorf("OTEL_TRACES_EXPORTER must be none, console, or otlp")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("initialize trace exporter: %w", err)
	}
	if exporter != nil {
		// The SDK's bounded queue drops excess spans instead of blocking DNS.
		options = append(options, sdktrace.WithBatcher(exporter))
	}
	provider := sdktrace.NewTracerProvider(options...)
	return WithTracerProvider(ctx, provider), provider, nil
}

func Start(ctx context.Context, name string, options ...trace.SpanStartOption) (context.Context, trace.Span) {
	ctx, span := tracerProvider(ctx).Tracer("github.com/xxxsen/atlas").Start(ctx, name, options...)
	if s, ok := ctx.Value(stateKey{}).(*state); ok && span.IsRecording() {
		span.SetAttributes(attribute.String("atlas.domain", s.domain), attribute.Int("atlas.qtype", int(s.qtype)), attribute.Bool("atlas.background", s.background))
	}
	return ctx, span
}

func StartUpstream(ctx context.Context, req *dns.Msg, resolver, transport string) (context.Context, trace.Span) {
	ctx = WithQuery(ctx, req)
	attributes := []attribute.KeyValue{attribute.String("atlas.resolver", SafeText(resolver)), attribute.String("atlas.transport", transport)}
	if req != nil && len(req.Question) == 1 {
		attributes = append(attributes, attribute.String("dns.question.name", req.Question[0].Name), attribute.String("dns.question.type", dns.TypeToString[req.Question[0].Qtype]))
	}
	return Start(ctx, "dns.upstream", trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attributes...))
}

// Fork starts independent work with a link to its initiator. It copies only
// diagnostic values; cancellation and deadlines still belong to the manager.
func Fork(parent, source context.Context, name string, background bool) (context.Context, trace.Span) {
	s := &state{background: background}
	if previous, ok := source.Value(stateKey{}).(*state); ok {
		s.domain, s.qtype = previous.domain, previous.qtype
		s.background = s.background || previous.background
	}
	ctx := WithTracerProvider(parent, tracerProvider(source))
	if logger, ok := source.Value(loggerKey{}).(*zap.Logger); ok {
		ctx = WithLogger(ctx, logger)
	}
	ctx = context.WithValue(ctx, stateKey{}, s)
	options := []trace.SpanStartOption{trace.WithNewRoot()}
	if sc := trace.SpanContextFromContext(source); sc.IsValid() {
		options = append(options, trace.WithLinks(trace.Link{SpanContext: sc}))
	}
	return Start(ctx, name, options...)
}

func Finish(ctx context.Context, span trace.Span, err error) {
	if span.IsRecording() {
		s := Read(ctx)
		span.SetAttributes(
			attribute.String("atlas.result.source", s.Result.Source), attribute.String("atlas.result.resolver", s.Result.Resolver),
			attribute.String("atlas.result.action", s.Result.Action), attribute.Bool("atlas.result.via_fallback", s.Result.ViaFallback),
			attribute.String("atlas.cache.namespace", s.CacheNamespace),
			attribute.String("atlas.cache.status", s.CacheStatus))
		if s.Result.Source != "" || s.FallbackExecuted {
			span.SetAttributes(attribute.Bool("atlas.fallback.executed", s.FallbackExecuted))
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			safe := SafeText(err.Error())
			span.RecordError(errors.New(safe))
			span.SetStatus(codes.Error, safe)
		}
	}
	span.End()
}
