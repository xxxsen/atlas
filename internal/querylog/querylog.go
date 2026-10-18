// Package querylog correlates DNS work and carries response provenance across
// shared cache work without coupling its cancellation to an individual client.
package querylog

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	commonlogger "github.com/xxxsen/common/logger"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Result struct {
	Source      string `json:"source,omitempty"`
	Resolver    string `json:"resolver,omitempty"`
	Action      string `json:"action,omitempty"`
	ViaFallback bool   `json:"via_fallback,omitempty"`
}

func (r Result) Sanitized() Result {
	r.Source = limit(r.Source, 32)
	r.Resolver = limit(SafeText(r.Resolver), 1024)
	r.Action = limit(r.Action, 256)
	return r
}

type Snapshot struct {
	Result           Result
	FallbackExecuted bool
	CacheNamespace   string
	CacheStatus      string
	Work             trace.SpanContext
}

type state struct {
	mu         sync.Mutex
	data       Snapshot
	domain     string
	qtype      uint16
	background bool
}

type stateKey struct{}
type loggerKey struct{}

// WithLogger provides a logger for this query and its detached work. It also
// allows log assertions without replacing the process-wide logger in tests.
func WithLogger(ctx context.Context, logger *zap.Logger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerKey{}, logger)
}

func WithQuery(ctx context.Context, req *dns.Msg) context.Context {
	if _, ok := ctx.Value(stateKey{}).(*state); ok {
		return ctx
	}
	s := &state{}
	if req != nil && len(req.Question) == 1 {
		s.domain, s.qtype = req.Question[0].Name, req.Question[0].Qtype
	}
	return context.WithValue(ctx, stateKey{}, s)
}

func ID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

func Logger(ctx context.Context) *zap.Logger {
	logger, ok := ctx.Value(loggerKey{}).(*zap.Logger)
	if !ok {
		logger = commonlogger.Logger()
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		logger = logger.With(zap.String("trace_id", sc.TraceID().String()), zap.String("span_id", sc.SpanID().String()))
	}
	if s, ok := ctx.Value(stateKey{}).(*state); ok {
		logger = logger.With(zap.String("domain", s.domain), zap.Uint16("qtype", s.qtype), zap.Bool("background", s.background))
	}
	return logger
}

func Read(ctx context.Context) Snapshot {
	if s, ok := ctx.Value(stateKey{}).(*state); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.data
	}
	return Snapshot{}
}

func SetResult(ctx context.Context, result Result) {
	Apply(ctx, result, false)
}

func Apply(ctx context.Context, result Result, fallbackExecuted bool) {
	if s, ok := ctx.Value(stateKey{}).(*state); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.data.Result = result.Sanitized()
		s.data.FallbackExecuted = s.data.FallbackExecuted || fallbackExecuted
	}
}

func StartFallback(ctx context.Context) {
	if s, ok := ctx.Value(stateKey{}).(*state); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.data.Result = Result{}
		s.data.FallbackExecuted = true
	}
}

func SetCache(ctx context.Context, namespace, status string) {
	if s, ok := ctx.Value(stateKey{}).(*state); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.data.CacheNamespace, s.data.CacheStatus = namespace, status
	}
}

func SetWork(ctx context.Context, work trace.SpanContext) {
	if s, ok := ctx.Value(stateKey{}).(*state); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.data.Work = work
	}
}

func Fields(ctx context.Context) []zap.Field {
	s := Read(ctx)
	fields := []zap.Field{
		zap.String("result_source", s.Result.Source), zap.String("result_resolver", s.Result.Resolver),
		zap.String("result_action", s.Result.Action), zap.Bool("result_via_fallback", s.Result.ViaFallback),
		zap.String("cache_namespace", s.CacheNamespace), zap.String("cache_status", s.CacheStatus),
	}
	fields = append(fields, WorkFields("work", s.Work)...)
	// A timed-out shared flight can still be running. Omit an unobserved false
	// value rather than suggesting that no fallback occurred in that work.
	if s.Result.Source != "" || s.FallbackExecuted {
		fields = append(fields, zap.Bool("fallback_executed", s.FallbackExecuted))
	}
	return fields
}

// WorkFields makes cross-trace links searchable in ordinary log files as well
// as in exported spans. All identifiers come from OpenTelemetry SpanContexts.
func WorkFields(prefix string, sc trace.SpanContext) []zap.Field {
	if !sc.IsValid() {
		return nil
	}
	return []zap.Field{zap.String(prefix+"_trace_id", sc.TraceID().String()), zap.String(prefix+"_span_id", sc.SpanID().String())}
}

func Elapsed(start time.Time) zap.Field {
	return zap.Float64("elapsed_ms", float64(time.Since(start))/float64(time.Millisecond))
}

func IPs(msg *dns.Msg) []string {
	var addresses []string
	if msg == nil {
		return addresses
	}
	for _, rr := range msg.Answer {
		var values []dns.SVCBKeyValue
		switch record := rr.(type) {
		case *dns.A:
			addresses = append(addresses, record.A.String())
		case *dns.AAAA:
			addresses = append(addresses, record.AAAA.String())
		case *dns.HTTPS:
			values = record.Value
		case *dns.SVCB:
			values = record.Value
		}
		for _, value := range values {
			switch hint := value.(type) {
			case *dns.SVCBIPv4Hint:
				for _, ip := range hint.Hint {
					addresses = append(addresses, ip.String())
				}
			case *dns.SVCBIPv6Hint:
				for _, ip := range hint.Hint {
					addresses = append(addresses, ip.String())
				}
			}
		}
		if len(addresses) > 8 {
			return append(addresses[:8], "...")
		}
	}
	return addresses
}

var urlPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

// SafeText omits URL credentials, query strings and fragments, and bounds
// messages originating from upstreams. TXT payloads must never be logged.
func SafeText(value string) string {
	value = urlPattern.ReplaceAllStringFunc(value, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return "[invalid URL]"
		}
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		u.ForceQuery = false
		return u.String()
	})
	return limit(value, 1024)
}

func Error(err error) zap.Field {
	if err == nil {
		return zap.Skip()
	}
	return zap.String("error", SafeText(err.Error()))
}

func limit(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return strings.ToValidUTF8(value[:maximum], "") + "..."
}
