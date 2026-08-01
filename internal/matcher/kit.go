package matcher

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

func NormalizeDomain(in string) string {
	return strings.TrimSuffix(in, ".")
}

type requestMetaKey struct{}

type requestMeta struct {
	normalizedName string
	results        map[string]matchResult
}

type matchResult struct {
	matched bool
	err     error
}

// WithRequestMeta adds request-scoped memoization for normalized query data
// and matcher results. The metadata is intentionally local to one synchronous
// rule evaluation and therefore needs no locks.
func WithRequestMeta(ctx context.Context, req *dns.Msg) context.Context {
	meta := &requestMeta{results: make(map[string]matchResult)}
	if req != nil && len(req.Question) == 1 {
		meta.normalizedName = strings.ToLower(NormalizeDomain(req.Question[0].Name))
	}
	return context.WithValue(ctx, requestMetaKey{}, meta)
}

// NormalizedRequestName returns the lower-case, non-FQDN query name.
func NormalizedRequestName(ctx context.Context, req *dns.Msg) string {
	if meta, ok := ctx.Value(requestMetaKey{}).(*requestMeta); ok {
		return meta.normalizedName
	}
	if req == nil || len(req.Question) != 1 {
		return ""
	}
	return strings.ToLower(NormalizeDomain(req.Question[0].Name))
}

// Evaluate memoizes a named matcher for the lifetime of one request.
func Evaluate(ctx context.Context, item IDNSMatcher, req *dns.Msg) (bool, error) {
	if item == nil {
		return false, nil
	}
	meta, ok := ctx.Value(requestMetaKey{}).(*requestMeta)
	if !ok {
		return item.Match(ctx, req)
	}
	key := item.Type() + "\x00" + item.Name()
	if result, exists := meta.results[key]; exists {
		return result.matched, result.err
	}
	matched, err := item.Match(ctx, req)
	meta.results[key] = matchResult{matched: matched, err: err}
	return matched, err
}
