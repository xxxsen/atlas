package resolver

import (
	"context"
	"time"
)

type queryBudgetKey struct{}

// WithQueryBudget shares one deadline across all steps of a query strategy.
// A caller can stop waiting earlier without cancelling other cache waiters.
func WithQueryBudget(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = defaultCacheQueryTimeout
	}
	deadline, ok := ctx.Value(queryBudgetKey{}).(time.Time)
	limit := time.Now().Add(timeout)
	if !ok || limit.Before(deadline) {
		deadline = limit
		ctx = context.WithValue(ctx, queryBudgetKey{}, deadline)
	}
	return context.WithDeadline(ctx, deadline)
}

// Cache work belongs to the manager, independently of any individual waiter.
// Preserve the strategy deadline when starting a nested miss or refresh so
// fallback does not receive a new timeout at every cache layer.
func cacheQueryContext(parent, source context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := source.Value(queryBudgetKey{}).(time.Time); ok {
		parent = context.WithValue(parent, queryBudgetKey{}, deadline)
	}
	return WithQueryBudget(parent, timeout)
}
