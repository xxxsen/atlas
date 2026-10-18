package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type budgetQuery func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f budgetQuery) Name() string { return "budget-test" }
func (f budgetQuery) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f(ctx, req)
}

func TestCacheSharedWorkSurvivesWaiterCancellation(t *testing.T) {
	manager := newTestCache(t, nil)
	base := &boundedRefreshResolver{release: make(chan struct{})}
	wrapper, err := manager.Wrap("cancelled-waiter", base)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := wrapper.Query(ctx, newRequest())
		first <- err
	}()
	waitFor(t, time.Second, func() bool { return base.calls.Load() == 1 }, "shared work to start")
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter cancellation failed: %v", err)
	}
	second := make(chan error, 1)
	go func() {
		_, err := wrapper.Query(context.Background(), newRequest())
		second <- err
	}()
	close(base.release)
	if err := <-second; err != nil {
		t.Fatalf("first waiter cancelled shared work: %v", err)
	}
	if base.calls.Load() != 1 {
		t.Fatalf("shared work was restarted: %d", base.calls.Load())
	}
}

func TestStaleRefreshAndNestedMissShareOriginalBudget(t *testing.T) {
	manager := newTestCache(t, func(options *CacheOptions) {
		options.Lazy = true
		options.MaxStale = time.Minute
	})
	req := newRequest()
	key, _ := buildCacheKey("outer", req)
	msg := newResponse(60)
	msg.Question = req.Question
	if !manager.store(key, msg) {
		t.Fatal("could not seed cache")
	}
	shard := manager.shard(key)
	shard.mu.Lock()
	entry, _ := shard.cache.Get(key)
	entry.expire = time.Now().Add(-time.Second)
	shard.mu.Unlock()
	observed := make(chan time.Time, 2)
	finished := make(chan error, 1)
	target := budgetQuery(func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		deadline, _ := ctx.Deadline()
		observed <- deadline
		<-ctx.Done()
		finished <- ctx.Err()
		return nil, ctx.Err()
	})
	strategy := budgetQuery(func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		deadline, _ := ctx.Deadline()
		observed <- deadline
		timer := time.NewTimer(10 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return manager.Query(ctx, "target", target, req)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	ctx, cancel := WithQueryBudget(context.Background(), 300*time.Millisecond)
	original, _ := ctx.Deadline()
	msg, err := manager.Query(ctx, "outer", strategy, req)
	cancel()
	if err != nil || msg.Answer[0].Header().Ttl != 0 {
		t.Fatalf("expected immediate stale response: %v, %v", msg, err)
	}
	for i := 0; i < 2; i++ {
		select {
		case deadline := <-observed:
			if !deadline.Equal(original) {
				t.Fatalf("background/nested query reset deadline: %s != %s", deadline, original)
			}
		case <-time.After(time.Second):
			t.Fatal("refresh stopped when caller left")
		}
	}
	select {
	case err := <-finished:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected background error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("background work outlived original budget")
	}
}
