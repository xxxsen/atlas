package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
	"go.uber.org/zap"
)

const (
	defaultCircuitFailureThreshold = 3
	defaultCircuitInitialBackoff   = time.Second
	defaultCircuitMaximumBackoff   = 10 * time.Second
	defaultCircuitJitterPercent    = 20
)

var (
	ErrUpstreamCircuitOpen = errors.New("upstream circuit is open")
	ErrNoAvailableUpstream = errors.New("no upstream resolver is currently available")
)

type circuitState uint8

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

type circuitBreakerConfig struct {
	FailureThreshold int
	InitialBackoff   time.Duration
	MaximumBackoff   time.Duration
	JitterPercent    int
	Now              func() time.Time
}

func defaultCircuitBreakerConfig() circuitBreakerConfig {
	return circuitBreakerConfig{
		FailureThreshold: defaultCircuitFailureThreshold,
		InitialBackoff:   defaultCircuitInitialBackoff,
		MaximumBackoff:   defaultCircuitMaximumBackoff,
		JitterPercent:    defaultCircuitJitterPercent,
		Now:              time.Now,
	}
}

func normalizeCircuitBreakerConfig(cfg circuitBreakerConfig) circuitBreakerConfig {
	defaults := defaultCircuitBreakerConfig()
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = defaults.FailureThreshold
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaults.InitialBackoff
	}
	if cfg.MaximumBackoff < cfg.InitialBackoff {
		cfg.MaximumBackoff = defaults.MaximumBackoff
		if cfg.MaximumBackoff < cfg.InitialBackoff {
			cfg.MaximumBackoff = cfg.InitialBackoff
		}
	}
	if cfg.JitterPercent < 0 || cfg.JitterPercent > 50 {
		cfg.JitterPercent = defaults.JitterPercent
	}
	if cfg.Now == nil {
		cfg.Now = defaults.Now
	}
	return cfg
}

type circuitPermit struct {
	epoch uint64
	probe bool
}

type circuitTransition struct {
	state      circuitState
	retryAfter time.Duration
	failures   int
}

type upstreamHealth struct {
	Available bool
	Probing   bool
	RetryAt   time.Time
}

type healthReportingResolver interface {
	resolverHealth() upstreamHealth
}

type circuitBreakerResolver struct {
	next IDNSResolver
	cfg  circuitBreakerConfig

	mu                  sync.Mutex
	state               circuitState
	epoch               uint64
	consecutiveFailures int
	backoff             time.Duration
	openUntil           time.Time
	openCount           uint64

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func newCircuitBreakerResolver(next IDNSResolver) IDNSResolver {
	return newCircuitBreakerResolverWithConfig(next, defaultCircuitBreakerConfig())
}

func newCircuitBreakerResolverWithConfig(next IDNSResolver, cfg circuitBreakerConfig) *circuitBreakerResolver {
	cfg = normalizeCircuitBreakerConfig(cfg)
	return &circuitBreakerResolver{next: next, cfg: cfg, backoff: cfg.InitialBackoff}
}

func (r *circuitBreakerResolver) Name() string {
	return r.next.Name()
}

func (r *circuitBreakerResolver) Query(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		return nil, fmt.Errorf("circuit breaker context is nil")
	}
	if r.closed.Load() {
		return nil, net.ErrClosed
	}
	permit, transition, err := r.acquire()
	if transition != nil {
		r.logTransition(ctx, *transition)
	}
	if err != nil {
		return nil, err
	}

	response, queryErr := r.next.Query(ctx, request)
	if shouldIgnoreCircuitResult(ctx, queryErr) {
		if permit.probe {
			r.recordAbortedProbe(permit)
		}
		return response, queryErr
	}
	if queryErr == nil && response != nil && !response.Truncated && !retryableRcode(response.Rcode) {
		if transition := r.recordSuccess(permit); transition != nil {
			r.logTransition(ctx, *transition)
		}
		return response, nil
	}
	if transition := r.recordFailure(permit); transition != nil {
		r.logTransition(ctx, *transition)
	}
	return response, queryErr
}

func (r *circuitBreakerResolver) recordAbortedProbe(permit circuitPermit) {
	now := r.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !permit.probe || permit.epoch != r.epoch || r.state != circuitHalfOpen {
		return
	}
	// A group winner may cancel a healthy but slower recovery probe. Return to
	// open without counting a failure so a future query can probe again; never
	// leave the endpoint permanently stuck in half-open.
	r.state = circuitOpen
	r.epoch++
	r.openUntil = now.Add(r.backoff)
}

func shouldIgnoreCircuitResult(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}

func (r *circuitBreakerResolver) acquire() (circuitPermit, *circuitTransition, error) {
	now := r.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.state {
	case circuitClosed:
		return circuitPermit{epoch: r.epoch}, nil, nil
	case circuitOpen:
		if now.Before(r.openUntil) {
			return circuitPermit{}, nil, fmt.Errorf("%w for %s until %s", ErrUpstreamCircuitOpen, r.Name(), r.openUntil.Format(time.RFC3339Nano))
		}
		r.state = circuitHalfOpen
		r.epoch++
		return circuitPermit{epoch: r.epoch, probe: true}, &circuitTransition{state: circuitHalfOpen}, nil
	case circuitHalfOpen:
		return circuitPermit{}, nil, fmt.Errorf("%w for %s while a recovery probe is running", ErrUpstreamCircuitOpen, r.Name())
	default:
		return circuitPermit{}, nil, fmt.Errorf("invalid circuit state for %s", r.Name())
	}
}

func (r *circuitBreakerResolver) recordSuccess(permit circuitPermit) *circuitTransition {
	r.mu.Lock()
	defer r.mu.Unlock()
	if permit.epoch != r.epoch {
		return nil
	}
	if r.state == circuitHalfOpen && permit.probe {
		r.state = circuitClosed
		r.epoch++
		r.consecutiveFailures = 0
		r.backoff = r.cfg.InitialBackoff
		r.openUntil = time.Time{}
		return &circuitTransition{state: circuitClosed}
	}
	if r.state == circuitClosed {
		r.consecutiveFailures = 0
	}
	return nil
}

func (r *circuitBreakerResolver) recordFailure(permit circuitPermit) *circuitTransition {
	now := r.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if permit.epoch != r.epoch {
		return nil
	}
	switch r.state {
	case circuitClosed:
		r.consecutiveFailures++
		if r.consecutiveFailures < r.cfg.FailureThreshold {
			return nil
		}
		return r.openLocked(now, false)
	case circuitHalfOpen:
		return r.openLocked(now, true)
	default:
		return nil
	}
}

func (r *circuitBreakerResolver) openLocked(now time.Time, increaseBackoff bool) *circuitTransition {
	if increaseBackoff {
		if r.backoff >= r.cfg.MaximumBackoff/2 {
			r.backoff = r.cfg.MaximumBackoff
		} else {
			r.backoff *= 2
		}
	}
	if r.backoff < r.cfg.InitialBackoff {
		r.backoff = r.cfg.InitialBackoff
	}
	if r.backoff > r.cfg.MaximumBackoff {
		r.backoff = r.cfg.MaximumBackoff
	}
	r.openCount++
	retryAfter := jitterDuration(r.backoff, r.cfg.JitterPercent, hashString(r.Name())+r.openCount)
	r.state = circuitOpen
	r.epoch++
	r.openUntil = now.Add(retryAfter)
	failures := r.consecutiveFailures
	if increaseBackoff && failures == 0 {
		failures = 1
	}
	r.consecutiveFailures = 0
	return &circuitTransition{state: circuitOpen, retryAfter: retryAfter, failures: failures}
}

func jitterDuration(base time.Duration, percent int, seed uint64) time.Duration {
	if base <= 0 || percent <= 0 {
		return base
	}
	spread := int64(base) * int64(percent) / 100
	if spread <= 0 {
		return base
	}
	width := uint64(spread*2 + 1)
	offset := int64(seed%width) - spread
	return base + time.Duration(offset)
}

func hashString(value string) uint64 {
	const (
		offset64 = uint64(14695981039346656037)
		prime64  = uint64(1099511628211)
	)
	hash := offset64
	for index := 0; index < len(value); index++ {
		hash ^= uint64(value[index])
		hash *= prime64
	}
	return hash
}

func (r *circuitBreakerResolver) resolverHealth() upstreamHealth {
	if r.closed.Load() {
		return upstreamHealth{}
	}
	now := r.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.state {
	case circuitClosed:
		return upstreamHealth{Available: true}
	case circuitOpen:
		return upstreamHealth{Available: !now.Before(r.openUntil), RetryAt: r.openUntil}
	case circuitHalfOpen:
		return upstreamHealth{Probing: true}
	default:
		return upstreamHealth{}
	}
}

func (r *circuitBreakerResolver) logTransition(ctx context.Context, transition circuitTransition) {
	logger := querylog.Logger(ctx).With(zap.String("upstream", querylog.SafeText(r.Name())))
	switch transition.state {
	case circuitOpen:
		logger.Warn("upstream circuit opened", zap.Int("consecutive_failures", transition.failures), zap.Duration("retry_after", transition.retryAfter))
	case circuitHalfOpen:
		logger.Info("upstream circuit probing recovery")
	case circuitClosed:
		logger.Info("upstream circuit recovered")
	}
}

func (r *circuitBreakerResolver) Close() error {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		if closer, ok := r.next.(ResolverCloser); ok {
			r.closeErr = closer.Close()
		}
	})
	return r.closeErr
}

var _ IDNSResolver = (*circuitBreakerResolver)(nil)
var _ ResolverCloser = (*circuitBreakerResolver)(nil)
var _ healthReportingResolver = (*circuitBreakerResolver)(nil)
