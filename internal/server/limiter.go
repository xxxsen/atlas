package server

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const limiterShards = 16

type clientRateLimiter struct {
	qps    float64
	burst  float64
	shards []rateLimitShard
}

type rateLimitShard struct {
	mu      sync.Mutex
	clients *lru.Cache[string, *tokenBucket]
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newClientRateLimiter(qps float64, burst, maxClients int) (*clientRateLimiter, error) {
	if qps <= 0 {
		return nil, nil
	}
	count := limiterShards
	if maxClients < count {
		count = maxClients
	}
	limiter := &clientRateLimiter{qps: qps, burst: float64(burst), shards: make([]rateLimitShard, count)}
	base := maxClients / count
	remainder := maxClients % count
	for i := range limiter.shards {
		capacity := base
		if i < remainder {
			capacity++
		}
		cache, err := lru.New[string, *tokenBucket](capacity)
		if err != nil {
			return nil, err
		}
		limiter.shards[i].clients = cache
	}
	return limiter, nil
}

func (l *clientRateLimiter) Allow(client string, now time.Time) bool {
	if l == nil {
		return true
	}
	shard := &l.shards[hashClient(client)%uint64(len(l.shards))]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	bucket, ok := shard.clients.Get(client)
	if !ok {
		shard.clients.Add(client, &tokenBucket{tokens: l.burst - 1, last: now})
		return true
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * l.qps
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func hashClient(client string) uint64 {
	const offset64 = uint64(14695981039346656037)
	const prime64 = uint64(1099511628211)
	h := offset64
	for i := 0; i < len(client); i++ {
		h ^= uint64(client[i])
		h *= prime64
	}
	return h
}
