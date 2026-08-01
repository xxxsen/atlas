package resolver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

const (
	defaultCacheQueryTimeout = 10 * time.Second
	defaultNegativeTTLMax    = time.Hour
	maxCacheShards           = 16
	maxCacheNamespaceBytes   = 256
)

type CacheOptions struct {
	Size               int64
	MaxBytes           int64
	MaxEntryBytes      int64
	Lazy               bool
	MaxStale           time.Duration
	Persist            bool
	File               string
	Interval           time.Duration
	RefreshConcurrency int
	QueryTimeout       time.Duration
	Fingerprint        string
	NegativeTTLMax     time.Duration
}

type CacheStats struct {
	Hits              uint64 `json:"hits"`
	Misses            uint64 `json:"misses"`
	StaleHits         uint64 `json:"stale_hits"`
	Bypasses          uint64 `json:"bypasses"`
	Refreshes         uint64 `json:"refreshes"`
	PersistenceErrors uint64 `json:"persistence_errors"`
	Entries           int    `json:"entries"`
	Bytes             int64  `json:"bytes"`
	Generation        uint64 `json:"generation"`
}

type CacheManager struct {
	cfg    CacheOptions
	ctx    context.Context
	cancel context.CancelFunc

	shards []*cacheShard

	generation     atomic.Uint64
	persisted      atomic.Uint64
	hits           atomic.Uint64
	misses         atomic.Uint64
	staleHits      atomic.Uint64
	bypasses       atomic.Uint64
	refreshes      atomic.Uint64
	persistErrors  atomic.Uint64
	persistErrMu   sync.RWMutex
	lastPersistErr error

	flightMu sync.Mutex
	flights  map[cacheKey]*cacheFlight

	refreshMu  sync.Mutex
	refreshing map[cacheKey]struct{}
	refreshSem chan struct{}

	lifecycleMu  sync.Mutex
	closed       bool
	tasks        sync.WaitGroup
	stopPersist  chan struct{}
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	closeErrMu   sync.Mutex
	closeErr     error
}

type cacheShard struct {
	mu       sync.Mutex
	cache    *lru.Cache[cacheKey, *cacheEntry]
	bytes    int64
	maxBytes int64
}

type cacheEntry struct {
	key        cacheKey
	data       []byte
	storedAt   time.Time
	expire     time.Time
	staleUntil time.Time
	size       int64
}

type cacheKey struct {
	Namespace string
	Name      string
	Qtype     uint16
	Qclass    uint16
	UDPSize   uint16
	Flags     uint8
}

const (
	cacheFlagRD uint8 = 1 << iota
	cacheFlagDO
	cacheFlagCD
	cacheFlagAD
)

type cacheFlight struct {
	done chan struct{}
	msg  *dns.Msg
	err  error
}

type cacheResolver struct {
	manager   *CacheManager
	namespace string
	next      IDNSResolver
}

func NewCacheManager(parent context.Context, cfg CacheOptions) (*CacheManager, error) {
	if parent == nil {
		parent = context.Background()
	}
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = defaultCacheQueryTimeout
	}
	if cfg.NegativeTTLMax == 0 {
		cfg.NegativeTTLMax = defaultNegativeTTLMax
	}
	if err := validateCacheOptions(cfg); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	manager := &CacheManager{
		cfg:          cfg,
		ctx:          ctx,
		cancel:       cancel,
		flights:      make(map[cacheKey]*cacheFlight),
		refreshing:   make(map[cacheKey]struct{}),
		refreshSem:   make(chan struct{}, cfg.RefreshConcurrency),
		stopPersist:  make(chan struct{}),
		shutdownDone: make(chan struct{}),
	}
	if err := manager.initShards(); err != nil {
		cancel()
		return nil, err
	}
	if cfg.Persist {
		if err := manager.loadFromFile(); err != nil {
			manager.recordPersistenceError(fmt.Errorf("load DNS cache: %w", err))
			// Persistence is an optimization. Never retain a partially decoded
			// checkpoint when any record, schema, or fingerprint is invalid.
			if resetErr := manager.initShards(); resetErr != nil {
				cancel()
				return nil, resetErr
			}
			// Mark the empty replacement generation dirty so the next periodic
			// checkpoint (or Close) replaces the unusable file.
			manager.generation.Add(1)
		}
		manager.tasks.Add(1)
		go func() {
			defer manager.tasks.Done()
			manager.persistLoop()
		}()
	}
	return manager, nil
}

func validateCacheOptions(cfg CacheOptions) error {
	if cfg.Size < 1 || cfg.Size > 1_000_000 {
		return fmt.Errorf("cache size must be between 1 and 1000000")
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > 16*1024*1024*1024 {
		return fmt.Errorf("cache max bytes must be between 1 and 16 GiB")
	}
	if cfg.MaxEntryBytes < 1 || cfg.MaxEntryBytes > dns.MaxMsgSize || cfg.MaxEntryBytes > cfg.MaxBytes {
		return fmt.Errorf("cache max entry bytes must be between 1 and 65535 and no larger than max bytes")
	}
	if cfg.MaxStale < 0 {
		return fmt.Errorf("cache max stale cannot be negative")
	}
	if !cfg.Lazy && cfg.MaxStale != 0 {
		return fmt.Errorf("cache max stale requires lazy mode")
	}
	if cfg.RefreshConcurrency < 1 || cfg.RefreshConcurrency > 1024 {
		return fmt.Errorf("cache refresh concurrency must be between 1 and 1024")
	}
	if cfg.QueryTimeout <= 0 || cfg.QueryTimeout > 5*time.Minute {
		return fmt.Errorf("cache query timeout must be between 1ns and 5 minutes")
	}
	if cfg.MaxStale > 7*24*time.Hour {
		return fmt.Errorf("cache max stale cannot exceed 7 days")
	}
	if cfg.NegativeTTLMax <= 0 || cfg.NegativeTTLMax > 7*24*time.Hour {
		return fmt.Errorf("cache negative TTL maximum must be between 1ns and 7 days")
	}
	if cfg.Persist {
		if strings.TrimSpace(cfg.File) == "" {
			return fmt.Errorf("cache persistence file is required")
		}
		if cfg.Interval <= 0 {
			return fmt.Errorf("cache persistence interval must be positive")
		}
		if cfg.Interval > 24*time.Hour {
			return fmt.Errorf("cache persistence interval cannot exceed 24 hours")
		}
		if strings.TrimSpace(cfg.Fingerprint) == "" {
			return fmt.Errorf("cache persistence fingerprint is required")
		}
	} else if strings.TrimSpace(cfg.File) != "" || cfg.Interval != 0 {
		return fmt.Errorf("cache persistence file and interval require persistence")
	}
	return nil
}

func (c *CacheManager) initShards() error {
	shardCount := int(c.cfg.Size)
	if shardCount > maxCacheShards {
		shardCount = maxCacheShards
	}
	if byteLimited := int(c.cfg.MaxBytes / c.cfg.MaxEntryBytes); byteLimited > 0 && shardCount > byteLimited {
		shardCount = byteLimited
	}
	if shardCount < 1 {
		shardCount = 1
	}
	c.shards = make([]*cacheShard, shardCount)
	entryBase := int(c.cfg.Size) / shardCount
	entryRemainder := int(c.cfg.Size) % shardCount
	byteBase := c.cfg.MaxBytes / int64(shardCount)
	byteRemainder := c.cfg.MaxBytes % int64(shardCount)
	for i := range c.shards {
		capacity := entryBase
		if i < entryRemainder {
			capacity++
		}
		maxBytes := byteBase
		if int64(i) < byteRemainder {
			maxBytes++
		}
		shard := &cacheShard{maxBytes: maxBytes}
		cache, err := lru.NewWithEvict[cacheKey, *cacheEntry](capacity, func(_ cacheKey, entry *cacheEntry) {
			shard.bytes -= entry.size
		})
		if err != nil {
			return fmt.Errorf("create cache shard %d: %w", i, err)
		}
		shard.cache = cache
		c.shards[i] = shard
	}
	return nil
}

func (c *CacheManager) Wrap(namespace string, next IDNSResolver) (IDNSResolver, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("cache namespace is required")
	}
	if len(namespace) > maxCacheNamespaceBytes {
		return nil, fmt.Errorf("cache namespace cannot exceed %d bytes", maxCacheNamespaceBytes)
	}
	if next == nil {
		return nil, fmt.Errorf("cannot cache a nil resolver")
	}
	return &cacheResolver{manager: c, namespace: namespace, next: next}, nil
}

func (c *cacheResolver) Name() string {
	return fmt.Sprintf("cache[%s](%s)", c.namespace, c.next.Name())
}

func (c *cacheResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return c.manager.Query(ctx, c.namespace, c.next, req)
}

func (c *cacheResolver) Close() error {
	if closer, ok := c.next.(ResolverCloser); ok {
		return closer.Close()
	}
	return nil
}

func (c *CacheManager) Query(ctx context.Context, namespace string, resolver IDNSResolver, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		return nil, fmt.Errorf("cache query context is nil")
	}
	if resolver == nil {
		return nil, fmt.Errorf("cache resolver is nil")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, fmt.Errorf("cache namespace is empty")
	}
	if len(namespace) > maxCacheNamespaceBytes {
		return nil, fmt.Errorf("cache namespace cannot exceed %d bytes", maxCacheNamespaceBytes)
	}
	if req == nil || len(req.Question) != 1 {
		return nil, fmt.Errorf("cache requires exactly one DNS question")
	}
	if c.isClosed() {
		return nil, context.Canceled
	}
	key, cacheable := buildCacheKey(namespace, req)
	if !cacheable {
		c.bypasses.Add(1)
		resp, err := resolver.Query(ctx, req)
		if err == nil {
			err = ValidateResponse(req, resp)
		}
		return resp, err
	}

	msg, state, found := c.get(key)
	if found {
		if state == cacheFresh {
			c.hits.Add(1)
			return prepareCachedResponse(msg, req), nil
		}
		c.staleHits.Add(1)
		c.scheduleRefresh(key, resolver, req.Copy())
		return prepareCachedResponse(msg, req), nil
	}

	c.misses.Add(1)
	return c.queryFlight(ctx, key, resolver, req)
}

type cacheState uint8

const (
	cacheFresh cacheState = iota
	cacheStale
)

func (c *CacheManager) get(key cacheKey) (*dns.Msg, cacheState, bool) {
	shard := c.shard(key)
	now := time.Now()
	shard.mu.Lock()
	entry, ok := shard.cache.Get(key)
	if !ok {
		shard.mu.Unlock()
		return nil, cacheFresh, false
	}
	if now.After(entry.staleUntil) {
		shard.cache.Remove(key)
		shard.mu.Unlock()
		c.generation.Add(1)
		return nil, cacheFresh, false
	}
	data := entry.data
	storedAt := entry.storedAt
	expire := entry.expire
	shard.mu.Unlock()

	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		c.remove(key)
		return nil, cacheFresh, false
	}
	if now.After(expire) {
		adjustMessageTTL(msg, 0, true)
		return msg, cacheStale, true
	}
	elapsed := uint64(now.Sub(storedAt) / time.Second)
	adjustMessageTTL(msg, elapsed, false)
	return msg, cacheFresh, true
}

func (c *CacheManager) queryFlight(ctx context.Context, key cacheKey, resolver IDNSResolver, req *dns.Msg) (*dns.Msg, error) {
	c.flightMu.Lock()
	flight, ok := c.flights[key]
	if !ok {
		flight = &cacheFlight{done: make(chan struct{})}
		c.flights[key] = flight
		request := req.Copy()
		if !c.startTask(func() { c.runFlight(key, resolver, request, flight) }) {
			delete(c.flights, key)
			flight.err = context.Canceled
			close(flight.done)
		}
	}
	c.flightMu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-flight.done:
		if flight.err != nil {
			return nil, flight.err
		}
		return prepareCachedResponse(flight.msg, req), nil
	}
}

func (c *CacheManager) runFlight(key cacheKey, resolver IDNSResolver, req *dns.Msg, flight *cacheFlight) {
	queryCtx, cancel := context.WithTimeout(c.ctx, c.cfg.QueryTimeout)
	defer cancel()
	msg, err := resolver.Query(queryCtx, req)
	if err == nil {
		err = ValidateResponse(req, msg)
	}
	if err == nil {
		c.store(key, msg)
		msg = msg.Copy()
	}

	c.flightMu.Lock()
	flight.msg = msg
	flight.err = err
	delete(c.flights, key)
	close(flight.done)
	c.flightMu.Unlock()
}

func (c *CacheManager) scheduleRefresh(key cacheKey, resolver IDNSResolver, req *dns.Msg) {
	c.refreshMu.Lock()
	if _, exists := c.refreshing[key]; exists {
		c.refreshMu.Unlock()
		return
	}
	select {
	case c.refreshSem <- struct{}{}:
		c.refreshing[key] = struct{}{}
	default:
		c.refreshMu.Unlock()
		return
	}
	c.refreshMu.Unlock()

	if !c.startTask(func() {
		defer func() {
			<-c.refreshSem
			c.refreshMu.Lock()
			delete(c.refreshing, key)
			c.refreshMu.Unlock()
		}()
		c.refreshes.Add(1)
		ctx, cancel := context.WithTimeout(c.ctx, c.cfg.QueryTimeout)
		defer cancel()
		msg, err := resolver.Query(ctx, req)
		if err == nil {
			err = ValidateResponse(req, msg)
		}
		if err == nil {
			c.store(key, msg)
		}
	}) {
		<-c.refreshSem
		c.refreshMu.Lock()
		delete(c.refreshing, key)
		c.refreshMu.Unlock()
	}
}

func (c *CacheManager) store(key cacheKey, msg *dns.Msg) bool {
	if c.isClosed() || !cacheableResponse(msg) {
		return false
	}
	ttl, ok := messageTTL(msg)
	if !ok || ttl == 0 {
		return false
	}
	cacheMessage := msg
	if negativeResponse(msg) {
		maximum := uint64(c.cfg.NegativeTTLMax / time.Second)
		if maximum == 0 {
			maximum = 1
		}
		if uint64(ttl) > maximum {
			ttl = uint32(maximum)
		}
		// RFC 2308 uses min(SOA TTL, SOA.MINIMUM) as both the cache
		// lifetime and the TTL of the cached SOA included in replies.
		cacheMessage = msg.Copy()
		clampNegativeTTL(cacheMessage, ttl)
	}
	packed, err := cacheMessage.Pack()
	if err != nil || int64(len(packed)) > c.cfg.MaxEntryBytes {
		return false
	}
	now := time.Now()
	expire := now.Add(time.Duration(ttl) * time.Second)
	staleUntil := expire
	if c.cfg.Lazy && c.cfg.MaxStale > 0 {
		staleUntil = expire.Add(c.cfg.MaxStale)
	}
	entry := &cacheEntry{
		key:        key,
		data:       packed,
		storedAt:   now,
		expire:     expire,
		staleUntil: staleUntil,
	}
	entry.size = cacheEntrySize(entry)
	if !c.addEntry(entry) {
		return false
	}
	c.generation.Add(1)
	return true
}

func cacheableResponse(msg *dns.Msg) bool {
	if msg == nil || !msg.Response || msg.Truncated {
		return false
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return false
	}
	for _, rr := range msg.Extra {
		switch record := rr.(type) {
		case *dns.OPT:
			if len(record.Option) != 0 {
				return false
			}
		case *dns.TSIG:
			return false
		}
	}
	return true
}

func messageTTL(msg *dns.Msg) (uint32, bool) {
	if negativeResponse(msg) {
		var ttl uint32
		found := false
		for _, rr := range msg.Ns {
			soa, ok := rr.(*dns.SOA)
			if !ok {
				continue
			}
			candidate := soa.Hdr.Ttl
			if soa.Minttl < candidate {
				candidate = soa.Minttl
			}
			if !found || candidate < ttl {
				ttl = candidate
				found = true
			}
		}
		return ttl, found
	}
	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) == 0 {
		return 0, false
	}
	var ttl uint32
	found := false
	sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
	for _, section := range sections {
		for _, rr := range section {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			if _, ok := rr.(*dns.TSIG); ok {
				continue
			}
			candidate := rr.Header().Ttl
			if !found || candidate < ttl {
				ttl = candidate
				found = true
			}
		}
	}
	return ttl, found
}

func negativeResponse(msg *dns.Msg) bool {
	return msg != nil && (msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0))
}

func clampNegativeTTL(msg *dns.Msg, maximum uint32) {
	for _, record := range msg.Ns {
		soa, ok := record.(*dns.SOA)
		if !ok {
			continue
		}
		if soa.Hdr.Ttl > maximum {
			soa.Hdr.Ttl = maximum
		}
		if soa.Minttl > maximum {
			soa.Minttl = maximum
		}
	}
}

func adjustMessageTTL(msg *dns.Msg, elapsed uint64, stale bool) {
	sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
	for _, section := range sections {
		for _, rr := range section {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			if _, ok := rr.(*dns.TSIG); ok {
				continue
			}
			header := rr.Header()
			if stale || elapsed >= uint64(header.Ttl) {
				header.Ttl = 0
			} else {
				header.Ttl -= uint32(elapsed)
			}
		}
	}
}

func buildCacheKey(namespace string, req *dns.Msg) (cacheKey, bool) {
	if req == nil || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 || len(req.Answer) != 0 || len(req.Ns) != 0 || req.IsTsig() != nil {
		return cacheKey{}, false
	}
	q := req.Question[0]
	name := strings.ToLower(dns.Fqdn(strings.TrimSpace(q.Name)))
	if name == "" {
		return cacheKey{}, false
	}
	if _, valid := dns.IsDomainName(name); !valid {
		return cacheKey{}, false
	}
	key := cacheKey{Namespace: namespace, Name: name, Qtype: q.Qtype, Qclass: q.Qclass}
	if req.RecursionDesired {
		key.Flags |= cacheFlagRD
	}
	if req.CheckingDisabled {
		key.Flags |= cacheFlagCD
	}
	if req.AuthenticatedData {
		key.Flags |= cacheFlagAD
	}
	optCount := 0
	for _, rr := range req.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			return cacheKey{}, false
		}
		optCount++
		if optCount > 1 || opt.Version() != 0 || len(opt.Option) != 0 {
			return cacheKey{}, false
		}
		key.UDPSize = opt.UDPSize()
		if key.UDPSize < dns.MinMsgSize {
			key.UDPSize = dns.MinMsgSize
		}
		if opt.Do() {
			key.Flags |= cacheFlagDO
		}
	}
	return key, true
}

func prepareCachedResponse(msg, req *dns.Msg) *dns.Msg {
	if msg == nil {
		return nil
	}
	response := msg.Copy()
	response.Id = req.Id
	response.Question = append([]dns.Question(nil), req.Question...)
	response.RecursionDesired = req.RecursionDesired
	response.CheckingDisabled = req.CheckingDisabled
	return response
}

func cacheEntrySize(entry *cacheEntry) int64 {
	const metadataOverhead = int64(160)
	return int64(len(entry.data)+len(entry.key.Namespace)+len(entry.key.Name)) + metadataOverhead
}

func (c *CacheManager) addEntry(entry *cacheEntry) bool {
	shard := c.shard(entry.key)
	if entry.size > shard.maxBytes {
		return false
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if _, exists := shard.cache.Peek(entry.key); exists {
		shard.cache.Remove(entry.key)
	}
	for shard.bytes+entry.size > shard.maxBytes {
		if _, _, ok := shard.cache.RemoveOldest(); !ok {
			return false
		}
	}
	shard.cache.Add(entry.key, entry)
	shard.bytes += entry.size
	return true
}

func (c *CacheManager) remove(key cacheKey) {
	shard := c.shard(key)
	shard.mu.Lock()
	present := shard.cache.Remove(key)
	shard.mu.Unlock()
	if present {
		c.generation.Add(1)
	}
}

func (c *CacheManager) shard(key cacheKey) *cacheShard {
	const offset64 = uint64(14695981039346656037)
	const prime64 = uint64(1099511628211)
	h := offset64
	addString := func(value string) {
		for i := 0; i < len(value); i++ {
			h ^= uint64(value[i])
			h *= prime64
		}
	}
	addByte := func(value byte) {
		h ^= uint64(value)
		h *= prime64
	}
	addString(key.Namespace)
	addByte(0)
	addString(key.Name)
	addByte(byte(key.Qtype >> 8))
	addByte(byte(key.Qtype))
	addByte(byte(key.Qclass >> 8))
	addByte(byte(key.Qclass))
	addByte(byte(key.UDPSize >> 8))
	addByte(byte(key.UDPSize))
	addByte(key.Flags)
	return c.shards[h%uint64(len(c.shards))]
}

func (c *CacheManager) startTask(task func()) bool {
	c.lifecycleMu.Lock()
	if c.closed {
		c.lifecycleMu.Unlock()
		return false
	}
	c.tasks.Add(1)
	c.lifecycleMu.Unlock()
	go func() {
		defer c.tasks.Done()
		task()
	}()
	return true
}

func (c *CacheManager) isClosed() bool {
	c.lifecycleMu.Lock()
	closed := c.closed
	c.lifecycleMu.Unlock()
	return closed
}

func (c *CacheManager) Stats() CacheStats {
	stats := CacheStats{
		Hits:              c.hits.Load(),
		Misses:            c.misses.Load(),
		StaleHits:         c.staleHits.Load(),
		Bypasses:          c.bypasses.Load(),
		Refreshes:         c.refreshes.Load(),
		PersistenceErrors: c.persistErrors.Load(),
		Generation:        c.generation.Load(),
	}
	for _, shard := range c.shards {
		shard.mu.Lock()
		stats.Entries += shard.cache.Len()
		stats.Bytes += shard.bytes
		shard.mu.Unlock()
	}
	return stats
}

func (c *CacheManager) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.shutdownOnce.Do(func() {
		c.lifecycleMu.Lock()
		c.closed = true
		c.lifecycleMu.Unlock()
		c.cancel()
		close(c.stopPersist)
		go func() {
			c.tasks.Wait()
			if c.cfg.Persist && c.generation.Load() != c.persisted.Load() {
				if err := c.persist(); err != nil {
					c.recordPersistenceError(err)
					c.closeErrMu.Lock()
					c.closeErr = err
					c.closeErrMu.Unlock()
				}
			}
			close(c.shutdownDone)
		}()
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.shutdownDone:
		c.closeErrMu.Lock()
		defer c.closeErrMu.Unlock()
		return c.closeErr
	}
}

func (c *CacheManager) persistLoop() {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.generation.Load() == c.persisted.Load() {
				continue
			}
			if err := c.persist(); err != nil {
				c.recordPersistenceError(err)
			}
		case <-c.stopPersist:
			return
		}
	}
}

var _ IDNSResolver = (*cacheResolver)(nil)
var _ ResolverCloser = (*cacheResolver)(nil)

func (c *CacheManager) recordPersistenceError(err error) {
	if err == nil {
		return
	}
	c.persistErrors.Add(1)
	c.persistErrMu.Lock()
	c.lastPersistErr = err
	c.persistErrMu.Unlock()
}

// LastPersistenceError reports the latest recoverable checkpoint error.
func (c *CacheManager) LastPersistenceError() error {
	c.persistErrMu.RLock()
	defer c.persistErrMu.RUnlock()
	return c.lastPersistErr
}
