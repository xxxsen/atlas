package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

// CacheOptions controls the behaviour of the cache resolver wrapper.
type CacheOptions struct {
	Size    int64
	Lazy    bool
	Persist bool
	File    string
}

const persistInterval = 1 * time.Minute

var globalCacheOptions atomic.Value

func init() {
	ConfigureCache(CacheOptions{ //默认启用基础缓存, 缓存1w个key, 用户需要的情况下, 再开启lazycache
		Size: 10000,
	})
}

// ConfigureCache sets the global cache options that will be used when wrapping resolvers.
func ConfigureCache(opt CacheOptions) {
	if opt.Size < 0 {
		opt.Size = 0
	}
	globalCacheOptions.Store(opt)
}

// TryEnableResolverCache adds a caching layer on top of the supplied resolver when enabled.
func TryEnableResolverCache(in IDNSResolver) IDNSResolver {
	if in == nil {
		return nil
	}
	opt := globalCacheOptions.Load().(CacheOptions)
	if opt.Size <= 0 {
		return in
	}
	return newCacheResolver(in, opt)
}

type cacheResolver struct {
	next     IDNSResolver
	cfg      CacheOptions
	cache    *lru.Cache[string, *cacheEntry]
	mu       sync.Mutex
	inflight map[string]struct{}
	dirty    bool
}

type cacheEntry struct {
	key    string
	msg    *dns.Msg
	expire time.Time
}

func newCacheResolver(next IDNSResolver, cfg CacheOptions) *cacheResolver {
	lruCache, err := lru.New[string, *cacheEntry](int(cfg.Size))
	if err != nil {
		logutil.GetLogger(context.Background()).Error("init lru failed", zap.Error(err))
		return &cacheResolver{next: next, cfg: CacheOptions{}}
	}
	c := &cacheResolver{
		next:     next,
		cfg:      cfg,
		cache:    lruCache,
		inflight: make(map[string]struct{}),
	}
	if cfg.Persist {
		if err := c.loadFromFile(); err != nil {
			logutil.GetLogger(context.Background()).Error("load persist file failed", zap.Error(err))
		}
		go c.persistLoop()
	}
	return c
}

func (c *cacheResolver) Name() string {
	return fmt.Sprintf("cache(%s)", c.next.Name())
}

func (c *cacheResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	key := c.buildCacheKey(req)
	msg, expired, found := c.get(key)
	if found {
		msg.Id = req.Id
		msg.Question = append([]dns.Question(nil), req.Question...)
		if !expired {
			logutil.GetLogger(ctx).Debug("read dns response from cache")
			return msg, nil
		}
		if c.cfg.Lazy {
			logutil.GetLogger(ctx).Debug("use expire dns response from cache, start refresh it")
			c.scheduleRefresh(key, req.Copy())
			return msg, nil
		}
		c.remove(key)
	}

	resp, err := c.next.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	c.store(key, resp)
	return resp, nil
}

func (c *cacheResolver) get(key string) (*dns.Msg, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache.Get(key)
	if !ok {
		return nil, false, false
	}
	copy := entry.msg.Copy()
	remaining := time.Until(entry.expire)
	var ttlSeconds uint32
	if remaining > 0 {
		ttlSeconds = uint32(remaining / time.Second)
	}
	c.adjustTTL(copy, ttlSeconds)
	expired := time.Now().After(entry.expire)
	return copy, expired, true
}

func (c *cacheResolver) remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		return
	}
	c.cache.Remove(key)
	c.dirty = true
}

func (c *cacheResolver) store(key string, msg *dns.Msg) {
	ttl, ok := c.extractTTL(msg)
	if !ok || ttl == 0 {
		return
	}
	copy := msg.Copy()
	expire := time.Now().Add(time.Duration(ttl) * time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Add(key, &cacheEntry{
		key:    key,
		msg:    copy,
		expire: expire,
	})
	c.dirty = true
}

func (c *cacheResolver) scheduleRefresh(key string, req *dns.Msg) {
	c.mu.Lock()
	if _, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		return
	}
	c.inflight[key] = struct{}{}
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			delete(c.inflight, key)
			c.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := c.next.Query(ctx, req)
		if err != nil {
			logutil.GetLogger(ctx).Error("lazy cache update but refresh failed", zap.Error(err), zap.String("key", key))
			return
		}
		logutil.GetLogger(ctx).Debug("lazy cache update succ", zap.String("key", key))
		c.store(key, resp)
	}()
}

type persistRecord struct {
	Key    string `json:"key"`
	Expire int64  `json:"expire"`
	Msg    []byte `json:"msg"`
}

func (c *cacheResolver) persist(ctx context.Context) {
	snapshot := c.snapshot()
	path := strings.TrimSpace(c.cfg.File)
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logutil.GetLogger(ctx).Error("create persist dir failed", zap.Error(err))
		return
	}
	tmpFile, err := os.OpenFile(path+".temp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		logutil.GetLogger(ctx).Error("create temp persist file failed", zap.Error(err))
		return
	}
	tmpPath := tmpFile.Name()
	enc := json.NewEncoder(tmpFile)
	writeErr := false
	for _, rec := range snapshot {
		if err := enc.Encode(rec); err != nil {
			logutil.GetLogger(ctx).Error("write snapshot record failed", zap.Error(err))
			writeErr = true
			break
		}
	}
	if err := tmpFile.Close(); err != nil {
		logutil.GetLogger(ctx).Error("close temp persist file failed", zap.Error(err))
		writeErr = true
	}
	if writeErr {
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		logutil.GetLogger(ctx).Error("replace persist dns cache file failed", zap.Error(err))
		_ = os.Remove(tmpPath)
		return
	}
	logutil.GetLogger(ctx).Debug("save persist dns cache file succ", zap.Int("record_count", len(snapshot)))
}

func (c *cacheResolver) snapshot() []persistRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	values := c.cache.Values()
	records := make([]persistRecord, 0, len(values))
	for _, entry := range values {
		msg := entry.msg.Copy()
		bs, err := msg.Pack()
		if err != nil {
			continue
		}
		records = append(records, persistRecord{
			Key:    entry.key,
			Expire: entry.expire.UnixMilli(),
			Msg:    bs,
		})
	}
	return records
}

func (c *cacheResolver) persistLoop() {
	ticker := time.NewTicker(persistInterval)
	defer ticker.Stop()
	ctx := context.Background()
	for range ticker.C {
		c.mu.Lock()
		if !c.dirty {
			c.mu.Unlock()
			continue
		}
		c.dirty = false
		c.mu.Unlock()
		c.persist(ctx)
	}
}

func (c *cacheResolver) loadFromFile() error {
	if c.cache == nil {
		return nil
	}
	path := strings.TrimSpace(c.cfg.File)
	if path == "" {
		return nil
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 1024*1024)
	now := time.Now()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec persistRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg := &dns.Msg{}
		if err := msg.Unpack(rec.Msg); err != nil {
			continue
		}
		expire := time.UnixMilli(rec.Expire)
		if expire.Before(now) && !c.cfg.Lazy { //已经过期了, 且没有懒加载, 则直接跳过
			continue
		}
		entry := &cacheEntry{
			key:    rec.Key,
			msg:    msg,
			expire: expire,
		}
		c.mu.Lock()
		c.cache.Add(rec.Key, entry)
		c.mu.Unlock()
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (c *cacheResolver) buildCacheKey(req *dns.Msg) string {
	if req == nil || len(req.Question) == 0 {
		return ""
	}
	q := req.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if domain == "" {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d", domain, q.Qtype, q.Qclass)
}

func (c *cacheResolver) extractTTL(msg *dns.Msg) (uint32, bool) {
	var minTTL uint32
	found := false

	for _, rr := range msg.Answer {
		if !found || rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
			found = true
		}
	}
	if !found {
		for _, rr := range msg.Ns {
			if !found || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
				found = true
			}
		}
	}
	if !found {
		for _, rr := range msg.Extra {
			if !found || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
				found = true
			}
		}
	}
	return minTTL, found
}

func (c *cacheResolver) adjustTTL(msg *dns.Msg, ttl uint32) {
	for _, rr := range msg.Answer {
		if rr.Header().Ttl > ttl {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Ttl > ttl {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range msg.Extra {
		if rr.Header().Ttl > ttl {
			rr.Header().Ttl = ttl
		}
	}
}
