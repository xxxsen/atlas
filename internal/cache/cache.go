package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const lazyTTL = 1 * time.Second

// Result describes the outcome of a cache lookup.
type Result struct {
	Msg           *dns.Msg
	Expired       bool
	ShouldRefresh bool
}

// IDNSCache abstracts cache operations used by the server.
type IDNSCache interface {
	Get(key string) (Result, bool)
	Set(key string, msg *dns.Msg)
	MarkRefreshComplete(key string)
}

// Cache is a simple LRU cache with TTL support and optional lazy refresh.
type Cache struct {
	mu       sync.Mutex
	items    map[string]*list.Element
	order    *list.List
	capacity int
	lazy     bool
	now      func() time.Time
	lazyTTLS time.Duration
}

type entry struct {
	key        string
	message    *dns.Msg
	expiry     time.Time
	refreshing bool
}

// New creates a cache with a max capacity and lazy-refresh behaviour.
func New(capacity int, lazy bool) *Cache {
	if capacity <= 0 {
		capacity = 1
	}
	return &Cache{
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
		capacity: capacity,
		lazy:     lazy,
		now:      time.Now,
		lazyTTLS: lazyTTL,
	}
}

// Get returns the cached response if present.
func (c *Cache) Get(key string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return Result{}, false
	}

	ent := elem.Value.(*entry)
	c.order.MoveToFront(elem)

	now := c.now()
	remaining := ent.expiry.Sub(now)
	if remaining <= 0 {
		if !c.lazy {
			c.removeElement(elem)
			return Result{}, false
		}
		res := Result{
			Msg:           cloneAndAdjust(ent.message, c.lazyTTLS),
			Expired:       true,
			ShouldRefresh: false,
		}
		if !ent.refreshing {
			ent.refreshing = true
			res.ShouldRefresh = true
		}
		return res, true
	}
	return Result{
		Msg: cloneAndAdjust(ent.message, remaining),
	}, true
}

// Set inserts or updates a cache entry if the message is cacheable.
func (c *Cache) Set(key string, msg *dns.Msg) {
	if msg == nil {
		return
	}
	ttl := messageTTL(msg)
	if ttl <= 0 {
		c.Delete(key)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		ent := elem.Value.(*entry)
		ent.message = msg.Copy()
		ent.expiry = c.now().Add(ttl)
		ent.refreshing = false
		c.order.MoveToFront(elem)
		return
	}

	ent := &entry{
		key:     key,
		message: msg.Copy(),
		expiry:  c.now().Add(ttl),
	}
	elem := c.order.PushFront(ent)
	c.items[key] = elem

	if c.order.Len() > c.capacity {
		c.evictOldest()
	}
}

// MarkRefreshComplete clears the refreshing flag allowing future lazy refreshes.
func (c *Cache) MarkRefreshComplete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		ent := elem.Value.(*entry)
		ent.refreshing = false
	}
}

// Delete removes an entry from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

func (c *Cache) evictOldest() {
	elem := c.order.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

func (c *Cache) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	ent := elem.Value.(*entry)
	delete(c.items, ent.key)
	c.order.Remove(elem)
}

func cloneAndAdjust(msg *dns.Msg, ttl time.Duration) *dns.Msg {
	if msg == nil {
		return nil
	}
	copy := msg.Copy()
	setAllTTL(copy, ttl)
	return copy
}

func setAllTTL(msg *dns.Msg, ttl time.Duration) {
	if msg == nil {
		return
	}
	seconds := uint32(ttl / time.Second)
	for _, rr := range msg.Answer {
		rr.Header().Ttl = seconds
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = seconds
	}
	for _, rr := range msg.Extra {
		rr.Header().Ttl = seconds
	}
}

func messageTTL(msg *dns.Msg) time.Duration {
	if msg == nil {
		return 0
	}
	var minTTL uint32 = ^uint32(0)
	found := false
	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}
		ttl := rr.Header().Ttl
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}
	for _, rr := range msg.Ns {
		if rr == nil {
			continue
		}
		ttl := rr.Header().Ttl
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}
	for _, rr := range msg.Extra {
		if rr == nil {
			continue
		}
		ttl := rr.Header().Ttl
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}
	if !found || minTTL == ^uint32(0) {
		return 0
	}
	return time.Duration(minTTL) * time.Second
}
