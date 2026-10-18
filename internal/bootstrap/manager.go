package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/hosts"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/common/logutil"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Options uses the existing DNS cache policy. Upstreams and Now are optional
// dependencies; when absent, New constructs transports and uses the wall clock.
type Options struct {
	Cache     resolver.CacheOptions
	Hosts     hosts.IHostResolver
	Upstreams []resolver.IDNSResolver
	Now       func() time.Time
}

type candidate struct {
	record Record
	wire   string
	fresh  time.Time
	source string
}

type cachedRecord struct {
	candidate
	stale time.Time
	size  int64
}

type watermark struct {
	Version int64  `json:"version"`
	Digest  string `json:"digest"`
}

type flight struct {
	done chan struct{}
	data candidate
	err  error
	span trace.Span
}

// Manager owns authenticated discovery, per-domain versions, bounded caching,
// and checkpointing. Resolve returns handled=true even when a protected name
// fails, so callers must never fall through to ordinary DNS on that path.
type Manager struct {
	config      Config
	options     Options
	domains     map[string]string
	keys        map[string]ed25519.PublicKey
	upstreams   []resolver.IDNSResolver
	fingerprint string
	now         func() time.Time
	ctx         context.Context
	cancel      context.CancelFunc

	mu         sync.Mutex
	cache      *lru.Cache[string, cachedRecord]
	cacheBytes int64
	versions   map[string]watermark
	flights    map[string]*flight
	refreshSem chan struct{}
	closed     bool
	generation uint64
	persisted  uint64
	tasks      sync.WaitGroup
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
	next       atomic.Uint64
}

func New(parent context.Context, config Config, options Options) (*Manager, error) {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	domains, err := LoadDomains(config.Files)
	if err != nil {
		return nil, err
	}
	keys, err := loadPublicKeys(config.PublicKeys)
	if err != nil {
		return nil, err
	}
	if options.Hosts != nil {
		for domain := range domains {
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if _, ok := options.Hosts.Resolve(dns.Question{Name: domain + ".", Qtype: qtype, Qclass: dns.ClassINET}); ok {
					return nil, fmt.Errorf("bootstrap domain %s conflicts with hosts", domain)
				}
			}
		}
	}
	if err := normalizeCacheOptions(&options.Cache); err != nil {
		return nil, err
	}
	upstreams := options.Upstreams
	if len(upstreams) == 0 {
		upstreams, err = resolver.MakeResolvers(config.ServerList)
		if err != nil {
			return nil, fmt.Errorf("build bootstrap upstreams: %w", err)
		}
	}
	if len(upstreams) != len(config.ServerList) {
		return nil, fmt.Errorf("bootstrap upstream dependency count does not match server_list")
	}
	for _, upstream := range upstreams {
		if upstream == nil {
			return nil, fmt.Errorf("bootstrap upstream dependency is nil")
		}
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{
		config: config, options: options, domains: domains, keys: keys,
		upstreams: upstreams, now: options.Now, ctx: ctx, cancel: cancel,
		versions: make(map[string]watermark), flights: make(map[string]*flight),
		refreshSem: make(chan struct{}, options.Cache.RefreshConcurrency),
		closeDone:  make(chan struct{}),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if options.Cache.Size > 0 {
		m.cache, _ = lru.New[string, cachedRecord](int(options.Cache.Size))
	}
	// Include file contents and actual public keys, not just their paths.
	encoded, _ := json.Marshal(struct {
		Config  Config
		Domains map[string]string
		Keys    map[string]ed25519.PublicKey
		Cache   resolver.CacheOptions
	}{config, domains, keys, options.Cache})
	sum := sha256.Sum256(encoded)
	m.fingerprint = hex.EncodeToString(sum[:])
	if options.Cache.Persist {
		if err := m.load(); err != nil {
			m.cache.Purge()
			m.cacheBytes = 0
			clear(m.versions)
			m.generation++
			logutil.GetLogger(ctx).Warn("discarded unusable bootstrap checkpoint", zap.Error(err))
		}
		m.tasks.Add(1)
		go m.persistLoop()
	}
	keyIDs := make([]string, 0, len(keys))
	for id := range keys {
		keyIDs = append(keyIDs, id)
	}
	slices.Sort(keyIDs)
	querylog.Logger(ctx).Info("bootstrap initialized", zap.Int("domain_count", len(domains)), zap.Int("public_key_count", len(keys)), zap.Strings("public_key_ids", keyIDs), zap.Int("upstream_count", len(upstreams)))
	return m, nil
}

func normalizeCacheOptions(c *resolver.CacheOptions) error {
	if c.Size < 0 || c.Size > 1_000_000 || c.MaxStale < 0 || c.MaxStale > 7*24*time.Hour {
		return fmt.Errorf("invalid bootstrap cache size or max_stale")
	}
	if c.RefreshConcurrency == 0 {
		c.RefreshConcurrency = 4
	}
	if c.RefreshConcurrency < 1 || c.RefreshConcurrency > 1024 {
		return fmt.Errorf("invalid bootstrap cache refresh concurrency")
	}
	if c.Size > 0 {
		if c.MaxBytes == 0 {
			c.MaxBytes = min(c.Size*4096, 512*1024*1024)
		}
		if c.MaxEntryBytes == 0 {
			c.MaxEntryBytes = dns.MaxMsgSize
		}
		if c.MaxBytes < 1 || c.MaxBytes > 16*1024*1024*1024 || c.MaxEntryBytes < 1 || c.MaxEntryBytes > dns.MaxMsgSize {
			return fmt.Errorf("invalid bootstrap cache byte limits")
		}
	}
	if c.Persist && (c.Size == 0 || strings.TrimSpace(c.File) == "") {
		return fmt.Errorf("bootstrap persistence requires an enabled cache and cache.file")
	}
	if c.Persist && c.Interval == 0 {
		c.Interval = 10 * time.Minute
	}
	if c.Persist && (c.Interval < time.Second || c.Interval > 24*time.Hour) {
		return fmt.Errorf("invalid bootstrap cache persistence interval")
	}
	return nil
}

// Resolve handles only exact names from files. Unsupported types are locally
// empty; missing address families are derived from the signed set, never DNS.
func (m *Manager) Resolve(ctx context.Context, req *dns.Msg) (message *dns.Msg, handled bool, resultErr error) {
	if req == nil || len(req.Question) != 1 {
		return nil, false, fmt.Errorf("bootstrap requires exactly one question")
	}
	domain, err := normalizeDomain(req.Question[0].Name)
	if err != nil {
		return nil, false, nil
	}
	if _, ok := m.domains[domain]; !ok {
		return nil, false, nil
	}
	if ctx == nil {
		return nil, true, fmt.Errorf("bootstrap context is nil")
	}
	ctx = querylog.WithQuery(ctx, req)
	ctx, span := querylog.Start(ctx, "bootstrap.resolve", trace.WithAttributes(attribute.String("bootstrap.txt_domain", m.domains[domain])))
	defer func() { querylog.Finish(ctx, span, resultErr) }()
	querylog.SetResult(ctx, querylog.Result{Source: "bootstrap", Action: "bootstrap"})
	if req.Question[0].Qclass != dns.ClassINET {
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeRefused)
		return msg, true, nil
	}
	qtype := req.Question[0].Qtype
	if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeANY {
		return response(req, Record{}, 0), true, nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, true, fmt.Errorf("bootstrap is closed")
	}
	now := m.now()
	if m.cache != nil {
		if entry, ok := m.cache.Get(domain); ok {
			// Signature validity is independent of DNS TTL and lazy max_stale.
			if entry.record.validAt(now, m.config.skew()) == nil && now.Before(entry.stale) {
				stale := !now.Before(entry.fresh)
				var refresh trace.SpanContext
				if stale {
					if work := m.startFlightLocked(domain, ctx, true); work != nil {
						refresh = work.span.SpanContext()
					}
				}
				m.mu.Unlock()
				ttl := remainingTTL(entry.fresh, now)
				if stale {
					ttl = 0
				}
				status := "fresh"
				if stale {
					status = "stale"
				}
				querylog.SetCache(ctx, "bootstrap", status)
				querylog.SetResult(ctx, bootstrapResult(entry.candidate))
				fields := append(querylog.Fields(ctx), querylog.WorkFields("refresh", refresh)...)
				querylog.Logger(ctx).Debug("bootstrap cache hit", append(fields, zap.String("key_id", entry.record.KeyID), zap.Int64("issued_at", entry.record.IssuedAt), zap.Int64("expires_at", entry.record.ExpiresAt))...)
				return response(req, entry.record, ttl), true, nil
			}
			m.removeCacheLocked(domain)
		}
	}
	work := m.startFlightLocked(domain, ctx, false)
	m.mu.Unlock()
	querylog.SetCache(ctx, "bootstrap", "miss")
	sc := work.span.SpanContext()
	querylog.SetWork(ctx, sc)
	ctx, waitSpan := querylog.Start(ctx, "bootstrap.wait", trace.WithLinks(trace.Link{SpanContext: sc}))
	defer func() { querylog.Finish(ctx, waitSpan, resultErr) }()
	querylog.Logger(ctx).Debug("bootstrap query waiting", append(querylog.WorkFields("work", sc), zap.String("txt_domain", m.domains[domain]))...)
	select {
	case <-ctx.Done():
		return nil, true, ctx.Err()
	case <-work.done:
		if work.err != nil {
			return nil, true, work.err
		}
		now = m.now()
		if err := work.data.record.validAt(now, m.config.skew()); err != nil {
			return nil, true, err
		}
		querylog.SetResult(ctx, bootstrapResult(work.data))
		return response(req, work.data.record, remainingTTL(work.data.fresh, now)), true, nil
	}
}

func remainingTTL(deadline, now time.Time) uint32 {
	seconds := deadline.Sub(now) / time.Second
	if seconds <= 0 {
		return 0
	}
	return uint32(min(int64(seconds), int64(1<<32-1)))
}

func response(req *dns.Msg, record Record, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	q := req.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
		for _, address := range record.A {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP(address).To4(),
			})
		}
	}
	if q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY {
		for _, address := range record.AAAA {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: net.ParseIP(address),
			})
		}
	}
	return msg
}

// Caller holds mu. Foreground flights share their work; stale refresh admission
// is bounded separately and never delays returning an authenticated stale value.
func (m *Manager) startFlightLocked(domain string, caller context.Context, background bool) *flight {
	if work, ok := m.flights[domain]; ok {
		return work
	}
	if background {
		select {
		case m.refreshSem <- struct{}{}:
		default:
			querylog.Logger(caller).Debug("bootstrap refresh skipped", zap.String("reason", "concurrency_limit"))
			return nil
		}
	}
	name := "bootstrap.query"
	if background {
		name = "bootstrap.refresh"
	}
	parent, workSpan := querylog.Fork(m.ctx, caller, name, background)
	work := &flight{done: make(chan struct{}), span: workSpan}
	m.flights[domain] = work
	queryCtx, cancel := context.WithTimeout(parent, time.Duration(m.config.RequestTimeout)*time.Second)
	if !background {
		if deadline, ok := caller.Deadline(); ok {
			var deadlineCancel context.CancelFunc
			queryCtx, deadlineCancel = context.WithDeadline(queryCtx, deadline)
			previous := cancel
			cancel = func() { deadlineCancel(); previous() }
		}
	}
	m.tasks.Add(1)
	go func() {
		defer m.tasks.Done()
		defer cancel()
		var err error
		defer func() { querylog.Finish(queryCtx, workSpan, err) }()
		if background {
			defer func() { <-m.refreshSem }()
		}
		start := time.Now()
		logger := querylog.Logger(queryCtx).With(zap.String("txt_domain", m.domains[domain]))
		logger.Debug("bootstrap query started", zap.Int("upstream_count", len(m.upstreams)), zap.Int("parallel", m.config.Parallel), zap.Bool("wait_for_all", true))
		selected, err := m.collect(queryCtx, domain)
		m.mu.Lock()
		previousVersion := m.versions[domain].Version
		if err == nil && !m.closed {
			err = m.acceptLocked(domain, selected)
		} else if m.closed {
			err = fmt.Errorf("bootstrap is closed")
		}
		work.data, work.err = selected, err
		delete(m.flights, domain)
		close(work.done)
		m.mu.Unlock()
		if err != nil {
			if queryCtx.Err() == context.Canceled && m.ctx.Err() != nil {
				logger.Debug("bootstrap query stopped", querylog.Error(err), querylog.Elapsed(start))
			} else {
				logger.Warn("bootstrap query failed", querylog.Error(err), querylog.Elapsed(start), zap.String("candidate_resolver", querylog.SafeText(selected.source)), zap.Int64("previous_issued_at", previousVersion), zap.Int64("candidate_issued_at", selected.record.IssuedAt))
			}
		} else {
			querylog.SetResult(queryCtx, bootstrapResult(selected))
			addresses := append(append([]string(nil), selected.record.A...), selected.record.AAAA...)
			if len(addresses) > 8 {
				addresses = addresses[:8]
			}
			logger.Info("accepted signed bootstrap addresses", append(querylog.Fields(queryCtx), querylog.Elapsed(start), zap.Strings("ips", addresses), zap.String("key_id", selected.record.KeyID), zap.Int64("issued_at", selected.record.IssuedAt), zap.Int64("expires_at", selected.record.ExpiresAt))...)
		}
	}()
	return work
}

func (m *Manager) acceptLocked(domain string, selected candidate) error {
	if err := selected.record.validAt(m.now(), m.config.skew()); err != nil {
		return err
	}
	version := watermark{Version: selected.record.IssuedAt, Digest: selected.record.digest()}
	old := m.versions[domain]
	if version.Version < old.Version {
		return fmt.Errorf("bootstrap rejected rollback for %s", domain)
	}
	if version.Version == old.Version && version.Digest != old.Digest {
		return fmt.Errorf("bootstrap rejected conflicting version for %s", domain)
	}
	m.versions[domain] = version
	m.generation++
	m.removeCacheLocked(domain)
	if m.cache != nil && selected.fresh.After(m.now()) {
		stale := selected.fresh
		if m.options.Cache.Lazy {
			stale = stale.Add(m.options.Cache.MaxStale)
		}
		expiration := time.UnixMilli(selected.record.ExpiresAt)
		if stale.After(expiration) {
			stale = expiration
		}
		entry := cachedRecord{candidate: selected, stale: stale, size: int64(len(selected.wire) + len(domain) + 256)}
		if entry.size <= m.options.Cache.MaxEntryBytes && entry.size <= m.options.Cache.MaxBytes {
			for m.cache.Len() >= int(m.options.Cache.Size) || m.cacheBytes+entry.size > m.options.Cache.MaxBytes {
				_, oldEntry, ok := m.cache.RemoveOldest()
				if !ok {
					break
				}
				m.cacheBytes -= oldEntry.size
			}
			m.cache.Add(domain, entry)
			m.cacheBytes += entry.size
		}
	}
	return nil
}

func bootstrapResult(value candidate) querylog.Result {
	if value.source == "checkpoint" {
		return querylog.Result{Source: "bootstrap_checkpoint", Resolver: "unknown", Action: "bootstrap"}
	}
	return querylog.Result{Source: "bootstrap", Resolver: querylog.SafeText(value.source), Action: "bootstrap"}
}

func (m *Manager) removeCacheLocked(domain string) {
	if m.cache == nil {
		return
	}
	if entry, ok := m.cache.Peek(domain); ok {
		m.cacheBytes -= entry.size
		m.cache.Remove(domain)
		m.generation++
	}
}

type queryResult struct {
	candidates []candidate
	err        error
}

func (m *Manager) collect(ctx context.Context, domain string) (candidate, error) {
	results := make(chan queryResult, len(m.upstreams))
	var workers sync.WaitGroup
	var index atomic.Uint64
	start := int(m.next.Add(1)-1) % len(m.upstreams)
	for worker := 0; worker < m.config.Parallel; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				at := int(index.Add(1) - 1)
				if at >= len(m.upstreams) || ctx.Err() != nil {
					return
				}
				upstream := m.upstreams[(start+at)%len(m.upstreams)]
				values, err := m.queryUpstream(ctx, domain, upstream)
				results <- queryResult{candidates: values, err: err}
			}
		}()
	}
	go func() { workers.Wait(); close(results) }()
	var selected candidate
	conflict := false
	var errs []error
	for result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
		}
		for _, value := range result.candidates {
			if err := value.record.validAt(m.now(), m.config.skew()); err != nil {
				querylog.Logger(ctx).Warn("bootstrap candidate lifetime invalid before selection", querylog.Error(err), zap.String("resolver", querylog.SafeText(value.source)), zap.Int64("issued_at", value.record.IssuedAt), zap.Int64("expires_at", value.record.ExpiresAt))
				continue
			}
			if value.record.IssuedAt > selected.record.IssuedAt {
				selected, conflict = value, false
			} else if value.record.IssuedAt == selected.record.IssuedAt {
				if value.record.digest() != selected.record.digest() {
					querylog.Logger(ctx).Warn("bootstrap signed candidate conflict", zap.Int64("issued_at", value.record.IssuedAt), zap.String("resolver", querylog.SafeText(value.source)), zap.String("previous_resolver", querylog.SafeText(selected.source)))
					conflict = true
				} else if value.fresh.Before(selected.fresh) {
					selected.fresh = value.fresh
				}
			}
		}
	}
	if conflict {
		return candidate{}, fmt.Errorf("conflicting bootstrap records at the highest timestamp %d for %s", selected.record.IssuedAt, domain)
	}
	if selected.wire == "" {
		return candidate{}, fmt.Errorf("no valid signed bootstrap result for %s: %w", domain, errors.Join(append(errs, ctx.Err())...))
	}
	return selected, nil
}

func (m *Manager) queryUpstream(ctx context.Context, domain string, upstream resolver.IDNSResolver) (values []candidate, resultErr error) {
	ctx, span := querylog.Start(ctx, "bootstrap.upstream", trace.WithAttributes(attribute.String("atlas.resolver", querylog.SafeText(upstream.Name())), attribute.String("bootstrap.txt_domain", m.domains[domain])))
	defer func() { querylog.Finish(ctx, span, resultErr) }()
	start := time.Now()
	logger := querylog.Logger(ctx).With(zap.String("resolver", querylog.SafeText(upstream.Name())), zap.String("txt_domain", m.domains[domain]), zap.Uint16("upstream_qtype", dns.TypeTXT))
	rejected := 0
	defer func() {
		fields := []zap.Field{querylog.Elapsed(start), zap.Int("valid_candidates", len(values)), zap.Int("rejected_candidates", rejected), querylog.Error(resultErr)}
		if resultErr != nil {
			logger.Warn("bootstrap upstream query failed", fields...)
		} else {
			logger.Debug("bootstrap upstream query completed", fields...)
		}
	}()
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(m.domains[domain]), dns.TypeTXT)
	request.SetEdns0(1232, false)
	msg, err := upstream.Query(ctx, request)
	if err == nil {
		err = resolver.ValidateResponse(request, msg)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", upstream.Name(), err)
	}
	if msg.Truncated || msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%s: no complete successful TXT response (rcode=%s, truncated=%t)", upstream.Name(), dns.RcodeToString[msg.Rcode], msg.Truncated)
	}
	var lastErr error
	count := 0
	for _, rr := range msg.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		count++
		if count > 64 {
			return nil, fmt.Errorf("%s: too many bootstrap TXT candidates", upstream.Name())
		}
		var text strings.Builder
		for _, part := range txt.Txt {
			if text.Len()+len(part) > maxRecordBytes {
				return nil, fmt.Errorf("%s: bootstrap TXT exceeds size limit", upstream.Name())
			}
			text.WriteString(part)
		}
		wire := text.String()
		now := m.now()
		record, err := Verify(wire, domain, m.keys, now, m.config.skew())
		if err != nil {
			lastErr = err
			rejected++
			span.AddEvent("bootstrap.candidate.rejected", trace.WithAttributes(attribute.Int("bootstrap.txt_index", count), attribute.String("error.message", querylog.SafeText(err.Error()))))
			fields := []zap.Field{zap.Int("txt_index", count), querylog.Error(err)}
			if id, decodeErr := hex.DecodeString(record.KeyID); decodeErr == nil && len(id) == 32 {
				fields = append(fields, zap.String("candidate_key_id", record.KeyID))
			}
			logger.Warn("bootstrap TXT candidate rejected", fields...)
			continue
		}
		ttl := min(int64(txt.Hdr.Ttl), m.config.TTLMax, (record.ExpiresAt-now.UnixMilli())/1000)
		values = append(values, candidate{record: record, wire: wire,
			fresh: now.Add(time.Duration(ttl) * time.Second), source: upstream.Name()})
		logger.Debug("bootstrap TXT candidate verified", zap.Int("txt_index", count), zap.String("key_id", record.KeyID), zap.Int64("issued_at", record.IssuedAt), zap.Int64("expires_at", record.ExpiresAt))
		span.AddEvent("bootstrap.candidate.verified", trace.WithAttributes(attribute.Int("bootstrap.txt_index", count), attribute.String("bootstrap.key_id", record.KeyID), attribute.Int64("bootstrap.issued_at", record.IssuedAt), attribute.Int64("bootstrap.expires_at", record.ExpiresAt)))
	}
	if len(values) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("missing signed TXT record")
		}
		return nil, fmt.Errorf("%s: %w", upstream.Name(), lastErr)
	}
	return values, nil
}

// Close stops refreshes, checkpoints the latest state, and closes transports.
// A caller whose deadline expires may call Close again to await completion.
func (m *Manager) Close(ctx context.Context) error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.cancel()
		m.mu.Unlock()
		go func() {
			m.tasks.Wait()
			if m.options.Cache.Persist {
				m.closeErr = m.persist()
			}
			m.closeErr = errors.Join(m.closeErr, resolver.CloseResolvers(m.upstreams))
			close(m.closeDone)
		}()
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.closeDone:
		return m.closeErr
	}
}
