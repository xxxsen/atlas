package outbound

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

// IDnsOutbound represents a DNS outbound transport abstraction.
type IDnsOutbound interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// IDNSResolver represents a downstream resolver.
type IDNSResolver interface {
	String() string
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// Manager holds all configured outbound groups.
type Manager struct {
	groups map[string]*Group
}

// NewManager creates an empty outbound manager.
func NewManager() *Manager {
	return &Manager{groups: make(map[string]*Group)}
}

// AddOutbound registers a configured outbound group using pre-built resolvers.
func (m *Manager) AddOutbound(tag string, resolvers []IDNSResolver, parallel int) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return errors.New("outbound tag must not be empty")
	}
	if _, exists := m.groups[tag]; exists {
		return fmt.Errorf("outbound tag %q already exists", tag)
	}
	if len(resolvers) == 0 {
		return fmt.Errorf("outbound %q requires at least one resolver", tag)
	}
	if parallel <= 0 {
		parallel = 1
	}
	m.groups[tag] = &Group{tag: tag, parallel: parallel, resolvers: resolvers}
	return nil
}

// Get retrieves a configured outbound group.
func (m *Manager) Get(tag string) (IDnsOutbound, bool) {
	group, ok := m.groups[tag]
	if !ok {
		return nil, false
	}
	return group, true
}

// Group is an outbound group containing multiple resolvers.
type Group struct {
	tag       string
	parallel  int
	resolvers []IDNSResolver
}

// Query forwards the DNS request using the group's configured resolvers.
func (g *Group) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(g.resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}

	choices := g.pickResolvers()
	logger := logutil.GetLogger(ctx).With(
		zap.String("outbound_tag", g.tag),
		zap.Int("available_resolvers", len(g.resolvers)),
		zap.Int("parallel", len(choices)),
		zap.String("question", questionName(req)),
	)
	logger.Debug("outbound group dispatching query")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type response struct {
		msg *dns.Msg
		err error
	}

	respCh := make(chan response, len(choices))
	var once sync.Once
	for _, res := range choices {
		resolver := res
		go func() {
			msg, err := resolver.Query(ctx, cloneMessage(req))
			if err == nil && msg != nil {
				logger.Debug("resolver succeeded", zap.String("resolver", resolver.String()))
				once.Do(func() { cancel() })
			} else if err != nil {
				logger.Warn("resolver failed", zap.String("resolver", resolver.String()), zap.Error(err))
			}
			respCh <- response{msg: msg, err: err}
		}()
	}

	var firstErr error
	for range choices {
		resp := <-respCh
		if resp.err == nil && resp.msg != nil {
			logger.Debug("returning fastest resolver response")
			return resp.msg, nil
		}
		if firstErr == nil {
			firstErr = resp.err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("all outbound resolvers failed")
	}
	logger.Error("all resolvers failed", zap.Error(firstErr))
	return nil, firstErr
}

func (g *Group) pickResolvers() []IDNSResolver {
	count := g.parallel
	if count > len(g.resolvers) {
		count = len(g.resolvers)
	}
	indexes := make([]int, len(g.resolvers))
	for i := range indexes {
		indexes[i] = i
	}
	randMutex.Lock()
	rand.Shuffle(len(indexes), func(i, j int) {
		indexes[i], indexes[j] = indexes[j], indexes[i]
	})
	randMutex.Unlock()
	selected := make([]IDNSResolver, 0, count)
	for i := 0; i < count; i++ {
		selected = append(selected, g.resolvers[indexes[i]])
	}
	return selected
}

// ResolverParams captures parsed resolver configuration options.
type ResolverParams struct {
	Timeout  time.Duration
	Path     string
	RawQuery string
	RawURL   string
	Values   url.Values
}

// ResolverFactory builds a resolver for the given schema/host.
type ResolverFactory func(schema string, host string, params *ResolverParams) (IDNSResolver, error)

var (
	resolverFactories = make(map[string]ResolverFactory)
	hostProviderData  map[string]map[string][]net.IP
)

// RegisterResolverFactory registers a resolver factory for a schema.
func RegisterResolverFactory(schema string, factory ResolverFactory) {
	schema = strings.ToLower(schema)
	resolverFactories[schema] = factory
}

// SetHostData supplies host provider records for host resolvers.
func SetHostData(data map[string]map[string][]net.IP) {
	hostProviderData = data
}

func getHostRecords(key string) (map[string][]net.IP, bool) {
	if hostProviderData == nil {
		return nil, false
	}
	records, ok := hostProviderData[key]
	return records, ok
}

// CreateResolver constructs a resolver from the raw endpoint definition.
func CreateResolver(raw string) (IDNSResolver, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty server endpoint")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse server %q: %w", raw, err)
	}
	schema := strings.ToLower(u.Scheme)
	factory, ok := resolverFactories[schema]
	if !ok {
		return nil, fmt.Errorf("unsupported resolver scheme %q", schema)
	}
	params, err := parseResolverParams(u)
	if err != nil {
		return nil, err
	}
	return factory(schema, u.Host, params)
}

// CreateResolvers constructs a resolver slice from raw endpoints.
func CreateResolvers(endpoints []string) ([]IDNSResolver, error) {
	resolvers := make([]IDNSResolver, 0, len(endpoints))
	for _, endpoint := range endpoints {
		resolver, err := CreateResolver(endpoint)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, resolver)
	}
	return resolvers, nil
}

func parseResolverParams(u *url.URL) (*ResolverParams, error) {
	values := u.Query()
	params := &ResolverParams{
		Path:   u.Path,
		RawURL: u.String(),
		Values: values,
	}
	if timeoutStr := values.Get("timeout"); timeoutStr != "" {
		d, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf("parse timeout for %s: %w", u.String(), err)
		}
		params.Timeout = d
		values.Del("timeout")
	}
	params.RawQuery = values.Encode()
	return params, nil
}

func cloneMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		return nil
	}
	c := msg.Copy()
	c.RecursionDesired = true
	return c
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func questionName(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return ""
	}
	return strings.TrimSuffix(msg.Question[0].Name, ".")
}

var randMutex sync.Mutex
