package outbound

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"

	"atlas/internal/config"
)

// IDnsOutbound represents a DNS outbound transport abstraction.
type IDnsOutbound interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// Manager holds all configured outbound groups.
type Manager struct {
	groups map[string]*Group
}

// IManager exposes the subset of outbound manager behaviour required by consumers.
type IManager interface {
	Get(tag string) (IDnsOutbound, bool)
}

// Group is an outbound group containing multiple resolvers.
type Group struct {
	tag       string
	parallel  int
	resolvers []IDNSResolver
}

type IDNSResolver interface {
	String() string
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// NewManager constructs all outbound groups from configuration.
func NewManager(cfg []config.OutboundConfig) (*Manager, error) {
	groups := make(map[string]*Group, len(cfg))
	for _, item := range cfg {
		group, err := buildGroup(item)
		if err != nil {
			return nil, fmt.Errorf("build outbound %q: %w", item.Tag, err)
		}
		groups[item.Tag] = group
	}
	return &Manager{groups: groups}, nil
}

// Get retrieves a configured outbound group.
func (m *Manager) Get(tag string) (IDnsOutbound, bool) {
	group, ok := m.groups[tag]
	if !ok {
		return nil, false
	}
	return group, true
}

var randMutex sync.Mutex // ensure rand usage is goroutine-safe

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
				once.Do(func() {
					cancel()
				})
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

func buildGroup(cfg config.OutboundConfig) (*Group, error) {
	resolvers := make([]IDNSResolver, 0, len(cfg.ServerList))
	for _, raw := range cfg.ServerList {
		resolver, err := buildResolver(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, resolver)
	}
	return &Group{
		tag:       cfg.Tag,
		parallel:  cfg.Parallel,
		resolvers: resolvers,
	}, nil
}

func buildResolver(raw string) (IDNSResolver, error) {
	if raw == "" {
		return nil, errors.New("empty server endpoint")
	}
	if strings.HasPrefix(raw, "reject://") {
		return &rejectResolver{}, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse server %q: %w", raw, err)
	}
	switch parsed.Scheme {
	case "udp", "tcp", "dot":
		return newClassicResolver(parsed)
	case "https", "http":
		return newDoHResolver(parsed)
	default:
		return nil, fmt.Errorf("unsupported resolver scheme %q", parsed.Scheme)
	}
}

func cloneMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		return nil
	}
	c := msg.Copy()
	// Ensure recursion desired flag remains set.
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
