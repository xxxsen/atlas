package server

import (
	"time"

	"github.com/xxxsen/atlas/internal/hosts"
	"github.com/xxxsen/atlas/internal/rule"
)

// Option configures the DNS server.
type Option func(*options)

type options struct {
	bind               string
	re                 rule.IDNSRuleEngine
	hosts              hosts.IHostResolver
	udpSize            int
	maxResponseUDPSize int
	maxInflight        int
	requestTimeout     time.Duration
	rateLimitQPS       float64
	rateLimitBurst     int
	rateLimitClients   int
	ready              func()
	allowedCIDRs       []string
}

// WithAllowedCIDRs restricts clients to the supplied IP prefixes. An empty
// list leaves access control disabled.
func WithAllowedCIDRs(prefixes []string) Option {
	return func(o *options) { o.allowedCIDRs = append([]string(nil), prefixes...) }
}

// WithReady registers a callback invoked after both UDP and TCP listeners are ready.
func WithReady(callback func()) Option {
	return func(o *options) { o.ready = callback }
}

func WithUDPSize(size int) Option {
	return func(o *options) { o.udpSize = size }
}

func WithMaxResponseUDPSize(size int) Option {
	return func(o *options) { o.maxResponseUDPSize = size }
}

func WithMaxInflight(limit int) Option {
	return func(o *options) { o.maxInflight = limit }
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(o *options) { o.requestTimeout = timeout }
}

func WithClientRateLimit(qps float64, burst, maxClients int) Option {
	return func(o *options) {
		o.rateLimitQPS = qps
		o.rateLimitBurst = burst
		o.rateLimitClients = maxClients
	}
}

// WithBind configures the bind address.
func WithBind(bind string) Option {
	return func(o *options) {
		o.bind = bind

	}
}

func WithRuleEngine(re rule.IDNSRuleEngine) Option {
	return func(o *options) {
		o.re = re
	}
}

func WithHostResolver(hts hosts.IHostResolver) Option {
	return func(o *options) {
		o.hosts = hts
	}
}
