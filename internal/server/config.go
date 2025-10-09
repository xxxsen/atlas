package server

import (
	"atlas/internal/cache"
	"atlas/internal/outbound"
	"atlas/internal/routing"
	"strings"
	"time"
)

// Option configures the DNS server.
type Option func(*options)

type options struct {
	bind    string
	timeout time.Duration
	manager outbound.IOutboundManager
	routes  []routing.IRouteRule
	cache   cache.IDNSCache
}

// WithBind configures the bind address.
func WithBind(bind string) Option {
	return func(o *options) {
		if strings.TrimSpace(bind) != "" {
			o.bind = bind
		}
	}
}

// WithTimeout overrides the request timeout.
func WithTimeout(t time.Duration) Option {
	return func(o *options) {
		if t > 0 {
			o.timeout = t
		}
	}
}

// WithOutboundManager provides the outbound manager implementation.
func WithOutboundManager(m outbound.IOutboundManager) Option {
	return func(o *options) {
		o.manager = m
	}
}

// WithRoutes supplies routing rules.
func WithRoutes(routes []routing.IRouteRule) Option {
	return func(o *options) {
		o.routes = append([]routing.IRouteRule(nil), routes...)
	}
}

// WithCache sets the cache implementation.
func WithCache(c cache.IDNSCache) Option {
	return func(o *options) {
		o.cache = c
	}
}
