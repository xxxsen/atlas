package server

import (
	"github.com/xxxsen/atlas/internal/rule"
)

// Option configures the DNS server.
type Option func(*options)

type options struct {
	bind string
	re   rule.IDNSRuleEngine
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
