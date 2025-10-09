package routing

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"

	"atlas/internal/config"
	providerpkg "atlas/internal/provider"
)

// RouteDecision captures the outcome of a routing decision.
type RouteDecision struct {
	OutboundTag string
	Records     []dns.RR
	Cacheable   bool
}

// IRouteRule is implemented by all routing rules.
type IRouteRule interface {
	Match(question dns.Question) (*RouteDecision, bool)
}

// BuildRules builds routing rules based on configuration order.
func BuildRules(cfg []config.RouteConfig, providers map[string]*providerpkg.ProviderData) ([]IRouteRule, error) {
	rules := make([]IRouteRule, 0, len(cfg))
	for _, item := range cfg {
		providerList := make([]*providerpkg.ProviderData, 0, len(item.DataKeyList))
		for _, key := range item.DataKeyList {
			provider, ok := providers[key]
			if !ok {
				return nil, fmt.Errorf("route references unknown data_key %q", key)
			}
			providerList = append(providerList, provider)
		}
		domainRules, err := providerpkg.BuildChunks(providerList)
		if err != nil {
			return nil, err
		}
		matchers := make([]IDomainMatcher, 0, len(domainRules))
		for _, rule := range domainRules {
			matcher, err := ParseDomainMatcher(rule)
			if err != nil {
				return nil, fmt.Errorf("parse domain rule from data providers: %w", err)
			}
			matchers = append(matchers, matcher)
		}
		rule, err := newRouteRule(item.OutboundTag, matchers)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

type routeRule struct {
	tag            string
	domainMatchers []IDomainMatcher
}

func newRouteRule(tag string, matchers []IDomainMatcher) (*routeRule, error) {
	if len(matchers) == 0 {
		return nil, fmt.Errorf("route requires domain data providers")
	}
	if strings.TrimSpace(tag) == "" {
		return nil, fmt.Errorf("route requires outbound tag")
	}
	return &routeRule{
		tag:            tag,
		domainMatchers: matchers,
	}, nil
}

func (r *routeRule) Match(question dns.Question) (*RouteDecision, bool) {
	name := NormalizeDomain(question.Name)
	for _, matcher := range r.domainMatchers {
		if matcher.Match(name) {
			return &RouteDecision{
				OutboundTag: r.tag,
				Cacheable:   true,
			}, true
		}
	}
	return nil, false
}

type IDomainMatcher interface {
	Match(name string) bool
}

type suffixMatcher struct{ suffix string }

func (m suffixMatcher) Match(name string) bool {
	if name == m.suffix {
		return true
	}
	return strings.HasSuffix(name, "."+m.suffix)
}

type fullMatcher struct{ value string }

func (m fullMatcher) Match(name string) bool {
	return name == m.value
}

type keywordMatcher struct{ keyword string }

func (m keywordMatcher) Match(name string) bool {
	return strings.Contains(name, m.keyword)
}

type regexpMatcher struct{ expr *regexp.Regexp }

func (m regexpMatcher) Match(name string) bool {
	return m.expr.MatchString(name)
}

func ParseDomainMatcher(raw string) (IDomainMatcher, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) == 1 {
		return suffixMatcher{suffix: NormalizeDomain(raw)}, nil
	}
	kind := strings.ToLower(strings.TrimSpace(parts[0]))
	valueRaw := strings.TrimSpace(parts[1])
	value := NormalizeDomain(valueRaw)
	switch kind {
	case "suffix":
		return suffixMatcher{suffix: value}, nil
	case "full":
		return fullMatcher{value: value}, nil
	case "keyword":
		return keywordMatcher{keyword: value}, nil
	case "regexp":
		re, err := regexp.Compile(valueRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid regexp %q: %w", parts[1], err)
		}
		return regexpMatcher{expr: re}, nil
	default:
		return nil, fmt.Errorf("unknown domain matcher %q", kind)
	}
}

func NormalizeDomain(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	return strings.ToLower(name)
}
