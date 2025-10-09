package routing

import (
	"fmt"
	"net"
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
		matchers := make([]IDomainMatcher, 0)
		hostRecords := make(map[string][]net.IP)
		for _, key := range item.DataKeyList {
			provider, ok := providers[key]
			if !ok {
				return nil, fmt.Errorf("route references unknown data_key %q", key)
			}
			switch provider.Kind {
			case providerpkg.KindDomainFile:
				for _, rule := range provider.DomainRules {
					matcher, err := ParseDomainMatcher(rule)
					if err != nil {
						return nil, fmt.Errorf("parse domain rule from data_key %q: %w", key, err)
					}
					matchers = append(matchers, matcher)
				}
			case providerpkg.KindHost:
				for domain, ips := range provider.HostRecords {
					existing := hostRecords[domain]
					hostRecords[domain] = append(existing, ips...)
				}
			default:
				return nil, fmt.Errorf("unsupported provider kind %q for data_key %s", provider.Kind, key)
			}
		}
		rule, err := newRouteRule(item.OutboundTag, matchers, hostRecords)
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
	hostRecords    map[string][]net.IP
}

func newRouteRule(tag string, matchers []IDomainMatcher, hosts map[string][]net.IP) (*routeRule, error) {
	if len(matchers) == 0 && len(hosts) == 0 {
		return nil, fmt.Errorf("route requires domain or host data")
	}
	if len(matchers) > 0 && strings.TrimSpace(tag) == "" {
		return nil, fmt.Errorf("route with domain data requires outbound tag")
	}
	return &routeRule{
		tag:            tag,
		domainMatchers: matchers,
		hostRecords:    hosts,
	}, nil
}

func (r *routeRule) Match(question dns.Question) (*RouteDecision, bool) {
	name := NormalizeDomain(question.Name)
	if len(r.hostRecords) > 0 {
		if ips, ok := r.hostRecords[name]; ok && len(ips) > 0 {
			answers := buildHostRecords(question, ips)
			if len(answers) > 0 {
				return &RouteDecision{
					Records:   answers,
					Cacheable: false,
				}, true
			}
		}
		if len(r.domainMatchers) == 0 && strings.TrimSpace(r.tag) != "" {
			return &RouteDecision{
				OutboundTag: r.tag,
				Cacheable:   true,
			}, true
		}
	}
	if len(r.domainMatchers) > 0 {
		for _, matcher := range r.domainMatchers {
			if matcher.Match(name) {
				return &RouteDecision{
					OutboundTag: r.tag,
					Cacheable:   true,
				}, true
			}
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

func buildHostRecords(question dns.Question, ips []net.IP) []dns.RR {
	if len(ips) == 0 {
		return nil
	}
	name := question.Name
	if name == "" {
		return nil
	}
	var records []dns.RR
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY) {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: ip4,
			}
			records = append(records, rr)
		} else if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil && (question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypeANY) {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: ip6,
			}
			records = append(records, rr)
		}
	}
	return records
}

func NormalizeDomain(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	return strings.ToLower(name)
}
