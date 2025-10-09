package routing

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/miekg/dns"

	"atlas/internal/config"
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
func BuildRules(cfg []config.RouteConfig) ([]IRouteRule, error) {
	rules := make([]IRouteRule, 0, len(cfg))
	for _, item := range cfg {
		switch strings.ToLower(item.Type) {
		case "domain":
			rule, err := newDomainRule(item.OutboundTag, item.DomainList)
			if err != nil {
				return nil, fmt.Errorf("domain rule: %w", err)
			}
			rules = append(rules, rule)
		case "host":
			rule, err := newHostRule(item.OutboundTag, item.File)
			if err != nil {
				return nil, fmt.Errorf("host rule: %w", err)
			}
			rules = append(rules, rule)
		default:
			return nil, fmt.Errorf("unsupported rule type %q", item.Type)
		}
	}
	return rules, nil
}

type domainRule struct {
	tag      string
	matchers []IDomainMatcher
}

func newDomainRule(tag string, patterns []string) (*domainRule, error) {
	if tag == "" {
		return nil, fmt.Errorf("domain rule requires outbound tag")
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("domain rule requires domain_list entries")
	}
	matchers := make([]IDomainMatcher, 0, len(patterns))
	for _, raw := range patterns {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		matcher, err := parseDomainMatcher(raw)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}
	if len(matchers) == 0 {
		return nil, fmt.Errorf("domain rule has no valid matchers")
	}
	return &domainRule{
		tag:      tag,
		matchers: matchers,
	}, nil
}

func (r *domainRule) Match(question dns.Question) (*RouteDecision, bool) {
	name := normalizeDomain(question.Name)
	for _, matcher := range r.matchers {
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

func parseDomainMatcher(raw string) (IDomainMatcher, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) == 1 {
		return suffixMatcher{suffix: normalizeDomain(raw)}, nil
	}
	kind := strings.ToLower(strings.TrimSpace(parts[0]))
	valueRaw := strings.TrimSpace(parts[1])
	value := normalizeDomain(valueRaw)
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

type hostRule struct {
	tag     string
	records map[string][]net.IP
}

func newHostRule(tag, file string) (*hostRule, error) {
	records, err := loadHostFile(file)
	if err != nil {
		return nil, err
	}
	return &hostRule{
		tag:     tag,
		records: records,
	}, nil
}

func (r *hostRule) Match(question dns.Question) (*RouteDecision, bool) {
	name := normalizeDomain(question.Name)
	if ips, ok := r.records[name]; ok && len(ips) > 0 {
		answers := buildHostRecords(question, ips)
		if len(answers) == 0 {
			return nil, false
		}
		return &RouteDecision{
			Records:   answers,
			Cacheable: false,
		}, true
	}

	if r.tag != "" {
		return &RouteDecision{
			OutboundTag: r.tag,
			Cacheable:   true,
		}, true
	}
	return nil, false
}

func loadHostFile(path string) (map[string][]net.IP, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open host file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	result := make(map[string][]net.IP)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		domain, ips := parseHostLine(line)
		if domain == "" || len(ips) == 0 {
			continue
		}
		result[domain] = ips
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read host file: %w", err)
	}
	return result, nil
}

func parseHostLine(line string) (string, []net.IP) {
	parts := strings.SplitN(line, "#", 2)
	if len(parts) != 2 {
		return "", nil
	}
	domain := normalizeDomain(strings.TrimSpace(parts[0]))
	if domain == "" {
		return "", nil
	}
	rawList := strings.TrimSpace(parts[1])
	rawList = strings.TrimPrefix(rawList, "[")
	rawList = strings.TrimSuffix(rawList, "]")
	if rawList == "" {
		return "", nil
	}
	chunks := strings.Split(rawList, ",")
	ips := make([]net.IP, 0, len(chunks))
	for _, chunk := range chunks {
		ip := net.ParseIP(strings.TrimSpace(chunk))
		if ip == nil {
			continue
		}
		ips = append(ips, ip)
	}
	return domain, ips
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

func normalizeDomain(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	return strings.ToLower(name)
}
