package matcher

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/atlas/internal/strictdecode"
)

type domainMatcher struct {
	name  string
	index *domainTrie
	kw    *ahoMatcher
	reg   []*regexp.Regexp
}

const (
	maxDomainRules = 1_000_000
	maxRegexRules  = 10_000
	maxRegexLength = 4096
)

func (d *domainMatcher) Name() string {
	return d.name
}

func (d *domainMatcher) Type() string {
	return "domain"
}

func (d *domainMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	if req == nil || len(req.Question) != 1 {
		return false, fmt.Errorf("domain matcher requires exactly one DNS question")
	}
	name := matcher.NormalizedRequestName(ctx, req)
	exact, suffix := d.index.match(name)
	if exact || suffix {
		return true, nil
	}
	if d.kw.match(name) {
		return true, nil
	}
	for _, reg := range d.reg {
		if reg.MatchString(name) {
			return true, nil
		}
	}
	return false, nil
}

func (d *domainMatcher) extractKindData(in string) (string, string) {
	if idx := strings.IndexByte(in, ':'); idx >= 0 {
		kind := strings.ToLower(strings.TrimSpace(in[:idx]))
		data := strings.TrimSpace(in[idx+1:])
		return kind, data
	}
	return "suffix", strings.TrimSpace(in)
}

func (d *domainMatcher) init(drs []string) error {
	if len(drs) == 0 {
		return fmt.Errorf("domain matcher requires at least one rule")
	}
	if len(drs) > maxDomainRules {
		return fmt.Errorf("domain matcher has %d rules; maximum is %d", len(drs), maxDomainRules)
	}
	seen := make(map[string]struct{}, len(drs))
	regexCount := 0
	for _, dr := range drs {
		if len(dr) == 0 {
			return fmt.Errorf("nil domain found")
		}
		kind, data := d.extractKindData(dr)
		if len(data) == 0 {
			return fmt.Errorf("invalid rule:%s", dr)
		}
		normalized := strings.ToLower(matcher.NormalizeDomain(data))
		key := kind + "\x00" + normalized
		if kind == "regexp" {
			key = kind + "\x00" + data
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		switch kind {
		case "suffix":
			if _, ok := dns.IsDomainName(dns.Fqdn(normalized)); !ok {
				return fmt.Errorf("invalid suffix domain %q", data)
			}
			d.index.add(normalized)
		case "keyword":
			if len(data) > 253 {
				return fmt.Errorf("domain keyword is too long")
			}
			d.kw.add(strings.ToLower(data))
		case "full":
			if _, ok := dns.IsDomainName(dns.Fqdn(normalized)); !ok {
				return fmt.Errorf("invalid full domain %q", data)
			}
			d.index.addExact(normalized)
		case "regexp":
			regexCount++
			if regexCount > maxRegexRules {
				return fmt.Errorf("domain matcher has more than %d regular expressions", maxRegexRules)
			}
			if len(data) > maxRegexLength {
				return fmt.Errorf("domain regular expression exceeds %d bytes", maxRegexLength)
			}
			exp, err := regexp.Compile("(?i:" + data + ")")
			if err != nil {
				return err
			}
			d.reg = append(d.reg, exp)
		default:
			return fmt.Errorf("unknow domain rule kind:%s", kind)
		}
	}
	return nil
}

func newDomainMatcher(name string, drs []string) (matcher.IDNSMatcher, error) {
	d := &domainMatcher{
		name:  name,
		index: newDomainTrie(),
		kw:    newAhoMatcher(),
	}
	if err := d.init(drs); err != nil {
		return nil, err
	}
	d.index.freeze()
	d.kw.build()
	return d, nil
}

func createDomainMatcher(name string, args interface{}) (matcher.IDNSMatcher, error) {
	c := &config{}
	if err := strictdecode.Decode(args, c); err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(c.Domains))
	domains = append(domains, c.Domains...)
	fileDomains, err := loadDomainFiles(c.Files)
	if err != nil {
		return nil, err
	}
	domains = append(domains, fileDomains...)
	if len(domains) > maxDomainRules {
		return nil, fmt.Errorf("domain matcher has %d rules; maximum is %d", len(domains), maxDomainRules)
	}
	return newDomainMatcher(name, domains)
}

func init() {
	matcher.Register("domain", createDomainMatcher)
}

func loadDomainFiles(files []string) ([]string, error) {
	var domains []string
	for _, path := range files {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open domain file %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			domains = append(domains, line)
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("read domain file %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("close domain file %s: %w", path, err)
		}
	}
	return domains, nil
}
