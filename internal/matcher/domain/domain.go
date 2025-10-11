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
	"github.com/xxxsen/common/utils"
)

type domainMatcher struct {
	name   string
	full   *domainTrie
	suffix *domainTrie
	kw     *ahoMatcher
	reg    []*regexp.Regexp
}

func (d *domainMatcher) Name() string {
	return d.name
}

func (d *domainMatcher) Type() string {
	return "domain"
}

func (d *domainMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	name := strings.ToLower(matcher.NormalizeDomain(req.Question[0].Name))
	if d.full.matchExact(name) {
		return true, nil
	}
	if d.suffix.matchSuffix(name) {
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
	for _, dr := range drs {
		if len(dr) == 0 {
			return fmt.Errorf("nil domain found")
		}
		kind, data := d.extractKindData(dr)
		if len(data) == 0 {
			return fmt.Errorf("invalid rule:%s", dr)
		}
		normalized := strings.ToLower(matcher.NormalizeDomain(data))
		switch kind {
		case "suffix":
			d.suffix.add(normalized)
		case "keyword":
			d.kw.add(strings.ToLower(data))
		case "full":
			d.full.add(normalized)
		case "regexp":
			exp, err := regexp.Compile(data)
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
		name:   name,
		full:   newDomainTrie(),
		suffix: newDomainTrie(),
		kw:     newAhoMatcher(),
	}
	if err := d.init(drs); err != nil {
		return nil, err
	}
	d.kw.build()
	return d, nil
}

func createDomainMatcher(name string, args interface{}) (matcher.IDNSMatcher, error) {
	c := &config{}
	if err := utils.ConvStructJson(args, c); err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(c.Domains))
	domains = append(domains, c.Domains...)
	fileDomains, err := loadDomainFiles(c.Files)
	if err != nil {
		return nil, err
	}
	domains = append(domains, fileDomains...)
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
