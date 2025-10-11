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
	full   map[string]struct{}
	suffix []string
	kw     []string
	reg    []*regexp.Regexp
}

func (d *domainMatcher) Name() string {
	return d.name
}

func (d *domainMatcher) Type() string {
	return "domain"
}

func (d *domainMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	name := matcher.NormalizeDomain(req.Question[0].Name)
	if _, ok := d.full[name]; ok {
		return true, nil
	}
	for _, suffix := range d.suffix {
		if strings.HasSuffix(name, suffix) {
			return true, nil
		}
	}
	for _, kw := range d.kw {
		if strings.Contains(name, kw) {
			return true, nil
		}
	}
	for _, reg := range d.reg {
		if reg.MatchString(name) {
			return true, nil
		}
	}
	return false, nil
}

func (d *domainMatcher) init(drs []string) error {
	for _, dr := range drs {
		if len(dr) == 0 {
			return fmt.Errorf("nil domain found")
		}
		items := strings.Split(dr, ":")
		if len(items) != 2 {
			return fmt.Errorf("invalid domain config")
		}
		kind := items[0]
		data := items[1]
		switch kind {
		case "suffix":
			d.suffix = append(d.suffix, data)
		case "keyword":
			d.kw = append(d.kw, data)
		case "full":
			d.full[data] = struct{}{}
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
		name: name,
		full: map[string]struct{}{},
	}
	if err := d.init(drs); err != nil {
		return nil, err
	}
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
