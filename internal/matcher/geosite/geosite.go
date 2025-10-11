package matcher

import (
	"fmt"
	"os"
	"strings"
	"sync"

	mainmatcher "github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/common/utils"
)

const (
	geoDomainTypePlain  = 0
	geoDomainTypeRegex  = 1
	geoDomainTypeDomain = 2
	geoDomainTypeFull   = 3
)

type geoDomain struct {
	value      string
	typ        int
	attributes map[string]domainAttribute
}

type domainAttribute struct {
	boolValue *bool
	intValue  *int64
}

func (d geoDomain) toRule() (string, bool) {
	switch d.typ {
	case geoDomainTypePlain:
		return "keyword:" + d.value, true
	case geoDomainTypeRegex:
		return "regexp:" + d.value, true
	case geoDomainTypeDomain:
		return "suffix:" + d.value, true
	case geoDomainTypeFull:
		return "full:" + d.value, true
	default:
		return "", false
	}
}

func (d geoDomain) matchesAttribute(attr string, negate bool) bool {
	if attr == "" {
		return true
	}
	val, ok := d.attributes[attr]
	if !ok {
		return negate
	}
	if val.boolValue != nil {
		has := *val.boolValue
		if negate {
			return !has
		}
		return has
	}
	if val.intValue != nil {
		has := *val.intValue != 0
		if negate {
			return !has
		}
		return has
	}
	return negate
}

type listSpec struct {
	name       string
	attr       string
	attrNegate bool
}

func parseListSpec(spec string) listSpec {
	parts := strings.SplitN(spec, "@", 2)
	name := strings.TrimSpace(parts[0])
	attr := ""
	negate := false
	if len(parts) == 2 {
		attr = strings.TrimSpace(parts[1])
		if strings.HasPrefix(attr, "!") {
			attr = strings.TrimSpace(attr[1:])
			negate = true
		}
	}
	return listSpec{
		name:       strings.ToLower(name),
		attr:       strings.ToLower(attr),
		attrNegate: negate,
	}
}

var geositeCache sync.Map // map[string]map[string][]geoDomain

func loadGeositeFile(path string) (map[string][]geoDomain, error) {
	if cached, ok := geositeCache.Load(path); ok {
		return cached.(map[string][]geoDomain), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read geosite file %s: %w", path, err)
	}
	parsed, err := parseGeoSiteList(data)
	if err != nil {
		return nil, fmt.Errorf("parse geosite file %s: %w", path, err)
	}
	geositeCache.Store(path, parsed)
	return parsed, nil
}

func createGeositeMatcher(name string, args interface{}) (mainmatcher.IDNSMatcher, error) {
	cfg := &config{}
	if err := utils.ConvStructJson(args, cfg); err != nil {
		return nil, err
	}
	if cfg.File == "" {
		return nil, fmt.Errorf("geosite matcher requires file")
	}
	if len(cfg.Categories) == 0 {
		return nil, fmt.Errorf("geosite matcher requires categories")
	}
	entries, err := loadGeositeFile(cfg.File)
	if err != nil {
		return nil, err
	}
	var domainRules []string
	seen := make(map[string]struct{})
	for _, rawSpec := range cfg.Categories {
		spec := parseListSpec(rawSpec)
		if spec.name == "" {
			continue
		}
		domains, ok := entries[spec.name]
		if !ok {
			return nil, fmt.Errorf("geosite list %s not found", spec.name)
		}
		for _, domain := range domains {
			if !domain.matchesAttribute(spec.attr, spec.attrNegate) {
				continue
			}
			if rule, ok := domain.toRule(); ok {
				if _, exists := seen[rule]; exists {
					continue
				}
				seen[rule] = struct{}{}
				domainRules = append(domainRules, rule)
			}
		}
	}
	if len(domainRules) == 0 {
		return nil, fmt.Errorf("geosite matcher produced no domains")
	}
	data := map[string]interface{}{
		"domains": domainRules,
	}
	return mainmatcher.MakeMatcher("domain", name, data)
}

func init() {
	mainmatcher.Register("geosite", createGeositeMatcher)
}
