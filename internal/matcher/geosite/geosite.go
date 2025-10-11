package matcher

import (
	"fmt"
	"strings"

	geositeprovider "github.com/xxxsen/atlas/internal/data/geosite"
	mainmatcher "github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/common/utils"
)

func domainToRule(d geositeprovider.Domain) (string, bool) {
	switch d.Type {
	case geositeprovider.DomainTypePlain:
		return "keyword:" + d.Value, true
	case geositeprovider.DomainTypeRegex:
		return "regexp:" + d.Value, true
	case geositeprovider.DomainTypeDomain:
		return "suffix:" + d.Value, true
	case geositeprovider.DomainTypeFull:
		return "full:" + d.Value, true
	default:
		return "", false
	}
}

func matchesAttribute(attrs map[string]geositeprovider.Attribute, attr string, negate bool) bool {
	if attr == "" {
		return true
	}
	val, ok := attrs[attr]
	if !ok {
		return negate
	}
	if val.BoolValue != nil {
		has := *val.BoolValue
		if negate {
			return !has
		}
		return has
	}
	if val.IntValue != nil {
		has := *val.IntValue != 0
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

	specs := make([]listSpec, 0, len(cfg.Categories))
	uniqueNames := make(map[string]struct{})
	for _, rawSpec := range cfg.Categories {
		spec := parseListSpec(rawSpec)
		if spec.name == "" {
			continue
		}
		specs = append(specs, spec)
		uniqueNames[spec.name] = struct{}{}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("geosite matcher requires valid categories")
	}

	names := make([]string, 0, len(uniqueNames))
	for name := range uniqueNames {
		names = append(names, name)
	}

	categories, err := geositeprovider.GeositeProvider.LoadCategories(cfg.File, names)
	if err != nil {
		return nil, err
	}

	var domainRules []string
	seen := make(map[string]struct{})
	for _, spec := range specs {
		domains, ok := categories[spec.name]
		if !ok {
			return nil, fmt.Errorf("geosite category %s not found", spec.name)
		}
		for _, domain := range domains {
			if !matchesAttribute(domain.Attributes, spec.attr, spec.attrNegate) {
				continue
			}
			if rule, ok := domainToRule(domain); ok {
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
	dataMap := map[string]interface{}{
		"domains": domainRules,
	}
	return mainmatcher.MakeMatcher("domain", name, dataMap)
}

func init() {
	mainmatcher.Register("geosite", createGeositeMatcher)
}
