// Package ipset loads immutable, named CIDR sets and compiles address policies.
package ipset

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"unicode"
)

type Config struct {
	Name  string   `json:"name" yaml:"name"`
	Files []string `json:"files" yaml:"files"`
}

type ValidationConfig struct {
	IPSets   []string `json:"ip_sets" yaml:"ip_sets"`
	Networks []string `json:"networks" yaml:"networks"`
}

type Registry struct {
	sets map[string]*prefixSet
}

// Validator accepts an address if any configured set or network contains it.
// It is immutable and safe to share between queries.
type Validator struct {
	sets []*prefixSet
}

type prefixSet struct {
	prefixes map[netip.Prefix]struct{}
	v4Bits   []int
	v6Bits   []int
}

var networks = map[string][]string{
	"private":    {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
	"loopback":   {"127.0.0.0/8", "::1/128"},
	"link_local": {"169.254.0.0/16", "fe80::/10"},
	"shared":     {"100.64.0.0/10"},
}

// Validate checks declarations without opening files. An empty set is valid.
func Validate(configs []Config) error {
	seen := make(map[string]bool, len(configs))
	for i, cfg := range configs {
		name := strings.TrimSpace(cfg.Name)
		if name == "" || strings.ContainsFunc(name, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.'
		}) {
			return fmt.Errorf("resource.ip_set[%d] has invalid name %q", i, cfg.Name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate IP set name %q", name)
		}
		seen[name] = true
		for j, file := range cfg.Files {
			if strings.TrimSpace(file) == "" {
				return fmt.Errorf("IP set %q files[%d] is empty", name, j)
			}
		}
	}
	return nil
}

func Load(configs []Config) (*Registry, error) {
	if err := Validate(configs); err != nil {
		return nil, err
	}
	r := &Registry{sets: make(map[string]*prefixSet, len(configs))}
	for _, cfg := range configs {
		name := strings.TrimSpace(cfg.Name)
		set := newPrefixSet()
		for _, path := range cfg.Files {
			if err := set.load(strings.TrimSpace(path)); err != nil {
				return nil, fmt.Errorf("IP set %q: %w", name, err)
			}
		}
		set.index()
		r.sets[name] = set
	}
	return r, nil
}

func (r *Registry) Compile(cfg ValidationConfig) (*Validator, error) {
	if len(cfg.IPSets)+len(cfg.Networks) == 0 {
		return nil, fmt.Errorf("validate requires at least one ip_sets or networks rule")
	}
	v := &Validator{}
	for _, rawName := range cfg.IPSets {
		name := strings.TrimSpace(rawName)
		if r == nil || r.sets[name] == nil {
			return nil, fmt.Errorf("validate references undefined IP set %q", name)
		}
		v.sets = append(v.sets, r.sets[name])
	}
	if len(cfg.Networks) > 0 {
		set := newPrefixSet()
		for _, rawName := range cfg.Networks {
			name := strings.TrimSpace(rawName)
			prefixes, ok := networks[name]
			if !ok {
				return nil, fmt.Errorf("validate references unknown network %q", name)
			}
			for _, prefix := range prefixes {
				set.prefixes[netip.MustParsePrefix(prefix)] = struct{}{}
			}
		}
		set.index()
		v.sets = append(v.sets, set)
	}
	return v, nil
}

func (v *Validator) Allows(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	for _, set := range v.sets {
		if set.contains(addr) {
			return true
		}
	}
	return false
}

func newPrefixSet() *prefixSet {
	return &prefixSet{prefixes: make(map[netip.Prefix]struct{})}
}

func (s *prefixSet) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4096)
	for line := 1; scanner.Scan(); line++ {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return fmt.Errorf("%s:%d: invalid CIDR %q: %w", path, line, text, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return fmt.Errorf("%s:%d: IPv4-mapped CIDR must be /96 or longer", path, line)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		s.prefixes[prefix.Masked()] = struct{}{}
		if len(s.prefixes) > 1_000_000 {
			return fmt.Errorf("%s:%d: IP set exceeds 1000000 unique CIDRs", path, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func (s *prefixSet) index() {
	var v4 [33]bool
	var v6 [129]bool
	for prefix := range s.prefixes {
		if prefix.Addr().Is4() {
			v4[prefix.Bits()] = true
		} else {
			v6[prefix.Bits()] = true
		}
	}
	for bits, exists := range v4 {
		if exists {
			s.v4Bits = append(s.v4Bits, bits)
		}
	}
	for bits, exists := range v6 {
		if exists {
			s.v6Bits = append(s.v6Bits, bits)
		}
	}
	slices.Reverse(s.v4Bits)
	slices.Reverse(s.v6Bits)
}

func (s *prefixSet) contains(addr netip.Addr) bool {
	lengths := s.v6Bits
	if addr.Is4() {
		lengths = s.v4Bits
	}
	// At most 33/129 hash lookups, independent of the number of CIDRs.
	for _, bits := range lengths {
		if _, ok := s.prefixes[netip.PrefixFrom(addr, bits).Masked()]; ok {
			return true
		}
	}
	return false
}
