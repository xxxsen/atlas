package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Config is the root runtime configuration.
type Config struct {
	Bind      string           `json:"bind"`
	Outbounds []OutboundConfig `json:"outbound"`
	Routes    []RouteConfig    `json:"route"`
	Cache     CacheConfig      `json:"cache"`
}

// OutboundConfig defines an outbound resolver group.
type OutboundConfig struct {
	Tag      string   `json:"tag"`
	Servers  []string `json:"server"`
	Parallel int      `json:"parallel"`
}

// RouteConfig defines a single routing rule.
type RouteConfig struct {
	Type        string   `json:"type"`
	DomainList  []string `json:"domain_list"`
	OutboundTag string   `json:"outbound_tag"`
	File        string   `json:"file"`
}

// CacheConfig controls response caching.
type CacheConfig struct {
	Size int  `json:"size"`
	Lazy bool `json:"lazy"`
}

// Load reads the configuration file from disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cleaned, err := stripJSONComments(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("strip comments: %w", err)
	}

	cfg := &Config{}
	if err := json.Unmarshal(cleaned, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if strings.TrimSpace(cfg.Bind) == "" {
		cfg.Bind = ":5353"
	}
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Parallel <= 0 {
			cfg.Outbounds[i].Parallel = 1
		}
		servers := cfg.Outbounds[i].Servers[:0]
		for _, srv := range cfg.Outbounds[i].Servers {
			srv = strings.TrimSpace(srv)
			if srv != "" {
				servers = append(servers, srv)
			}
		}
		cfg.Outbounds[i].Servers = servers
	}
	if cfg.Cache.Size <= 0 {
		cfg.Cache.Size = 1024
	}
}

func validate(cfg *Config) error {
	if len(cfg.Outbounds) == 0 {
		return errors.New("at least one outbound group required")
	}
	seenTags := make(map[string]struct{}, len(cfg.Outbounds))
	for _, outbound := range cfg.Outbounds {
		if outbound.Tag == "" {
			return errors.New("outbound tag must not be empty")
		}
		if _, exists := seenTags[outbound.Tag]; exists {
			return fmt.Errorf("duplicate outbound tag %q", outbound.Tag)
		}
		seenTags[outbound.Tag] = struct{}{}
		if len(outbound.Servers) == 0 {
			return fmt.Errorf("outbound %q must define at least one server", outbound.Tag)
		}
	}

	if len(cfg.Routes) == 0 {
		return errors.New("at least one route rule required")
	}
	for _, route := range cfg.Routes {
		switch strings.ToLower(route.Type) {
		case "domain":
			if len(route.DomainList) == 0 {
				return fmt.Errorf("route (type=domain) requires domain_list entries (outbound %q)", route.OutboundTag)
			}
			if route.OutboundTag == "" {
				return errors.New("domain route requires outbound_tag")
			}
			if _, ok := seenTags[route.OutboundTag]; !ok {
				return fmt.Errorf("domain route references unknown outbound_tag %q", route.OutboundTag)
			}
		case "host":
			if route.File == "" {
				return errors.New("host route requires file path")
			}
		default:
			return fmt.Errorf("unknown route type %q", route.Type)
		}
	}
	return nil
}

func stripJSONComments(r io.Reader) ([]byte, error) {
	all, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	inString := false
	escaped := false
	for i := 0; i < len(all); i++ {
		c := all[i]

		if inString {
			out.WriteByte(c)
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}

		switch c {
		case '"':
			inString = true
			out.WriteByte(c)
		case '/':
			if i+1 >= len(all) {
				out.WriteByte(c)
				continue
			}
			next := all[i+1]
			if next == '/' {
				i++
				for i < len(all) && all[i] != '\n' {
					i++
				}
				out.WriteByte('\n')
			} else if next == '*' {
				i += 2
				for i < len(all)-1 {
					if all[i] == '*' && all[i+1] == '/' {
						i++
						break
					}
					i++
				}
			} else {
				out.WriteByte(c)
			}
		default:
			out.WriteByte(c)
		}
	}

	return out.Bytes(), nil
}
