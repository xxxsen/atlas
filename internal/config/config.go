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

	"github.com/xxxsen/common/logger"
)

// Config is the root runtime configuration.
type Config struct {
	Bind          string               `json:"bind"`
	DataProviders []DataProviderConfig `json:"data_provider"`
	Outbounds     []OutboundConfig     `json:"outbound"`
	Routes        []RouteConfig        `json:"route"`
	Cache         CacheConfig          `json:"cache"`
	Log           logger.LogConfig     `json:"log"`
}

// OutboundConfig defines an outbound resolver group.
type OutboundConfig struct {
	Tag        string   `json:"tag"`
	ServerList []string `json:"server_list"`
	Parallel   int      `json:"parallel"`
}

// RouteConfig defines a single routing rule.
type RouteConfig struct {
	DataKeyList []string `json:"data_key_list"`
	OutboundTag string   `json:"outbound_tag"`
}

// CacheConfig controls response caching.
type CacheConfig struct {
	Size int  `json:"size"`
	Lazy bool `json:"lazy"`
}

// DataProviderConfig defines reusable data source configuration.
type DataProviderConfig struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
	File string `json:"file"`
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
	for i := range cfg.DataProviders {
		cfg.DataProviders[i].Key = strings.TrimSpace(cfg.DataProviders[i].Key)
		cfg.DataProviders[i].Kind = strings.ToLower(strings.TrimSpace(cfg.DataProviders[i].Kind))
		cfg.DataProviders[i].File = strings.TrimSpace(cfg.DataProviders[i].File)
	}
	for i := range cfg.Outbounds {
		if cfg.Outbounds[i].Parallel <= 0 {
			cfg.Outbounds[i].Parallel = 1
		}
		servers := cfg.Outbounds[i].ServerList[:0]
		for _, srv := range cfg.Outbounds[i].ServerList {
			srv = strings.TrimSpace(srv)
			if srv != "" {
				servers = append(servers, srv)
			}
		}
		cfg.Outbounds[i].ServerList = servers
	}
	if cfg.Cache.Size <= 0 {
		cfg.Cache.Size = 1024
	}
}

func validate(cfg *Config) error {
	providerKeys := make(map[string]string, len(cfg.DataProviders))
	for _, provider := range cfg.DataProviders {
		if provider.Key == "" {
			return errors.New("data provider key must not be empty")
		}
		if _, exists := providerKeys[provider.Key]; exists {
			return fmt.Errorf("duplicate data provider key %q", provider.Key)
		}
		if provider.Kind == "" {
			return fmt.Errorf("data provider %q must set kind", provider.Key)
		}
		switch provider.Kind {
		case "file", "host":
			if provider.File == "" {
				return fmt.Errorf("data provider %q (kind=%s) requires file path", provider.Key, provider.Kind)
			}
		default:
			return fmt.Errorf("unsupported data provider kind %q (key=%s)", provider.Kind, provider.Key)
		}
		providerKeys[provider.Key] = provider.Kind
	}

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
		if len(outbound.ServerList) == 0 {
			return fmt.Errorf("outbound %q must define at least one server", outbound.Tag)
		}
	}

	if len(cfg.Routes) == 0 {
		return errors.New("at least one route rule required")
	}
	for _, route := range cfg.Routes {
		if len(route.DataKeyList) == 0 {
			return fmt.Errorf("route requires at least one data_key (outbound=%q)", route.OutboundTag)
		}
		if strings.TrimSpace(route.OutboundTag) == "" {
			return errors.New("route requires outbound_tag")
		}
		if _, ok := seenTags[route.OutboundTag]; !ok {
			return fmt.Errorf("route references unknown outbound_tag %q", route.OutboundTag)
		}
		hasDomain := false
		hasHost := false
		for _, key := range route.DataKeyList {
			key = strings.TrimSpace(key)
			if key == "" {
				return errors.New("route contains empty data_key")
			}
			kind, ok := providerKeys[key]
			if !ok {
				return fmt.Errorf("route references unknown data_key %q", key)
			}
			switch kind {
			case "file":
				hasDomain = true
			case "host":
				hasHost = true
			default:
				return fmt.Errorf("route references unsupported provider kind %q (key=%s)", kind, key)
			}
		}
		if !hasDomain && !hasHost {
			return errors.New("route must reference at least one data provider")
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
