package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/xxxsen/common/logger"
	"gopkg.in/yaml.v3"
)

// Config is the root runtime configuration.
type Config struct {
	Bind     string           `json:"bind" yaml:"bind"`
	Server   ServerConfig     `json:"server" yaml:"server"`
	Resource Resource         `json:"resource" yaml:"resource"`
	Rule     []Rule           `json:"rule" yaml:"rule"`
	Log      logger.LogConfig `json:"log" yaml:"log"`
	Cache    CacheConfig      `json:"cache" yaml:"cache"`
	Pprof    PprofConfig      `json:"pprof" yaml:"pprof"`
}

type CacheConfig struct {
	Size               int64  `json:"size" yaml:"size"`
	MaxBytes           int64  `json:"max_bytes" yaml:"max_bytes"`
	MaxEntryBytes      int64  `json:"max_entry_bytes" yaml:"max_entry_bytes"`
	Lazy               bool   `json:"lazy" yaml:"lazy"`
	MaxStale           int64  `json:"max_stale" yaml:"max_stale"`
	Persist            bool   `json:"persist" yaml:"persist"`
	File               string `json:"file" yaml:"file"`
	Interval           int64  `json:"interval" yaml:"interval"`
	RefreshConcurrency int    `json:"refresh_concurrency" yaml:"refresh_concurrency"`
	NegativeTTLMax     int64  `json:"negative_ttl_max" yaml:"negative_ttl_max"`
}

type ServerConfig struct {
	UDPSize            int      `json:"udp_size" yaml:"udp_size"`
	MaxResponseUDPSize int      `json:"max_response_udp_size" yaml:"max_response_udp_size"`
	MaxInflight        int      `json:"max_inflight" yaml:"max_inflight"`
	RequestTimeout     int64    `json:"request_timeout" yaml:"request_timeout"`
	RateLimitQPS       float64  `json:"rate_limit_qps" yaml:"rate_limit_qps"`
	RateLimitBurst     int      `json:"rate_limit_burst" yaml:"rate_limit_burst"`
	RateLimitClients   int      `json:"rate_limit_clients" yaml:"rate_limit_clients"`
	AllowedCIDRs       []string `json:"allowed_cidrs" yaml:"allowed_cidrs"`
}

type MatcherConfig struct {
	Name string      `json:"name" yaml:"name"`
	Type string      `json:"type" yaml:"type"`
	Data interface{} `json:"data" yaml:"data"`
}

type ActionConfig struct {
	Name string      `json:"name" yaml:"name"`
	Type string      `json:"type" yaml:"type"`
	Data interface{} `json:"data" yaml:"data"`
}

type PprofConfig struct {
	Enable bool   `json:"enable" yaml:"enable"`
	Bind   string `json:"bind" yaml:"bind"`
}

type Rule struct {
	Remark string `json:"remark" yaml:"remark"`
	Match  string `json:"match" yaml:"match"`
	Action string `json:"action" yaml:"action"`
}

type HostConfig struct {
	Records map[string]string `json:"records" yaml:"records"`
	Files   []string          `json:"files" yaml:"files"`
}

type Resource struct {
	Host    HostConfig      `json:"host" yaml:"host"`
	Matcher []MatcherConfig `json:"matcher" yaml:"matcher"`
	Action  []ActionConfig  `json:"action" yaml:"action"`
}

// Load reads the configuration file from disk.
func Load(path string) (*Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer file.Close()
	cfg := &Config{}
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse config: multiple YAML documents are not supported")
		}
		return nil, fmt.Errorf("parse config trailing document: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	c.Bind = strings.TrimSpace(c.Bind)
	if strings.TrimSpace(c.Bind) == "" {
		c.Bind = "127.0.0.1:5353"
	}
	if c.Server.UDPSize == 0 {
		c.Server.UDPSize = 4096
	}
	if c.Server.MaxResponseUDPSize == 0 {
		c.Server.MaxResponseUDPSize = 1232
	}
	if c.Server.MaxInflight == 0 {
		c.Server.MaxInflight = 256
	}
	if c.Server.RequestTimeout == 0 {
		c.Server.RequestTimeout = 10
	}
	if c.Server.RateLimitClients == 0 {
		c.Server.RateLimitClients = 4096
	}
	if c.Cache.Size > 0 {
		if c.Cache.MaxBytes == 0 {
			c.Cache.MaxBytes = defaultCacheBytes(c.Cache.Size)
		}
		if c.Cache.MaxEntryBytes == 0 {
			c.Cache.MaxEntryBytes = 64*1024 - 1
		}
		if c.Cache.Lazy && c.Cache.MaxStale == 0 {
			c.Cache.MaxStale = 5 * 60
		}
		if c.Cache.Persist && c.Cache.Interval == 0 {
			c.Cache.Interval = 10 * 60
		}
		if c.Cache.RefreshConcurrency == 0 {
			c.Cache.RefreshConcurrency = 4
		}
		if c.Cache.NegativeTTLMax == 0 {
			c.Cache.NegativeTTLMax = 60 * 60
		}
	}
	if c.Pprof.Enable && strings.TrimSpace(c.Pprof.Bind) == "" {
		c.Pprof.Bind = "127.0.0.1:6060"
	}
	c.Pprof.Bind = strings.TrimSpace(c.Pprof.Bind)
	c.Cache.File = strings.TrimSpace(c.Cache.File)
	for i := range c.Resource.Matcher {
		c.Resource.Matcher[i].Name = strings.TrimSpace(c.Resource.Matcher[i].Name)
		c.Resource.Matcher[i].Type = strings.ToLower(strings.TrimSpace(c.Resource.Matcher[i].Type))
	}
	for i := range c.Resource.Action {
		c.Resource.Action[i].Name = strings.TrimSpace(c.Resource.Action[i].Name)
		c.Resource.Action[i].Type = strings.ToLower(strings.TrimSpace(c.Resource.Action[i].Type))
	}
	for i := range c.Rule {
		c.Rule[i].Remark = strings.TrimSpace(c.Rule[i].Remark)
		c.Rule[i].Match = strings.TrimSpace(c.Rule[i].Match)
		c.Rule[i].Action = strings.TrimSpace(c.Rule[i].Action)
	}
}

func defaultCacheBytes(entries int64) int64 {
	const (
		bytesPerEntry = int64(4096)
		maxDefault    = int64(512 * 1024 * 1024)
	)
	if entries > maxDefault/bytesPerEntry {
		return maxDefault
	}
	return entries * bytesPerEntry
}

func (c *Config) Validate() error {
	var errs []error
	if err := validateAddress("bind", c.Bind); err != nil {
		errs = append(errs, err)
	}
	if c.Server.UDPSize < 512 || c.Server.UDPSize > 64*1024 {
		errs = append(errs, fmt.Errorf("server.udp_size must be between 512 and 65536"))
	}
	if c.Server.MaxResponseUDPSize < 512 || c.Server.MaxResponseUDPSize > c.Server.UDPSize {
		errs = append(errs, fmt.Errorf("server.max_response_udp_size must be between 512 and server.udp_size"))
	}
	if c.Server.MaxInflight < 1 || c.Server.MaxInflight > 1_000_000 {
		errs = append(errs, fmt.Errorf("server.max_inflight must be between 1 and 1000000"))
	}
	if c.Server.RequestTimeout < 1 || c.Server.RequestTimeout > 300 {
		errs = append(errs, fmt.Errorf("server.request_timeout must be between 1 and 300 seconds"))
	}
	if math.IsNaN(c.Server.RateLimitQPS) || math.IsInf(c.Server.RateLimitQPS, 0) || c.Server.RateLimitQPS < 0 || c.Server.RateLimitQPS > 1_000_000_000 {
		errs = append(errs, fmt.Errorf("server.rate_limit_qps must be finite and between 0 and 1000000000"))
	}
	if c.Server.RateLimitQPS > 0 && c.Server.RateLimitBurst < 1 {
		errs = append(errs, fmt.Errorf("server.rate_limit_burst must be positive when rate limiting is enabled"))
	}
	if c.Server.RateLimitQPS == 0 && c.Server.RateLimitBurst != 0 {
		errs = append(errs, fmt.Errorf("server.rate_limit_burst requires server.rate_limit_qps > 0"))
	}
	if c.Server.RateLimitClients < 1 || c.Server.RateLimitClients > 1_000_000 {
		errs = append(errs, fmt.Errorf("server.rate_limit_clients must be between 1 and 1000000"))
	}
	if len(c.Server.AllowedCIDRs) > 256 {
		errs = append(errs, fmt.Errorf("server.allowed_cidrs cannot contain more than 256 entries"))
	}
	for index, rawPrefix := range c.Server.AllowedCIDRs {
		prefix := strings.TrimSpace(rawPrefix)
		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			errs = append(errs, fmt.Errorf("server.allowed_cidrs[%d] is invalid: %q", index, rawPrefix))
		} else if parsed.Addr().Is4In6() && parsed.Bits() < 96 {
			errs = append(errs, fmt.Errorf("server.allowed_cidrs[%d] IPv4-mapped prefix must be /96 or longer: %q", index, rawPrefix))
		} else {
			c.Server.AllowedCIDRs[index] = prefix
		}
	}
	if c.Cache.Size < 0 || c.Cache.Size > 1_000_000 {
		errs = append(errs, fmt.Errorf("cache.size must be between 0 and 1000000; zero disables cache"))
	}
	if c.Cache.Size == 0 {
		if c.Cache.Persist || c.Cache.Lazy || c.Cache.File != "" || c.Cache.MaxBytes != 0 || c.Cache.MaxEntryBytes != 0 || c.Cache.MaxStale != 0 || c.Cache.Interval != 0 || c.Cache.RefreshConcurrency != 0 || c.Cache.NegativeTTLMax != 0 {
			errs = append(errs, fmt.Errorf("cache options require cache.size > 0"))
		}
	} else {
		if c.Cache.MaxBytes < 1 || c.Cache.MaxBytes > 16*1024*1024*1024 {
			errs = append(errs, fmt.Errorf("cache.max_bytes must be between 1 and 16 GiB"))
		}
		if c.Cache.MaxEntryBytes < 1 || c.Cache.MaxEntryBytes > 65535 || c.Cache.MaxEntryBytes > c.Cache.MaxBytes {
			errs = append(errs, fmt.Errorf("cache.max_entry_bytes must be between 1 and 65535 and no larger than cache.max_bytes"))
		}
		if c.Cache.MaxStale < 0 || c.Cache.MaxStale > 7*24*60*60 {
			errs = append(errs, fmt.Errorf("cache.max_stale must be between 0 and 7 days"))
		}
		if !c.Cache.Lazy && c.Cache.MaxStale != 0 {
			errs = append(errs, fmt.Errorf("cache.max_stale requires cache.lazy=true"))
		}
		if c.Cache.RefreshConcurrency < 1 || c.Cache.RefreshConcurrency > 1024 {
			errs = append(errs, fmt.Errorf("cache.refresh_concurrency must be between 1 and 1024"))
		}
		if c.Cache.NegativeTTLMax < 1 || c.Cache.NegativeTTLMax > 7*24*60*60 {
			errs = append(errs, fmt.Errorf("cache.negative_ttl_max must be between 1 second and 7 days"))
		}
		if c.Cache.Persist {
			if strings.TrimSpace(c.Cache.File) == "" {
				errs = append(errs, fmt.Errorf("cache.file is required when persistence is enabled"))
			}
			if c.Cache.Interval < 1 || c.Cache.Interval > 24*60*60 {
				errs = append(errs, fmt.Errorf("cache.interval must be between 1 and 86400 seconds"))
			}
		} else if c.Cache.File != "" || c.Cache.Interval != 0 {
			errs = append(errs, fmt.Errorf("cache.file and cache.interval require cache.persist=true"))
		}
	}
	if c.Pprof.Enable {
		if err := validateAddress("pprof.bind", c.Pprof.Bind); err != nil {
			errs = append(errs, err)
		}
		if c.Pprof.Bind == c.Bind {
			errs = append(errs, fmt.Errorf("pprof.bind cannot equal the DNS bind address"))
		}
	}

	matcherNames := make(map[string]struct{}, len(c.Resource.Matcher))
	for i, item := range c.Resource.Matcher {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			errs = append(errs, fmt.Errorf("resource.matcher[%d].name is required", i))
		} else if name == "any" {
			errs = append(errs, fmt.Errorf("resource.matcher[%d].name %q is reserved", i, name))
		} else if _, exists := matcherNames[name]; exists {
			errs = append(errs, fmt.Errorf("duplicate matcher name %q", name))
		}
		if name != "" && !validComponentName(name) {
			errs = append(errs, fmt.Errorf("resource.matcher[%d].name %q contains unsupported characters", i, name))
		}
		matcherNames[name] = struct{}{}
		if strings.TrimSpace(item.Type) == "" {
			errs = append(errs, fmt.Errorf("resource.matcher[%d].type is required", i))
		}
	}
	actionNames := make(map[string]struct{}, len(c.Resource.Action))
	for i, item := range c.Resource.Action {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			errs = append(errs, fmt.Errorf("resource.action[%d].name is required", i))
		} else if _, exists := actionNames[name]; exists {
			errs = append(errs, fmt.Errorf("duplicate action name %q", name))
		}
		if name != "" && !validComponentName(name) {
			errs = append(errs, fmt.Errorf("resource.action[%d].name %q contains unsupported characters", i, name))
		}
		actionNames[name] = struct{}{}
		if strings.TrimSpace(item.Type) == "" {
			errs = append(errs, fmt.Errorf("resource.action[%d].type is required", i))
		}
	}
	if len(c.Rule) == 0 {
		errs = append(errs, fmt.Errorf("at least one rule is required"))
	}
	for i, item := range c.Rule {
		if strings.TrimSpace(item.Action) == "" {
			errs = append(errs, fmt.Errorf("rule[%d].action is required", i))
		} else if _, exists := actionNames[item.Action]; !exists {
			errs = append(errs, fmt.Errorf("rule[%d].action %q is not defined", i, item.Action))
		}
		unconditional := item.Match == "" || strings.EqualFold(item.Match, "any")
		if unconditional && i != len(c.Rule)-1 {
			errs = append(errs, fmt.Errorf("rule[%d] is unconditional and makes later rules unreachable", i))
		}
		if i == len(c.Rule)-1 && !unconditional {
			errs = append(errs, fmt.Errorf("the final rule must use match: any as an explicit fallback"))
		}
	}
	return errorsJoin(errs)
}

func validateAddress(field, address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return fmt.Errorf("%s is required", field)
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("%s must be a host:port address: %q", field, address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("%s must use a port between 1 and 65535: %q", field, address)
	}
	return nil
}

func validComponentName(name string) bool {
	for _, value := range name {
		if unicode.IsLetter(value) || unicode.IsDigit(value) || value == '-' || value == '_' || value == '.' {
			continue
		}
		return false
	}
	return name != ""
}

func errorsJoin(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var message strings.Builder
	message.WriteString("invalid configuration")
	for _, err := range errs {
		message.WriteString("; ")
		message.WriteString(err.Error())
	}
	return fmt.Errorf("%s", message.String())
}

func (c *Config) Fingerprint() (string, error) {
	data, err := json.Marshal(struct {
		Resource Resource    `json:"resource"`
		Rule     []Rule      `json:"rule"`
		Cache    CacheConfig `json:"cache"`
	}{Resource: c.Resource, Rule: c.Rule, Cache: c.Cache})
	if err != nil {
		return "", fmt.Errorf("encode configuration fingerprint: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
