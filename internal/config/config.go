package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xxxsen/common/logger"
	"gopkg.in/yaml.v3"
)

// Config is the root runtime configuration.
type Config struct {
	Bind     string           `json:"bind" yaml:"bind"`
	Resource Resource         `json:"resource" yaml:"resource"`
	Rule     []Rule           `json:"rule" yaml:"rule"`
	Log      logger.LogConfig `json:"log" yaml:"log"`
	Cache    CacheConfig      `json:"cache" yaml:"cache"`
	Pprof    PprofConfig      `json:"pprof" yaml:"pprof"`
}

type CacheConfig struct {
	Size     int64  `json:"size" yaml:"size"`
	Lazy     bool   `json:"lazy" yaml:"lazy"`
	Persist  bool   `json:"persist" yaml:"persist"`
	File     string `json:"file" yaml:"file"`
	Interval int64  `json:"interval" yaml:"interval"`
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
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
