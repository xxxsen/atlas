package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xxxsen/common/logger"
)

// Config is the root runtime configuration.
type Config struct {
	Bind     string           `json:"bind"`
	Resource Resource         `json:"resource"`
	Rules    []Rule           `json:"rules"`
	Log      logger.LogConfig `json:"log"`
	Cache    CacheConfig      `json:"cache"`
}

type CacheConfig struct {
	Size    int64  `json:"size"`
	Lazy    bool   `json:"lazy"`
	Persist bool   `json:"persist"`
	File    string `json:"file"`
}

type MatcherConfig struct {
	Name string      `json:"name"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type ActionConfig struct {
	Name string      `json:"name"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type Rule struct {
	Remark string `json:"remark"`
	Match  string `json:"match"`
	Action string `json:"action"`
}

type Resource struct {
	Matcher []MatcherConfig `json:"matcher"`
	Action  []ActionConfig  `json:"action"`
}

// Load reads the configuration file from disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
