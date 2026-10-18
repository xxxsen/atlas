package bootstrap

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config binds a single global trust set and upstream pool to local domain files.
type Config struct {
	ServerList     []string `json:"server_list" yaml:"server_list"`
	Parallel       int      `json:"parallel" yaml:"parallel"`
	RequestTimeout int64    `json:"request_timeout" yaml:"request_timeout"`
	TTLMax         int64    `json:"ttl_max" yaml:"ttl_max"`
	ClockSkew      *int64   `json:"clock_skew" yaml:"clock_skew"`
	Files          []string `json:"files" yaml:"files"`
	PublicKeys     []string `json:"public_keys" yaml:"public_keys"`
}

func (c *Config) ApplyDefaults() {
	if c.Parallel == 0 {
		c.Parallel = min(3, len(c.ServerList))
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 3
	}
	if c.TTLMax == 0 {
		c.TTLMax = 300
	}
	if c.ClockSkew == nil {
		value := int64(30)
		c.ClockSkew = &value
	}
}

func (c Config) Validate() error {
	var errs []error
	for _, item := range []struct {
		name   string
		values []string
	}{{"server_list", c.ServerList}, {"files", c.Files}, {"public_keys", c.PublicKeys}} {
		if len(item.values) == 0 {
			errs = append(errs, fmt.Errorf("bootstrap.%s is required", item.name))
		}
		for _, value := range item.values {
			if strings.TrimSpace(value) == "" {
				errs = append(errs, fmt.Errorf("bootstrap.%s contains an empty value", item.name))
			}
		}
	}
	if c.Parallel < 1 || c.Parallel > len(c.ServerList) {
		errs = append(errs, fmt.Errorf("bootstrap.parallel must be between 1 and the number of upstreams"))
	}
	if c.RequestTimeout < 1 || c.RequestTimeout > 300 {
		errs = append(errs, fmt.Errorf("bootstrap.request_timeout must be between 1 and 300 seconds"))
	}
	if c.TTLMax < 1 || c.TTLMax > 1<<32-1 {
		errs = append(errs, fmt.Errorf("bootstrap.ttl_max must fit a positive DNS TTL"))
	}
	if c.ClockSkew == nil || *c.ClockSkew < 0 || *c.ClockSkew > 86400 {
		errs = append(errs, fmt.Errorf("bootstrap.clock_skew must be between 0 and 86400 seconds"))
	}
	return errors.Join(errs...)
}

func (c Config) skew() time.Duration {
	return time.Duration(*c.ClockSkew) * time.Second
}
