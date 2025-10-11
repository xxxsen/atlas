package geosite

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Provider loads and caches geosite datasets.
type Provider struct {
	cache sync.Map // map[string]*Data
}

// GeositeProvider is the global provider instance.
var GeositeProvider = NewProvider()

// NewProvider creates a new provider instance.
func NewProvider() *Provider {
	return &Provider{}
}

// Load parses the provided geosite file and returns the decoded dataset.
// Results are cached so subsequent calls with the same file avoid re-reading.
func (p *Provider) Load(path string) (*Data, error) {
	if p == nil {
		return nil, fmt.Errorf("geosite provider is nil")
	}
	cleanPath := filepath.Clean(path)
	if value, ok := p.cache.Load(cleanPath); ok {
		return value.(*Data), nil
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read geosite file %s: %w", cleanPath, err)
	}
	entries, err := parseGeoSiteList(data)
	if err != nil {
		return nil, fmt.Errorf("parse geosite file %s: %w", cleanPath, err)
	}
	dataset := newData(entries)
	actual, _ := p.cache.LoadOrStore(cleanPath, dataset)
	return actual.(*Data), nil
}
