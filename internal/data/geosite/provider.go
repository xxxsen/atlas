package geosite

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Provider loads and caches geosite datasets.
type Provider struct {
	cache sync.Map // map[string]*fileCache
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
	cache, err := p.getFileCache(path)
	if err != nil {
		return nil, err
	}
	return cache.loadAll()
}

// LoadCategories loads only the specified categories from the geosite file.
func (p *Provider) LoadCategories(path string, categories []string) (map[string][]Domain, error) {
	if p == nil {
		return nil, fmt.Errorf("geosite provider is nil")
	}
	cache, err := p.getFileCache(path)
	if err != nil {
		return nil, err
	}
	return cache.loadCategories(categories)
}

type fileCache struct {
	mu         sync.Mutex
	raw        []byte
	all        *Data
	categories map[string][]Domain
}

func (p *Provider) getFileCache(path string) (*fileCache, error) {
	cleanPath := filepath.Clean(path)
	if value, ok := p.cache.Load(cleanPath); ok {
		return value.(*fileCache), nil
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read geosite file %s: %w", cleanPath, err)
	}
	cache := &fileCache{raw: data, categories: make(map[string][]Domain)}
	actual, _ := p.cache.LoadOrStore(cleanPath, cache)
	if actual != cache {
		return actual.(*fileCache), nil
	}
	return cache, nil
}

func (f *fileCache) loadAll() (*Data, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.all != nil {
		return f.all, nil
	}
	entries, err := parseGeoSiteList(f.raw, nil)
	if err != nil {
		return nil, err
	}
	if f.categories == nil {
		f.categories = make(map[string][]Domain, len(entries))
	}
	for k, v := range entries {
		f.categories[k] = v
	}
	f.all = newData(entries)
	return f.all, nil
}

func (f *fileCache) loadCategories(categories []string) (map[string][]Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(categories) == 0 {
		return map[string][]Domain{}, nil
	}
	if f.categories == nil {
		f.categories = make(map[string][]Domain)
	}
	result := make(map[string][]Domain, len(categories))
	missingSet := make(map[string]struct{})
	for _, raw := range categories {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if domains, ok := f.categories[name]; ok {
			result[name] = domains
			continue
		}
		missingSet[name] = struct{}{}
	}
	if len(missingSet) > 0 {
		entries, err := parseGeoSiteList(f.raw, missingSet)
		if err != nil {
			return nil, err
		}
		for name, domains := range entries {
			f.categories[name] = domains
			result[name] = domains
			delete(missingSet, name)
		}
	}
	return result, nil
}
