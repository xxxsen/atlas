package geosite

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxGeositeFileBytes = 256 * 1024 * 1024

// Provider loads geosite datasets from disk.
type Provider struct{}

// GeositeProvider is the global provider instance.
var GeositeProvider = NewProvider()

// NewProvider creates a new provider instance.
func NewProvider() *Provider {
	return &Provider{}
}

// Load parses the provided geosite file and returns the decoded dataset.
func (p *Provider) Load(path string) (*Data, error) {
	if p == nil {
		return nil, fmt.Errorf("geosite provider is nil")
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	entries, err := parseGeoSiteList(data, nil)
	if err != nil {
		return nil, err
	}
	return newData(entries), nil
}

// LoadCategories loads only the specified categories from the geosite file.
func (p *Provider) LoadCategories(path string, categories []string) (map[string][]Domain, error) {
	if p == nil {
		return nil, fmt.Errorf("geosite provider is nil")
	}
	filter := buildCategoryFilter(categories)
	if len(filter) == 0 {
		return map[string][]Domain{}, nil
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parseGeoSiteList(data, filter)
}

func readFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("read geosite file %s: %w", cleanPath, err)
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil {
		return nil, fmt.Errorf("stat geosite file %s: %w", cleanPath, err)
	} else if info.Size() > maxGeositeFileBytes {
		return nil, fmt.Errorf("geosite file %s exceeds %d bytes", cleanPath, maxGeositeFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxGeositeFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read geosite file %s: %w", cleanPath, err)
	}
	if len(data) > maxGeositeFileBytes {
		return nil, fmt.Errorf("geosite file %s exceeds %d bytes", cleanPath, maxGeositeFileBytes)
	}
	return data, nil
}

func buildCategoryFilter(categories []string) map[string]struct{} {
	filter := make(map[string]struct{}, len(categories))
	for _, raw := range categories {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		filter[name] = struct{}{}
	}
	return filter
}
