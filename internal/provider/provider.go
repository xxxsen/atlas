package provider

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"atlas/internal/config"
)

const (
	KindDomainFile = "file"
	KindHost       = "host"
)

// ProviderData represents prepared domain data.
type ProviderData struct {
	Key         string
	DomainRules []string
}

// LoadProviders processes domain provider configuration into runtime datasets.
func LoadProviders(cfg []config.DataProviderConfig) (map[string]*ProviderData, error) {
	result := make(map[string]*ProviderData, len(cfg))
	for _, item := range cfg {
		key := strings.TrimSpace(item.Key)
		if key == "" {
			return nil, errors.New("data provider key must not be empty")
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate data provider key %q", key)
		}
		rules, err := loadDomainRulesFromFile(strings.TrimSpace(item.File))
		if err != nil {
			return nil, fmt.Errorf("load data provider %q: %w", key, err)
		}
		result[key] = &ProviderData{Key: key, DomainRules: rules}
	}
	return result, nil
}

// BuildChunks converts provider data into normalized routing inputs.
func BuildChunks(providers []*ProviderData) ([]string, error) {
	domainRules := make([]string, 0, len(providers))
	for _, provider := range providers {
		domainRules = append(domainRules, provider.DomainRules...)
	}
	return domainRules, nil
}

// LoadHostProviders loads host mapping datasets.
func LoadHostProviders(cfg []config.HostProviderConfig) (map[string]map[string][]net.IP, error) {
	result := make(map[string]map[string][]net.IP, len(cfg))
	for _, item := range cfg {
		key := strings.TrimSpace(item.Key)
		if key == "" {
			return nil, errors.New("host provider key must not be empty")
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate host provider key %q", key)
		}
		data, err := loadHostFile(strings.TrimSpace(item.File))
		if err != nil {
			return nil, fmt.Errorf("load host provider %q: %w", key, err)
		}
		result[key] = data
	}
	return result, nil
}

func loadDomainRulesFromFile(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("domain provider file is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open domain file: %w", err)
	}
	defer file.Close()

	rules := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		rules = append(rules, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read domain file %s: %w", path, err)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("domain file %s produced no rules", path)
	}
	return rules, nil
}

func loadHostFile(path string) (map[string][]net.IP, error) {
	if path == "" {
		return nil, errors.New("host provider file is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open host file: %w", err)
	}
	defer file.Close()

	result := make(map[string][]net.IP)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		domain, ips := parseHostLine(line)
		if domain == "" || len(ips) == 0 {
			continue
		}
		result[domain] = append(result[domain], ips...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read host file %s: %w", path, err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("host file %s produced no records", path)
	}
	return result, nil
}

func parseHostLine(line string) (string, []net.IP) {
	parts := strings.SplitN(line, "#", 2)
	if len(parts) != 2 {
		return "", nil
	}
	domain := normalizeDomain(strings.TrimSpace(parts[0]))
	if domain == "" {
		return "", nil
	}
	rawList := strings.TrimSpace(parts[1])
	rawList = strings.TrimPrefix(rawList, "[")
	rawList = strings.TrimSuffix(rawList, "]")
	if rawList == "" {
		return "", nil
	}
	chunks := strings.Split(rawList, ",")
	ips := make([]net.IP, 0, len(chunks))
	for _, chunk := range chunks {
		ip := net.ParseIP(strings.TrimSpace(chunk))
		if ip == nil {
			continue
		}
		ips = append(ips, ip)
	}
	return domain, ips
}

func normalizeDomain(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	return strings.ToLower(name)
}
