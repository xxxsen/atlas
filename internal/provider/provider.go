package provider

import (
	"bufio"
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

// ProviderData represents prepared data produced by a provider.
type ProviderData struct {
	Key         string
	Kind        string
	DomainRules []string
	HostRecords map[string][]net.IP
}

// IRouteDataProvider loads routing data from a configured source.
type IRouteDataProvider interface {
	Key() string
	Kind() string
	Provide() (*ProviderData, error)
}

// LoadProviders processes provider configuration into runtime datasets.
func LoadProviders(cfg []config.DataProviderConfig) (map[string]*ProviderData, error) {
	result := make(map[string]*ProviderData, len(cfg))
	for _, item := range cfg {
		provider, err := newProvider(item)
		if err != nil {
			return nil, err
		}
		if _, exists := result[provider.Key()]; exists {
			return nil, fmt.Errorf("duplicate data provider key %q", provider.Key())
		}
		data, err := provider.Provide()
		if err != nil {
			return nil, err
		}
		result[provider.Key()] = data
	}
	return result, nil
}

func newProvider(cfg config.DataProviderConfig) (IRouteDataProvider, error) {
	key := strings.TrimSpace(cfg.Key)
	kind := strings.ToLower(strings.TrimSpace(cfg.Kind))
	file := strings.TrimSpace(cfg.File)
	switch kind {
	case KindDomainFile:
		if file == "" {
			return nil, fmt.Errorf("data provider %q requires file path", key)
		}
		return &domainFileProvider{key: key, path: file}, nil
	case KindHost:
		if file == "" {
			return nil, fmt.Errorf("data provider %q requires file path", key)
		}
		return &hostFileProvider{key: key, path: file}, nil
	default:
		return nil, fmt.Errorf("unsupported data provider kind %q (key=%s)", cfg.Kind, cfg.Key)
	}
}

type domainFileProvider struct {
	key  string
	path string
}

func (p *domainFileProvider) Key() string  { return p.key }
func (p *domainFileProvider) Kind() string { return KindDomainFile }

func (p *domainFileProvider) Provide() (*ProviderData, error) {
	rules, err := loadDomainRulesFromFile(p.path)
	if err != nil {
		return nil, fmt.Errorf("load domain provider %q: %w", p.key, err)
	}
	return &ProviderData{
		Key:         p.key,
		Kind:        KindDomainFile,
		DomainRules: rules,
	}, nil
}

type hostFileProvider struct {
	key  string
	path string
}

func (p *hostFileProvider) Key() string  { return p.key }
func (p *hostFileProvider) Kind() string { return KindHost }

func (p *hostFileProvider) Provide() (*ProviderData, error) {
	records, err := loadHostFile(p.path)
	if err != nil {
		return nil, fmt.Errorf("load host provider %q: %w", p.key, err)
	}
	return &ProviderData{
		Key:         p.key,
		Kind:        KindHost,
		HostRecords: records,
	}, nil
}

func loadDomainRulesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open domain file: %w", err)
	}
	defer file.Close()

	var rules []string
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
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
