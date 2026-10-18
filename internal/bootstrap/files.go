package bootstrap

import (
	"bufio"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func normalizeDomain(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" || len(name) > 253 || strings.ContainsAny(name, ":/\\*") {
		return "", fmt.Errorf("invalid bootstrap domain %q", raw)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid bootstrap domain %q", raw)
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return "", fmt.Errorf("bootstrap domains must use ASCII DNS labels: %q", raw)
			}
		}
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(name)); !ok {
		return "", fmt.Errorf("invalid bootstrap domain %q", raw)
	}
	return name, nil
}

// LoadDomains reads domain[:TXT-name] lines. Only exact domain names are bound.
func LoadDomains(files []string) (map[string]string, error) {
	domains := make(map[string]string)
	for _, path := range files {
		if err := loadDomainFile(path, domains); err != nil {
			return nil, err
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("bootstrap files contain no domains")
	}
	return domains, nil
}

func loadDomainFile(path string, domains map[string]string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open bootstrap file %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4096)
	for line := 1; scanner.Scan(); line++ {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		domain, txt, _ := strings.Cut(text, ":")
		domain, err = normalizeDomain(domain)
		if err == nil && strings.TrimSpace(txt) == "" {
			txt = "_atlas." + domain
		}
		if err == nil {
			txt, err = normalizeDomain(txt)
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if old, ok := domains[domain]; ok && old != txt {
			return fmt.Errorf("%s:%d: conflicting TXT names for bootstrap domain %s", path, line, domain)
		}
		domains[domain] = txt
		if len(domains) > 100_000 {
			return fmt.Errorf("%s:%d: too many bootstrap domains", path, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read bootstrap file %s: %w", path, err)
	}
	return nil
}

// ReadPublicKey loads one Ed25519 SubjectPublicKeyInfo PEM file.
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s: expected one PUBLIC KEY PEM block", path)
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parse public key: %w", path, err)
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: public key must be Ed25519", path)
	}
	return key, nil
}

// ReadPrivateKey loads one unencrypted Ed25519 PKCS#8 PEM file.
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s: expected one PRIVATE KEY PEM block", path)
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parse private key: %w", path, err)
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: private key must be Ed25519", path)
	}
	return key, nil
}

func loadPublicKeys(files []string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)
	for _, path := range files {
		key, err := ReadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("load bootstrap public key: %w", err)
		}
		keys[KeyID(key)] = key
	}
	return keys, nil
}
