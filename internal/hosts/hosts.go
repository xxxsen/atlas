package hosts

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

// DefaultTTL is the TTL applied to host records.
const defaultHostTTL = 5

type IHostResolver interface {
	Resolve(q dns.Question) ([]dns.RR, bool)
}

type record struct {
	ipv4 []net.IP
	ipv6 []net.IP
}

// Store holds static host records.
type hostStore struct {
	records map[string]*record
}

// NewStore builds a Store from config.
func New(records ...map[string]string) (IHostResolver, error) {
	m := make(map[string]*record, 32)
	st := &hostStore{records: m}
	for _, rec := range records {
		if err := st.mergeRecords(rec, m); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func (s *hostStore) mergeRecords(m map[string]string, out map[string]*record) error {
	for domain, list := range m {
		var err error
		domain, err = validDomain(domain)
		if err != nil {
			return fmt.Errorf("hosts: %w in records", err)
		}
		res, ok := out[domain]
		if !ok {
			res = &record{}
			out[domain] = res
		}
		for token := range strings.SplitSeq(list, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				return fmt.Errorf("hosts: empty IP for domain %s", domain)
			}
			ip := net.ParseIP(token)
			if ip == nil {
				return fmt.Errorf("hosts: invalid IP %q for domain %s", token, domain)
			}
			if ip4 := ip.To4(); ip4 != nil {
				res.ipv4 = appendUniqueIP(res.ipv4, ip4)
				continue
			}
			if ip6 := ip.To16(); ip6 != nil {
				res.ipv6 = appendUniqueIP(res.ipv6, ip6)
				continue
			}
			return fmt.Errorf("hosts: invalid IP %q for domain %s", token, domain)
		}
	}
	return nil
}

// Resolve returns DNS answers for a given question.
func (s *hostStore) Resolve(q dns.Question) ([]dns.RR, bool) {
	if q.Qclass != dns.ClassINET {
		return nil, false
	}
	domain := normalize(q.Name)
	if domain == "" {
		return nil, false
	}
	entry, ok := s.records[domain]
	if !ok {
		return nil, false
	}
	var answers []dns.RR
	switch q.Qtype {
	case dns.TypeA:
		answers = s.appendIPv4(nil, q, entry.ipv4)
	case dns.TypeAAAA:
		answers = s.appendIPv6(nil, q, entry.ipv6)
	case dns.TypeANY:
		answers = s.appendIPv4(nil, q, entry.ipv4)
		answers = s.appendIPv6(answers, q, entry.ipv6)
	default:
		return nil, false
	}
	if len(answers) == 0 {
		return nil, false
	}
	return answers, true
}

func (s *hostStore) appendIPv4(dst []dns.RR, question dns.Question, ips []net.IP) []dns.RR {
	for _, ip := range ips {
		dst = append(dst, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    defaultHostTTL,
			},
			A: append(net.IP(nil), ip.To4()...),
		})
	}
	return dst
}

func (s *hostStore) appendIPv6(dst []dns.RR, question dns.Question, ips []net.IP) []dns.RR {
	for _, ip := range ips {
		dst = append(dst, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    defaultHostTTL,
			},
			AAAA: append(net.IP(nil), ip.To16()...),
		})
	}
	return dst
}

func LoadRecordsFromFile(path string) (map[string]string, error) {
	rs := make(map[string]string, 32)
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("hosts: file path is empty")
	}
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("hosts: open file %s: %w", cleanPath, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("hosts: invalid line in %s:%d", cleanPath, lineNum)
		}
		if ip := net.ParseIP(fields[0]); ip != nil {
			// Standard /etc/hosts format: IP followed by one or more names.
			for _, rawDomain := range fields[1:] {
				domain, err := validDomain(rawDomain)
				if err != nil {
					return nil, fmt.Errorf("hosts: %w in %s:%d", err, cleanPath, lineNum)
				}
				appendFileRecord(rs, domain, ip.String())
			}
			continue
		}

		// Backwards-compatible Atlas format: domain followed by one or more IPs.
		domain, err := validDomain(fields[0])
		if err != nil {
			return nil, fmt.Errorf("hosts: %w in %s:%d", err, cleanPath, lineNum)
		}
		for _, rawIP := range fields[1:] {
			ip := net.ParseIP(rawIP)
			if ip == nil {
				return nil, fmt.Errorf("hosts: invalid IP %q in %s:%d", rawIP, cleanPath, lineNum)
			}
			appendFileRecord(rs, domain, ip.String())
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("hosts: read file %s: %w", cleanPath, err)
	}
	return rs, nil
}

func LoadRecordsFromFiles(files []string) ([]map[string]string, error) {
	rs := make([]map[string]string, 0, len(files))
	for _, path := range files {
		item, err := LoadRecordsFromFile(path)
		if err != nil {
			return nil, err
		}
		rs = append(rs, item)
	}
	return rs, nil
}

func normalize(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.TrimSuffix(d, ".")
	return strings.ToLower(d)
}

func validDomain(raw string) (string, error) {
	domain := normalize(raw)
	if domain == "" {
		return "", fmt.Errorf("domain is empty")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(domain)); !ok {
		return "", fmt.Errorf("invalid domain %q", raw)
	}
	return domain, nil
}

func appendFileRecord(records map[string]string, domain, ip string) {
	if records[domain] == "" {
		records[domain] = ip
		return
	}
	records[domain] += "," + ip
}

func appendUniqueIP(items []net.IP, candidate net.IP) []net.IP {
	for _, item := range items {
		if item.Equal(candidate) {
			return items
		}
	}
	return append(items, append(net.IP(nil), candidate...))
}
