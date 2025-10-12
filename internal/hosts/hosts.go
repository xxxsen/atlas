package hosts

import (
	"bufio"
	"fmt"
	"net"
	"os"
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
		domain = normalize(domain)
		if domain == "" {
			return fmt.Errorf("hosts: invalid domain in records")
		}
		res, ok := out[domain]
		if !ok {
			res = &record{}
			out[domain] = res
		}
		for token := range strings.SplitSeq(list, ",") {
			token = strings.TrimSpace(token)
			ip := net.ParseIP(token)
			if ip == nil {
				return fmt.Errorf("invalid ip in host, str:%s", token)
			}
			if ip4 := ip.To4(); ip4 != nil {
				res.ipv4 = append(res.ipv4, ip4)
				continue
			}
			if ip6 := ip.To16(); ip6 != nil {
				res.ipv6 = append(res.ipv6, ip6)
				continue
			}
			return fmt.Errorf("invalid ip? data:%s", token)
		}
	}
	return nil
}

// Resolve returns DNS answers for a given question.
func (s *hostStore) Resolve(q dns.Question) ([]dns.RR, bool) {
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
				Class:  question.Qclass,
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
				Class:  question.Qclass,
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
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("hosts: open file %s: %w", path, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("hosts: invalid line in %s:%d", path, lineNum)
		}
		domain := normalize(fields[0])
		if domain == "" {
			return nil, fmt.Errorf("hosts: invalid domain in %s:%d", path, lineNum)
		}
		rs[domain] = strings.Join(fields[1:], ",")
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("hosts: read file %s: %w", path, err)
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
