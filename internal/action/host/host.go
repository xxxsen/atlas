package host

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/common/utils"
)

const defaultHostRecordTTL = 5

type hostRecord struct {
	ipv4 []net.IP
	ipv6 []net.IP
}

type hostAction struct {
	name    string
	records map[string]*hostRecord
}

func (h *hostAction) Name() string {
	return h.name
}

func (h *hostAction) Type() string {
	return "host"
}

func (h *hostAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if req == nil {
		return nil, fmt.Errorf("dns request is nil")
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	for _, question := range req.Question {
		domain := normalize(question.Name)
		record, ok := h.records[domain]
		if !ok {
			continue
		}
		switch question.Qtype {
		case dns.TypeA:
			addIPv4Answers(resp, question, record.ipv4)
		case dns.TypeAAAA:
			addIPv6Answers(resp, question, record.ipv6)
		case dns.TypeANY:
			addIPv4Answers(resp, question, record.ipv4)
			addIPv6Answers(resp, question, record.ipv6)
		}
	}

	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("no host record matched request")
	}
	return resp, nil
}

func addIPv4Answers(resp *dns.Msg, question dns.Question, ips []net.IP) {
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  question.Qclass,
				Ttl:    defaultHostRecordTTL,
			},
			A: ip,
		})
	}
}

func addIPv6Answers(resp *dns.Msg, question dns.Question, ips []net.IP) {
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  question.Qclass,
				Ttl:    defaultHostRecordTTL,
			},
			AAAA: ip,
		})
	}
}

func createHostAction(name string, args interface{}) (action.IDNSAction, error) {
	c := &config{}
	if err := utils.ConvStructJson(args, c); err != nil {
		return nil, err
	}

	rawRecords := make(map[string]string)
	for domainKey, ipList := range c.Records {
		if strings.TrimSpace(domainKey) == "" {
			return nil, fmt.Errorf("host action:%s has empty domain", name)
		}
		domain := normalize(domainKey)
		if domain == "" {
			return nil, fmt.Errorf("host action:%s has invalid domain:%s", name, domainKey)
		}
		rawRecords[domain] = appendIPList(rawRecords[domain], ipList)
	}

	fileRecords, err := loadHostRecordsFromFiles(c.Files)
	if err != nil {
		return nil, err
	}
	for domain, ipList := range fileRecords {
		rawRecords[domain] = appendIPList(rawRecords[domain], ipList)
	}

	if len(rawRecords) == 0 {
		return nil, fmt.Errorf("host action:%s has no valid records", name)
	}

	records := make(map[string]*hostRecord, len(rawRecords))
	for domain, ipList := range rawRecords {
		entry := &hostRecord{}
		for rawIP := range strings.SplitSeq(ipList, ",") {
			addr := strings.TrimSpace(rawIP)
			if addr == "" {
				return nil, fmt.Errorf("host action:%s empty ip for domain:%s", name, domain)
			}
			ip := net.ParseIP(addr)
			if ip == nil {
				return nil, fmt.Errorf("host action:%s invalid ip:%s", name, addr)
			}
			if ip4 := ip.To4(); ip4 != nil {
				entry.ipv4 = append(entry.ipv4, ip4)
				continue
			}
			if ip6 := ip.To16(); ip6 != nil {
				entry.ipv6 = append(entry.ipv6, ip6)
				continue
			}
			return nil, fmt.Errorf("host action:%s unsupported ip:%s", name, addr)
		}
		if len(entry.ipv4) == 0 && len(entry.ipv6) == 0 {
			return nil, fmt.Errorf("host action:%s has no valid ip for domain:%s", name, domain)
		}
		records[domain] = entry
	}

	return &hostAction{
		name:    name,
		records: records,
	}, nil
}

func normalize(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.TrimSuffix(d, ".")
	return strings.ToLower(d)
}

func init() {
	action.Register("host", createHostAction)
}

func appendIPList(existing, add string) string {
	add = strings.TrimSpace(add)
	if add == "" {
		return existing
	}
	if existing == "" {
		return add
	}
	return existing + "," + add
}

func loadHostRecordsFromFiles(files []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, path := range files {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open host file %s: %w", path, err)
		}
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
				f.Close()
				return nil, fmt.Errorf("invalid host file line %s:%d", path, lineNum)
			}
			domain := normalize(fields[0])
			if domain == "" {
				f.Close()
				return nil, fmt.Errorf("invalid domain in host file %s:%d", path, lineNum)
			}
			var ips []string
			for _, token := range fields[1:] {
				for _, part := range strings.Split(token, ",") {
					part = strings.TrimSpace(part)
					if part != "" {
						ips = append(ips, part)
					}
				}
			}
			if len(ips) == 0 {
				f.Close()
				return nil, fmt.Errorf("no ip specified in host file %s:%d", path, lineNum)
			}
			result[domain] = appendIPList(result[domain], strings.Join(ips, ","))
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("read host file %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("close host file %s: %w", path, err)
		}
	}
	return result, nil
}
