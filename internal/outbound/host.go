package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func init() {
	RegisterResolverFactory("host", func(schema, host string, params *ResolverParams) (IDNSResolver, error) {
		key := params.Values.Get("key")
		if key == "" {
			return nil, errors.New("host resolver requires key parameter")
		}
		records, ok := getHostRecords(key)
		if !ok {
			return nil, fmt.Errorf("host resolver references unknown key %q", key)
		}
		return newHostResolver(key, records), nil
	})
}

type hostResolver struct {
	key     string
	records map[string][]net.IP
}

func newHostResolver(key string, records map[string][]net.IP) IDNSResolver {
	normalized := make(map[string][]net.IP, len(records))
	for domain, ips := range records {
		normalized[normalizeDomain(domain)] = append([]net.IP(nil), ips...)
	}
	return &hostResolver{key: key, records: normalized}
}

func (r *hostResolver) String() string {
	return "host:" + r.key
}

func (r *hostResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r == nil || len(req.Question) == 0 {
		return nil, errors.New("invalid request")
	}
	q := req.Question[0]
	name := normalizeDomain(q.Name)
	ips, ok := r.records[name]
	resp := new(dns.Msg)
	resp.SetReply(req)
	if !ok {
		resp.Rcode = dns.RcodeNameError
		return resp, nil
	}
	resp.Answer = buildHostRecords(q, ips)
	return resp, nil
}

func buildHostRecords(q dns.Question, ips []net.IP) []dns.RR {
	records := make([]dns.RR, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) {
			records = append(records, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: v4})
		} else if v6 := ip.To16(); v6 != nil && ip.To4() == nil && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
			records = append(records, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: v6})
		}
	}
	return records
}

func normalizeDomain(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	return strings.ToLower(name)
}
