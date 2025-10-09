package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func init() {
	RegisterResolverFactory("udp", classicFactory("udp", "53", 4*time.Second))
	RegisterResolverFactory("tcp", classicFactory("tcp", "53", 4*time.Second))
	RegisterResolverFactory("dot", classicFactory("dot", "853", 6*time.Second))
}

func classicFactory(schema, defaultPort string, defaultTimeout time.Duration) ResolverFactory {
	return func(_ string, host string, params *ResolverParams) (IDNSResolver, error) {
		timeout := params.Timeout
		if timeout <= 0 {
			timeout = defaultTimeout
		}
		switch schema {
		case "udp", "tcp":
			addr := ensurePort(host, defaultPort)
			client := &dns.Client{Net: schema, Timeout: timeout}
			return &classicResolver{addr: addr, client: client}, nil
		case "dot":
			hostname, port := splitHostPort(host, defaultPort)
			client := &dns.Client{
				Net:     "tcp-tls",
				Timeout: timeout,
				TLSConfig: &tls.Config{
					ServerName: hostname,
					MinVersion: tls.VersionTLS12,
				},
			}
			return &classicResolver{addr: net.JoinHostPort(hostname, port), client: client}, nil
		default:
			return nil, fmt.Errorf("unsupported classic schema %q", schema)
		}
	}
}

type classicResolver struct {
	addr   string
	client *dns.Client
}

func (r *classicResolver) String() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s", r.client.Net, r.addr)
}

func (r *classicResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("resolver not initialised")
	}
	return exchangeContext(ctx, r.client, req, r.addr)
}

func ensurePort(host, defaultPort string) string {
	if hasPort(host) {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}

func splitHostPort(host, defaultPort string) (string, string) {
	if hasPort(host) {
		name, port, _ := net.SplitHostPort(host)
		return name, port
	}
	return host, defaultPort
}

func hasPort(host string) bool {
	return strings.LastIndex(host, ":") > strings.LastIndex(host, "]")
}
