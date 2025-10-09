package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type classicResolver struct {
	addr   string
	client *dns.Client
}

func newClassicResolver(u *url.URL) (resolver, error) {
	if u == nil {
		return nil, fmt.Errorf("nil url")
	}

	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	switch u.Scheme {
	case "udp", "tcp":
		if !hasPort(host) {
			host = net.JoinHostPort(u.Hostname(), "53")
		}
		client := &dns.Client{
			Net:     u.Scheme,
			Timeout: 4 * time.Second,
		}
		return &classicResolver{addr: host, client: client}, nil
	case "dot":
		port := u.Port()
		if port == "" {
			port = "853"
		}
		serverName := u.Hostname()
		addr := net.JoinHostPort(serverName, port)
		client := &dns.Client{
			Net:       "tcp-tls",
			Timeout:   6 * time.Second,
			TLSConfig: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12},
		}
		return &classicResolver{addr: addr, client: client}, nil
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
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

func hasPort(host string) bool {
	return strings.LastIndex(host, ":") > strings.LastIndex(host, "]")
}
