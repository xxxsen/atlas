package outbound

import (
	"atlas/internal/outbound/model"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func init() {
	Register("tcp", basicResolverFactory)
	Register("udp", basicResolverFactory)
	Register("dot", basicResolverFactory)
}

func basicResolverFactory(schema string, host string, params *model.ResolverParams) (IDNSResolver, error) {
	if schema == "udp" || schema == "tcp" {
		client := &dns.Client{Net: schema, Timeout: time.Duration(params.CustomParams.Timeout) * time.Millisecond}
		return &classicResolver{
			addr:   host,
			client: client,
		}, nil
	} else if schema == "dot" {
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
		client := &dns.Client{
			Net:     "tcp-tls",
			Timeout: time.Duration(params.CustomParams.Timeout) * time.Millisecond,
			TLSConfig: &tls.Config{
				ServerName: hostname,
				MinVersion: tls.VersionTLS12,
			},
		}
		return &classicResolver{addr: host, client: client}, nil
	}
	return nil, fmt.Errorf("unsupported dns type:%s", schema)
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

func hasPort(host string) bool {
	return strings.LastIndex(host, ":") > strings.LastIndex(host, "]")
}
