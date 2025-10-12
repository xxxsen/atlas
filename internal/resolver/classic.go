package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

func init() {
	Register("tcp", basicResolverFactory)
	Register("udp", basicResolverFactory)
	Register("dot", basicResolverFactory)
}

func basicResolverFactory(schema string, host string, params *model.Params) (IDNSResolver, error) {
	if schema == "udp" || schema == "tcp" {
		addr, err := ensurePort(host, "53")
		if err != nil {
			return nil, err
		}
		client := &dns.Client{Net: schema, Timeout: time.Duration(params.CustomParams.Timeout) * time.Millisecond}
		return &classicResolver{
			addr:   addr,
			client: client,
		}, nil
	} else if schema == "dot" {
		addr, err := ensurePort(host, "853")
		if err != nil {
			return nil, err
		}
		hostname, _, err := net.SplitHostPort(addr)
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
		return &classicResolver{addr: addr, client: client}, nil
	}
	return nil, fmt.Errorf("unsupported dns type:%s", schema)
}

type classicResolver struct {
	addr   string
	client *dns.Client
}

func (r *classicResolver) Name() string {
	return fmt.Sprintf("%s/%s", r.client.Net, r.addr)
}

func (r *classicResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchangeContext(ctx, r.client, req, r.addr)
}

func (r *classicResolver) exchangeContext(ctx context.Context, client *dns.Client, req *dns.Msg, addr string) (*dns.Msg, error) {
	logger := logutil.GetLogger(ctx).With(
		zap.String("resolver", r.Name()),
		zap.String("server_addr", addr),
	)
	logger.Debug("classic resolver start query")
	resp, _, err := client.ExchangeContext(ctx, req, addr)
	if err != nil {
		logger.Error("classic resolver query failed", zap.Error(err))
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("no response from %s", addr)
	}
	logger.Debug("classic resolver query success", zap.Int("answer_count", len(resp.Answer)))
	return resp, nil
}

func ensurePort(host string, defaultPort string) (string, error) {
	if defaultPort == "" {
		return host, nil
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	cleanHost := host
	if strings.HasPrefix(cleanHost, "[") && strings.HasSuffix(cleanHost, "]") {
		cleanHost = strings.TrimPrefix(cleanHost, "[")
		cleanHost = strings.TrimSuffix(cleanHost, "]")
	}
	return net.JoinHostPort(cleanHost, defaultPort), nil
}
