package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
)

func init() {
	Register("https", dohResolverFactory)
}

func dohResolverFactory(schema string, host string, params *model.Params) (IDNSResolver, error) {
	endpoint := fmt.Sprintf("%s://%s%s", schema, host, params.URL.RawPath)
	return newDoHResolver(endpoint, time.Duration(params.CustomParams.Timeout)*time.Millisecond)
}

func newDoHResolver(endpoint string, timeout time.Duration) (IDNSResolver, error) {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxConnsPerHost:     10,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
	}
	if strings.HasPrefix(endpoint, "https://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse doh endpoint: %w", err)
		}
		transport.TLSClientConfig = &tls.Config{ServerName: u.Hostname()}
	}
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	return &dohResolver{endpoint: endpoint, client: client}, nil
}

type dohResolver struct {
	endpoint string
	client   *http.Client
}

func (r *dohResolver) String() string {
	return "doh:" + r.endpoint
}

func (r *dohResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("invalid doh resolver")
	}

	payload, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create doh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("doh %s returned %d: %s", r.endpoint, resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}

	message := &dns.Msg{}
	if err := message.Unpack(body); err != nil {
		return nil, fmt.Errorf("decode doh response: %w", err)
	}
	return message, nil
}
