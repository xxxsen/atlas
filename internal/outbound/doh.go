package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

type dohResolver struct {
	endpoint string
	client   *http.Client
}

func newDoHResolver(u *url.URL) (resolver, error) {
	if u == nil {
		return nil, fmt.Errorf("nil url")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("unsupported DoH scheme %q", u.Scheme)
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxConnsPerHost:     10,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
	}
	if u.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			ServerName: u.Hostname(),
		}
	}

	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: transport,
	}

	return &dohResolver{
		endpoint: u.String(),
		client:   client,
	}, nil
}

func (r *dohResolver) String() string {
	return fmt.Sprintf("doh:%s", r.endpoint)
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
