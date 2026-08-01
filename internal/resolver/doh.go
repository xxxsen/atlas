package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

const defaultDoHMaxConnections = 100

func init() {
	Register("https", dohResolverFactory)
}

func dohResolverFactory(scheme string, host string, params *model.Params) (IDNSResolver, error) {
	if params == nil || params.URL == nil {
		return nil, fmt.Errorf("DoH resolver parameters are required")
	}
	endpointURL := *params.URL
	endpointURL.Scheme = scheme
	endpointURL.Host = host
	if endpointURL.EscapedPath() == "" {
		endpointURL.Path = "/"
	}
	maxConnections := params.CustomParams.MaxConns
	if maxConnections == 0 {
		maxConnections = defaultDoHMaxConnections
	}
	return newDoHResolver(endpointURL.String(), time.Duration(params.CustomParams.Timeout)*time.Millisecond, maxConnections)
}

func newDoHResolver(endpoint string, timeout time.Duration, maxConnections ...int) (IDNSResolver, error) {
	connections := defaultDoHMaxConnections
	if len(maxConnections) > 0 && maxConnections[0] > 0 {
		connections = maxConnections[0]
	}
	transport := &http.Transport{
		MaxConnsPerHost:       connections,
		MaxIdleConns:          connections,
		MaxIdleConnsPerHost:   connections,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse DoH endpoint: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("DoH endpoint must be an https URL with a host")
	}
	transport.TLSClientConfig = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &dohResolver{endpoint: endpoint, client: client, transport: transport}, nil
}

type dohResolver struct {
	endpoint  string
	client    *http.Client
	transport *http.Transport
}

func (r *dohResolver) Name() string {
	return "doh:" + r.endpoint
}

func (r *dohResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if req == nil {
		return nil, fmt.Errorf("DoH resolver received a nil request")
	}
	logger := logutil.GetLogger(ctx).With(zap.String("resolver", r.Name()))
	payload, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("DoH %s returned %d: %s", r.endpoint, resp.StatusCode, string(body))
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, fmt.Errorf("DoH %s returned invalid Content-Type %q", r.endpoint, resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > dns.MaxMsgSize {
		return nil, fmt.Errorf("DoH response is too large: %d bytes", resp.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if len(body) > dns.MaxMsgSize {
		return nil, fmt.Errorf("DoH response exceeds %d bytes", dns.MaxMsgSize)
	}
	message := new(dns.Msg)
	if err := message.Unpack(body); err != nil {
		return nil, fmt.Errorf("decode DoH response: %w", err)
	}
	if err := ValidateResponse(req, message); err != nil {
		return nil, fmt.Errorf("validate DoH response: %w", err)
	}
	logger.Debug("DoH resolver query succeeded", zap.Int("answer_count", len(message.Answer)))
	return message, nil
}

func (r *dohResolver) Close() error {
	r.transport.CloseIdleConnections()
	return nil
}

var _ ResolverCloser = (*dohResolver)(nil)
