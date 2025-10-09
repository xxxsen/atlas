package outbound

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func exchangeContext(ctx context.Context, client *dns.Client, req *dns.Msg, addr string) (*dns.Msg, error) {
	if client == nil {
		return nil, fmt.Errorf("dns client is nil")
	}
	resp, _, err := client.ExchangeContext(ctx, req, addr)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("no response from %s", addr)
	}
	return resp, nil
}

func clampTTL(ttl uint32, max time.Duration) uint32 {
	if max <= 0 {
		return ttl
	}
	if ttl == 0 {
		return 0
	}
	maxSeconds := uint32(max / time.Second)
	if maxSeconds == 0 {
		return 0
	}
	if ttl > maxSeconds {
		return maxSeconds
	}
	return ttl
}
