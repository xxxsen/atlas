package forward

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/ipset"
	"github.com/xxxsen/atlas/internal/querylog"
	"github.com/xxxsen/atlas/internal/resolver"
	"go.uber.org/zap"
)

// validatedResolver is inside the action's cache. Only a new primary response
// is checked; the final fallback response is trusted and cached as a whole.
type validatedResolver struct {
	name         string
	primary      resolver.IDNSResolver
	validator    *ipset.Validator
	fallbackName string
	fallback     action.IDNSAction
}

func (r *validatedResolver) Name() string { return r.primary.Name() }

func (r *validatedResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	msg, err := r.primary.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	address, rejected := rejectedAddress(msg, r.validator)
	if !rejected {
		return msg, nil
	}
	logger := querylog.Logger(ctx).With(
		zap.String("action", r.name), zap.String("fallback", r.fallbackName),
		zap.String("primary_resolver", querylog.Read(ctx).Result.Resolver),
		zap.Float64("primary_elapsed_ms", float64(time.Since(start))/float64(time.Millisecond)),
		zap.String("rejected_ip", address), zap.String("reason", "address_validation"))
	logger.Warn("forward response failed address validation")
	querylog.StartFallback(ctx)
	if r.fallback == nil {
		return nil, fmt.Errorf("forward action %q fallback %q is not bound", r.name, r.fallbackName)
	}
	fallbackStart := time.Now()
	msg, err = r.fallback.Perform(ctx, req)
	if err != nil {
		querylog.SetResult(ctx, querylog.Result{})
		logger.Warn("forward fallback failed", querylog.Error(err), querylog.Elapsed(start), zap.Float64("fallback_elapsed_ms", float64(time.Since(fallbackStart))/float64(time.Millisecond)))
		return nil, fmt.Errorf("forward action %q rejected IP %s; fallback %q failed: %w", r.name, address, r.fallbackName, err)
	}
	result := querylog.Read(ctx).Result
	result.ViaFallback = true
	querylog.SetResult(ctx, result)
	rcode := -1
	if msg != nil {
		rcode = msg.Rcode
	}
	logger.Info("forward fallback succeeded", append(querylog.Fields(ctx), querylog.Elapsed(start), zap.Float64("fallback_elapsed_ms", float64(time.Since(fallbackStart))/float64(time.Millisecond)), zap.Int("rcode", rcode), zap.Strings("ips", querylog.IPs(msg)))...)
	return msg, nil
}

func (r *validatedResolver) Close() error {
	// The action map owns the shared fallback. Closing it here would also
	// close another parent's upstreams and cause repeated shutdown calls.
	if closer, ok := r.primary.(resolver.ResolverCloser); ok {
		return closer.Close()
	}
	return nil
}

func rejectedAddress(msg *dns.Msg, validator *ipset.Validator) (string, bool) {
	if msg.Rcode == dns.RcodeNameError {
		return "", false
	}
	check := func(ip net.IP) (string, bool) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !validator.Allows(addr) {
			return ip.String(), true
		}
		return "", false
	}
	for _, rr := range msg.Answer {
		var values []dns.SVCBKeyValue
		switch record := rr.(type) {
		case *dns.A:
			if ip, bad := check(record.A); bad {
				return ip, true
			}
		case *dns.AAAA:
			if ip, bad := check(record.AAAA); bad {
				return ip, true
			}
		case *dns.SVCB:
			values = record.Value
		case *dns.HTTPS:
			values = record.Value
		}
		for _, value := range values {
			var hints []net.IP
			switch hint := value.(type) {
			case *dns.SVCBIPv4Hint:
				hints = hint.Hint
			case *dns.SVCBIPv6Hint:
				hints = hint.Hint
			}
			for _, hint := range hints {
				if ip, bad := check(hint); bad {
					return ip, true
				}
			}
		}
	}
	return "", false
}
