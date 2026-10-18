package forward

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/action"
	"github.com/xxxsen/atlas/internal/ipset"
	"github.com/xxxsen/atlas/internal/resolver"
	"github.com/xxxsen/common/logutil"
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
	msg, err := r.primary.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	address, rejected := rejectedAddress(msg, r.validator)
	if !rejected {
		return msg, nil
	}
	logger := logutil.GetLogger(ctx).With(
		zap.String("action", r.name), zap.String("fallback", r.fallbackName),
		zap.String("domain", req.Question[0].Name), zap.Uint16("qtype", req.Question[0].Qtype),
		zap.String("rejected_ip", address))
	logger.Warn("forward response failed address validation")
	if r.fallback == nil {
		return nil, fmt.Errorf("forward action %q fallback %q is not bound", r.name, r.fallbackName)
	}
	msg, err = r.fallback.Perform(ctx, req)
	if err != nil {
		logger.Debug("forward fallback failed", zap.Error(err))
		return nil, fmt.Errorf("forward action %q rejected IP %s; fallback %q failed: %w", r.name, address, r.fallbackName, err)
	}
	logger.Debug("forward fallback succeeded")
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
