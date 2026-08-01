package matcher

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/atlas/internal/strictdecode"
)

type qclassMatcher struct {
	name    string
	classes map[uint16]struct{}
}

func (q *qclassMatcher) Name() string {
	return q.name
}

func (q *qclassMatcher) Type() string {
	return "qclass"
}

func (q *qclassMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	if req == nil || len(req.Question) != 1 {
		return false, fmt.Errorf("qclass matcher requires exactly one DNS question")
	}
	_, matched := q.classes[req.Question[0].Qclass]
	return matched, nil
}

func newQClassMatcher(name string, classes []uint16) (matcher.IDNSMatcher, error) {
	if len(classes) == 0 {
		return nil, fmt.Errorf("qclass matcher requires at least one class")
	}
	m := make(map[uint16]struct{}, len(classes))
	for _, c := range classes {
		if c == 0 {
			return nil, fmt.Errorf("qclass matcher cannot use class 0")
		}
		m[c] = struct{}{}
	}
	return &qclassMatcher{name: name, classes: m}, nil
}

func createQClassMatcher(name string, args interface{}) (matcher.IDNSMatcher, error) {
	cfg := &config{}
	if err := strictdecode.Decode(args, cfg); err != nil {
		return nil, err
	}
	return newQClassMatcher(name, cfg.Classes)
}

func init() {
	matcher.Register("qclass", createQClassMatcher)
}
