package matcher

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/atlas/internal/strictdecode"
)

type qtypeMatcher struct {
	name string
	typs map[uint16]struct{}
}

func (q *qtypeMatcher) Name() string {
	return q.name
}

func (q *qtypeMatcher) Type() string {
	return "qtype"
}

func (q *qtypeMatcher) Match(ctx context.Context, req *dns.Msg) (bool, error) {
	if req == nil || len(req.Question) != 1 {
		return false, fmt.Errorf("qtype matcher requires exactly one DNS question")
	}
	_, matched := q.typs[req.Question[0].Qtype]
	return matched, nil
}

func newQTypeMatcher(name string, typs []uint16) (matcher.IDNSMatcher, error) {
	if len(typs) == 0 {
		return nil, fmt.Errorf("qtype matcher requires at least one type")
	}
	t := make(map[uint16]struct{}, len(typs))
	for _, item := range typs {
		if item == 0 {
			return nil, fmt.Errorf("qtype matcher cannot use type 0")
		}
		t[item] = struct{}{}
	}
	return &qtypeMatcher{name: name, typs: t}, nil
}

func createQTypeMatcher(name string, args interface{}) (matcher.IDNSMatcher, error) {
	c := &config{}
	if err := strictdecode.Decode(args, c); err != nil {
		return nil, err
	}
	return newQTypeMatcher(name, c.Types)
}

func init() {
	matcher.Register("qtype", createQTypeMatcher)
}
