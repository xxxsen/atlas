package matcher

import (
	"atlas/internal/matcher"
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/utils"
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
	for _, item := range req.Question {
		if _, ok := q.typs[item.Qtype]; ok {
			return true, nil
		}
	}
	return false, nil
}

func newQTypeMatcher(name string, typs []uint16) (matcher.IDNSMatcher, error) {
	t := make(map[uint16]struct{}, len(typs))
	for _, item := range typs {
		t[item] = struct{}{}
	}
	return &qtypeMatcher{typs: t}, nil
}

func createQTypeMatcher(name string, args interface{}) (matcher.IDNSMatcher, error) {
	c := &config{}
	if err := utils.ConvStructJson(args, c); err != nil {
		return nil, err
	}
	return newQTypeMatcher(name, c.Types)
}

func init() {
	matcher.Register("qtype", createQTypeMatcher)
}
