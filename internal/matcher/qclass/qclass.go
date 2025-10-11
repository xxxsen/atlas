package matcher

import (
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/matcher"
	"github.com/xxxsen/common/utils"
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
	for _, item := range req.Question {
		if _, ok := q.classes[item.Qclass]; ok {
			return true, nil
		}
	}
	return false, nil
}

func newQClassMatcher(name string, classes []uint16) (matcher.IDNSMatcher, error) {
	m := make(map[uint16]struct{}, len(classes))
	for _, c := range classes {
		m[c] = struct{}{}
	}
	return &qclassMatcher{name: name, classes: m}, nil
}

func createQClassMatcher(name string, args interface{}) (matcher.IDNSMatcher, error) {
	cfg := &config{}
	if err := utils.ConvStructJson(args, cfg); err != nil {
		return nil, err
	}
	return newQClassMatcher(name, cfg.Classes)
}

func init() {
	matcher.Register("qclass", createQClassMatcher)
}
