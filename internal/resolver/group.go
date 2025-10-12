package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

type groupResolver struct {
	name       string
	res        []IDNSResolver
	concurrent int
}

func (p *groupResolver) Name() string {
	return p.name
}

func (p *groupResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(p.concurrent)
	logger := logutil.GetLogger(ctx).With(zap.Int("concurrent", p.concurrent))
	logger.Debug("group resolver start query")
	var result atomic.Value
	pos := rand.Int()
	for i := 0; i < p.concurrent; i++ {
		res := p.res[(i+pos)%len(p.res)]
		eg.Go(func() error {
			subLogger := logger.With(zap.String("child_resolver", res.Name()))
			subLogger.Debug("group resolver delegate query")
			rs, err := res.Query(ctx, req)
			if err != nil {
				if errors.Is(err, context.Canceled) { //默认会有大量的取消, 所以这里忽略cancel场景的日志打印
					return err
				}
				subLogger.Error("group resolver delegate failed", zap.Error(err))
				return err
			}
			cancel()
			result.Store(rs)
			subLogger.Debug("group resolver delegate success", zap.Int("answer_count", len(rs.Answer)))
			return nil
		})
	}
	err := eg.Wait()
	v, ok := result.Load().(*dns.Msg)
	if ok {
		logger.Debug("group resolver query success")
		return v, nil
	}
	if err != nil {
		logger.Error("group resolver query failed", zap.Error(err))
		return nil, err
	}
	return nil, fmt.Errorf("no err return and no dns record found?")
}

func NewGroupResolver(res []IDNSResolver, concurrent int) IDNSResolver {
	return &groupResolver{name: buildGroupName(res, concurrent), res: res, concurrent: concurrent}
}

func buildGroupName(res []IDNSResolver, cc int) string {
	return fmt.Sprintf("group:{%d:%d}", len(res), cc)
}
