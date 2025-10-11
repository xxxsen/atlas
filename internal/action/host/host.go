package host

import (
	"atlas/internal/action"
	"context"

	"github.com/miekg/dns"
	"github.com/xxxsen/common/utils"
)

type hostAction struct {
	name string
}

func (h *hostAction) Name() string {
	return h.name
}

func (h *hostAction) Type() string {
	return "host"
}

func (h *hostAction) Perform(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	//TODO: 实现dns填充
	panic("TODO: Implement")
}

func createHostAction(name string, args interface{}) (action.IDNSAction, error) {
	c := &config{}
	if err := utils.ConvStructJson(args, c); err != nil {
		return nil, err
	}

	//TODO: 这里要遍历c.Records 并生成hostAction实例
	panic("impl it")
}

func init() {
	action.Register("host", createHostAction)
}
