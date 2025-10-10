package outbound

import (
	"atlas/internal/outbound/model"
	"fmt"
	"net/url"

	"github.com/gorilla/schema"
)

// IOutboundManager describes the behaviour required from an outbound manager.

type IOutboundManager interface {
	Get(tag string) (IDnsOutbound, bool)
}

type LinkParams struct {
	Timeout int64  `schema:"timeout"`
	Key     string `schema:"key"`
}

type Factory func(schema string, host string, params *model.ResolverParams) (IDNSResolver, error)

var m = make(map[string]Factory)

func MakeOutbound(link string) (IDNSResolver, error) {
	uri, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	cr, ok := m[uri.Scheme]
	if !ok {
		return nil, fmt.Errorf("no resolver type found, type:%s", uri.Scheme)
	}
	urlinfo := &model.ResolverParams{
		URL: uri,
	}
	if err := decodeParams(&urlinfo.CustomParams, uri.Query()); err != nil {
		return nil, err
	}
	return cr(uri.Scheme, uri.Host, urlinfo)
}

func Register(schema string, fac Factory) {
	m[schema] = fac
}

func decodeParams(out interface{}, in map[string][]string) error {
	d := schema.NewDecoder()
	d.IgnoreUnknownKeys(true)
	if err := d.Decode(out, in); err != nil {
		return err
	}
	return nil
}
