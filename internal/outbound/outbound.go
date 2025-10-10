package outbound

import (
	"atlas/internal/outbound/model"
	"context"
	"fmt"
	"net/url"

	"github.com/gorilla/schema"
	"github.com/miekg/dns"
)

type Factory func(schema string, host string, params *model.ResolverParams) (IDNSResolver, error)

var m = make(map[string]Factory)

func MakeOutbounds(links []string) ([]IDNSResolver, error) {
	rs := make([]IDNSResolver, 0, len(links))
	for _, item := range links {
		r, err := MakeOutbound(item)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return rs, nil
}

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

func decodeParams(out interface{}, in map[string][]string) error {
	d := schema.NewDecoder()
	d.IgnoreUnknownKeys(true)
	if err := d.Decode(out, in); err != nil {
		return err
	}
	return nil
}

func Register(schema string, fac Factory) {
	m[schema] = fac
}

// IDNSOutbound represents a DNS outbound transport abstraction.
type IDNSOutbound interface {
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// IDNSResolver represents a downstream resolver.
type IDNSResolver interface {
	String() string
	Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}
