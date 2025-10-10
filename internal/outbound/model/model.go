package model

import "net/url"

type BasicResolverParam struct {
	Timeout int64 `schema:"timeout"`
}

type ResolverParams struct {
	URL          *url.URL
	CustomParams *BasicResolverParam
}
