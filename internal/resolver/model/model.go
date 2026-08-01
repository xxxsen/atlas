package model

import "net/url"

type BasicParam struct {
	Timeout     int64 `schema:"timeout"`
	PoolSize    int   `schema:"pool"`
	MaxConns    int   `schema:"max_conns"`
	MaxInflight int   `schema:"max_inflight"`
}

type Params struct {
	URL          *url.URL
	CustomParams BasicParam
}
