package model

import "net/url"

type BasicParam struct {
	Timeout int64 `schema:"timeout"`
}

type Params struct {
	URL          *url.URL
	CustomParams BasicParam
}
