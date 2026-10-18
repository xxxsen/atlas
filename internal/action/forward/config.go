package forward

import "github.com/xxxsen/atlas/internal/ipset"

type config struct {
	ServerList []string                `json:"server_list"`
	Parallel   int                     `json:"parallel"`
	Validate   *ipset.ValidationConfig `json:"validate"`
	Fallback   *string                 `json:"fallback"`
}
