package matcher

import "strings"

func NormalizeDomain(in string) string {
	return strings.TrimSuffix(in, ".")
}
