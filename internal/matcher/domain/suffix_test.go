package matcher

import "testing"

func TestSuffixNodeMatch(t *testing.T) {
	n := newSuffixNode()
	n.add("example.com")
	n.add("co.uk")
	n.add("sub.domain.org")

	tests := []struct {
		name    string
		domain  string
		matched bool
	}{
		{"exact match", "example.com", true},
		{"subdomain match", "www.example.com", true},
		{"partial mismatch", "example.co", false},
		{"multi-label suffix", "service.co.uk", true},
		{"suffix only", "co.uk", true},
		{"deep suffix exact", "sub.domain.org", true},
		{"deep suffix subdomain", "deep.sub.domain.org", true},
		{"non matching", "wrongdomain.org", false},
	}

	for _, tt := range tests {
		if got := n.match(tt.domain); got != tt.matched {
			t.Errorf("%s: match(%s) = %t, want %t", tt.name, tt.domain, got, tt.matched)
		}
	}
}

func TestSuffixNodeEmpty(t *testing.T) {
	n := newSuffixNode()
	if n.match("example.com") {
		t.Fatal("expected empty trie not to match any domain")
	}
}
