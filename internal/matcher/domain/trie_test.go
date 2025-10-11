package matcher

import "testing"

func TestDomainTrieMatchSuffix(t *testing.T) {
	trie := newDomainTrie()
	trie.add("example.com")
	trie.add("co.uk")
	trie.add("sub.domain.org")

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
		if got := trie.matchSuffix(tt.domain); got != tt.matched {
			t.Errorf("%s: matchSuffix(%s) = %t, want %t", tt.name, tt.domain, got, tt.matched)
		}
	}
}

func TestDomainTrieMatchExact(t *testing.T) {
	trie := newDomainTrie()
	trie.add("example.com")
	trie.add("sub.domain.org")

	tests := []struct {
		domain  string
		matched bool
	}{
		{"example.com", true},
		{"www.example.com", false},
		{"sub.domain.org", true},
		{"deep.sub.domain.org", false},
		{"other.org", false},
	}

	for _, tt := range tests {
		if got := trie.matchExact(tt.domain); got != tt.matched {
			t.Errorf("matchExact(%s) = %t, want %t", tt.domain, got, tt.matched)
		}
	}
}

func TestDomainTrieEmpty(t *testing.T) {
	trie := newDomainTrie()
	if trie.matchSuffix("example.com") {
		t.Fatal("expected empty trie not to match suffix")
	}
	if trie.matchExact("example.com") {
		t.Fatal("expected empty trie not to match exact")
	}
}
