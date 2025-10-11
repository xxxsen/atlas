package matcher

import "testing"

func TestAhoMatcherMatch(t *testing.T) {
	m := newAhoMatcher()
	m.add("foo")
	m.add("bar")
	m.add("baz")
	m.add("拼音")
	m.build()

	tests := []struct {
		name    string
		text    string
		matched bool
	}{
		{"exact foo", "foo", true},
		{"contains foo", "xxfooyy", true},
		{"overlap barbaz", "barbaz", true},
		{"non match", "qux", false},
		{"unicode match", "测试拼音是否匹配", true},
		{"prefix only", "ba", false},
	}

	for _, tt := range tests {
		if got := m.match(tt.text); got != tt.matched {
			t.Errorf("%s: match(%s) = %t, want %t", tt.name, tt.text, got, tt.matched)
		}
	}
}

func TestAhoMatcherEmpty(t *testing.T) {
	m := newAhoMatcher()
	if m.match("anything") {
		t.Fatal("expected empty matcher not to match")
	}
}
