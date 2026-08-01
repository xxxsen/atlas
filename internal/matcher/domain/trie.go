package matcher

import (
	"sort"
	"strings"
)

// domainTrie uses maps only while it is being built. freeze converts the
// structure to sorted contiguous edges, dropping thousands of tiny maps that
// otherwise dominate large geosite indexes.
type domainTrie struct {
	building []domainBuildNode
	nodes    []domainNode
	edges    []domainEdge
	frozen   bool
}

type domainBuildNode struct {
	children map[string]uint32
	exact    bool
	suffix   bool
}

type domainNode struct {
	edgeStart uint32
	edgeCount uint32
	exact     bool
	suffix    bool
}

type domainEdge struct {
	label string
	next  uint32
}

func newDomainTrie() *domainTrie {
	return &domainTrie{building: []domainBuildNode{{}}}
}

// add preserves the old helper's suffix semantics for package tests.
func (t *domainTrie) add(domain string) {
	t.addRule(domain, false)
}

func (t *domainTrie) addExact(domain string) {
	t.addRule(domain, true)
}

func (t *domainTrie) addRule(domain string, exact bool) {
	if domain == "" {
		return
	}
	if t.frozen {
		panic("cannot add a domain rule after the trie is frozen")
	}
	current := uint32(0)
	visitLabelsReverse(domain, func(label string, _ bool) bool {
		node := &t.building[current]
		if node.children == nil {
			node.children = make(map[string]uint32)
		}
		next, ok := node.children[label]
		if !ok {
			next = uint32(len(t.building))
			node.children[label] = next
			t.building = append(t.building, domainBuildNode{})
		}
		current = next
		return true
	})
	if exact {
		t.building[current].exact = true
	} else {
		// A suffix rule also matches the suffix itself.
		t.building[current].exact = true
		t.building[current].suffix = true
	}
}

func (t *domainTrie) freeze() {
	if t.frozen {
		return
	}
	t.nodes = make([]domainNode, len(t.building))
	for index := range t.building {
		building := &t.building[index]
		node := &t.nodes[index]
		node.exact = building.exact
		node.suffix = building.suffix
		if len(building.children) == 0 {
			continue
		}
		labels := make([]string, 0, len(building.children))
		for label := range building.children {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		node.edgeStart = uint32(len(t.edges))
		node.edgeCount = uint32(len(labels))
		for _, label := range labels {
			t.edges = append(t.edges, domainEdge{label: label, next: building.children[label]})
		}
	}
	t.building = nil
	t.frozen = true
}

func (t *domainTrie) child(node uint32, label string) (uint32, bool) {
	item := t.nodes[node]
	edges := t.edges[item.edgeStart : item.edgeStart+item.edgeCount]
	index := sort.Search(len(edges), func(i int) bool { return edges[i].label >= label })
	if index == len(edges) || edges[index].label != label {
		return 0, false
	}
	return edges[index].next, true
}

func (t *domainTrie) match(domain string) (exact bool, suffix bool) {
	if domain == "" {
		return false, false
	}
	if !t.frozen {
		t.freeze()
	}
	current := uint32(0)
	completed := true
	visitLabelsReverse(domain, func(label string, last bool) bool {
		next, ok := t.child(current, label)
		if !ok {
			completed = false
			return false
		}
		current = next
		if t.nodes[current].suffix {
			suffix = true
		}
		if last {
			exact = t.nodes[current].exact
		}
		return true
	})
	if !completed {
		return false, suffix
	}
	return exact, suffix
}

func (t *domainTrie) matchSuffix(domain string) bool {
	_, suffix := t.match(domain)
	return suffix
}

func (t *domainTrie) matchExact(domain string) bool {
	exact, _ := t.match(domain)
	return exact
}

// visitLabelsReverse scans labels from the TLD towards the host without
// allocating the []string produced by strings.Split.
func visitLabelsReverse(domain string, visit func(label string, last bool) bool) {
	end := len(domain)
	for end > 0 {
		separator := strings.LastIndexByte(domain[:end], '.')
		start := separator + 1
		if start == end || !visit(domain[start:end], separator < 0) {
			return
		}
		if separator < 0 {
			return
		}
		end = separator
	}
}
