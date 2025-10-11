package matcher

import "strings"

type suffixNode struct {
	children map[string]*suffixNode
	terminal bool
}

func newSuffixNode() *suffixNode {
	return &suffixNode{children: make(map[string]*suffixNode)}
}

func (n *suffixNode) add(domain string) {
	if domain == "" {
		return
	}
	labels := strings.Split(domain, ".")
	cur := n
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		child, ok := cur.children[label]
		if !ok {
			child = newSuffixNode()
			cur.children[label] = child
		}
		cur = child
	}
	cur.terminal = true
}

func (n *suffixNode) match(domain string) bool {
	if domain == "" {
		return false
	}
	labels := strings.Split(domain, ".")
	cur := n
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		child, ok := cur.children[label]
		if !ok {
			return false
		}
		cur = child
		if cur.terminal {
			return true
		}
	}
	return cur.terminal
}
