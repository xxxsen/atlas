package matcher

import "strings"

type domainTrie struct {
	children map[string]*domainTrie
	terminal bool
}

func newDomainTrie() *domainTrie {
	return &domainTrie{children: make(map[string]*domainTrie)}
}

func (t *domainTrie) add(domain string) {
	if domain == "" {
		return
	}
	labels := strings.Split(domain, ".")
	cur := t
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		child, ok := cur.children[label]
		if !ok {
			child = newDomainTrie()
			cur.children[label] = child
		}
		cur = child
	}
	cur.terminal = true
}

func (t *domainTrie) matchSuffix(domain string) bool {
	if domain == "" {
		return false
	}
	labels := strings.Split(domain, ".")
	cur := t
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

func (t *domainTrie) matchExact(domain string) bool {
	if domain == "" {
		return false
	}
	labels := strings.Split(domain, ".")
	cur := t
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		child, ok := cur.children[label]
		if !ok {
			return false
		}
		cur = child
	}
	return cur.terminal
}
