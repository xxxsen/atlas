package matcher

type ahoNode struct {
	children map[byte]*ahoNode
	fail     *ahoNode
	output   bool
}

type ahoMatcher struct {
	root        *ahoNode
	patterns    int
	constructed bool
}

func newAhoMatcher() *ahoMatcher {
	return &ahoMatcher{root: newAhoNode()}
}

func newAhoNode() *ahoNode {
	return &ahoNode{children: make(map[byte]*ahoNode)}
}

func (a *ahoMatcher) add(pattern string) {
	if a == nil || pattern == "" {
		return
	}
	node := a.root
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		child, ok := node.children[ch]
		if !ok {
			child = newAhoNode()
			node.children[ch] = child
		}
		node = child
	}
	if !node.output {
		node.output = true
		a.patterns++
	}
	a.constructed = false
}

func (a *ahoMatcher) build() {
	if a == nil || a.constructed || a.patterns == 0 {
		a.constructed = true
		return
	}
	queue := make([]*ahoNode, 0, len(a.root.children))
	for _, child := range a.root.children {
		child.fail = a.root
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for ch, child := range node.children {
			fail := node.fail
			for fail != nil && fail.children[ch] == nil {
				fail = fail.fail
			}
			if fail == nil {
				child.fail = a.root
			} else {
				child.fail = fail.children[ch]
			}
			if child.fail != nil && child.fail.output {
				child.output = true
			}
			queue = append(queue, child)
		}
	}
	a.constructed = true
}

func (a *ahoMatcher) match(text string) bool {
	if a == nil || a.patterns == 0 {
		return false
	}
	if !a.constructed {
		a.build()
	}
	node := a.root
	for i := 0; i < len(text); i++ {
		ch := text[i]
		for node != a.root && node.children[ch] == nil {
			node = node.fail
		}
		if next := node.children[ch]; next != nil {
			node = next
		} else {
			node = a.root
		}
		if node.output {
			return true
		}
	}
	return false
}
