package matcher

import "sort"

type ahoBuildNode struct {
	children map[byte]uint32
	fail     uint32
	output   bool
}

type ahoNode struct {
	edgeStart uint32
	edgeCount uint32
	fail      uint32
	output    bool
}

type ahoEdge struct {
	character byte
	next      uint32
}

// ahoMatcher freezes its construction maps into sorted contiguous edges.
// Matching then performs no allocation and keeps failure links as indexes,
// avoiding one heap object and one map per byte of every keyword.
type ahoMatcher struct {
	building    []ahoBuildNode
	nodes       []ahoNode
	edges       []ahoEdge
	patterns    int
	constructed bool
}

func newAhoMatcher() *ahoMatcher {
	return &ahoMatcher{building: []ahoBuildNode{{}}}
}

func (a *ahoMatcher) add(pattern string) {
	if pattern == "" {
		return
	}
	if a.constructed {
		panic("cannot add an Aho pattern after the matcher is frozen")
	}
	current := uint32(0)
	for i := 0; i < len(pattern); i++ {
		node := &a.building[current]
		if node.children == nil {
			node.children = make(map[byte]uint32)
		}
		next, ok := node.children[pattern[i]]
		if !ok {
			next = uint32(len(a.building))
			node.children[pattern[i]] = next
			a.building = append(a.building, ahoBuildNode{})
		}
		current = next
	}
	if !a.building[current].output {
		a.building[current].output = true
		a.patterns++
	}
}

func (a *ahoMatcher) build() {
	if a.constructed {
		return
	}
	queue := make([]uint32, 0)
	for _, child := range a.building[0].children {
		a.building[child].fail = 0
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		current := queue[head]
		for character, child := range a.building[current].children {
			fail := a.building[current].fail
			for fail != 0 {
				if _, ok := a.building[fail].children[character]; ok {
					break
				}
				fail = a.building[fail].fail
			}
			if next, ok := a.building[fail].children[character]; ok && next != child {
				a.building[child].fail = next
			}
			if a.building[a.building[child].fail].output {
				a.building[child].output = true
			}
			queue = append(queue, child)
		}
	}

	a.nodes = make([]ahoNode, len(a.building))
	for index := range a.building {
		building := &a.building[index]
		node := &a.nodes[index]
		node.fail = building.fail
		node.output = building.output
		if len(building.children) == 0 {
			continue
		}
		characters := make([]int, 0, len(building.children))
		for character := range building.children {
			characters = append(characters, int(character))
		}
		sort.Ints(characters)
		node.edgeStart = uint32(len(a.edges))
		node.edgeCount = uint32(len(characters))
		for _, character := range characters {
			ch := byte(character)
			a.edges = append(a.edges, ahoEdge{character: ch, next: building.children[ch]})
		}
	}
	a.building = nil
	a.constructed = true
}

func (a *ahoMatcher) transition(node uint32, character byte) (uint32, bool) {
	item := a.nodes[node]
	edges := a.edges[item.edgeStart : item.edgeStart+item.edgeCount]
	index := sort.Search(len(edges), func(i int) bool { return edges[i].character >= character })
	if index == len(edges) || edges[index].character != character {
		return 0, false
	}
	return edges[index].next, true
}

func (a *ahoMatcher) match(text string) bool {
	if a.patterns == 0 {
		return false
	}
	if !a.constructed {
		a.build()
	}
	current := uint32(0)
	for i := 0; i < len(text); i++ {
		for current != 0 {
			if _, ok := a.transition(current, text[i]); ok {
				break
			}
			current = a.nodes[current].fail
		}
		if next, ok := a.transition(current, text[i]); ok {
			current = next
		}
		if a.nodes[current].output {
			return true
		}
	}
	return false
}
