package action

import (
	"fmt"
	"sort"
	"strings"
)

// ReferencingAction binds shared actions after every action has been created.
// References do not transfer ownership of the referenced action.
type ReferencingAction interface {
	References() []string
	BindReferences(map[string]IDNSAction) error
}

// ResolveReferences validates the entire graph before binding any references.
func ResolveReferences(actions map[string]IDNSAction) error {
	names := make([]string, 0, len(actions))
	for name := range actions {
		names = append(names, name)
	}
	sort.Strings(names)
	state := make(map[string]uint8, len(actions))
	var path []string
	var visit func(string) error
	visit = func(name string) error {
		if state[name] == 1 {
			return fmt.Errorf("action reference cycle: %s", strings.Join(append(path, name), " -> "))
		}
		if state[name] == 2 {
			return nil
		}
		state[name] = 1
		path = append(path, name)
		if source, ok := actions[name].(ReferencingAction); ok {
			for _, target := range source.References() {
				if _, exists := actions[target]; !exists {
					return fmt.Errorf("action %q references undefined action %q", name, target)
				}
				if err := visit(target); err != nil {
					return err
				}
			}
		}
		path = path[:len(path)-1]
		state[name] = 2
		return nil
	}
	for _, name := range names {
		if err := visit(name); err != nil {
			return err
		}
	}
	for _, name := range names {
		if source, ok := actions[name].(ReferencingAction); ok {
			if err := source.BindReferences(actions); err != nil {
				return fmt.Errorf("bind action %q: %w", name, err)
			}
		}
	}
	return nil
}
