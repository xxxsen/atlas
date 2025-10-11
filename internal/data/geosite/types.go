package geosite

// DomainType represents the matching type defined in the geosite dataset.
type DomainType int

const (
	DomainTypePlain  DomainType = 0
	DomainTypeRegex  DomainType = 1
	DomainTypeDomain DomainType = 2
	DomainTypeFull   DomainType = 3
)

// Attribute captures optional metadata attached to a domain entry.
type Attribute struct {
	BoolValue *bool
	IntValue  *int64
}

// Domain is a single entry inside a geosite category.
type Domain struct {
	Type       DomainType
	Value      string
	Attributes map[string]Attribute
}

// Data contains all categories decoded from a geosite dataset.
type Data struct {
	categories map[string][]Domain
}

func newData(entries map[string][]Domain) *Data {
	return &Data{categories: entries}
}

// Domains returns all domain entries for the given category.
func (d *Data) Domains(category string) ([]Domain, bool) {
	if d == nil {
		return nil, false
	}
	items, ok := d.categories[category]
	return items, ok
}
