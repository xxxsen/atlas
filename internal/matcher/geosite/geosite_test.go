package matcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	geositeprovider "github.com/xxxsen/atlas/internal/data/geosite"
	_ "github.com/xxxsen/atlas/internal/matcher/domain"
)

func testVarint(destination []byte, value uint64) []byte {
	for value >= 0x80 {
		destination = append(destination, byte(value)|0x80)
		value >>= 7
	}
	return append(destination, byte(value))
}

func testBytes(destination []byte, field int, value []byte) []byte {
	destination = testVarint(destination, uint64(field<<3|2))
	destination = testVarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func testString(destination []byte, field int, value string) []byte {
	return testBytes(destination, field, []byte(value))
}

func testInteger(destination []byte, field int, value uint64) []byte {
	destination = testVarint(destination, uint64(field<<3))
	return testVarint(destination, value)
}

func geositeDomain(kind geositeprovider.DomainType, value string, attribute string) []byte {
	var domain []byte
	domain = testInteger(domain, 1, uint64(kind))
	domain = testString(domain, 2, value)
	if attribute != "" {
		var attr []byte
		attr = testString(attr, 1, attribute)
		attr = testInteger(attr, 2, 1)
		domain = testBytes(domain, 3, attr)
	}
	return domain
}

func writeGeositeFixture(t *testing.T) string {
	t.Helper()
	var category []byte
	category = testString(category, 1, "CN")
	category = testBytes(category, 2, geositeDomain(geositeprovider.DomainTypeDomain, "example.cn", "preferred"))
	category = testBytes(category, 2, geositeDomain(geositeprovider.DomainTypeFull, "router.local", ""))
	var data []byte
	data = testBytes(data, 1, category)
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCreateGeositeMatcherWithAttributeFilter(t *testing.T) {
	path := writeGeositeFixture(t)
	item, err := createGeositeMatcher("geo", map[string]any{
		"file":       path,
		"categories": []string{"CN@preferred"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]bool{
		"www.example.cn.": true,
		"router.local.":   false,
		"other.test.":     false,
	} {
		request := new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		matched, err := item.Match(context.Background(), request)
		if err != nil || matched != expected {
			t.Fatalf("%s: matched=%v want=%v err=%v", name, matched, expected, err)
		}
	}
}

func TestGeositeMatcherValidationAndAttributeSemantics(t *testing.T) {
	path := writeGeositeFixture(t)
	if _, err := createGeositeMatcher("strict", map[string]any{"file": path, "category": []string{"cn"}}); err == nil {
		t.Fatal("unknown geosite config key should fail")
	}
	if _, err := createGeositeMatcher("missing", map[string]any{"file": path, "categories": []string{"missing"}}); err == nil {
		t.Fatal("missing category should fail")
	}
	if _, err := createGeositeMatcher("empty", map[string]any{"file": path}); err == nil {
		t.Fatal("empty categories should fail")
	}
	truth := true
	attrs := map[string]geositeprovider.Attribute{"flag": {BoolValue: &truth}}
	if !matchesAttribute(attrs, "flag", false) || matchesAttribute(attrs, "flag", true) {
		t.Fatal("boolean attribute semantics are incorrect")
	}
	if matchesAttribute(nil, "missing", false) || !matchesAttribute(nil, "missing", true) {
		t.Fatal("negated missing-attribute semantics are incorrect")
	}
	spec := parseListSpec(" CN@!Private ")
	if spec.name != "cn" || spec.attr != "private" || !spec.attrNegate {
		t.Fatalf("unexpected list spec: %+v", spec)
	}
}
