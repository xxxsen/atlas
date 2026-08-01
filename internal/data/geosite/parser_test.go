package geosite

import (
	"os"
	"path/filepath"
	"testing"
)

func appendTestVarint(destination []byte, value uint64) []byte {
	for value >= 0x80 {
		destination = append(destination, byte(value)|0x80)
		value >>= 7
	}
	return append(destination, byte(value))
}

func appendTestBytes(destination []byte, field int, value []byte) []byte {
	destination = appendTestVarint(destination, uint64(field<<3|wireTypeLengthDelimited))
	destination = appendTestVarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func appendTestString(destination []byte, field int, value string) []byte {
	return appendTestBytes(destination, field, []byte(value))
}

func appendTestInt(destination []byte, field int, value uint64) []byte {
	destination = appendTestVarint(destination, uint64(field<<3|wireTypeVarint))
	return appendTestVarint(destination, value)
}

func testAttribute(key string, boolean bool) []byte {
	var data []byte
	data = appendTestString(data, 1, key)
	if boolean {
		data = appendTestInt(data, 2, 1)
	} else {
		data = appendTestInt(data, 2, 0)
	}
	return data
}

func testDomain(kind DomainType, value string, attributes ...[]byte) []byte {
	var data []byte
	data = appendTestInt(data, 1, uint64(kind))
	data = appendTestString(data, 2, value)
	for _, attribute := range attributes {
		data = appendTestBytes(data, 3, attribute)
	}
	return data
}

func testCategory(name string, domains ...[]byte) []byte {
	var data []byte
	// Put domains before the name to verify protobuf field-order independence.
	for _, domain := range domains {
		data = appendTestBytes(data, 2, domain)
	}
	return appendTestString(data, 1, name)
}

func testGeositeData() []byte {
	cn := testCategory("CN",
		testDomain(DomainTypeDomain, "Example.COM"),
		testDomain(DomainTypePlain, "Ads", testAttribute("Tracking", true)),
	)
	private := testCategory("PRIVATE", testDomain(DomainTypeFull, "Router.Local"))
	var data []byte
	data = appendTestBytes(data, 1, cn)
	data = appendTestBytes(data, 1, private)
	return data
}

func TestParseGeoSiteFilteringAttributesAndFieldOrder(t *testing.T) {
	entries, err := parseGeoSiteList(testGeositeData(), map[string]struct{}{"cn": {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(entries["cn"]) != 2 {
		t.Fatalf("unexpected filtered geosite entries: %+v", entries)
	}
	if entries["cn"][0].Value != "example.com" || entries["cn"][0].Attributes != nil {
		t.Fatalf("attribute-free domain should remain compact: %+v", entries["cn"][0])
	}
	attribute, ok := entries["cn"][1].Attributes["tracking"]
	if !ok || attribute.BoolValue == nil || !*attribute.BoolValue {
		t.Fatalf("attribute was not decoded: %+v", entries["cn"][1])
	}
}

func TestProviderLoadsOnlyRequestedCategories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, testGeositeData(), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := NewProvider()
	entries, err := provider.LoadCategories(path, []string{" PRIVATE ", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(entries["private"]) != 1 || entries["private"][0].Value != "router.local" {
		t.Fatalf("unexpected category load: %+v", entries)
	}
	all, err := provider.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if domains, ok := all.Domains("cn"); !ok || len(domains) != 2 {
		t.Fatalf("full provider load failed: %+v", domains)
	}
}

func TestProviderRejectsOversizedDatasetBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-geosite.dat")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxGeositeFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewProvider().LoadCategories(path, []string{"cn"}); err == nil {
		t.Fatal("oversized geosite dataset should be rejected")
	}
}

func TestParseGeoSiteRejectsMalformedData(t *testing.T) {
	for _, data := range [][]byte{{0}, {0x0a, 0x80}, {0x0a, 0x02, 0x08}} {
		if _, err := parseGeoSiteList(data, nil); err == nil {
			t.Fatalf("expected malformed data %x to fail", data)
		}
	}
}

func FuzzParseGeoSiteList(f *testing.F) {
	f.Add(testGeositeData())
	f.Add([]byte{0x0a, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseGeoSiteList(data, map[string]struct{}{"cn": {}})
	})
}
