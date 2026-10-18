package ipset

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func countryFixture(name string) string {
	return filepath.Join("testdata", name+"-Country-Test.mmdb")
}

func TestMMDBCountrySelectionIPv4IPv6AndBoundaries(t *testing.T) {
	for _, edition := range []string{"GeoLite2", "GeoIP2"} {
		t.Run(edition, func(t *testing.T) {
			r, err := Load([]Config{{Name: "cn", Format: formatMaxMindCountry, Files: []string{countryFixture(edition)}, Countries: []string{" cn "}}})
			if err != nil {
				t.Fatal(err)
			}
			v, err := r.Compile(ValidationConfig{IPSets: []string{"cn"}})
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range []string{
				"111.235.160.0", "111.235.163.255", "::ffff:111.235.160.1",
				"2001:250::", "2001:251:ffff:ffff:ffff:ffff:ffff:ffff", "2001:252::1", "2001:254::1", "2001:256::1",
			} {
				if !v.Allows(netip.MustParseAddr(raw)) {
					t.Errorf("rejected CN address %s", raw)
				}
			}
			for _, raw := range []string{
				"111.235.159.255", "111.235.164.0", "175.16.198.255", "175.16.200.0",
				"81.2.69.142", "2001:249::1", "2001:253::1", "2001:258::1", "2001:2e0::1", "1.1.1.1", "10.0.0.1",
			} {
				if v.Allows(netip.MustParseAddr(raw)) {
					t.Errorf("accepted non-CN or unknown address %s", raw)
				}
			}
		})
	}
}

func TestMMDBUsesGeographicalCountryAndUnionsMultipleCountries(t *testing.T) {
	r, err := Load([]Config{
		{Name: "selected", Format: formatMaxMindCountry, Files: []string{countryFixture("GeoIP2")}, Countries: []string{"GB", "SE"}},
		{Name: "registered", Format: formatMaxMindCountry, Files: []string{countryFixture("GeoIP2")}, Countries: []string{"US", "DE"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := r.Compile(ValidationConfig{IPSets: []string{"selected"}})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := r.Compile(ValidationConfig{IPSets: []string{"registered"}})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture registers these in US/DE, but locates them in GB/SE.
	for _, raw := range []string{"81.2.69.142", "2001:220::"} {
		addr := netip.MustParseAddr(raw)
		if !selected.Allows(addr) || registered.Allows(addr) {
			t.Errorf("used registered_country instead of country for %s", raw)
		}
	}
	if selected.Allows(netip.MustParseAddr("111.235.160.1")) {
		t.Fatal("selected countries included CN unexpectedly")
	}
}

func TestMMDBRulesCanBeEmptyAndUnionWithCustomCIDRsAndNetworks(t *testing.T) {
	r, err := Load([]Config{
		{Name: "cn", Format: formatMaxMindCountry, Files: []string{countryFixture("GeoIP2"), countryFixture("GeoIP2")}, Countries: []string{"CN", "cn"}},
		{Name: "absent", Format: formatMaxMindCountry, Files: []string{countryFixture("GeoIP2")}, Countries: []string{"ZZ"}},
		{Name: "extra", Files: []string{writeSet(t, "192.0.2.0/24\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.Compile(ValidationConfig{IPSets: []string{"cn", "extra"}, Networks: []string{"private"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"111.235.160.1", "2001:250::1", "192.0.2.1", "10.0.0.1"} {
		if !v.Allows(netip.MustParseAddr(raw)) {
			t.Errorf("union rejected %s", raw)
		}
	}
	empty, err := r.Compile(ValidationConfig{IPSets: []string{"absent"}})
	if err != nil || empty.Allows(netip.MustParseAddr("111.235.160.1")) {
		t.Fatalf("absent country must produce a valid empty set: %v", err)
	}
}

func TestMMDBConfigurationIsStrict(t *testing.T) {
	for _, cfg := range []Config{
		{Name: "cn", Format: "typo"},
		{Name: "cn", Countries: []string{"CN"}},
		{Name: "cn", Format: "cidr", Countries: []string{"CN"}},
		{Name: "cn", Format: formatMaxMindCountry},
		{Name: "cn", Format: formatMaxMindCountry, Countries: []string{""}},
		{Name: "cn", Format: formatMaxMindCountry, Countries: []string{"CHN"}},
		{Name: "cn", Format: formatMaxMindCountry, Countries: []string{"C1"}},
		{Name: "cn", Format: formatMaxMindCountry, Countries: []string{"中国"}},
	} {
		if _, err := Load([]Config{cfg}); err == nil {
			t.Errorf("accepted invalid config: %+v", cfg)
		}
	}
}

func TestMMDBRejectsDamagedAndIncorrectDatabaseTypes(t *testing.T) {
	data, err := os.ReadFile(countryFixture("GeoIP2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"invalid", []byte("not an MMDB")},
		{"truncated", data[:100]},
		{"wrong type", bytes.ReplaceAll(data, []byte("GeoIP2-Country"), []byte("GeoIP2-Unknown"))},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "country.mmdb")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load([]Config{{Name: "cn", Format: formatMaxMindCountry, Files: []string{path}, Countries: []string{"CN"}}})
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("expected file-specific database error, got %v", err)
			}
		})
	}
}

func TestMMDBSnapshotStaysUsableUntilRestart(t *testing.T) {
	data, err := os.ReadFile(countryFixture("GeoIP2"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	configs := []Config{{Name: "cn", Format: formatMaxMindCountry, Files: []string{path}, Countries: []string{"CN"}}}
	r, err := Load(configs)
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.Compile(ValidationConfig{IPSets: []string{"cn"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !v.Allows(netip.MustParseAddr("111.235.160.1")) {
		t.Fatal("modifying the source file changed the running policy")
	}
	if _, err := Load(configs); err == nil {
		t.Fatal("restart accepted the invalid replacement")
	}
}
