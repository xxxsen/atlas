package hosts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestStoreNormalizesDeduplicatesAndRestrictsClass(t *testing.T) {
	resolver, err := New(map[string]string{
		"Example.COM.": "192.0.2.1,192.0.2.1,2001:db8::1",
	})
	if err != nil {
		t.Fatal(err)
	}
	answers, ok := resolver.Resolve(dns.Question{Name: "example.com.", Qtype: dns.TypeANY, Qclass: dns.ClassINET})
	if !ok || len(answers) != 2 {
		t.Fatalf("expected one unique A and AAAA answer, got %d", len(answers))
	}
	if _, ok := resolver.Resolve(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}); ok {
		t.Fatal("hosts must not synthesize non-IN records")
	}
	if answers[0].Header().Class != dns.ClassINET || answers[0].Header().Ttl != defaultHostTTL {
		t.Fatalf("unexpected host RR header: %+v", answers[0].Header())
	}
}

func TestLoadRecordsSupportsStandardAndLegacyFormats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	content := `
# standard /etc/hosts syntax
192.0.2.10 alpha.test alias.test # inline comment
2001:db8::10 alpha.test

# legacy Atlas syntax remains supported
legacy.test 192.0.2.20 2001:db8::20
192.0.2.10 alpha.test
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := LoadRecordsFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := New(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha.test.", "legacy.test."} {
		answers, ok := resolver.Resolve(dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET})
		if !ok || len(answers) != 2 {
			t.Fatalf("%s: expected A and AAAA, got %d", name, len(answers))
		}
	}
	answers, ok := resolver.Resolve(dns.Question{Name: "alias.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if !ok || len(answers) != 1 {
		t.Fatalf("standard hosts alias was not loaded")
	}
}

func TestLoadRecordsRejectsInvalidInput(t *testing.T) {
	for name, content := range map[string]string{
		"missing value":       "only-a-name\n",
		"bad standard domain": "192.0.2.1 bad..name\n",
		"bad legacy ip":       "example.test definitely-not-an-ip\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hosts")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRecordsFromFile(path); err == nil {
				t.Fatal("expected invalid hosts data to fail")
			}
		})
	}
	if _, err := LoadRecordsFromFile(""); err == nil {
		t.Fatal("expected empty hosts path to fail")
	}
}
