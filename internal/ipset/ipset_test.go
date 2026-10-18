package ipset

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSet(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ips.txt")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNamedSetsNormalizePrefixesAndUnionWithNetworks(t *testing.T) {
	file := writeSet(t, "# IP ranges\n192.0.2.17/25 # host bits allowed\n192.0.2.0/25\n\n2001:db8::1/127\n::ffff:198.51.100.9/120\n")
	r, err := Load([]Config{{Name: "cn", Files: []string{file, file}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.sets["cn"].prefixes); got != 3 {
		t.Fatalf("expected 3 normalized unique prefixes, got %d", got)
	}
	v, err := r.Compile(ValidationConfig{IPSets: []string{"cn"}, Networks: []string{"private"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"192.0.2.0", "192.0.2.127", "::ffff:192.0.2.1", "198.51.100.255", "2001:db8::", "2001:db8::1", "10.255.255.255", "fc00::1"} {
		if !v.Allows(netip.MustParseAddr(raw)) {
			t.Errorf("rejected %s", raw)
		}
	}
	for _, raw := range []string{"192.0.1.255", "192.0.2.128", "198.51.101.0", "2001:db8::2", "11.0.0.0", "fe80::1", "fe80::1%eth0"} {
		if v.Allows(netip.MustParseAddr(raw)) {
			t.Errorf("accepted %s", raw)
		}
	}
	if v.Allows(netip.Addr{}) {
		t.Fatal("accepted invalid address")
	}
}

func TestBuiltinNetworkBoundaries(t *testing.T) {
	tests := []struct {
		name string
		yes  []string
		no   []string
	}{
		{"private", []string{"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255", "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}, []string{"9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "fbff::1", "fe00::"}},
		{"loopback", []string{"127.0.0.0", "127.255.255.255", "::1", "::ffff:127.0.0.1"}, []string{"126.255.255.255", "128.0.0.0", "::", "::2"}},
		{"link_local", []string{"169.254.0.0", "169.254.255.255", "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}, []string{"169.253.255.255", "169.255.0.0", "fe7f::1", "fec0::", "ff02::1"}},
		{"shared", []string{"100.64.0.0", "100.127.255.255", "::ffff:100.64.0.1"}, []string{"100.63.255.255", "100.128.0.0", "::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *Registry
			v, err := r.Compile(ValidationConfig{Networks: []string{tt.name}})
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range tt.yes {
				if !v.Allows(netip.MustParseAddr(raw)) {
					t.Errorf("rejected boundary %s", raw)
				}
			}
			for _, raw := range tt.no {
				if v.Allows(netip.MustParseAddr(raw)) {
					t.Errorf("accepted outside boundary %s", raw)
				}
			}
		})
	}
}

func TestEmptySetsAndStrictDeclarations(t *testing.T) {
	r, err := Load([]Config{{Name: "empty"}, {Name: "empty-file", Files: []string{writeSet(t, "\n# no ranges\n")}}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.Compile(ValidationConfig{IPSets: []string{"empty", "empty-file"}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Allows(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("empty set accepted an address")
	}
	for _, cfg := range []ValidationConfig{{}, {IPSets: []string{}}, {IPSets: []string{"missing"}}, {IPSets: []string{""}}, {Networks: []string{"reserved"}}, {Networks: []string{""}}} {
		if _, err := r.Compile(cfg); err == nil {
			t.Errorf("accepted invalid validation: %+v", cfg)
		}
	}
	for _, configs := range [][]Config{
		{{Name: ""}}, {{Name: "bad name"}}, {{Name: "same"}, {Name: "same"}}, {{Name: "cn", Files: []string{" "}}},
		{{Name: "cn", Files: []string{filepath.Join(t.TempDir(), "missing")}}},
	} {
		if _, err := Load(configs); err == nil {
			t.Errorf("accepted invalid sets: %+v", configs)
		}
	}
}

func TestInvalidCIDRsReportFileAndLine(t *testing.T) {
	for _, invalid := range []string{"1.2.3.4", "1.2.3.4/33", "example.com/24", "::ffff:1.2.3.4/80", "1.2.3.0/24 2.3.4.0/24"} {
		path := writeSet(t, "# comment\n"+invalid+"\n")
		if _, err := Load([]Config{{Name: "bad", Files: []string{path}}}); err == nil || !strings.Contains(err.Error(), path+":2:") {
			t.Errorf("missing file and line for %q: %v", invalid, err)
		}
	}
}
