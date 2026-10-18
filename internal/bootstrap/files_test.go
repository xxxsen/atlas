package bootstrap_test

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xxxsen/atlas/internal/bootstrap"
)

func TestDomainFilesDefaultTargetsCommentsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	one, two := filepath.Join(dir, "one.txt"), filepath.Join(dir, "two.txt")
	writeFile(t, one, "# bootstrap entries\n  Disk.SenDev.CC. # default TXT name\nlocal.sendev.cc : proof.sendev.cc.\n")
	writeFile(t, two, "disk.sendev.cc:_atlas.disk.sendev.cc\nextra.sendev.cc:\n")
	got, err := bootstrap.LoadDomains([]string{one, two})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"disk.sendev.cc": "_atlas.disk.sendev.cc", "local.sendev.cc": "proof.sendev.cc", "extra.sendev.cc": "_atlas.extra.sendev.cc"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	writeFile(t, two, "# conflict\ndisk.sendev.cc:another.test\n")
	if _, err := bootstrap.LoadDomains([]string{one, two}); err == nil || !strings.Contains(err.Error(), two+":2:") {
		t.Fatalf("want conflict with file and line, got %v", err)
	}
}

func TestDomainFilesRejectMalformedAndEmptyLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	for _, text := range []string{"# empty\n", "*.sendev.cc\n", "disk.sendev.cc:bad:target\n", "bad..domain\n", "https://example.test\n", "domain with spaces\n", "disk.sendev.cc:" + strings.Repeat("x", 64) + ".test\n"} {
		writeFile(t, path, text)
		if _, err := bootstrap.LoadDomains([]string{path}); err == nil {
			t.Errorf("accepted malformed list: %q", text)
		}
	}
	if _, err := bootstrap.LoadDomains([]string{path + ".missing"}); err == nil {
		t.Fatal("missing file was ignored")
	}
}
