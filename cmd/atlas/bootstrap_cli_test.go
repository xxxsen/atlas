package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxxsen/atlas/internal/bootstrap"
)

func executeCLI(now time.Time, args ...string) (string, error) {
	var output, stderr bytes.Buffer
	cmd := newRootCommand(func() time.Time { return now })
	cmd.SetArgs(args)
	cmd.SetOut(&output)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return output.String(), err
}

func TestBootstrapCLIKeygenSignVerify(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "bootstrap.key"), filepath.Join(dir, "bootstrap.pub")
	if _, err := executeCLI(now, "bootstrap", "keygen", "--private-key", privatePath, "--public-key", publicPath); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(privatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions: info=%v err=%v", info, err)
	}
	if _, err := bootstrap.ReadPrivateKey(privatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.ReadPublicKey(publicPath); err != nil {
		t.Fatal(err)
	}
	wire, err := executeCLI(now, "bootstrap", "sign", "--private-key", privatePath, "--domain", "disk.sendev.cc", "--a", "1.2.3.4", "--a", "192.168.50.187", "--aaaa", "2001:db8::1", "--expires-at", fmt.Sprint(now.Add(365*24*time.Hour).UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(wire, "\n") != 1 || !strings.HasPrefix(wire, "atlas1.") {
		t.Fatalf("sign must output only the complete TXT value: %q", wire)
	}
	decoded, err := executeCLI(now, "bootstrap", "verify", "--public-key", publicPath, "--domain", "disk.sendev.cc", "--record", strings.TrimSpace(wire))
	if err != nil {
		t.Fatal(err)
	}
	var record bootstrap.Record
	if err := json.Unmarshal([]byte(decoded), &record); err != nil {
		t.Fatal(err)
	}
	if record.IssuedAt != now.UnixMilli() || record.Domain != "disk.sendev.cc" || len(record.A) != 2 || len(record.AAAA) != 1 {
		t.Fatalf("bad verified record: %+v", record)
	}
	if _, err := executeCLI(now, "bootstrap", "verify", "--public-key", publicPath, "--domain", "local.sendev.cc", "--record", strings.TrimSpace(wire)); err == nil {
		t.Fatal("verify accepted a different domain")
	}
	original, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeCLI(now, "bootstrap", "keygen", "--private-key", privatePath, "--public-key", publicPath); err == nil {
		t.Fatal("keygen overwrote existing keys")
	}
	after, err := os.ReadFile(privatePath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("existing private key was changed")
	}
	newPrivate := filepath.Join(dir, "must-be-removed.key")
	if _, err := executeCLI(now, "bootstrap", "keygen", "--private-key", newPrivate, "--public-key", publicPath); err == nil {
		t.Fatal("existing public key was overwritten")
	}
	if _, err := os.Stat(newPrivate); !os.IsNotExist(err) {
		t.Fatal("failed keygen left a partial key pair")
	}
}

func TestCobraCLIRejectsBadArgumentsAndSupportsHelp(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	for _, args := range [][]string{
		{"bootstrap", "unknown"},
		{"bootstrap", "keygen"},
		{"bootstrap", "sign", "--expires-at", "2027-01-01"},
		{"bootstrap", "sign", "--valid-for", "24h"},
		{"bootstrap", "sign", "--serial", "42"},
		{"bootstrap", "verify", "extra"},
		{"--version", "extra"},
	} {
		if _, err := executeCLI(now, args...); err == nil {
			t.Errorf("accepted invalid arguments: %v", args)
		}
	}
	for _, args := range [][]string{{"--help"}, {"bootstrap", "--help"}, {"bootstrap", "sign", "--help"}} {
		out, err := executeCLI(now, args...)
		if err != nil || !strings.Contains(out, "Usage:") {
			t.Fatalf("help failed: %v %q", err, out)
		}
	}
	out, err := executeCLI(now, "--version")
	if err != nil || out != fmt.Sprintf("atlas %s (commit %s, built %s)\n", version, commit, buildDate) {
		t.Fatalf("version changed: %q %v", out, err)
	}
	_, err = executeCLI(now, "--config", filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "initialize config") {
		t.Fatalf("legacy --config entry was not dispatched: %v", err)
	}
}

func TestSignExpiresAtRequiresUnixMillisecondsAndAnAddress(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "key"), filepath.Join(dir, "pub")
	if _, err := executeCLI(now, "bootstrap", "keygen", "--private-key", privatePath, "--public-key", publicPath); err != nil {
		t.Fatal(err)
	}
	base := []string{"bootstrap", "sign", "--private-key", privatePath, "--domain", "disk.sendev.cc"}
	for _, tail := range [][]string{
		{"--a", "1.2.3.4"},
		{"--a", "1.2.3.4", "--expires-at", fmt.Sprint(now.Add(time.Hour).Unix())},
		{"--a", "1.2.3.4", "--expires-at", fmt.Sprint(now.UnixMilli())},
		{"--a", "1.2.3.4", "--expires-at", "2027-01-01T00:00:00Z"},
		{"--expires-at", fmt.Sprint(now.Add(time.Hour).UnixMilli())},
	} {
		if _, err := executeCLI(now, append(append([]string(nil), base...), tail...)...); err == nil {
			t.Errorf("accepted invalid signing arguments: %v", tail)
		}
	}
}
