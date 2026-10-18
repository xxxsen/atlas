package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalConfig = `
resource:
  action:
    - name: answer
      type: rcode
      data:
        code: 0
rule:
  - match: any
    action: answer
`

func loadText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoadAppliesSafeDefaults(t *testing.T) {
	cfg, err := loadText(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bind != "127.0.0.1:5353" || cfg.Server.UDPSize != 4096 || cfg.Server.MaxResponseUDPSize != 1232 || cfg.Server.MaxInflight != 256 || cfg.Server.RequestTimeout != 10 {
		t.Fatalf("unexpected server defaults: %+v", cfg.Server)
	}
	if cfg.Cache.Size != 0 {
		t.Fatalf("cache must remain disabled when size is omitted")
	}
}

func TestLoadRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	if _, err := loadText(t, minimalConfig+"unknown_root: true\n"); err == nil || !strings.Contains(err.Error(), "field unknown_root not found") {
		t.Fatalf("expected strict unknown-field error, got %v", err)
	}
	if _, err := loadText(t, minimalConfig+"---\n{}\n"); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func TestLoadAggregatesUnsafeConfiguration(t *testing.T) {
	text := `
bind: "127.0.0.1:70000"
server:
  max_inflight: -1
  request_timeout: -1
  rate_limit_burst: 2
cache:
  size: 10
  lazy: false
  max_stale: 1
resource:
  matcher:
    - name: any
      type: domain
  action:
    - name: bad name
      type: rcode
rule:
  - match: custom
    action: missing
`
	_, err := loadText(t, text)
	if err == nil {
		t.Fatal("expected validation failure")
	}
	for _, fragment := range []string{
		"port between 1 and 65535",
		"max_inflight",
		"request_timeout",
		"rate_limit_burst requires",
		"max_stale requires",
		"name \"any\" is reserved",
		"unsupported characters",
		"action \"missing\" is not defined",
		"final rule must use match: any",
	} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("validation error %q does not contain %q", err, fragment)
		}
	}
}

func TestLoadRejectsUnreachableRulesAndPprofCollision(t *testing.T) {
	text := `
bind: "127.0.0.1:15353"
pprof:
  enable: true
  bind: "127.0.0.1:15353"
resource:
  action:
    - name: answer
      type: rcode
rule:
  - match: any
    action: answer
  - match: any
    action: answer
`
	_, err := loadText(t, text)
	if err == nil || !strings.Contains(err.Error(), "pprof.bind cannot equal") || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected collision and reachability errors, got %v", err)
	}
}

func TestFingerprintChangesWithPolicy(t *testing.T) {
	first, err := loadText(t, minimalConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadText(t, strings.Replace(minimalConfig, "code: 0", "code: 3", 1))
	if err != nil {
		t.Fatal(err)
	}
	a, err := first.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("policy fingerprint did not change")
	}
}

func TestLoadRequiresPath(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("expected an empty path to fail")
	}
}

func TestDisabledCacheRejectsInertPersistenceFile(t *testing.T) {
	text := "cache:\n  file: cache.jsonl\n" + minimalConfig
	if _, err := loadText(t, text); err == nil || !strings.Contains(err.Error(), "cache options require cache.size > 0") {
		t.Fatalf("expected disabled-cache options to fail, got %v", err)
	}
}

const bootstrapConfig = `
bootstrap:
  server_list:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  files:
    - /config/bootstrap-domains.txt
  public_keys:
    - /config/bootstrap.pub
`

func TestBootstrapConfigDefaultsGlobalKeysAndPolicyFingerprint(t *testing.T) {
	cfg, err := loadText(t, minimalConfig+bootstrapConfig)
	if err != nil {
		t.Fatal(err)
	}
	b := cfg.Bootstrap
	if b == nil || b.Parallel != 2 || b.RequestTimeout != 3 || b.TTLMax != 300 || b.ClockSkew == nil || *b.ClockSkew != 30 || len(b.Files) != 1 || len(b.PublicKeys) != 1 {
		t.Fatalf("unexpected bootstrap defaults: %+v", b)
	}
	before, err := cfg.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	b.PublicKeys = append(b.PublicKeys, "/config/next.pub")
	after, err := cfg.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("bootstrap policy omitted from fingerprint")
	}
	cfg, err = loadText(t, minimalConfig+bootstrapConfig+"  clock_skew: 0\n")
	if err != nil || *cfg.Bootstrap.ClockSkew != 0 {
		t.Fatalf("explicit zero skew was lost: %v", err)
	}
}

func TestBootstrapConfigRejectsOldRecordsAndInvalidBounds(t *testing.T) {
	for _, addition := range []string{"  records: {}\n", "  parallel: 3\n", "  clock_skew: -1\n", "  ttl_max: -1\n", "  request_timeout: 301\n"} {
		if _, err := loadText(t, minimalConfig+bootstrapConfig+addition); err == nil {
			t.Errorf("accepted invalid bootstrap config: %s", addition)
		}
	}
	if _, err := loadText(t, minimalConfig+"bootstrap: {}\n"); err == nil {
		t.Fatal("accepted an empty bootstrap configuration")
	}
}
