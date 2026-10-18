package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxxsen/atlas/internal/bootstrap"
	"github.com/xxxsen/atlas/internal/ipset"
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

func TestValidationPolicyPreservesLegacyFingerprintWithoutMutatingConfig(t *testing.T) {
	cfg, err := loadText(t, `
resource:
  action:
    - name: cn
      type: forward
      data:
        server_list: ["udp://127.0.0.1:53"]
        parallel: 1
    - name: remote
      type: forward
      data:
        server_list: ["udp://127.0.0.2:53"]
        parallel: 1
rule:
  - match: any
    action: cn
`+bootstrapConfig)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the pre-feature JSON shape, including field order and nulls.
	legacyResource := struct {
		Host    HostConfig      `json:"host"`
		Matcher []MatcherConfig `json:"matcher"`
		Action  []ActionConfig  `json:"action"`
	}{cfg.Resource.Host, cfg.Resource.Matcher, cfg.Resource.Action}
	encoded, err := json.Marshal(struct {
		Resource  any               `json:"resource"`
		Rule      []Rule            `json:"rule"`
		Cache     CacheConfig       `json:"cache"`
		Bootstrap *bootstrap.Config `json:"bootstrap,omitempty"`
	}{legacyResource, cfg.Rule, cfg.Cache, cfg.Bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	legacy := hex.EncodeToString(sum[:])
	before, err := cfg.Fingerprint()
	if err != nil || before != legacy {
		t.Fatalf("legacy fingerprint changed: %s != %s (%v)", before, legacy, err)
	}
	cfg.Resource.IPSet = []ipset.Config{{Name: "cn", Files: []string{"/new/cn.txt"}}}
	data := cfg.Resource.Action[0].Data.(map[string]any)
	data["validate"] = map[string]any{"ip_sets": []string{"cn"}, "networks": []string{"private"}}
	data["fallback"] = "remote"
	after, err := cfg.Fingerprint()
	if err != nil || after != legacy {
		t.Fatalf("validation policy invalidated old cache: %s != %s (%v)", after, legacy, err)
	}
	if _, exists := data["validate"]; !exists || len(cfg.Resource.IPSet) != 1 {
		t.Fatal("fingerprinting modified live configuration")
	}
	data["fallback"] = "another-forward"
	cfg.Resource.IPSet[0].Files[0] = "/migrated/new-cn.txt"
	cfg.Resource.IPSet[0].Format = "maxmind_mmdb"
	cfg.Resource.IPSet[0].Countries = []string{"CN", "HK"}
	if changed, err := cfg.Fingerprint(); err != nil || changed != legacy {
		t.Fatalf("fallback/IP file change invalidated cache: %s (%v)", changed, err)
	}
	data["server_list"] = []string{"udp://127.0.0.3:53"}
	if changed, err := cfg.Fingerprint(); err != nil || changed == legacy {
		t.Fatalf("upstream change failed to invalidate cache: %s (%v)", changed, err)
	}
}

func TestIPSetDeclarationsAreStrictButMayBeEmpty(t *testing.T) {
	for _, declaration := range []string{
		"    - name: cn\n      file: /cn.txt\n",
		"    - name: cn\n    - name: cn\n",
		"    - name: 'bad name'\n",
		"    - name: cn\n      files: ['']\n",
		"    - name: cn\n      format: unsupported\n",
		"    - name: cn\n      format: maxmind_mmdb\n",
		"    - name: cn\n      countries: [CN]\n",
		"    - name: cn\n      format: maxmind_mmdb\n      countries: [CHN]\n",
	} {
		text := strings.Replace(minimalConfig, "resource:\n", "resource:\n  ip_set:\n"+declaration, 1)
		if _, err := loadText(t, text); err == nil {
			t.Errorf("accepted invalid declaration: %s", declaration)
		}
	}
	text := strings.Replace(minimalConfig, "resource:\n", "resource:\n  ip_set:\n    - name: empty\n      files: []\n", 1)
	if _, err := loadText(t, text); err != nil {
		t.Fatalf("empty set should be allowed: %v", err)
	}
	text = strings.Replace(minimalConfig, "resource:\n", `resource:
  ip_set:
    - name: cn
      format: maxmind_mmdb
      files: [/data/GeoLite2-Country.mmdb]
      countries: [CN, HK]
`, 1)
	cfg, err := loadText(t, text)
	if err != nil {
		t.Fatal(err)
	}
	set := cfg.Resource.IPSet[0]
	if set.Format != "maxmind_mmdb" || len(set.Countries) != 2 || set.Countries[0] != "CN" {
		t.Fatalf("GeoIP configuration was not preserved: %+v", set)
	}
}
