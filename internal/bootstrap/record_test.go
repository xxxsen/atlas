package bootstrap_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xxxsen/atlas/internal/bootstrap"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func rawSigned(private ed25519.PrivateKey, payload string) string {
	signature := ed25519.Sign(private, append([]byte("atlas1\x00"), []byte(payload)...))
	return "atlas1." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestRecordRoundTripAndAddressFamilies(t *testing.T) {
	public, private := keyPair(t)
	now := time.UnixMilli(1_800_000_000_000)
	keys := map[string]ed25519.PublicKey{bootstrap.KeyID(public): public}
	for _, tc := range []struct {
		name    string
		a, aaaa []string
	}{
		{"A only", []string{"192.168.50.187", "192.168.50.187", "1.2.3.4"}, nil},
		{"AAAA only", nil, []string{"2001:0db8::1"}},
		{"dual stack", []string{"1.2.3.4"}, []string{"2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bootstrap.Record{Domain: "DiSk.SenDev.CC.", IssuedAt: now.UnixMilli(), ExpiresAt: math.MaxInt64, A: tc.a, AAAA: tc.aaaa}
			aBefore, aaaaBefore := append([]string(nil), input.A...), append([]string(nil), input.AAAA...)
			wire, err := bootstrap.Sign(private, input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := bootstrap.Verify(wire, "disk.sendev.cc.", keys, now, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got.Domain != "disk.sendev.cc" || got.ExpiresAt != math.MaxInt64 || got.KeyID != bootstrap.KeyID(public) {
				t.Fatalf("unexpected signed record: %+v", got)
			}
			if !reflect.DeepEqual(input.A, aBefore) || !reflect.DeepEqual(input.AAAA, aaaaBefore) {
				t.Fatal("signing mutated the caller's address arrays")
			}
			if len(tc.aaaa) != 0 && got.AAAA[0] != "2001:db8::1" {
				t.Fatalf("IPv6 not normalized: %v", got.AAAA)
			}
		})
	}
}

func TestRecordRejectsUntrustedTamperedAndWrongDomain(t *testing.T) {
	public, private := keyPair(t)
	other, _ := keyPair(t)
	now := time.UnixMilli(1_800_000_000_000)
	record := bootstrap.Record{Domain: "disk.sendev.cc", IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).UnixMilli(), A: []string{"1.2.3.4"}}
	wire, err := bootstrap.Sign(private, record)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(wire, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := "atlas1." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), "1.2.3.4", "2.3.4.5", 1))) + "." + parts[2]
	keys := map[string]ed25519.PublicKey{bootstrap.KeyID(public): public}
	for _, tc := range []struct {
		name, wire, domain string
		keys               map[string]ed25519.PublicKey
	}{
		{"tampered addresses", tampered, record.Domain, keys},
		{"wrong domain", wire, "local.sendev.cc", keys},
		{"unknown key", wire, record.Domain, map[string]ed25519.PublicKey{bootstrap.KeyID(other): other}},
		{"wrong version", strings.Replace(wire, "atlas1.", "atlas2.", 1), record.Domain, keys},
		{"padded base64", "atlas1." + parts[1] + "=." + parts[2], record.Domain, keys},
		{"newline in encoding", "atlas1." + parts[1][:10] + "\n" + parts[1][10:] + "." + parts[2], record.Domain, keys},
		{"multiple envelopes", wire + ".extra", record.Domain, keys},
		{"oversized", strings.Repeat("a", 17000), record.Domain, keys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := bootstrap.Verify(tc.wire, tc.domain, tc.keys, now, 0); err == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
}

func TestRecordRejectsAmbiguousSignedJSON(t *testing.T) {
	public, private := keyPair(t)
	now := time.UnixMilli(1_800_000_000_000)
	keys := map[string]ed25519.PublicKey{bootstrap.KeyID(public): public}
	valid := fmt.Sprintf(`{"kid":%q,"domain":"disk.sendev.cc","issued_at":%d,"expires_at":%d,"a":["1.2.3.4"]}`, bootstrap.KeyID(public), now.UnixMilli(), now.Add(time.Hour).UnixMilli())
	for _, payload := range []string{
		strings.Replace(valid, `"domain":`, `"domain":"other.test","domain":`, 1),
		strings.Replace(valid, `"a":`, `"unknown":1,"a":`, 1),
		strings.Replace(valid, `["1.2.3.4"]`, `null`, 1),
		strings.Replace(valid, `["1.2.3.4"]`, `[null]`, 1),
		strings.Replace(valid, fmt.Sprint(now.UnixMilli()), `"1800000000000"`, 1),
		strings.Replace(valid, fmt.Sprint(now.UnixMilli()), `1800000000000.5`, 1),
		valid + `{}`,
		`[]`,
	} {
		if _, err := bootstrap.Verify(rawSigned(private, payload), "disk.sendev.cc", keys, now, 0); err == nil {
			t.Errorf("accepted ambiguous JSON: %s", payload)
		}
	}
}

func TestRecordLifetimeAndInvalidAddresses(t *testing.T) {
	public, private := keyPair(t)
	now := time.UnixMilli(1_800_000_000_000)
	keys := map[string]ed25519.PublicKey{bootstrap.KeyID(public): public}
	record := bootstrap.Record{Domain: "disk.sendev.cc", IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).UnixMilli(), A: []string{"1.2.3.4"}}
	wire, err := bootstrap.Sign(private, record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Verify(wire, record.Domain, keys, now.Add(time.Hour), time.Hour); err == nil {
		t.Fatal("expiry must have no grace period")
	}
	if _, err := bootstrap.Verify(wire, record.Domain, keys, now.Add(-31*time.Second), 30*time.Second); err == nil {
		t.Fatal("accepted future timestamp outside skew")
	}
	if _, err := bootstrap.Verify(wire, record.Domain, keys, now.Add(-30*time.Second), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ a, aaaa []string }{
		{}, {[]string{"2001:db8::1"}, nil}, {nil, []string{"1.2.3.4"}},
		{nil, []string{"::ffff:1.2.3.4"}}, {nil, []string{"fe80::1%eth0"}}, {[]string{"invalid"}, nil},
	} {
		bad := record
		bad.A, bad.AAAA = tc.a, tc.aaaa
		if _, err := bootstrap.Sign(private, bad); err == nil {
			t.Errorf("accepted invalid addresses: %+v", tc)
		}
	}
}
