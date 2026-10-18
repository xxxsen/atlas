package bootstrap_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCheckpointReverifiesAndDoesNotRenewTTL(t *testing.T) {
	f := newFixture(t, "")
	f.options.Cache.Persist = true
	f.options.Cache.File = filepath.Join(t.TempDir(), "dns-cache.jsonl")
	f.options.Cache.Interval = time.Hour
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), time.Hour)
	var calls atomic.Int64
	upstream := queryFunc{"checkpoint", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		return txtReply(req, 60, wire), nil
	}}
	m := f.manager(upstream)
	if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.options.Cache.File + ".bootstrap"); !os.IsNotExist(err) {
		t.Fatalf("every update must not trigger a synchronous checkpoint: %v", err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.advance(20 * time.Second)
	restored := f.manager(upstream)
	msg, handled, err := lookup(restored, "disk.sendev.cc", dns.TypeA)
	requireAddress(t, msg, handled, err, "1.2.3.4", 40)
	if calls.Load() != 1 {
		t.Fatal("valid saved record not restored")
	}
	if err := restored.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A syntactically valid snapshot is still untrusted address data: changing
	// the signed bytes must discard it and fetch a fresh verified record.
	path := f.options.Cache.File + ".bootstrap"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["entries"].([]any)
	entry := entries[0].(map[string]any)
	saved := entry["wire"].(string)
	parts := strings.Split(saved, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	entry["wire"] = strings.Join(parts, ".")
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(encoded))
	rebuilt := f.manager(upstream)
	if _, _, err := lookup(rebuilt, "disk.sendev.cc", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("tampered checkpoint was used")
	}
}

func TestCheckpointKeepsWatermarkAfterDataExpires(t *testing.T) {
	f := newFixture(t, "")
	f.options.Cache.Persist = true
	f.options.Cache.File = filepath.Join(t.TempDir(), "cache")
	version := f.now().UnixMilli()
	high := f.wire("disk.sendev.cc", "1.2.3.4", version, 2*time.Second)
	low := f.wire("disk.sendev.cc", "2.3.4.5", version-1, time.Hour)
	var replay atomic.Bool
	upstream := queryFunc{"replay", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		if replay.Load() {
			return txtReply(req, 60, low), nil
		}
		return txtReply(req, 60, high), nil
	}}
	m := f.manager(upstream)
	if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	f.advance(3 * time.Second)
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	replay.Store(true)
	restored := f.manager(upstream)
	if _, handled, err := lookup(restored, "disk.sendev.cc", dns.TypeA); !handled || err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("lost persisted watermark for expired answer: %v", err)
	}
}

func TestCheckpointUsesActualTrustedKeysAndAbsoluteExpiry(t *testing.T) {
	for _, tc := range []string{"expired", "key replaced", "corrupt"} {
		t.Run(tc, func(t *testing.T) {
			f := newFixture(t, "")
			f.options.Cache.Persist = true
			f.options.Cache.File = filepath.Join(t.TempDir(), "cache")
			wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), 5*time.Second)
			var offline atomic.Bool
			upstream := queryFunc{"offline", func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
				if offline.Load() {
					return nil, errors.New("offline")
				}
				return txtReply(req, 60, wire), nil
			}}
			m := f.manager(upstream)
			if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
				t.Fatal(err)
			}
			if err := m.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch tc {
			case "expired":
				f.advance(5 * time.Second)
			case "key replaced":
				public, _ := keyPair(t)
				der, err := x509.MarshalPKIXPublicKey(public)
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, f.config.PublicKeys[0], string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
			case "corrupt":
				writeFile(t, f.options.Cache.File+".bootstrap", "{partial write")
			}
			offline.Store(true)
			restored := f.manager(upstream)
			if _, handled, err := lookup(restored, "disk.sendev.cc", dns.TypeA); !handled || err == nil {
				t.Fatal("unusable checkpoint served an address")
			}
		})
	}
}

func TestCheckpointPeriodicWrite(t *testing.T) {
	f := newFixture(t, "")
	f.options.Cache.Persist = true
	f.options.Cache.File = filepath.Join(t.TempDir(), "cache")
	f.options.Cache.Interval = time.Second
	wire := f.wire("disk.sendev.cc", "1.2.3.4", f.now().UnixMilli(), time.Hour)
	m := f.manager(answer(wire, 60))
	if _, _, err := lookup(m, "disk.sendev.cc", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(f.options.Cache.File + ".bootstrap"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("checkpoint timer did not persist")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
