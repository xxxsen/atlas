// Package bootstrap resolves explicitly configured names from signed TXT data.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	recordPrefix   = "atlas1."
	signingContext = "atlas1\x00"
	maxRecordBytes = 16 * 1024
)

// Record is the authenticated address set. All timestamps are Unix milliseconds.
// An omitted address family is an empty set, never a request to another resolver.
type Record struct {
	KeyID     string   `json:"kid"`
	Domain    string   `json:"domain"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
	A         []string `json:"a,omitempty"`
	AAAA      []string `json:"aaaa,omitempty"`
}

// KeyID identifies a locally trusted key; no key material is learned from DNS.
func KeyID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// Sign generates one complete TXT value. The caller supplies the signing time
// explicitly so the CLI and tests use precisely the same protocol.
func Sign(key ed25519.PrivateKey, record Record) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("bootstrap signing key must be Ed25519")
	}
	record.KeyID = KeyID(key.Public().(ed25519.PublicKey))
	record.A = slices.Clone(record.A)
	record.AAAA = slices.Clone(record.AAAA)
	if err := record.normalize(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(key, append([]byte(signingContext), payload...))
	wire := recordPrefix + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(wire) > maxRecordBytes {
		return "", fmt.Errorf("bootstrap TXT exceeds %d bytes", maxRecordBytes)
	}
	return wire, nil
}

// Verify checks the exact signed bytes, domain binding, and absolute lifetime.
func Verify(wire, domain string, keys map[string]ed25519.PublicKey, now time.Time, skew time.Duration) (Record, error) {
	record, err := authenticate(wire, domain, keys)
	if err == nil {
		err = record.validAt(now, skew)
	}
	return record, err
}

func authenticate(wire, domain string, keys map[string]ed25519.PublicKey) (Record, error) {
	var record Record
	if len(wire) > maxRecordBytes || !strings.HasPrefix(wire, recordPrefix) {
		return record, fmt.Errorf("invalid bootstrap TXT protocol or size")
	}
	parts := strings.Split(strings.TrimPrefix(wire, recordPrefix), ".")
	if len(parts) != 2 {
		return record, fmt.Errorf("bootstrap TXT requires a payload and signature")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return record, fmt.Errorf("invalid bootstrap payload encoding")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != parts[1] {
		return record, fmt.Errorf("invalid bootstrap signature encoding")
	}
	if err := decodeRecord(payload, &record); err != nil {
		return record, err
	}
	key, ok := keys[record.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return record, fmt.Errorf("bootstrap TXT uses an untrusted key")
	}
	if !ed25519.Verify(key, append([]byte(signingContext), payload...), signature) {
		return record, fmt.Errorf("bootstrap signature verification failed")
	}
	if err := record.normalize(); err != nil {
		return record, err
	}
	expected, err := normalizeDomain(domain)
	if err != nil || record.Domain != expected {
		return record, fmt.Errorf("bootstrap signature domain mismatch")
	}
	return record, nil
}

func decodeRecord(payload []byte, record *Record) error {
	// encoding/json otherwise accepts duplicate keys. Reject ambiguous signed
	// documents as well as unknown fields, trailing JSON, and lossy numbers.
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("bootstrap payload must be a JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode bootstrap field: %w", err)
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return fmt.Errorf("duplicate or invalid bootstrap payload field")
		}
		seen[key] = true
		switch key {
		case "kid", "domain", "issued_at", "expires_at", "a", "aaaa":
		default:
			return fmt.Errorf("unknown bootstrap payload field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("invalid bootstrap payload field %q", key)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("decode bootstrap object: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data in bootstrap payload")
	}
	if err := json.Unmarshal(payload, record); err != nil {
		return fmt.Errorf("decode bootstrap payload: %w", err)
	}
	return nil
}

func (r *Record) normalize() error {
	var err error
	r.Domain, err = normalizeDomain(r.Domain)
	if err != nil {
		return err
	}
	if r.IssuedAt <= 0 || r.ExpiresAt <= r.IssuedAt {
		return fmt.Errorf("bootstrap expires_at must be a Unix millisecond timestamp after issued_at")
	}
	for _, family := range []struct {
		values *[]string
		ipv4   bool
	}{{&r.A, true}, {&r.AAAA, false}} {
		for index, raw := range *family.values {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.Zone() != "" || address.Is4() != family.ipv4 || address.Is4In6() {
				return fmt.Errorf("invalid bootstrap address %q for its address family", raw)
			}
			(*family.values)[index] = address.String()
		}
		slices.Sort(*family.values)
		*family.values = slices.Compact(*family.values)
	}
	if len(r.A)+len(r.AAAA) == 0 {
		return fmt.Errorf("bootstrap record requires at least one A or AAAA address")
	}
	return nil
}

func (r Record) validAt(now time.Time, skew time.Duration) error {
	if now.UnixMilli() >= r.ExpiresAt {
		return fmt.Errorf("bootstrap signature expired")
	}
	if r.IssuedAt > now.UnixMilli()+skew.Milliseconds() {
		return fmt.Errorf("bootstrap signature issued_at is in the future")
	}
	return nil
}

func (r Record) digest() string {
	payload, _ := json.Marshal(r)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
