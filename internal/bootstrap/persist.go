package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/xxxsen/common/logutil"
	"go.uber.org/zap"
)

type checkpointEntry struct {
	Domain string `json:"domain"`
	Wire   string `json:"wire"`
	Fresh  int64  `json:"fresh_until"`
	Stale  int64  `json:"stale_until"`
}

type checkpoint struct {
	Schema      int                  `json:"schema"`
	Fingerprint string               `json:"fingerprint"`
	Versions    map[string]watermark `json:"versions"`
	Entries     []checkpointEntry    `json:"entries"`
}

// A sidecar keeps bootstrap signatures and watermarks separate from disposable
// wire-message DNS entries, while using the same checkpoint schedule and policy.
func (m *Manager) checkpointPath() string {
	return m.options.Cache.File + ".bootstrap"
}

func (m *Manager) persistLoop() {
	defer m.tasks.Done()
	ticker := time.NewTicker(m.options.Cache.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.persist(); err != nil {
				logutil.GetLogger(m.ctx).Warn("persist bootstrap checkpoint failed", zap.Error(err))
			}
		}
	}
}

func (m *Manager) persist() error {
	m.mu.Lock()
	generation := m.generation
	if generation == m.persisted {
		m.mu.Unlock()
		return nil
	}
	data := checkpoint{Schema: 1, Fingerprint: m.fingerprint, Versions: make(map[string]watermark, len(m.versions))}
	for name, version := range m.versions {
		data.Versions[name] = version
	}
	now := m.now()
	for _, name := range m.cache.Keys() {
		entry, _ := m.cache.Peek(name)
		if !now.Before(entry.stale) || entry.record.validAt(now, m.config.skew()) != nil {
			continue
		}
		data.Entries = append(data.Entries, checkpointEntry{
			Domain: name, Wire: entry.wire, Fresh: entry.fresh.UnixMilli(), Stale: entry.stale.UnixMilli(),
		})
	}
	m.mu.Unlock()
	path := filepath.Clean(m.checkpointPath())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".atlas-bootstrap-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	// CreateTemp uses 0600; replace only after a complete durable write.
	if err := json.NewEncoder(file).Encode(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	m.mu.Lock()
	m.persisted = generation
	m.mu.Unlock()
	return nil
}

func (m *Manager) load() error {
	file, err := os.Open(m.checkpointPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	limit := m.options.Cache.MaxBytes*2 + 4096
	for name := range m.domains {
		limit += int64(len(name) + 128) // Watermarks survive answer eviction.
	}
	info, err := file.Stat()
	if err != nil || info.Size() > limit {
		return fmt.Errorf("bootstrap checkpoint exceeds its size budget or cannot be read")
	}
	var data checkpoint
	decoder := json.NewDecoder(io.LimitReader(file, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing data in bootstrap checkpoint")
	}
	if data.Schema != 1 || data.Fingerprint != m.fingerprint {
		return fmt.Errorf("bootstrap checkpoint schema or configuration changed")
	}
	if len(data.Versions) > len(m.domains) || int64(len(data.Entries)) > m.options.Cache.Size {
		return fmt.Errorf("bootstrap checkpoint exceeds configured entry count")
	}
	now := m.now()
	for name, version := range data.Versions {
		_, exists := m.domains[name]
		if !exists || version.Version <= 0 || version.Version > now.UnixMilli()+m.config.skew().Milliseconds() || len(version.Digest) != 64 {
			return fmt.Errorf("invalid bootstrap checkpoint version")
		}
	}
	seen := make(map[string]bool)
	for _, saved := range data.Entries {
		if _, exists := m.domains[saved.Domain]; !exists || seen[saved.Domain] {
			return fmt.Errorf("unknown or duplicate bootstrap checkpoint domain")
		}
		seen[saved.Domain] = true
		record, err := authenticate(saved.Wire, saved.Domain, m.keys)
		if err != nil {
			return fmt.Errorf("verify bootstrap checkpoint: %w", err)
		}
		version := data.Versions[saved.Domain]
		if version.Version != record.IssuedAt || version.Digest != record.digest() {
			return fmt.Errorf("bootstrap checkpoint version does not match its signed record")
		}
		// Absolute DNS deadlines cannot be renewed by a process restart or by
		// checkpoint data. Neither fresh nor stale may outlive the signature.
		if saved.Fresh <= 0 || saved.Stale < saved.Fresh || saved.Stale > record.ExpiresAt {
			return fmt.Errorf("invalid bootstrap checkpoint lifetime")
		}
		if now.UnixMilli() >= saved.Stale || record.validAt(now, m.config.skew()) != nil {
			continue
		}
		maxFresh := now.Add(time.Duration(m.config.TTLMax) * time.Second).UnixMilli()
		if saved.Fresh > maxFresh {
			return fmt.Errorf("bootstrap checkpoint TTL exceeds configured maximum")
		}
		maxStale := saved.Fresh
		if m.options.Cache.Lazy {
			maxStale += m.options.Cache.MaxStale.Milliseconds()
		}
		if saved.Stale > maxStale {
			return fmt.Errorf("bootstrap checkpoint stale window exceeds cache policy")
		}
		entry := cachedRecord{
			candidate: candidate{record: record, wire: saved.Wire, fresh: time.UnixMilli(saved.Fresh), source: "checkpoint"},
			stale:     time.UnixMilli(saved.Stale), size: int64(len(saved.Wire) + len(saved.Domain) + 256),
		}
		if entry.size > m.options.Cache.MaxEntryBytes || m.cacheBytes+entry.size > m.options.Cache.MaxBytes {
			return fmt.Errorf("bootstrap checkpoint exceeds cache byte budget")
		}
		m.cache.Add(saved.Domain, entry)
		m.cacheBytes += entry.size
	}
	m.versions = data.Versions
	if m.versions == nil {
		m.versions = make(map[string]watermark)
	}
	return nil
}
