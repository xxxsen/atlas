package resolver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/querylog"
)

const cachePersistenceVersion = 2

type persistHeader struct {
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
}

type persistKey struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Qtype     uint16 `json:"qtype"`
	Qclass    uint16 `json:"qclass"`
	UDPSize   uint16 `json:"udp_size,omitempty"`
	Flags     uint8  `json:"flags,omitempty"`
}

type persistRecord struct {
	Key        persistKey       `json:"key"`
	StoredAt   int64            `json:"stored_at"`
	Expire     int64            `json:"expire"`
	StaleUntil int64            `json:"stale_until"`
	Msg        []byte           `json:"msg"`
	Result     *querylog.Result `json:"result,omitempty"`
}

func (c *CacheManager) persist() error {
	targetGeneration := c.generation.Load()
	records := c.snapshot()
	path := filepath.Clean(strings.TrimSpace(c.cfg.File))
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache persistence directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".atlas-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create cache persistence temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set cache persistence permissions: %w", err)
	}
	writer := bufio.NewWriterSize(tmp, 256*1024)
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(persistHeader{Version: cachePersistenceVersion, Fingerprint: c.cfg.Fingerprint}); err != nil {
		return fmt.Errorf("write cache persistence header: %w", err)
	}
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("write cache persistence record: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush cache persistence file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync cache persistence file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cache persistence file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace cache persistence file: %w", err)
	}
	committed = true
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open cache persistence directory for sync: %w", err)
	}
	if err := dirFile.Sync(); err != nil {
		_ = dirFile.Close()
		return fmt.Errorf("sync cache persistence directory: %w", err)
	}
	if err := dirFile.Close(); err != nil {
		return fmt.Errorf("close cache persistence directory: %w", err)
	}
	c.persisted.Store(targetGeneration)
	return nil
}

func (c *CacheManager) snapshot() []persistRecord {
	now := time.Now()
	records := make([]persistRecord, 0)
	for _, shard := range c.shards {
		shard.mu.Lock()
		values := shard.cache.Values()
		for _, entry := range values {
			if now.After(entry.staleUntil) {
				continue
			}
			var result *querylog.Result
			if entry.result != (querylog.Result{}) {
				copy := entry.result
				result = &copy
			}
			records = append(records, persistRecord{
				Key: persistKey{
					Namespace: entry.key.Namespace,
					Name:      entry.key.Name,
					Qtype:     entry.key.Qtype,
					Qclass:    entry.key.Qclass,
					UDPSize:   entry.key.UDPSize,
					Flags:     entry.key.Flags,
				},
				StoredAt:   entry.storedAt.UnixMilli(),
				Expire:     entry.expire.UnixMilli(),
				StaleUntil: entry.staleUntil.UnixMilli(),
				Msg:        entry.data,
				Result:     result,
			})
		}
		shard.mu.Unlock()
	}
	return records
}

func (c *CacheManager) loadFromFile() error {
	path := filepath.Clean(strings.TrimSpace(c.cfg.File))
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat cache persistence file: %w", err)
	}
	maxFileBytes := c.cfg.MaxBytes*2 + c.cfg.Size*2048 + 4096
	if info.Size() > maxFileBytes {
		return fmt.Errorf("cache persistence file is too large: %d bytes (maximum %d)", info.Size(), maxFileBytes)
	}
	maxLineBytes := int(c.cfg.MaxEntryBytes*2 + 4096)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read cache persistence header: %w", err)
		}
		return fmt.Errorf("cache persistence file is empty")
	}
	var header persistHeader
	if err := json.Unmarshal(scanner.Bytes(), &header); err != nil {
		return fmt.Errorf("decode cache persistence header: %w", err)
	}
	if header.Version != cachePersistenceVersion {
		return fmt.Errorf("unsupported cache persistence version %d", header.Version)
	}
	if header.Fingerprint != c.cfg.Fingerprint {
		return fmt.Errorf("cache persistence fingerprint does not match current configuration")
	}
	now := time.Now()
	recordCount := int64(0)
	for scanner.Scan() {
		recordCount++
		if recordCount > c.cfg.Size {
			return fmt.Errorf("cache persistence contains more than %d records", c.cfg.Size)
		}
		var record persistRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("decode cache persistence record: %w", err)
		}
		entry, err := c.decodePersistRecord(record, now)
		if err != nil {
			return err
		}
		if entry == nil {
			continue
		}
		if !c.addEntry(entry) {
			return fmt.Errorf("cache persistence record exceeds its shard budget")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read cache persistence record: %w", err)
	}
	return nil
}

func (c *CacheManager) decodePersistRecord(record persistRecord, now time.Time) (*cacheEntry, error) {
	if len(record.Msg) == 0 || int64(len(record.Msg)) > c.cfg.MaxEntryBytes {
		return nil, fmt.Errorf("cache persistence record exceeds entry bounds")
	}
	key := cacheKey{
		Namespace: record.Key.Namespace,
		Name:      record.Key.Name,
		Qtype:     record.Key.Qtype,
		Qclass:    record.Key.Qclass,
		UDPSize:   record.Key.UDPSize,
		Flags:     record.Key.Flags,
	}
	if strings.TrimSpace(key.Namespace) == "" || strings.TrimSpace(key.Name) == "" {
		return nil, fmt.Errorf("cache persistence record has an invalid key")
	}
	storedAt := time.UnixMilli(record.StoredAt)
	expire := time.UnixMilli(record.Expire)
	staleUntil := time.UnixMilli(record.StaleUntil)
	if expire.Before(storedAt) || staleUntil.Before(expire) {
		return nil, fmt.Errorf("cache persistence record has invalid timestamps")
	}
	if now.After(staleUntil) {
		return nil, nil
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(record.Msg); err != nil {
		return nil, fmt.Errorf("cache persistence record contains invalid DNS data: %w", err)
	}
	if !cacheableResponse(msg) || len(msg.Question) != 1 {
		return nil, fmt.Errorf("cache persistence record contains an uncacheable DNS response")
	}
	question := msg.Question[0]
	if !strings.EqualFold(dns.Fqdn(question.Name), dns.Fqdn(key.Name)) || question.Qtype != key.Qtype || question.Qclass != key.Qclass {
		return nil, fmt.Errorf("cache persistence record question does not match its key")
	}
	entry := &cacheEntry{
		key:        key,
		data:       append([]byte(nil), record.Msg...),
		storedAt:   storedAt,
		expire:     expire,
		staleUntil: staleUntil,
	}
	if record.Result != nil {
		entry.result = record.Result.Sanitized()
	}
	entry.size = cacheEntrySize(entry)
	return entry, nil
}
