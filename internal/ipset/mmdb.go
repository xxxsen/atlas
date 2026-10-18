package ipset

import (
	"fmt"
	"io"
	"os"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	maxMMDBBytes    = 256 << 20
	maxMMDBNetworks = 2_000_000
)

// loadMaxMind takes an immutable snapshot, verifies it and extracts only the
// requested geographical countries. Queries use the existing CIDR index; the
// database reader is closed before startup completes.
func (s *prefixSet) loadMaxMind(filename string, countries []string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open MMDB %s: %w", filename, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMMDBBytes+1))
	if err != nil {
		return fmt.Errorf("read MMDB %s: %w", filename, err)
	}
	if len(data) > maxMMDBBytes {
		return fmt.Errorf("%s: MMDB exceeds 256 MiB", filename)
	}
	db, err := maxminddb.OpenBytes(data)
	if err != nil {
		return fmt.Errorf("open MMDB %s: %w", filename, err)
	}
	defer db.Close()
	if err := db.Verify(); err != nil {
		return fmt.Errorf("verify MMDB %s: %w", filename, err)
	}
	switch db.Metadata.DatabaseType {
	case "GeoLite2-Country", "GeoIP2-Country":
	default:
		return fmt.Errorf("%s: expected a MaxMind Country database, got %q", filename, db.Metadata.DatabaseType)
	}
	wanted := make(map[string]bool, len(countries))
	for _, raw := range countries {
		code, err := countryCode(raw)
		if err != nil {
			return err
		}
		wanted[code] = true
	}
	count := 0
	for result := range db.Networks() {
		count++
		if count > maxMMDBNetworks {
			return fmt.Errorf("%s: MMDB exceeds %d networks", filename, maxMMDBNetworks)
		}
		var rawCode string
		if err := result.DecodePath(&rawCode, "country", "iso_code"); err != nil {
			return fmt.Errorf("decode MMDB %s: %w", filename, err)
		}
		if rawCode == "" {
			// Missing country is not a match, even when registered_country
			// identifies an ISP registered in one of the allowed countries.
			continue
		}
		code, err := countryCode(rawCode)
		if err != nil {
			return fmt.Errorf("MMDB %s: %w", filename, err)
		}
		if wanted[code] {
			if err := s.add(result.Prefix()); err != nil {
				return fmt.Errorf("MMDB %s: %w", filename, err)
			}
		}
	}
	return nil
}
