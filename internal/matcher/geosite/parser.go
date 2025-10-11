package matcher

import (
	"fmt"
	"strings"
)

func parseGeoSiteList(data []byte) (map[string][]geoDomain, error) {
	result := make(map[string][]geoDomain)
	offset := 0
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return nil, err
		}
		if fieldNum == 1 && wireType == wireTypeLengthDelimited {
			msg, err := readBytes(data, &offset)
			if err != nil {
				return nil, err
			}
			entry, err := parseGeoSite(msg)
			if err != nil {
				return nil, err
			}
			if entry.name == "" {
				continue
			}
			result[entry.name] = append(result[entry.name], entry.domains...)
			continue
		}
		if err := skipField(data, &offset, wireType); err != nil {
			return nil, err
		}
	}
	return result, nil
}

type geoSite struct {
	name    string
	domains []geoDomain
}

func parseGeoSite(data []byte) (*geoSite, error) {
	offset := 0
	entry := &geoSite{}
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return nil, err
		}
		switch fieldNum {
		case 1:
			if wireType != wireTypeLengthDelimited {
				return nil, fmt.Errorf("unexpected wire type %d for GeoSite.country_code", wireType)
			}
			str, err := readString(data, &offset)
			if err != nil {
				return nil, err
			}
			entry.name = strings.ToLower(strings.TrimSpace(str))
		case 2:
			if wireType != wireTypeLengthDelimited {
				return nil, fmt.Errorf("unexpected wire type %d for GeoSite.domain", wireType)
			}
			msg, err := readBytes(data, &offset)
			if err != nil {
				return nil, err
			}
			domain, err := parseGeoDomain(msg)
			if err != nil {
				return nil, err
			}
			entry.domains = append(entry.domains, domain)
		default:
			if err := skipField(data, &offset, wireType); err != nil {
				return nil, err
			}
		}
	}
	return entry, nil
}

func parseGeoDomain(data []byte) (geoDomain, error) {
	offset := 0
	result := geoDomain{
		attributes: make(map[string]domainAttribute),
	}
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return geoDomain{}, err
		}
		switch fieldNum {
		case 1: // type
			if wireType != wireTypeVarint {
				return geoDomain{}, fmt.Errorf("unexpected wire type %d for Domain.type", wireType)
			}
			val, err := readVarint(data, &offset)
			if err != nil {
				return geoDomain{}, err
			}
			result.typ = int(val)
		case 2: // value
			if wireType != wireTypeLengthDelimited {
				return geoDomain{}, fmt.Errorf("unexpected wire type %d for Domain.value", wireType)
			}
			str, err := readString(data, &offset)
			if err != nil {
				return geoDomain{}, err
			}
			result.value = strings.TrimSpace(str)
		case 3: // attribute
			if wireType != wireTypeLengthDelimited {
				return geoDomain{}, fmt.Errorf("unexpected wire type %d for Domain.attribute", wireType)
			}
			msg, err := readBytes(data, &offset)
			if err != nil {
				return geoDomain{}, err
			}
			attr, key, err := parseDomainAttribute(msg)
			if err != nil {
				return geoDomain{}, err
			}
			if key != "" {
				result.attributes[key] = attr
			}
		default:
			if err := skipField(data, &offset, wireType); err != nil {
				return geoDomain{}, err
			}
		}
	}
	if result.value == "" {
		return geoDomain{}, fmt.Errorf("empty domain value")
	}
	return result, nil
}

func parseDomainAttribute(data []byte) (domainAttribute, string, error) {
	offset := 0
	key := ""
	attr := domainAttribute{}
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return domainAttribute{}, "", err
		}
		switch fieldNum {
		case 1:
			if wireType != wireTypeLengthDelimited {
				return domainAttribute{}, "", fmt.Errorf("unexpected wire type %d for Attribute.key", wireType)
			}
			str, err := readString(data, &offset)
			if err != nil {
				return domainAttribute{}, "", err
			}
			key = strings.ToLower(strings.TrimSpace(str))
		case 2:
			if wireType != wireTypeVarint {
				return domainAttribute{}, "", fmt.Errorf("unexpected wire type %d for Attribute.bool_value", wireType)
			}
			val, err := readVarint(data, &offset)
			if err != nil {
				return domainAttribute{}, "", err
			}
			boolean := val != 0
			attr.boolValue = &boolean
		case 3:
			if wireType != wireTypeVarint {
				return domainAttribute{}, "", fmt.Errorf("unexpected wire type %d for Attribute.int_value", wireType)
			}
			val, err := readVarint(data, &offset)
			if err != nil {
				return domainAttribute{}, "", err
			}
			intVal := int64(val)
			attr.intValue = &intVal
		default:
			if err := skipField(data, &offset, wireType); err != nil {
				return domainAttribute{}, "", err
			}
		}
	}
	return attr, key, nil
}

const (
	wireTypeVarint          = 0
	wireTypeSixtyFourBit    = 1
	wireTypeLengthDelimited = 2
	wireTypeStartGroup      = 3
	wireTypeEndGroup        = 4
	wireTypeThirtyTwoBit    = 5
)

func readTag(data []byte, offset *int) (int, int, error) {
	val, err := readVarint(data, offset)
	if err != nil {
		return 0, 0, err
	}
	if val == 0 {
		return 0, 0, fmt.Errorf("invalid tag 0")
	}
	return int(val >> 3), int(val & 0x7), nil
}

func readVarint(data []byte, offset *int) (uint64, error) {
	var value uint64
	var shift uint
	for {
		if *offset >= len(data) {
			return 0, fmt.Errorf("unexpected end of data")
		}
		b := data[*offset]
		*offset++
		value |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 64 {
			return 0, fmt.Errorf("varint overflow")
		}
	}
	return value, nil
}

func readBytes(data []byte, offset *int) ([]byte, error) {
	length, err := readVarint(data, offset)
	if err != nil {
		return nil, err
	}
	if length > uint64(len(data)-*offset) {
		return nil, fmt.Errorf("invalid length %d", length)
	}
	start := *offset
	end := start + int(length)
	*offset = end
	return data[start:end], nil
}

func readString(data []byte, offset *int) (string, error) {
	raw, err := readBytes(data, offset)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func skipField(data []byte, offset *int, wireType int) error {
	switch wireType {
	case wireTypeVarint:
		_, err := readVarint(data, offset)
		return err
	case wireTypeSixtyFourBit:
		return skipBytes(data, offset, 8)
	case wireTypeLengthDelimited:
		b, err := readBytes(data, offset)
		if err != nil {
			return err
		}
		_ = b
		return nil
	case wireTypeStartGroup:
		for {
			fieldNum, nextWire, err := readTag(data, offset)
			if err != nil {
				return err
			}
			if nextWire == wireTypeEndGroup {
				if fieldNum != 0 {
					// Groups are deprecated; expect proper encoding.
				}
				return nil
			}
			if err := skipField(data, offset, nextWire); err != nil {
				return err
			}
		}
	case wireTypeEndGroup:
		return nil
	case wireTypeThirtyTwoBit:
		return skipBytes(data, offset, 4)
	default:
		return fmt.Errorf("unsupported wire type %d", wireType)
	}
}

func skipBytes(data []byte, offset *int, n int) error {
	if *offset+n > len(data) {
		return fmt.Errorf("unexpected end of data")
	}
	*offset += n
	return nil
}
