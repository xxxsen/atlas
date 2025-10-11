package geosite

import (
	"fmt"
	"strings"
)

func parseGeoSiteList(data []byte, filter map[string]struct{}) (map[string][]Domain, error) {
	result := make(map[string][]Domain)
	offset := 0
	found := 0
	expected := len(filter)
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
			name, domains, include, err := parseGeoSiteFiltered(msg, filter)
			if err != nil {
				return nil, err
			}
			if !include || name == "" {
				if filter != nil && expected > 0 && found >= expected {
					break
				}
				continue
			}
			if _, ok := result[name]; !ok {
				found++
			}
			result[name] = append(result[name], domains...)
			if filter != nil && expected > 0 && found >= expected {
				break
			}
			continue
		}
		if err := skipField(data, &offset, wireType); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func parseGeoSiteFiltered(data []byte, filter map[string]struct{}) (string, []Domain, bool, error) {
	offset := 0
	name := ""
	include := filter == nil
	domains := make([]Domain, 0)
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return "", nil, false, err
		}
		switch fieldNum {
		case 1:
			if wireType != wireTypeLengthDelimited {
				return "", nil, false, fmt.Errorf("unexpected wire type %d for GeoSite.country_code", wireType)
			}
			str, err := readString(data, &offset)
			if err != nil {
				return "", nil, false, err
			}
			name = strings.ToLower(strings.TrimSpace(str))
			if !include && filter != nil {
				if _, ok := filter[name]; ok {
					include = true
				}
			}
		case 2:
			if wireType != wireTypeLengthDelimited {
				return "", nil, false, fmt.Errorf("unexpected wire type %d for GeoSite.domain", wireType)
			}
			msg, err := readBytes(data, &offset)
			if err != nil {
				return "", nil, false, err
			}
			if !include {
				continue
			}
			domain, err := parseGeoDomain(msg)
			if err != nil {
				return "", nil, false, err
			}
			domains = append(domains, domain)
		default:
			if err := skipField(data, &offset, wireType); err != nil {
				return "", nil, false, err
			}
		}
	}
	if name == "" || !include {
		return name, nil, false, nil
	}
	return name, domains, true, nil
}

func parseGeoDomain(data []byte) (Domain, error) {
	offset := 0
	result := Domain{
		Attributes: make(map[string]Attribute),
	}
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return Domain{}, err
		}
		switch fieldNum {
		case 1: // type
			if wireType != wireTypeVarint {
				return Domain{}, fmt.Errorf("unexpected wire type %d for Domain.type", wireType)
			}
			val, err := readVarint(data, &offset)
			if err != nil {
				return Domain{}, err
			}
			result.Type = DomainType(val)
		case 2: // value
			if wireType != wireTypeLengthDelimited {
				return Domain{}, fmt.Errorf("unexpected wire type %d for Domain.value", wireType)
			}
			str, err := readString(data, &offset)
			if err != nil {
				return Domain{}, err
			}
			if result.Type == DomainTypeRegex {
				result.Value = strings.TrimSpace(str)
			} else {
				result.Value = strings.ToLower(strings.TrimSpace(str))
			}
		case 3: // attribute
			if wireType != wireTypeLengthDelimited {
				return Domain{}, fmt.Errorf("unexpected wire type %d for Domain.attribute", wireType)
			}
			msg, err := readBytes(data, &offset)
			if err != nil {
				return Domain{}, err
			}
			attr, key, err := parseDomainAttribute(msg)
			if err != nil {
				return Domain{}, err
			}
			if key != "" {
				result.Attributes[key] = attr
			}
		default:
			if err := skipField(data, &offset, wireType); err != nil {
				return Domain{}, err
			}
		}
	}
	if result.Value == "" {
		return Domain{}, fmt.Errorf("empty domain value")
	}
	return result, nil
}

func parseDomainAttribute(data []byte) (Attribute, string, error) {
	offset := 0
	key := ""
	attr := Attribute{}
	for offset < len(data) {
		fieldNum, wireType, err := readTag(data, &offset)
		if err != nil {
			return Attribute{}, "", err
		}
		switch fieldNum {
		case 1:
			if wireType != wireTypeLengthDelimited {
				return Attribute{}, "", fmt.Errorf("unexpected wire type %d for Attribute.key", wireType)
			}
			str, err := readString(data, &offset)
			if err != nil {
				return Attribute{}, "", err
			}
			key = strings.ToLower(strings.TrimSpace(str))
		case 2:
			if wireType != wireTypeVarint {
				return Attribute{}, "", fmt.Errorf("unexpected wire type %d for Attribute.bool_value", wireType)
			}
			val, err := readVarint(data, &offset)
			if err != nil {
				return Attribute{}, "", err
			}
			boolean := val != 0
			attr.BoolValue = &boolean
		case 3:
			if wireType != wireTypeVarint {
				return Attribute{}, "", fmt.Errorf("unexpected wire type %d for Attribute.int_value", wireType)
			}
			val, err := readVarint(data, &offset)
			if err != nil {
				return Attribute{}, "", err
			}
			intVal := int64(val)
			attr.IntValue = &intVal
		default:
			if err := skipField(data, &offset, wireType); err != nil {
				return Attribute{}, "", err
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
			_, nextWire, err := readTag(data, offset)
			if err != nil {
				return err
			}
			if nextWire == wireTypeEndGroup {
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
