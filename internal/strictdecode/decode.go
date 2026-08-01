package strictdecode

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

// Decode maps an untyped YAML data block into a concrete configuration and
// rejects misspelled or unsupported keys.
func Decode(input, output any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused:      true,
		Result:           output,
		TagName:          "json",
		WeaklyTypedInput: true,
		ZeroFields:       true,
	})
	if err != nil {
		return fmt.Errorf("create strict config decoder: %w", err)
	}
	if err := decoder.Decode(input); err != nil {
		return fmt.Errorf("decode config data: %w", err)
	}
	return nil
}
