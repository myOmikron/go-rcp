package gorcp

import (
	"crypto/sha512"
	"fmt"
	"sort"
	"time"
)

type RCPConfig struct {
	SharedSecret     string
	UseTimeComponent bool
	TimeDelta        int64
}

func sortKeys(m *map[string]interface{}) (keys []string) {
	keys = make([]string, 0, len(*m))
	for k, _ := range *m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return
}

func ValidateChecksum(m *map[string]interface{}, checksum string, salt string, config *RCPConfig) (b bool) {
	var currentTimestamp int64
	if config.UseTimeComponent {
		currentTimestamp = time.Now().UTC().Unix()
	}

	// Create sorted slice of keys
	keys := sortKeys(m)

	var builder string
	for _, k := range keys {
		// Append key + value
		builder += k + fmt.Sprint((*m)[k])
	}

	// Append shared secret
	builder += config.SharedSecret

	// Prefix with salt
	builder = salt + builder

	h := sha512.New()
	if config.UseTimeComponent {
		for i := -config.TimeDelta; i <= config.TimeDelta; i++ {
			tmpBuilder := builder + fmt.Sprint(currentTimestamp+i)
			h.Reset()
			h.Write([]byte(tmpBuilder))
			hashed := h.Sum(nil)
			if fmt.Sprintf("%x", hashed) == checksum {
				b = true
				break
			}

		}

	} else {
		h.Write([]byte(builder))
		hashed := h.Sum(nil)
		if fmt.Sprintf("%x", hashed) == checksum {
			b = true
		}
	}

	return
}

func GetChecksum(m *map[string]interface{}, salt string, config *RCPConfig) (checksum string) {
	var currentTimestamp int64
	if config.UseTimeComponent {
		currentTimestamp = time.Now().UTC().Unix()
	}

	// Create sorted slice of keys
	keys := sortKeys(m)

	var builder string
	for _, k := range keys {
		// Append key + value
		builder += k + fmt.Sprint((*m)[k])
	}

	// Append shared secret
	builder += config.SharedSecret

	// Prefix with salt
	builder = salt + builder

	if config.UseTimeComponent {
		// Append timestamp
		builder += fmt.Sprint(currentTimestamp)
	}

	// Calculate SHA512
	hash := sha512.New()
	hash.Write([]byte(builder))
	hashed := hash.Sum(nil)

	checksum = fmt.Sprintf("%x", hashed)
	return
}
