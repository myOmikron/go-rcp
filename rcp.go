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

func sortKeys(m *map[string]string) (keys []string) {
	keys = make([]string, 0, len(*m))
	for k, _ := range *m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return
}

func ValidateChecksum(m *map[string]string, checksum string, salt string, config *RCPConfig) (b bool) {
	var currentTimestamp int64
	if config.UseTimeComponent {
		currentTimestamp = time.Now().UTC().Unix()
	}

	// Create sorted slice of keys
	keys := sortKeys(m)

	var builder string
	for _, k := range keys {
		// Append key + value
		builder += k + (*m)[k]
	}

	// Append shared secret
	builder += config.SharedSecret

	hash := sha512.New()
	if config.UseTimeComponent {
		for i := -config.TimeDelta; i < config.TimeDelta; i++ {
			// Append timestamp
			timestamp := currentTimestamp + i
			tmpBuilder := builder + fmt.Sprint(timestamp)

			// Prefix with salt
			tmpBuilder = salt + tmpBuilder

			hash.Reset()
			hash.Write([]byte(tmpBuilder))
			hashed := hash.Sum(nil)
			if fmt.Sprintf("%x", hashed) == checksum {
				b = true
				break
			}
		}
	} else {
		// Prefix with salt
		builder = salt + builder

		hash.Write([]byte(builder))
		hashed := hash.Sum(nil)
		b = fmt.Sprintf("%x", hashed) == checksum
	}

	return
}

func GetChecksum(m *map[string]string, salt string, config *RCPConfig) (checksum string) {
	var currentTimestamp int64
	if config.UseTimeComponent {
		currentTimestamp = time.Now().UTC().Unix()
	}

	// Create sorted slice of keys
	keys := sortKeys(m)

	var builder string
	for _, k := range keys {
		// Append key + value
		builder += k + (*m)[k]
	}

	// Append shared secret
	builder += config.SharedSecret

	if config.UseTimeComponent {
		// Append timestamp
		builder += fmt.Sprint(currentTimestamp)
	}

	// Prefix with salt
	builder = salt + builder

	// Calculate SHA512
	hash := sha512.New()
	hash.Write([]byte(builder))
	hashed := hash.Sum(nil)

	checksum = fmt.Sprintf("%x", hashed)
	return
}
