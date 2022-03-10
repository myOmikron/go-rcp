package gorcp

import (
	"crypto/sha512"
	"fmt"
	"sort"
	"strconv"
	"time"
)

type RCPConfig struct {
	UseTimeComponent bool
	SharedSecret     string
}

func GetChecksum(request *map[string]string, salt string, config *RCPConfig) (checksum string) {
	var currentTimestamp int64
	if config.UseTimeComponent {
		currentTimestamp = time.Now().UTC().Unix()
	}

	// Create sorted slice of keys
	keys := make([]string, 0, len(*request))
	for _, k := range *request {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var builder string
	for _, k := range keys {
		// Append key + value
		builder += k + (*request)[k]
	}

	// Append shared secret
	builder += config.SharedSecret

	if config.UseTimeComponent {
		// Append timestamp
		builder += strconv.FormatInt(currentTimestamp, 64)
	}

	// Prefix with salt
	builder = salt + builder

	hash := sha512.New()
	hashed := hash.Sum([]byte(builder))

	checksum = fmt.Sprintf("%x", hashed)
	return
}
