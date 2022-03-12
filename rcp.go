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

func createHash(builder string, timestamp int64, useTimeStamp bool, c chan<- string) {
	hash := sha512.New()
	if useTimeStamp {
		builder += fmt.Sprint(timestamp)
	}

	hash.Write([]byte(builder))
	hashed := hash.Sum(nil)

	c <- fmt.Sprintf("%x", hashed)
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

	// Prefix with salt
	builder = salt + builder

	if config.UseTimeComponent {
		channel := make(chan string, config.TimeDelta*2+1)
		for i := -config.TimeDelta; i <= config.TimeDelta; i++ {
			func() {
				go createHash(builder, currentTimestamp+i, true, channel)
			}()
		}

		for c := range channel {
			if c == checksum {
				b = true
				break
			}
		}

		close(channel)

	} else {
		c := make(chan string)
		go createHash(builder, 0, false, c)
		b = <-c == checksum
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
