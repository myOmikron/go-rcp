package gorcp

import (
	"testing"
)

func TestSortKeys(t *testing.T) {
	m := make(map[string]interface{})
	if len(sortKeys(&m)) != 0 {
		t.Error("Keys should be empty")
		return
	}
	m["b"] = "3"
	m["a"] = "2"
	sorted := sortKeys(&m)
	if sorted[0] != "a" || sorted[1] != "b" {
		t.Error("Sort failed")
		return
	}
}

func TestValidateChecksum(t *testing.T) {
	config := &RCPConfig{
		UseTimeComponent: false,
		SharedSecret:     "Hallo-123",
		TimeDelta:        5,
	}
	m := make(map[string]interface{})

	// Output of reference implementation:
	// rc_protocol.get_checksum({}, "Hallo-123", use_time_component=False)
	checksum := "477cec82c1c05f7acd42e4c9bd354f3021a59f9a0e8f6cca451c74511a75a8ee0aa4cddcf0a966e91de09b5708d26ce2a7737b65f286a368c87e751135cdc706"
	if !ValidateChecksum(&m, checksum, "", config) {
		t.Error("Not time based, empty map, no salt failed")
		return
	}

	// Output of reference implementation:
	// rc_protocol.get_checksum({"b": "test", "a": " long test"}, "Hallo-123", salt="TestSalt", use_time_component=False)
	checksum = "a85a29e01f295cba43de859a097b6f816826a0ef47bad9d210ab1410cc6ea8490f72a99e62c27b3aefd3b334b1a034d1b8ba1b8b0c6599c27674aeb96cebd591"
	m["b"] = "test"
	m["a"] = " long test"
	if !ValidateChecksum(&m, checksum, "TestSalt", config) {
		t.Error("Not time based, populated map, with salt failed")
		return
	}

	config.UseTimeComponent = true
	checksum = GetChecksum(&m, "TestSalt", config)
	if !ValidateChecksum(&m, checksum, "TestSalt", config) {
		t.Error("Time based, populated map, with salt failed")
		return
	}

}

func TestGetChecksum(t *testing.T) {
	config := &RCPConfig{
		UseTimeComponent: false,
		SharedSecret:     "Hallo-123",
		TimeDelta:        5,
	}
	m := make(map[string]interface{})

	// Output of reference implementation:
	// rc_protocol.get_checksum({}, "Hallo-123", use_time_component=False)
	correct := "477cec82c1c05f7acd42e4c9bd354f3021a59f9a0e8f6cca451c74511a75a8ee0aa4cddcf0a966e91de09b5708d26ce2a7737b65f286a368c87e751135cdc706"
	if GetChecksum(&m, "", config) != correct {
		t.Error("rc_protocol.get_checksum({}, \"Hallo-123\", use_time_component=False) is incorrect")
		return
	}

	// Output of reference implementation:
	// rc_protocol.get_checksum({}, "Hallo-123", salt="TestSalt", use_time_component=False)
	correct = "50acbd16790dc2ebcc246ea9050acf4bee79088d1a9b0a0cd9f812a3b054b7c39e6ce44aa9c6e53b6d31c9d7da527cdd9a85ecaf2f5d007533d4cde289432683"
	if GetChecksum(&m, "TestSalt", config) != correct {
		t.Error("rc_protocol.get_checksum({}, \"Hallo-123\", salt=\"TestSalt\", use_time_component=False) is incorrect")
		return
	}

	// Output of reference implementation:
	// rc_protocol.get_checksum({"b": "test", "a": " long test"}, "Hallo-123", salt="TestSalt", use_time_component=False)
	correct = "a85a29e01f295cba43de859a097b6f816826a0ef47bad9d210ab1410cc6ea8490f72a99e62c27b3aefd3b334b1a034d1b8ba1b8b0c6599c27674aeb96cebd591"
	m["b"] = "test"
	m["a"] = " long test"
	if GetChecksum(&m, "TestSalt", config) != correct {
		t.Error("rc_protocol.get_checksum({\"b\": \"test\", \"a\": \" long test\"}, \"Hallo-123\", salt=\"TestSalt\", use_time_component=False) is incorrect")
		return
	}
}
