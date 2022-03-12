# gorcp
![Coverage](https://img.shields.io/badge/Coverage-100.0%25-brightgreen)

Implemention of [RCP](https://github.com/myOmikron/rcp) in go

## Usage


```go
// Config is used to create a checksum as well as validate a checksum
config := &RCPConfig{
  UseTimeComponent: true,
  SharedSecret:     "Shared Secret Key",
  TimeDelta:        5,
}

m := make(map[string]string)
m["key1"] = "value1"
m["key2"] = "value2"

// Get the checksum for a given dictionary
checksum := GetChecksum(&m, "TestSalt", config) 

// Validate a given checksum
if !ValidateChecksum(&m, checksum, "TestSalt", config) {
     fmt.Println("Checksum was incorrect")
}
```
