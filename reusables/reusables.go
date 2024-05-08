package reusables

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// * Data struct contains the registry, file and other data that can be used to identify a VM.
type Data struct {
	Vbox struct {
		RegistryKeys []struct {
			RegPath  string `json:"regPath"`
			RegKey   string `json:"regKey"`
			RegValue string `json:"regValue"`
		} `json:"registryKeys"`
	} `json:"vbox"`
}

// * This instance of Data will contain data from the "data.json" file.
var S Data

// LoadJson will load the file "vmdetect_data.json" into the S instance.
func (s *Data) LoadJson() {
	jsonFile := "vmdetect_data.json"
	if FileAccessible(jsonFile) {
		f, _ := os.ReadFile(jsonFile)
		err := json.Unmarshal(f, &s)
		ErrCheck(err)

	}
}

// TODO: Implement concurrency to LogWriter and QueryReg
// QueryReg parses important registry keys which can be used to differentiate between virtual machines and normal operating systems.
func QueryReg(hive registry.Key, path, key, checkFor string) bool {
	// Openning the key
	k, err := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if err != nil {
		LogWriter(fmt.Sprintf("OpenKey from Key: %s returned error: %s", key, err))
		return false
	}
	defer k.Close()

	// Getting the value
	v, _, err := k.GetStringValue(key)
	if err != nil {
		LogWriter(fmt.Sprintf("GetStringValue from Key: %s returned error: %s", key, err))
		return false
	}
	if strings.Contains(v, checkFor) {
		LogWriter(fmt.Sprintf("Key: %s With Value: %s", key, v))
		return true
	}
	return false
}

// LogWriter creates & appends all retrieved data to a file named vmdetect_log.txt in the current working directory.
func LogWriter(value string) {
	logFile := "./vmdetect_log.txt"
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE, 0600)

	now := time.Now()

	w := bufio.NewWriter(f)
	w.WriteString(fmt.Sprintf("%s - %s \n", now.Format("02/01/2005 15:04:05 MST"), value))
	w.Flush()
	time.Sleep(time.Second)
}

// FileAccessible is used to check if a file is accessible or not. mostly utilized to check if the "vmdetect_data.json" exists or not.
func FileAccessible(path string) bool {
	if _, err := os.Stat(path); err == nil {
		LogWriter(fmt.Sprintf("Accessing File: %s Returned: Successful", path))
		return true
	} else {
		LogWriter(fmt.Sprintf("Accessing File: %s Returned: %s", path, err))
		return false
	}
}

// func DownloadFile(url, path string) bool {

// }

// ErrCheck just checks if an error is not nil, in which case it logs the error to stdout.
func ErrCheck(err error) {
	if err != nil {
		log.Println(err)
	}
}
