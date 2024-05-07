package reusables

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

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
	w.WriteString(fmt.Sprintf("%s %s \n", now.Format("02/01/2005 15:04:05 MST"), value))
	w.Flush()
}

// ErrCheck just checks if an error is not nil, in which case it logs the error to stdout.
func ErrCheck(err error) {
	if err != nil {
		log.Println(err)
	}
}
