/*
VMDetect, a go script to discover virtual environments
Copyright (C) 2024  CyberHotline - Mohab Gabber

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package reusables

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows/registry"
)

// * Data struct contains the registry, file and other data that can be used to identify a VM.
type Data struct {
	Vbox struct {
		RegistryKeys []struct {
			RegPath  string `json:"regPath"`
			RegKey   string `json:"regKey"`
			RegValue string `json:"regValue"`
			Hive     string `json:"hive"`
		} `json:"registryKeys"`
		Files     []string `json:"files"`
		Processes []string `json:"processes"`
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
		if err != nil {
			LogWriter(fmt.Sprintf("Loading Json from file \"vmdetect_data.json\" returned error: %s", err))
		}
	} else {
		url := "https://github.com/CyberHotline/vmdetect/raw/main/vmdetect_data.json"
		name := "vmdetect_data.json"
		if DownloadFile(url, name) {
			s.LoadJson()
		}

	}
}

// TODO: Implement concurrency to LogWriter and QueryReg
// TODO: Add support for multiple registry data types
// QueryReg parses important registry keys which can be used to differentiate between virtual machines and normal operating systems.
func QueryReg(hive, path, key, checkFor string) bool {
	hives := map[string]registry.Key{
		"HKLM": registry.LOCAL_MACHINE,
		"HKCU": registry.CURRENT_USER,
		"HKU":  registry.USERS,
		"HKCC": registry.CURRENT_CONFIG,
	}
	// Openning the key
	k, err := registry.OpenKey(hives[hive], path, registry.QUERY_VALUE)
	if err != nil {
		LogWriter(fmt.Sprintf("OpenKey Path: %s returned error: %s", path, err))
		return false
	}
	defer k.Close()

	// Getting the value
	if key == "" && checkFor == "" {
		LogWriter(fmt.Sprintf("Found Path: %s", path))
		return true
	} else {
		var buf []byte
		_, _, err := k.GetValue(key, buf)

		if err != nil {
			LogWriter(fmt.Sprintf("GetValue from Key: %s returned error: %s", key, err))
			return false
		}
		if strings.Contains(string(buf), checkFor) {
			LogWriter(fmt.Sprintf("Key: %s With Value: %s", key, string(buf)))
			return true
		}
	}
	return false
}

func ProcessEnum(service string) bool {
	processes, _ := process.Processes()
	for _, process := range processes {
		if name, _ := process.Name(); service == strings.ToLower(name) {
			LogWriter(fmt.Sprintf("Found Process: %s", name))
			return true
		}
	}
	return false
}

// LogWriter creates & appends all retrieved data to a file named vmdetect_log.txt in the current working directory.
func LogWriter(value string) {
	logFile := "./vmdetect_log.txt"
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE, 0600)
	defer f.Close()
	now := time.Now()

	w := bufio.NewWriter(f)
	w.WriteString(fmt.Sprintf("%s - %s \n", now.Format("02/01/2006 15:04:05 MST"), value))
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

// DownloadFile downloads a file to the current working directory. Used to donwload the "vmdetect_data.json" file when it is not available locally
func DownloadFile(url, name string) bool {
	go LogWriter(fmt.Sprintf("Downlaoding Remote File from resource: %s", url))
	f, err := os.Create(name)
	if err != nil {
		LogWriter(fmt.Sprintf("Error while downloading json file, %s", err))
	}
	defer f.Close()
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {

		LogWriter("Unable to access remote resource. Terminating")
		os.Exit(1)
	}
	defer resp.Body.Close()
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		LogWriter("Unable to create downloaded file locally. Terminating")
		os.Exit(1)
	}
	return true
}

// ErrCheck just checks if an error is not nil, in which case it logs the error to stdout.
// func ErrCheck(err error) {
// 	if err != nil {
// 		LogWriter(fmt.Sprint(err))
// 	}
// }
