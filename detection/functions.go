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
package detection

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/shirou/gopsutil/v3/winservices"
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
		Services  []string `json:"services"`
		Mac       []string `json:"mac"`
	} `json:"vbox"`
	Vmware struct {
		RegistryKeys []struct {
			RegPath  string `json:"regPath"`
			RegKey   string `json:"regKey"`
			RegValue string `json:"regValue"`
			Hive     string `json:"hive"`
		} `json:"registryKeys"`
		Files     []string `json:"files"`
		Processes []string `json:"processes"`
		Services  []string `json:"services"`
		Mac       []string `json:"mac"`
	} `json:"vmware"`
}

// * This instance of Data will contain data from the "vmdetect_data.json" file.
var S Data

// LoadJson will load the file "vmdetect_data.json" into the S instance.
func (s *Data) LoadJson() {
	jsonFile := "vmdetect_data.json"
	url := "https://github.com/CyberHotline/vmdetect/raw/main/vmdetect_data.json"
	if getJsonData(jsonFile, url) {
		f, _ := os.ReadFile(jsonFile)
		err := json.Unmarshal(f, &s)
		if err != nil {
			LogWriter(fmt.Sprintf("Loading Json from file \"vmdetect_data.json\" returned error: %s", err))
		}
	} else {
		LogWriter("Unable to access or download \"vmdetect_data.json\" file, please download it manually and place it in the current working directory.")
		os.Exit(1)
	}
}

// countChecks returns the number of checks the program will perform for each VM type. Vbox, Vmware
func (s Data) countChecks() (int, int) {
	vbox := (len(S.Vbox.RegistryKeys) + len(S.Vbox.Files) + len(S.Vbox.Processes) + len(S.Vbox.Services))
	vmware := (len(S.Vmware.RegistryKeys) + len(S.Vmware.Files) + len(S.Vmware.Processes) + len(S.Vmware.Services))
	return vbox, vmware
}

//* Main Functions

// QueryReg parses important registry keys which can be used to differentiate between virtual machines and normal operating systems.
func QueryReg(hive, path, key, checkFor string, m chan bool) {
	defer G.Done()
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
		m <- false
		return
	}
	defer k.Close()

	// Getting the value
	if key == "" && checkFor == "" {
		LogWriter(fmt.Sprintf("Found Registry Path: %s", path))
		m <- true
		return
	} else {
		var buf []byte
		_, _, err := k.GetValue(key, buf)

		if err != nil {
			LogWriter(fmt.Sprintf("GetValue from Key: %s returned error: %s", key, err))
			m <- false
			return
		}
		if strings.Contains(string(buf), checkFor) {
			LogWriter(fmt.Sprintf("Found Key: %s With Value: %s", key, string(buf)))
			m <- true
			return
		}
	}
}

// ProcessEnum enumerates the processes on the system to check if a process relating to a VM exists.
func ProcessEnum(proc string, m chan bool) {
	defer G.Done()
	processes, _ := process.Processes()
	for _, process := range processes {
		if name, _ := process.Name(); proc == strings.ToLower(name) {
			LogWriter(fmt.Sprintf("Found Process: %s", proc))
			m <- true
			return
		}
	}
}

// ServiceEnum enumerates the services on the sytem to check if a service relating to a VM exists.
func ServiceEnum(serv string, m chan bool) {
	defer G.Done()
	services, err := winservices.ListServices()
	if err != nil {
		LogWriter(fmt.Sprintf("ListServices returned error: %s", err))
	}
	for _, c := range services {
		if c.Name == serv {
			LogWriter(fmt.Sprintf("Found Service: %s", c.Name))
			m <- true
			return
		}
	}
}

// FileAccessible is used to check if a file is accessible or not. mainly utilized to check if the "vmdetect_data.json" exists or not, and to see if VM related files exist.
func FileAccessible(path string, m chan bool) {
	defer G.Done()
	if _, err := os.Stat(path); err == nil {
		LogWriter(fmt.Sprintf("Accessing File: %s Returned: Successful", path))
		m <- true
		return
	} else {
		LogWriter(fmt.Sprintf("Accessing File: %s Returned: %s", path, err))
		m <- false
		return
	}
}

// CheckMacAddr compares network interfaces on the device against a known set of default mac addresses used by VM platforms.
func CheckMacAddr(addr string, m chan bool) {
	defer G.Done()
	ifs, err := net.Interfaces()
	if err != nil {
		LogWriter(fmt.Sprintf("Accessing Network Interfaces returned error: %s", err))
		m <- false
		return
	}
	for _, c := range ifs {
		if c.HardwareAddr.String() != "" {
			if strings.ToLower(strings.TrimSpace(c.HardwareAddr.String()[0:8])) == addr {
				LogWriter(fmt.Sprintf("Found interface with mac address: %s", addr))
				m <- true
				return
			}
		}
	}
	m <- false
}

//* Helper Functions

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

// getJsonData checks if the "vmdetect_data.json" exists, if not downloads it to the current working directory.
func getJsonData(path, url string) bool {
	if _, err := os.Stat(path); err == nil {
		LogWriter(fmt.Sprintf("Accessing Json File: %s Returned: Successful", path))
		return true
	} else {
		LogWriter(fmt.Sprintf("Accessing Json File: %s Returned: %s", path, err))

		LogWriter(fmt.Sprintf("Downlaoding Remote File from resource: %s", url))
		f, err := os.Create(path)
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
}
