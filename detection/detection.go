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
	"fmt"
	"sync"
)

// The wait group is used to make sure execution does not end before all routines have finished executing
var G sync.WaitGroup

// buffered channels that will receive the results of the various checks performed against the machine
var VB = make(chan bool, 100)
var VM = make(chan bool, 100)
var HV = make(chan bool, 100)

func IsVM() {
	// Loading json data into the S instance
	S.LoadJson()

	// Start Check
	VboxCheck()
	VmwareCheck()

	go func() {
		G.Wait()
		close(VB)
		close(VM)
		close(HV)
	}()
	enumResults()
}
func VboxCheck() {
	for _, c := range S.Vbox.Files {
		G.Add(1)
		go FileAccessible(c, VB)
	}
	for _, c := range S.Vbox.Processes {
		G.Add(1)
		go ProcessEnum(c, VB)
	}
	for _, c := range S.Vbox.Services {
		G.Add(1)
		go ServiceEnum(c, VB)
	}
	for _, c := range S.Vbox.RegistryKeys {
		G.Add(1)
		go QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue, VB)
	}
}

func VmwareCheck() {
	for _, c := range S.Vmware.Files {
		G.Add(1)
		go FileAccessible(c, VM)
	}
	for _, c := range S.Vmware.Processes {
		G.Add(1)
		go ProcessEnum(c, VM)
	}
	for _, c := range S.Vmware.Services {
		G.Add(1)
		go ServiceEnum(c, VM)
	}
	for _, c := range S.Vmware.RegistryKeys {
		G.Add(1)
		go QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue, VM)
	}
}

func enumResults() {
	vbno, vmno, hvno := S.countChecks()
	var (
		vbco int
		vmco int
		hvco int
	)
	for i := range VB {
		if i {
			vbco++
		}
	}
	for i := range VM {
		if i {
			vmco++
		}
	}
	for i := range HV {
		if i {
			hvco++
		}
	}
	LogWriter(fmt.Sprintf("Results:\n%d of %d\tsuccessful virtualbox checks\n%d of %d\tsuccessful vmware checks\n%d of %d\t successful hyberv checks", vbco, vbno, vmco, vmno, hvco, hvno))
	if float64(vbco) >= (30.0/100.0)*float64(vbno) {
		verdictPrint("VM - VirtualBox")
	} else if float64(vmco) >= (30.0/100.0)*float64(vmno) {
		verdictPrint("VM - VMware")
	} else if float64(hvco) >= (30.0/100.0)*float64(hvno) {
		verdictPrint("VM - Hyper-V")
	} else {
		verdictPrint("Not VM")
	}
}

func verdictPrint(text string) {
	LogWriter(fmt.Sprintf("Verdict: %s", text))
	fmt.Printf("Verdict: %s", text)
}
