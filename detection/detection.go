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

var IsVbox bool
var IsVmware bool
var IsHyberv bool

func IsVM() {
	// Loading json data into the S instance
	S.LoadJson()

	// Starting Check
	VboxCheck()
	VmwareCheck()

	// Number of operations
	vbno, vmno, hvno := S.countChecks()
	var (
		vbco int
		vmco int
		hvco int
	)
	G.Wait()
	close(VB)
	close(VM)
	close(HV)

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
	fmt.Printf("Results:\n%d of %d\tsuccessful virtualbox checks\n%d of %d\tsuccessful vmware checks\n%d of %d\t successful hyberv checks", vbco, vbno, vmco, vmno, hvco, hvno)
}
func VboxCheck() {
	for _, c := range S.Vbox.Files {
		G.Add(1)
		FileAccessible(c, VB)
	}
	for _, c := range S.Vbox.Processes {
		G.Add(1)
		ProcessEnum(c, VB)
	}
	for _, c := range S.Vbox.Services {
		G.Add(1)
		ServiceEnum(c, VB)
	}
	for _, c := range S.Vbox.RegistryKeys {
		G.Add(1)
		QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue, VB)
	}
}

func VmwareCheck() {
	for _, c := range S.Vmware.Files {
		G.Add(1)
		FileAccessible(c, VM)
	}
	for _, c := range S.Vmware.Processes {
		G.Add(1)
		ProcessEnum(c, VM)
	}
	for _, c := range S.Vmware.Services {
		G.Add(1)
		ServiceEnum(c, VM)
	}
	for _, c := range S.Vmware.RegistryKeys {
		G.Add(1)
		QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue, VM)
	}
}
