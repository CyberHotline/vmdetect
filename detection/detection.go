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
	"sync"

	re "github.com/mohabgabber/vmdetect/reusables"
)

// The wait group is used to make sure execution does not end before all routines have finished executing
var G sync.WaitGroup

// C is a buffered channel that will receive the results of the various checks performed against the machine
var C = make(chan bool, 100)

var IsVbox bool
var IsVmware bool
var IsHyberv bool

func IsVM() bool {
	for _, c := range re.S.Vbox.RegistryKeys {
		re.QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue, C)
	}
	for _, c := range re.S.Vbox.Files {
		re.FileAccessible(c)
	}
	for _, c := range re.S.Vbox.Processes {
		re.ProcessEnum(c)
	}
	for _, c := range re.S.Vbox.Services {
		re.ServiceEnum(c)
	}
	return true
}
func VboxCheck()
