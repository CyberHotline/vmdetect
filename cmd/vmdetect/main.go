package main

import (
	"flag"

	de "github.com/cyberhotline/vmdetect/detection"
)

func main() {
	var (
		vbcheck bool
		vmcheck bool
		ancheck bool
		all     bool
	)
	flag.BoolVar(&vbcheck, "vbchk", false, "Check VirtualBox Artifacts")
	flag.BoolVar(&vmcheck, "vmchk", false, "Check VMware Artifacts")
	flag.BoolVar(&ancheck, "anchk", false, "Check For Analysis Tools and Artifacts")
	flag.BoolVar(&all, "all", false, "Perform All Available Checks")
	flag.Parse()
	de.IsVM(vbcheck, vmcheck, ancheck, all)
}

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
