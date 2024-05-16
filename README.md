# VMDetect
VM detect is a go library that tries to decide whether it is running inside a virtual machine.

Malware analysts can use this if they want to check if malware can detect their virtual environment or not.

## Features
- Checks for the existence of registry keys created by VM platforms
- Checks for applications/files created by VM platforms
- Checks running processes for known VM processes
- Checks registered services on the device for known VM services
- Extendible -> All the checks that are performed, are stored in the [vmdetect_data.json](https://github.com/CyberHotline/vmdetect/blob/main/vmdetect_data.json) if you want to add new artifacts to check for, it is as simple as editing the JSON file
- Automatic -> All you have to do is run the executable, it will download the latest JSON file available, and log all findings in the current working directory
- Uses the power of go routines
- Checks suspicious user desktop for lack of files (COMING SOON)
- Checks the CPUID and other hardware artifacts (COMING SOON)
- Checks running processes for analysis tools that might indicate a virtual environment (COMING SOON)

## Platform Support
VMDetect currently only supports the following platforms:
  - VirtualBox
  - VMware

With support for more platforms coming soon!

## How to use
You can either use the executable found in the "Releases" tab on Github. Or use `go get` to install it and use it within your project
```bash
go get github.com/cyberhotline/vmdetect@latest
go mod tidy
```
The import it into your project, and use the `detection.IsVM()` function, which will take care of everything else
```go
package main

import "github.com/cyberhotline/vmdetect/detection"

func main() {
  detection.IsVM()
}
```

## Contributions
To contribute, fork the repository, and submit a pull request.

All contributions are welcome!

## License
```
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
```
