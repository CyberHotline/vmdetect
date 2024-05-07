package vbox

import (
	"fmt"

	re "github.com/mohabgabber/vmdetect/reusables"
	"golang.org/x/sys/windows/registry"
)

type vbox struct {
	registryKeys []struct {
		regPath  string
		regKey   string
		regValue string
	}
}

var VboxRegKeys = []string{"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "SOFTWARE\\VMware, Inc.\\VMware Tools", "HARDWARE\\Description\\System", "SOFTWARE\\Oracle\\VirtualBox Guest Additions", "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "HARDWARE\\ACPI\\DSDT\\VBOX__", "HARDWARE\\ACPI\\FADT\\VBOX__", "HARDWARE\\ACPI\\RSDT\\VBOX__", "SYSTEM\\ControlSet001\\Services\\VBoxGuest", "SYSTEM\\ControlSet001\\Services\\VBoxMouse", "SYSTEM\\ControlSet001\\Services\\VBoxService", "SYSTEM\\ControlSet001\\Services\\VBoxSF", "SYSTEM\\ControlSet001\\Services\\VBoxVideo"}

func IsVbox() {
	for _, c := range VboxRegKeys {
		fmt.Println(re.QueryReg(registry.LOCAL_MACHINE, c, "Identifier", "VMware"))
	}
}
