package vbox

import (
	re "github.com/mohabgabber/vmdetect/reusables"
)

func IsVbox() {
	for _, c := range re.S.Vbox.RegistryKeys {
		re.QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue)
	}
	for _, c := range re.S.Vbox.Files {
		re.FileAccessible(c)
	}
	for _, c := range re.S.Vbox.Processes {
		re.ProcessEnum(c)
	}
}
