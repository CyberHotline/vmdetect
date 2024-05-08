package vbox

import (
	"fmt"

	re "github.com/mohabgabber/vmdetect/reusables"
	"golang.org/x/sys/windows/registry"
)

func IsVbox() {
	fmt.Println(len(re.S.Vbox.RegistryKeys))
	for _, c := range re.S.Vbox.RegistryKeys {
		fmt.Println(re.QueryReg(registry.LOCAL_MACHINE, c.RegPath, c.RegKey, c.RegValue))
	}
}
