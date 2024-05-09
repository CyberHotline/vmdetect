package vbox

import (
	"fmt"

	re "github.com/mohabgabber/vmdetect/reusables"
)

func IsVbox() {
	fmt.Println(len(re.S.Vbox.RegistryKeys))
	for _, c := range re.S.Vbox.RegistryKeys {
		fmt.Println(re.QueryReg(c.Hive, c.RegPath, c.RegKey, c.RegValue))
	}
}
