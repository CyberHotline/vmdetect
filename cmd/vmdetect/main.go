package main

import (
	re "github.com/mohabgabber/vmdetect/reusables"
	"github.com/mohabgabber/vmdetect/vbox"
)

func main() {
	re.S.LoadJson()
	vbox.IsVbox()
}
