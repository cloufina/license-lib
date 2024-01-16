package licenselib

import (
	"log"
	"testing"
)

func TestMain(t *testing.T) {
	if !Main() {
		t.Error("Something error")
	}
}

func TestNetworkStr(t *testing.T) {
	str := NetworkStr()
	log.Println("Str", StrPad(str, 32, "a", "RIGHT"))
	if str == "" {
		t.Error("Str must be not empty")
	}
}
