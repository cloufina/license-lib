package licenselib

import (
	"fmt"
	"testing"

	getmac "github.com/AchmadRifai/get-mac"
)

func TestMain(t *testing.T) {
	// if !Main() {
	// 	t.Error("Something error")
	// }
}

func TestInit(t *testing.T) {
	// InitTest()
	mac := getmac.GetMacAddr()
	for _, m := range mac {
		fmt.Println(m)
	}
}
