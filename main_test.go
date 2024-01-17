package licenselib

import (
	"testing"
)

func TestMain(t *testing.T) {
	if !Main() {
		t.Error("Something error")
	}
}
