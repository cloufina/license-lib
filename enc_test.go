package licenselib

import (
	"fmt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	pt, key := "Jajalan sek ya kapan kapan iso kan", StrPad("sejamberapa", 32, "a", "RIGHT")
	fmt.Println("Key", key, "Len", len(key))
	encrypted := EncryptAES([]byte(key), pt)
	back := DecryptAES([]byte(key), encrypted)
	fmt.Printf("iki \"%s\" Karo \"%s\"\n", pt, back)
	if pt != back {
		t.Error("Not same")
	}
}
