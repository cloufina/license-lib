package licenselib

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	pt, key := "Jajalan sek ya kapan kapan iso kan", "sejamberapa"
	fmt.Println("Key", key, "Len", len(key))
	encrypted := EncryptAES(key, pt)
	fmt.Println("Encrypted", base64.StdEncoding.EncodeToString(encrypted), "Panjang hasil", len(encrypted))
	back := DecryptAES(key, encrypted)
	fmt.Printf("iki \"%s\" Karo \"%s\"\n", pt, back)
	if pt != back {
		t.Error("Not same")
	}
}

func TestNetwrokStr(t *testing.T) {
	net := NetworkStr()
	fmt.Println(net)
	if net == "" {
		t.Error("Kudu ono isine")
	}
}
