package licenselib

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestMockFileEncrypt(t *testing.T) {
	pt := NetworkStr()
	key := StrPad(pt, 32, "a", "RIGHT")
	fmt.Println("Key", key, "Len", len(key))
	features := []string{"user", "dal", "collections"}
	pt = pt + "||" + strconv.FormatInt(time.Now().Unix(), 10) + "||" + strings.Join(features, ",|")
	encrypted := EncryptAES([]byte(key), pt)
	back := DecryptAES([]byte(key), encrypted)
	fmt.Printf("iki \"%s\" Karo \"%s\"\n", pt, back)
	if pt != back {
		t.Error("Not same")
	}
}
