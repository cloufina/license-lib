package licenselib

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"time"

	arrayutils "github.com/AchmadRifai/array-utils"
	getmac "github.com/AchmadRifai/get-mac"
)

func Init(svcName string) {
	defer licenseError()
	if !isFileExists("activation.cl") {
		createActivation()
	}
	if isFileExists("license.cl") {
		checkingLicense(svcName)
	} else {
		panic(fmt.Errorf("please get the license first"))
	}
	time.Sleep(time.Minute)
	go Init(svcName)
}

func checkingLicense(svcName string) {
	content, err := os.ReadFile("license.cl")
	if err != nil {
		panic(err)
	}
	pt := NetworkStr()
	key := StrPad(pt, 32, "c", "RIGHT")
	license := DecryptAES([]byte(key), content)
	data := strLisenceToData(license)
	if !arrayutils.AnyOf(getmac.GetMacAddr(), func(inter getmac.NetworkInterface, _ int) bool {
		if inter.Mac == data.mac {
			ips := arrayutils.Map(arrayutils.Filter(inter.IpAddrs, func(addr getmac.NetworkAddress, v int) bool {
				return len(strings.Split(addr.Network, ".")) > 1
			}), func(addr getmac.NetworkAddress, v int) string {
				return addr.Network
			})
			return arrayutils.Contains(ips, data.ip)
		}
		return false
	}) {
		panic(fmt.Errorf("invalid format license"))
	}
}

func strLisenceToData(lsc string) licenseData {
	var l licenseData
	sa1 := strings.Split(lsc, "||")
	if len(sa1) != 4 {
		panic(fmt.Errorf("invalid license format"))
	}
	l.mac = sa1[0]
	l.ip = sa1[1]
	return l
}

type licenseData struct {
	mac      string
	ip       string
	exp      time.Time
	features []string
}

func createActivation() {
	pt := NetworkStr()
	key := StrPad(pt, 32, "c", "RIGHT")
	encrypted := EncryptAES([]byte(key), pt)
	if err := os.WriteFile("activation.cl", encrypted, 0644); err != nil {
		panic(err)
	}
	panic(fmt.Errorf("please get the license first"))
}

func isFileExists(posisi string) bool {
	_, err := os.Stat(posisi)
	return err != nil
}

func licenseError() {
	if r := recover(); r != nil {
		log.Println("Catched", r)
		log.Println("Stack", string(debug.Stack()))
		os.Exit(0)
	}
}
