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

var IsNext bool
var Features []string

func Init(features []string) {
	defer licenseError()
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if !isFileExists(dir + "/activation.cl") {
		createActivation()
	}
	if isFileExists(dir + "/license.cl") {
		checkingLicense(features)
	} else {
		panic(fmt.Errorf("please get the license first"))
	}
	time.Sleep(time.Hour * 24)
	go Init(features)
}

func checkingLicense(features []string) {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	content, err := os.ReadFile(dir + "/license.cl")
	if err != nil {
		panic(err)
	}
	pt := NetworkStr()
	key := pt
	license := DecryptAES(key, content)
	data := strLicenseToData(license)
	Features = data.features
	if arrayutils.NoneOf(getmac.GetMacAddr(), func(inter getmac.NetworkInterface, _ int) bool {
		if inter.Mac == data.mac {
			ips := arrayutils.Filter(arrayutils.Map(arrayutils.Filter(inter.IpAddrs, func(addr getmac.NetworkAddress, v int) bool {
				return len(strings.Split(addr.Network, ".")) > 1
			}), func(addr getmac.NetworkAddress, v int) string {
				return addr.Network
			}), func(s string, v int) bool { return strings.HasPrefix(s, "192.") })
			return arrayutils.Contains(ips, data.ip)
		}
		return false
	}) {
		panic(fmt.Errorf("invalid format license"))
	}
	if data.exp.Before(time.Now()) {
		panic(fmt.Errorf("expired license"))
	}
	if arrayutils.AllOf(features, func(v string, index int) bool {
		return !arrayutils.Contains(data.features, v)
	}) {
		panic(fmt.Errorf("invalid license"))
	}

	IsNext = true
}

func strLicenseToData(lsc string) licenseData {
	var l licenseData
	sa1 := strings.Split(lsc, "||")
	if len(sa1) != 4 {
		panic(fmt.Errorf("invalid license format"))
	}
	l.mac = sa1[0]
	l.ip = sa1[1]
	exp, err := time.Parse("2006-01-02", sa1[2])
	if err != nil {
		panic(err)
	}
	l.exp = exp
	l.features = strings.Split(sa1[3], ",|")
	return l
}

type licenseData struct {
	mac      string
	ip       string
	exp      time.Time
	features []string
}

func createActivation() {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	pt := NetworkStr()
	key := pt
	encrypted := EncryptAES(key, pt)
	f, err := os.Create(dir + "/activation.cl")
	if err != nil {
		panic(err)
	}
	_, err = f.Write([]byte(encrypted))
	if err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
	f, err = os.Create(dir + "/network.cl")
	if err != nil {
		panic(err)
	}
	_, err = f.WriteString(pt)
	if err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
	panic(fmt.Errorf("please get the license first"))
}

func isFileExists(posisi string) bool {
	_, err := os.Stat(posisi)
	return err == nil
}

func licenseError() {
	if r := recover(); r != nil {
		log.Println("Catched", r)
		log.Println("Stack", string(debug.Stack()))
	}
}
