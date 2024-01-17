package licenselib

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	arrayutils "github.com/AchmadRifai/array-utils"
	getmac "github.com/AchmadRifai/get-mac"
)

func Main() bool {
	fmt.Println("Cok")
	fmt.Println(runtime.GOOS)
	for _, addr := range arrayutils.Filter(getmac.GetMacAddr(), filterAddrLan) {
		fmt.Println("Name", addr.Name)
		fmt.Println("Mac", addr.Mac)
		for _, a := range addr.IpAddrs {
			fmt.Println("Addr", a.Addr, "Network", a.Network)
		}
		fmt.Println()
	}
	for _, addr := range arrayutils.Filter(getmac.GetMacAddr(), filterAddrWifi) {
		fmt.Println("Name", addr.Name)
		fmt.Println("Mac", addr.Mac)
		for _, a := range addr.IpAddrs {
			fmt.Println("Addr", a.Addr, "Network", a.Network)
		}
		fmt.Println()
	}
	yesterday := time.Now().Add(time.Hour * -24)
	if yesterday.Before(time.Now()) {
		fmt.Println("Yesterday before now")
	} else {
		fmt.Println("Now before yesterday")
	}
	checking()
	return true
}

func checking() {
	features := []string{"features1", "features2"}
	license := "60:14:b3:6c:17:bf||192.168.1.18/24||2024-01-18||features1,|features2"
	data := strLisenceToData(license)
	if arrayutils.NoneOf(getmac.GetMacAddr(), func(inter getmac.NetworkInterface, _ int) bool {
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
	if data.exp.Before(time.Now()) {
		panic(fmt.Errorf("expired license"))
	}
	if arrayutils.AnyOf(features, func(v string, index int) bool {
		return !arrayutils.Contains(data.features, v)
	}) {
		panic(fmt.Errorf("invalid license"))
	}
}

func NetworkStr() string {
	addrs := arrayutils.Filter(getmac.GetMacAddr(), filterAddrLan)
	if addrs == nil {
		addrs = arrayutils.Filter(getmac.GetMacAddr(), filterAddrWifi)
	}
	strs := arrayutils.Filter[string](arrayutils.Map(addrs, interToStr), func(v string, index int) bool { return strings.Contains(v, "||") })
	if strs == nil {
		addrs = arrayutils.Filter(getmac.GetMacAddr(), filterAddrWifi)
		strs = arrayutils.Filter[string](arrayutils.Map(addrs, interToStr), func(v string, index int) bool { return strings.Contains(v, "||") })
	}
	if strs == nil {
		panic(fmt.Errorf("network interface not found"))
	}
	return strs[0]
}

func interToStr(inter getmac.NetworkInterface, _ int) string {
	sa := []string{inter.Mac}
	ips := arrayutils.Map(arrayutils.Filter(inter.IpAddrs, func(addr getmac.NetworkAddress, v int) bool {
		return len(strings.Split(addr.Network, ".")) > 1
	}), func(addr getmac.NetworkAddress, v int) string {
		return addr.Network
	})
	if ips != nil {
		sa = append(sa, ips[0])
	}
	return strings.Join(sa, "||")
}

func filterAddrLan(addr getmac.NetworkInterface, v int) bool {
	next := false
	if runtime.GOOS == "windows" {
		next = strings.HasPrefix(addr.Name, "Local Area")
	} else {
		prefixes := []string{"enp", "eth"}
		next = arrayutils.AnyOf(prefixes, func(s string, _ int) bool { return strings.HasPrefix(addr.Name, s) })
	}
	return arrayutils.Contains(addr.Flags, "broadcast") && next
}

func filterAddrWifi(addr getmac.NetworkInterface, v int) bool {
	next := false
	if runtime.GOOS == "windows" {
		next = strings.HasPrefix(addr.Name, "Wi-Fi")
	} else {
		next = strings.HasPrefix(addr.Name, "wl")
	}
	return arrayutils.Contains(addr.Flags, "broadcast") && next
}
