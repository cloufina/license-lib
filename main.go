package licenselib

import (
	"fmt"
	"runtime"
	"strings"

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
	return true
}

func NetworkStr() string {
	addrs := arrayutils.Filter(getmac.GetMacAddr(), filterAddrLan)
	if addrs == nil {
		addrs = arrayutils.Filter(getmac.GetMacAddr(), filterAddrWifi)
	}
	if addrs == nil {
		panic(fmt.Errorf("network interface not found"))
	}
	return arrayutils.Filter[string](arrayutils.Map(addrs, interToStr), func(v string, index int) bool { return strings.Contains(v, "||") })[0]
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
