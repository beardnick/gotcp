// +build linux

package main

import (
	"gotcp/tuntap"
	"log"
)

func main() {
	dev := "mytun"
	tun, err := tuntap.NewTun(dev)
	if err != nil {
		log.Fatal(err)
	}
	err = tuntap.SetIp(dev, "192.168.0.1/24")
	if err != nil {
		log.Fatal(err)
	}
	err = tuntap.SetUpLink(dev)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("tun:", tun)
}
