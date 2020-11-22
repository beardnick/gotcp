// +build linux

package main

import (
	"fmt"
	"gotcp/tcp"
	"gotcp/tuntap"
	"log"
	"time"
)

func main() {
	dev := "mytun"
	//net, err := tuntap.NewTap(dev)
	net, err := tuntap.NewTun(dev)
	if err != nil {
		log.Fatal(err)
	}
	err = tuntap.SetIp(dev, "192.168.1.1/24")
	if err != nil {
		log.Fatal(err)
	}
	err = tuntap.SetUpLink(dev)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("net:", net)
	conn, err := tcp.Accept(net)
	if err != nil {
		return
	}
	<-time.After(time.Second * 10)
	fmt.Println("conn:", conn)
	tuntap.Close(net)
}
