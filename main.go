package main

import (
	"log"

	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

// TUN拿到IP帧
// TAP拿到以太网帧

func main() {
	iface, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "mytun",
		},
	})
	if err != nil {
		log.Fatal("create tun failed:", err)
	}
	log.Println("successfully create ", iface.Name())
	var frame ethernet.Frame
	for {
		frame.Resize(15000)
		n, err := iface.Read([]byte(frame))
		if err != nil {
			log.Fatal("read:", err)
		}
		frame = frame[:n]
		log.Printf("% x\n", frame)
		log.Printf("dst mac addr:%s\n", frame.Destination())
		log.Printf("src mac addr:%s\n", frame.Source())
		log.Printf("ethertype: % x\n", frame.Ethertype())
		if frame.Ethertype() == ethernet.IPv4 {
			log.Printf("IPV4")
		}
		if frame.Ethertype() == ethernet.ARP {
			log.Printf("ARP")
		}
	}

}
