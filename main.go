package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	etherP := layers.Ethernet{}
	ipv4P := layers.IPv4{}
	ipv6P := layers.IPv6{}
	tcpP := layers.TCP{}
	udpP := layers.UDP{}
	icmpv4P := layers.ICMPv4{}
	icmpv6P := layers.ICMPv6{}
	arpP := layers.ARP{}
	frame := make([]byte, 1500)
	decoded := []gopacket.LayerType{}
	for {
		_, err := iface.Read(frame)
		if err != nil {
			log.Fatal("read:", err)
		}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &etherP, &ipv4P, &ipv6P, &tcpP, &udpP, &icmpv4P, &icmpv6P, &arpP)
		parser.IgnoreUnsupported = true
		err = parser.DecodeLayers(frame, &decoded)
		if err != nil {
			log.Fatal("parse:", err)
		}
		for _, v := range decoded {
			switch v {
			case layers.LayerTypeTCP:
				log.Printf("tcp %v -> %v\n", tcpP.SrcPort, tcpP.DstPort)
			case layers.LayerTypeEthernet:
				log.Println("ether type:", etherP.EthernetType)
			case layers.LayerTypeIPv4:
				log.Printf("ipv4 %v -> %v\n", ipv4P.SrcIP, ipv4P.DstIP)
			case layers.LayerTypeUDP:
				log.Printf("udp %v -> %v", udpP.SrcPort, udpP.DstPort)
			}
		}
	}

}
