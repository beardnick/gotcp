// +build linux

package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gotcp/tuntap"
	"log"
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
	//err = tuntap.SetRoute(dev,"192.168.1.0/24")
	//if err != nil {
	//	log.Fatal(err)
	//}
	log.Println("net:", net)
	buf := make([]byte, 1024)
	for {
		n, err := tuntap.Read(net, buf)
		if err != nil {
			log.Fatal(err)
		}
		//log.Printf("pack->\n%x",buf[:n])
		pack := gopacket.NewPacket(
			buf[:n],
			//layers.LayerTypeEthernet,
			layers.LayerTypeIPv4,
			gopacket.Default,
		)
		printPacketInfo(pack)
	}
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("ethernet %v %v -> %v\n", ethernetPacket.EthernetType, ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
	}
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("ip %v %v -> %v\n", ip.Protocol, ip.SrcIP, ip.DstIP)
	}
	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("tcp %v -> %v %v\n", tcp.SrcPort, tcp.DstPort, tcp.Seq)
	}
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Printf("payload:\n%s\n", applicationLayer.Payload())
		// Search for a string inside the payload
		//if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		//	fmt.Println("HTTP found!")
		//}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
